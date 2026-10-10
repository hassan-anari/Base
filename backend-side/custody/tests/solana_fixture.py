"""Deterministic policy fixtures; local test keys never represent genuine FROST."""

import base64
import copy
import hashlib
import uuid
from decimal import Decimal
from types import SimpleNamespace

from ops.models import Chain, NodeEndpoint
from solders.hash import Hash
from solders.keypair import Keypair

from custody.ledger import ensure_accounts, post_transaction
from custody.models import HotWallet, LedgerAccount, MpcKeyset

CAPS = {
    "max_fee_lamports": "20000",
    "max_ata_rent_lamports": "3000000",
    "native_reserve_lamports": "0",
}


def metadata_for(keyset):
    binding = {
        "session_id": str(uuid.uuid4()),
        "execution_id": str(keyset.dkg_execution_id),
        "keyset_id": str(keyset.keyset_id),
        "algorithm": "FROST_ED25519",
        "curve": "ed25519",
        "scope": "SOLANA",
        "derivation_version": "frost_keyset_v1",
        "threshold": 2,
        "party_count": 3,
        "participants": ["signer-a", "signer-b", "signer-c"],
    }
    receipts = [
        {
            "request": binding,
            "party_id": party,
            "status": "COMPLETED",
            "durable": True,
            "share_format_version": 1,
            "group_public_key": keyset.public_key,
            "public_key_package": [1, 2, 3],
            "verification_share": [i] * 32,
        }
        for i, party in enumerate(binding["participants"], 1)
    ]
    return {
        **binding,
        "status": "COMPLETED",
        "group_public_key": keyset.public_key,
        "result_fingerprint": keyset.dkg_result_fingerprint,
        "participant_agreement": receipts,
    }


def root(seed):
    private = Keypair.from_seed(bytes([seed]) * 32)
    keyset = MpcKeyset(
        keyset_id=uuid.uuid4(),
        algorithm="FROST_ED25519",
        curve="ed25519",
        scope="SOLANA",
        derivation_version="frost_keyset_v1",
        threshold=2,
        party_count=3,
        public_key=bytes(private.pubkey()).hex(),
        dkg_execution_id=uuid.uuid4(),
        dkg_result_fingerprint=hashlib.sha256(bytes(private.pubkey())).hexdigest(),
        participant_identities=["signer-a", "signer-b", "signer-c"],
        status="ACTIVE",
    )
    keyset.dkg_public_evidence = metadata_for(keyset)
    keyset.save()
    return private, keyset


def configure(keyset, address, url="http://127.0.0.1:8899"):
    Chain.objects.filter(chain_id="SOL").update(
        kind="solana",
        is_testnet=True,
        enabled=True,
        native_asset_key="SOL",
        evm_chain_id=None,
        min_confirmations=1,
        gas_settings=CAPS,
        sweep_threshold=Decimal("0.001"),
    )
    NodeEndpoint.objects.filter(chain_id="SOL", kind="rpc").update(enabled=False)
    NodeEndpoint.objects.create(
        chain_id="SOL", name="isolated-sol", kind="rpc", url=url, enabled=True
    )
    HotWallet.objects.update_or_create(
        chain_id="SOL",
        defaults={
            "address": address,
            "mpc_keyset": keyset,
            "signing_key_ref": f"keyset:{keyset.keyset_id}",
        },
    )


def fund(user, asset="SOL", amount=Decimal("10")):
    ensure_accounts(user, asset)
    available = LedgerAccount.objects.get(
        owner_type="USER", owner_id=user, asset_key=asset, bucket="AVAILABLE"
    )
    clearing = LedgerAccount.objects.get(
        owner_type="SYSTEM", owner_id="custody", asset_key=asset, bucket="CUSTODY_CLEARING"
    )
    post_transaction(
        event_key=f"fixture:{user}:{asset}",
        event_type="DEPOSIT_CREDIT",
        asset_key=asset,
        ref_type="fixture",
        ref_id=user,
        postings=[(available, amount), (clearing, -amount)],
    )


class SolRpc:
    def __init__(self, source, destination, genesis):
        self.genesis = genesis
        self.source, self.destination = source, destination
        self.blockhash = str(Hash.from_bytes(bytes([7]) * 32))
        self.height = 10
        self.calls = []
        self.status = None
        self.transaction = None
        self.responses = {}

    def rpc(self, url, method, params):
        self.calls.append((url, method, params))
        if method in self.responses:
            value = self.responses[method]
            if isinstance(value, Exception):
                raise value
            return copy.deepcopy(value)
        if method == "getGenesisHash":
            return self.genesis
        if method == "isBlockhashValid":
            return {"value": self.height <= 200}
        if method == "getBlockHeight":
            return self.height
        if method == "getLatestBlockhash":
            return {
                "context": {"slot": 10},
                "value": {"blockhash": self.blockhash, "lastValidBlockHeight": 200},
            }
        if method == "getFeeForMessage":
            return {"value": 5000}
        if method == "getMinimumBalanceForRentExemption":
            return 2039280 if params[0] == 165 else 890880
        if method == "getAccountInfo":
            return {
                "value": {
                    "owner": "11111111111111111111111111111111",
                    "executable": False,
                    "data": ["", "base64"],
                    "lamports": 20_000_000_000,
                }
            }
        if method == "getSignatureStatuses":
            return {"value": [self.status]}
        if method == "getTransaction":
            return self.transaction
        raise AssertionError(method)


def finalized(signed, slot=20, *, error=None, amount=1_000_000_000):
    from solders.transaction import Transaction

    tx = Transaction.from_bytes(bytes.fromhex(signed))
    keys = [str(k) for k in tx.message.account_keys]
    pre = [20_000_000_000] * len(keys)
    post = list(pre)
    fee = 5000
    post[0] -= fee + (0 if error else amount)
    if error is None:
        destination = tx.message.instructions[0].accounts[1]
        post[destination] += amount
    return SimpleNamespace(
        status={"slot": slot, "confirmationStatus": "finalized", "err": error},
        response={
            "slot": slot,
            "version": "legacy",
            "transaction": [base64.b64encode(bytes.fromhex(signed)).decode(), "base64"],
            "meta": {
                "err": error,
                "fee": fee,
                "preBalances": pre,
                "postBalances": post,
                "preTokenBalances": [],
                "postTokenBalances": [],
                "innerInstructions": [],
            },
        },
    )
