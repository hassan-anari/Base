"""Financial provenance contracts only. Fixture signatures are NOT MPC acceptance."""

import uuid
from decimal import Decimal

import pytest
from django.utils import timezone
from eth_account import Account
from eth_utils import keccak, to_checksum_address

from custody.chain_registry import get_chain_spec
from custody.indexer.evm_live import EvmLiveError, _internal_mpc_gas_grant
from custody.models import MpcKeyset, MpcSigningSession, OnchainTransactionAttempt

pytestmark = pytest.mark.django_db


@pytest.fixture
def grant():
    # Explicit disposable unit fixture; never used in live custody acceptance.
    fixture_key = bytes.fromhex("03".rjust(64, "0"))
    source = Account.from_key(fixture_key).address
    destination = to_checksum_address("0x" + "ab" * 20)
    prepared = {
        "chainId": 31337,
        "nonce": 0,
        "to": destination,
        "value": 10**16,
        "gas": 21000,
        "gasPrice": 10**9,
    }
    signed = Account.sign_transaction(prepared, fixture_key)
    txid = "0x" + keccak(signed.raw_transaction).hex()
    attempt = OnchainTransactionAttempt.objects.create(
        operation_type="GAS_TOPUP",
        operation_id=1,
        chain_id="ETH",
        asset_key="ETH",
        from_address=source,
        to_address=destination,
        amount=Decimal("0.01"),
        base_unit_amount=10**16,
        network_tx_id=txid,
        prepared_metadata=prepared,
        signed_payload=signed.raw_transaction.hex(),
        status="RECONCILIATION_REQUIRED",
    )
    keyset = MpcKeyset.objects.create(
        keyset_id=uuid.uuid4(),
        algorithm="CGGMP24_ECDSA",
        curve="secp256k1",
        scope="EVM",
        derivation_version="cggmp_hd_v1",
    )
    identity = {
        "attempt_id": attempt.pk,
        "operation_type": "GAS_TOPUP",
        "operation_id": 1,
        "chain": "ETH",
        "asset": "ETH",
        "source": source,
        "destination": destination,
        "base_unit_amount": str(10**16),
        "unsigned_transaction": prepared,
    }
    session = MpcSigningSession.objects.create(
        attempt=attempt,
        keyset=keyset,
        session_id=uuid.uuid4(),
        algorithm=keyset.algorithm,
        signing_payload=b"",
        message_fingerprint="12" * 32,
        payload_type="EVM_LEGACY_DIGEST",
        status="COMPLETED",
        signature_consumed_at=timezone.now(),
        transaction_identity=identity,
    )
    spec = get_chain_spec("ETH")
    from dataclasses import replace

    spec = replace(spec, evm_chain_id=31337)
    return spec, destination, {"from": source}, txid, 10**16, attempt, session


def test_observed_known_signed_grant_does_not_create_customer_liability(grant):
    assert _internal_mpc_gas_grant(*grant[:5]) is True
    # Same sender/amount is not enough to exclude a distinct external payment.
    assert _internal_mpc_gas_grant(*grant[:3], "0x" + "31" * 32, grant[4]) is False


@pytest.mark.parametrize("fault", ["consumption", "owner", "signed_bytes", "intent"])
def test_mismatched_grant_provenance_aborts_history(grant, fault):
    spec, address, tx, txid, value, attempt, session = grant
    if fault == "consumption":
        session.signature_consumed_at = None
        session.save()
    elif fault == "owner":
        tx["from"] = "0x" + "13" * 20
    elif fault == "signed_bytes":
        attempt.signed_payload = "00"
        attempt.save()
    else:
        session.transaction_identity["operation_type"] = "WITHDRAWAL"
        session.save()
    with pytest.raises(EvmLiveError, match="provenance"):
        _internal_mpc_gas_grant(spec, address, tx, txid, value)
