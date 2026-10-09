"""Fast coordinator/custody contracts. Test-only signatures are NOT real MPC acceptance."""

import copy
import hashlib
import importlib.util
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import rlp
from django.db import close_old_connections, connection
from eth_account import Account
from eth_keys import keys
from eth_utils import keccak
from ops.models import Chain, NodeEndpoint

from custody.ledger import ensure_accounts, post_transaction, user_balances
from custody.models import (
    Asset,
    GasTopupIntent,
    HotWallet,
    LedgerAccount,
    LedgerTransaction,
    MpcKeyset,
    MpcSigningSession,
    OnchainTransactionAttempt,
    SweepJob,
    UserWallet,
)
from custody.mpc_binding import (
    MpcBindingError,
    UnsupportedMpcDerivation,
    identity_fingerprint,
    local_root_keyset,
    transaction_identity,
    validate_custody_intent,
    verify_coordinator_keyset,
)
from custody.mpc_payload import assemble_evm_signature, evm_signing_digest
from custody.mpc_signing import advance_mpc_signing, coordinator_request
from custody.native_tx import AmbiguousBroadcast, ReconciliationResult, ReconciliationState
from custody.outbound import _restore, execute_attempt
from custody.reconciliation import reconcile_attempt
from custody.signer_adapter import CoordinatorSessionNotFound, SelfHostedMpcAdapter
from custody.withdrawals import approve, create_request

PARTIES = ["signer-a", "signer-b", "signer-c"]
CAPS = {
    "max_gas_limit": 200000,
    "max_fee_per_gas": 50_000_000_000,
    "max_priority_fee_per_gas": 5_000_000_000,
    "max_legacy_gas_price": 50_000_000_000,
    "max_total_fee_base_units": 10**17,
    "topup_amount": "0.005",
}


@pytest.fixture
def integration_settings(settings, tmp_path):
    path = Path(__file__).resolve().parents[3] / "mpc-side/integration/environment.py"
    spec = importlib.util.spec_from_file_location("phase6e_pki", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    directory = tmp_path / "pki"
    module.configure(directory)
    identity = directory / "custody/identity"
    settings.MPC_SIGNER_BACKEND = "self_hosted_mpc"
    settings.MPC_EVM_INTEGRATION_ENABLED = True
    settings.MPC_INTEGRATION_ENVIRONMENT = "development"
    settings.MPC_EVM_DEVELOPMENT_CHAINS = {"ETH": 31337}
    settings.CUSTODY_DEMO_MODE = False
    settings.CUSTODY_TX_MODE = "live"
    settings.MPC_COORDINATOR_URL = "https://localhost:8443"
    settings.MPC_CLIENT_CERT = str(identity / "tls.crt")
    settings.MPC_CLIENT_KEY = str(identity / "tls.key")
    settings.MPC_CA_CERT = str(identity / "ca.crt")
    with patch("custody.native_tx.RequestsTransport.rpc", return_value="0x7a69"):
        yield


def metadata_for(keyset):
    dkg = {
        "session_id": str(uuid.uuid4()),
        "execution_id": str(keyset.dkg_execution_id),
        "keyset_id": str(keyset.keyset_id),
        "algorithm": keyset.algorithm,
        "curve": keyset.curve,
        "scope": keyset.scope,
        "derivation_version": keyset.derivation_version,
        "threshold": 2,
        "party_count": 3,
        "participants": PARTIES,
    }
    auxiliary = {
        "dkg": dkg,
        "execution_id": str(uuid.uuid4()),
        "group_public_key": keyset.public_key,
        "public_key_package": [1, 2, 3],
    }
    return {
        **dkg,
        "status": "KEYGEN_COMPLETED",
        "group_public_key": keyset.public_key,
        "result_fingerprint": keyset.dkg_result_fingerprint,
        "participant_agreement": [
            {
                "request": dkg,
                "party_id": party,
                "status": "KEYGEN_COMPLETED",
                "durable": True,
                "group_public_key": keyset.public_key,
                "share_format_version": 1,
                "public_key_package": [1, 2, 3],
            }
            for party in PARTIES
        ],
        "auxiliary": {
            "request": auxiliary,
            "status": "AUXILIARY_COMPLETED",
            "internally_signable": True,
            "participant_agreement": [
                {
                    "request": auxiliary,
                    "party_id": party,
                    "status": "AUXILIARY_COMPLETED",
                    "durable": True,
                    "artifact_format_version": 1,
                    "public_parameters_fingerprint": "ab" * 32,
                }
                for party in PARTIES
            ],
        },
    }


@pytest.fixture
def context(db, integration_settings):
    NodeEndpoint.objects.filter(chain_id="ETH", kind="rpc").update(enabled=False)
    NodeEndpoint.objects.update_or_create(
        chain_id="ETH",
        name="phase6e-loopback",
        defaults={"kind": "rpc", "url": "http://127.0.0.1:18545", "enabled": True},
    )
    Chain.objects.update_or_create(
        chain_id="ETH",
        defaults={
            "display_name": "Phase 6E disposable",
            "is_testnet": True,
            "kind": "evm",
            "evm_chain_id": 31337,
            "gas_settings": CAPS,
            "enabled": True,
            "native_asset_key": "ETH",
        },
    )
    Asset.objects.update_or_create(
        asset_key="ETH",
        defaults={
            "chain_id": "ETH",
            "symbol": "ETH",
            "is_native": True,
            "enabled": True,
            "withdrawal_supported": True,
            "sweep_supported": True,
        },
    )
    private = keys.PrivateKey(bytes.fromhex("03".rjust(64, "0")))
    keyset = MpcKeyset.objects.create(
        keyset_id=uuid.uuid4(),
        algorithm="CGGMP24_ECDSA",
        curve="secp256k1",
        scope="EVM",
        derivation_version="cggmp_hd_v1",
        participant_identities=PARTIES,
        status="ACTIVE",
        public_key=private.public_key.to_compressed_bytes().hex(),
        dkg_execution_id=uuid.uuid4(),
        dkg_result_fingerprint="12" * 32,
    )
    source = private.public_key.to_checksum_address()
    HotWallet.objects.update_or_create(
        chain_id="ETH",
        defaults={
            "address": source,
            "mpc_keyset": keyset,
            "signing_key_ref": f"keyset:{keyset.keyset_id}",
        },
    )
    ensure_accounts("phase6e", "ETH")
    available = LedgerAccount.objects.get(owner_id="phase6e", bucket="AVAILABLE", asset_key="ETH")
    clearing = LedgerAccount.objects.get(
        owner_type="SYSTEM", bucket="CUSTODY_CLEARING", asset_key="ETH"
    )
    post_transaction(
        event_key="phase6e-funding",
        event_type="TEST_FUNDING",
        asset_key="ETH",
        ref_type="Test",
        ref_id="1",
        postings=[(available, Decimal(10)), (clearing, Decimal(-10))],
    )
    withdrawal = create_request(
        "phase6e", "ETH", "0x" + "22" * 20, Decimal(1), idempotency_key="phase6e-w"
    )
    withdrawal = approve("reviewer", withdrawal.pk)
    transaction = {
        "from": source,
        "nonce": 7,
        "gasPrice": 20_000_000_000,
        "gas": 21000,
        "to": withdrawal.to_address,
        "value": 10**18,
        "data": "0x",
        "chainId": 31337,
    }
    attempt = OnchainTransactionAttempt.objects.create(
        operation_type="WITHDRAWAL",
        operation_id=withdrawal.pk,
        chain_id="ETH",
        asset_key="ETH",
        from_address=source,
        to_address=withdrawal.to_address,
        amount=Decimal(1),
        base_unit_amount=10**18,
        sequence=7,
        status="SIGNING",
        prepared_metadata=transaction,
    )
    payload_type, digest = evm_signing_digest(transaction)
    identity = transaction_identity(attempt, keyset)
    session = MpcSigningSession.objects.create(
        attempt=attempt,
        session_id=uuid.uuid4(),
        keyset=keyset,
        algorithm=keyset.algorithm,
        signing_payload=digest,
        message_fingerprint=hashlib.sha256(digest).hexdigest(),
        payload_type=payload_type,
        transaction_identity=identity,
        coordinator_request_id=identity_fingerprint(identity),
    )
    return SimpleNamespace(
        private=private,
        keyset=keyset,
        attempt=attempt,
        session=session,
        withdrawal=withdrawal,
        metadata=metadata_for(keyset),
    )


class CoordinatorClient:
    """Deterministic transport fixture matching Rust's flattened response and explicit execute."""

    def __init__(self, context):
        self.context = context
        self.creates, self.executes, self.gets, self.reconciles = [], [], [], []
        self.request = None
        self.execution_id = str(uuid.uuid4())
        self.state = "CREATED"
        self.selected = []
        self.signature = None

    def get_keyset(self, keyset_id):
        assert keyset_id == str(self.context.keyset.keyset_id)
        return self.context.metadata

    def response(self):
        return {
            **self.request,
            "status": self.state,
            "crypto_execution_id": self.execution_id,
            "selected_signers": self.selected,
            "signature": self.signature,
            "error_code": None,
        }

    def create_signing_session(self, request):
        if self.request is not None and self.request != request:
            raise ValueError("conflicting request")
        self.creates.append(request)
        self.request = request
        return self.response()

    def execute_signing_session(self, session_id):
        self.executes.append(session_id)
        self.state, self.selected = "IN_PROGRESS", ["signer-b", "signer-c"]
        return self.response()

    def get_signing_session(self, session_id):
        self.gets.append(session_id)
        if self.request is None:
            raise CoordinatorSessionNotFound(session_id)
        return self.response()

    def reconcile_signing_session(self, session_id):
        self.reconciles.append(session_id)
        self.state = "COMPLETED" if self.signature else "RECONCILIATION_REQUIRED"
        return self.response()

    def complete(self):
        signature = self.context.private.sign_msg_hash(bytes(self.context.session.signing_payload))
        self.signature = {
            "logical_session_id": str(self.context.session.session_id),
            "crypto_execution_id": self.execution_id,
            "keyset_id": str(self.context.keyset.keyset_id),
            "selected_signers": self.selected,
            "algorithm": "CGGMP24_ECDSA",
            "payload_fingerprint": self.context.session.message_fingerprint,
            "signature_hex": f"{signature.r:064x}{signature.s:064x}",
            "r": f"{signature.r:064x}",
            "s": f"{signature.s:064x}",
            "recovery_id": signature.v,
            "y_parity": signature.v,
            "verified": True,
        }
        self.state = "COMPLETED"


def test_adapter_contract_routes():
    adapter = SelfHostedMpcAdapter()
    with patch.object(adapter, "_request", return_value={}) as transport:
        adapter.create_signing_session({"intent": "test"})
        adapter.execute_signing_session("id")
        adapter.get_signing_session("id")
        adapter.reconcile_signing_session("id")
        assert [(c.args[0], c.args[1]) for c in transport.call_args_list] == [
            ("POST", "/v1/sign-sessions"),
            ("POST", "/v1/sign-sessions/id/execute"),
            ("GET", "/v1/sign-sessions/id"),
            ("POST", "/v1/sign-sessions/id/reconcile"),
        ]


def test_advancement_sends_exact_persisted_bytes_and_reuses_session(context):
    client = CoordinatorClient(context)
    advance_mpc_signing(context.attempt.pk, client)
    advance_mpc_signing(context.attempt.pk, client)
    context.session.refresh_from_db()
    assert context.session.status == "IN_PROGRESS"
    assert str(context.session.crypto_execution_id) == client.execution_id
    assert context.session.selected_signers == ["signer-b", "signer-c"]
    assert client.creates[0]["payload_hex"] == bytes(context.session.signing_payload).hex()
    assert client.creates[0]["derivation_reference"] is None
    assert len(client.creates) == len(client.executes) == 1
    assert MpcSigningSession.objects.filter(attempt=context.attempt).count() == 1
    conflicting = dict(client.request, asset="USDT-ETH")
    with pytest.raises(ValueError, match="conflicting"):
        client.create_signing_session(conflicting)


def test_starting_missing_at_coordinator_reposts_same_session(context):
    context.session.status = "STARTING"
    context.session.save()
    client = CoordinatorClient(context)
    advance_mpc_signing(context.attempt.pk, client)
    assert client.gets == [str(context.session.session_id)]
    assert client.creates[0]["session_id"] == str(context.session.session_id)
    assert len(client.executes) == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("session_id", str(uuid.uuid4())),
        ("attempt_id", 123456),
        ("keyset_id", str(uuid.uuid4())),
        ("algorithm", "FROST_ED25519"),
        ("payload_type", "TRON_TXID"),
        ("message_fingerprint", "00" * 32),
        ("operation_type", "SWEEP"),
        ("chain", "BSC"),
        ("asset", "USDT"),
        ("expected_source", "0x" + "99" * 20),
        ("derivation_reference", "wrong/ref"),
        ("crypto_execution_id", str(uuid.uuid4())),
        ("selected_signers", ["signer-a", "signer-c"]),
        ("selected_signers", ["signer-a", "signer-a"]),
        ("selected_signers", []),
    ],
)
def test_coordinator_response_identity_mismatch_requires_reconciliation(context, field, value):
    client = CoordinatorClient(context)
    advance_mpc_signing(context.attempt.pk, client)
    response = client.response()
    response[field] = value
    with patch.object(client, "get_signing_session", return_value=response):
        advance_mpc_signing(context.attempt.pk, client)
    context.session.refresh_from_db()
    context.attempt.refresh_from_db()
    context.withdrawal.refresh_from_db()
    assert (
        context.session.status
        == context.attempt.status
        == context.withdrawal.status
        == "RECONCILIATION_REQUIRED"
    )
    assert context.session.selected_signers == ["signer-b", "signer-c"]
    assert user_balances("phase6e", "ETH")["reserved"] == Decimal(1)


@pytest.mark.parametrize("mutation", ["nonce", "chainId", "value", "to", "gasPrice"])
def test_persisted_transaction_changes_are_rejected_before_coordinator(context, mutation):
    raw = dict(context.attempt.prepared_metadata)
    raw[mutation] = "0x" + "33" * 20 if mutation == "to" else raw[mutation] + 1
    context.attempt.prepared_metadata = raw
    context.attempt.save()
    client = CoordinatorClient(context)
    advance_mpc_signing(context.attempt.pk, client)
    assert not client.creates
    context.attempt.refresh_from_db()
    assert context.attempt.status == "RECONCILIATION_REQUIRED"


def test_persisted_fingerprint_and_unsigned_reconstruction(context):
    prepared = _restore(context.attempt)
    assert prepared.unsigned_payload == context.attempt.prepared_metadata
    assert prepared.sequence == 7
    assert evm_signing_digest(prepared.unsigned_payload)[1] == bytes(
        context.session.signing_payload
    )
    context.session.message_fingerprint = "00" * 32
    with pytest.raises(ValueError, match="fingerprint mismatch"):
        coordinator_request(context.attempt, context.session)


@pytest.mark.parametrize(
    "field,value",
    [
        ("public_key", "02" + "11" * 32),
        ("status", "CREATING"),
        ("participant_identities", ["signer-a", "signer-b"]),
        ("dkg_result_fingerprint", ""),
    ],
)
def test_incomplete_or_inconsistent_keyset_rejected(context, field, value):
    MpcKeyset.objects.filter(pk=context.keyset.pk).update(**{field: value})
    with pytest.raises((MpcBindingError, ValueError)):
        local_root_keyset(context.attempt)


def test_root_address_binding_and_unsupported_derivation(context):
    assert local_root_keyset(context.attempt).pk == context.keyset.pk
    HotWallet.objects.filter(chain_id="ETH").update(signing_key_ref="m/44'/60'/0'/0/9")
    with pytest.raises(UnsupportedMpcDerivation):
        local_root_keyset(context.attempt)
    with pytest.raises(UnsupportedMpcDerivation):
        SelfHostedMpcAdapter().get_derived_address("ETH", "m/0")


@pytest.mark.parametrize("mutation", ["group", "auxiliary", "party", "dkg"])
def test_authoritative_dkg_and_auxiliary_evidence(context, mutation):
    metadata = copy.deepcopy(context.metadata)
    if mutation == "group":
        metadata["group_public_key"] = "03" + "11" * 32
    elif mutation == "auxiliary":
        metadata["auxiliary"]["internally_signable"] = False
    elif mutation == "party":
        metadata["auxiliary"]["participant_agreement"][0]["party_id"] = "other"
    else:
        metadata["execution_id"] = str(uuid.uuid4())
    with pytest.raises(MpcBindingError):
        verify_coordinator_keyset(context.keyset, metadata)


@pytest.mark.parametrize("typed", [False, True])
def test_exact_digest_and_signature_assembly(context, typed):
    raw = dict(context.attempt.prepared_metadata)
    if typed:
        raw.pop("gasPrice")
        raw.update(type=2, maxFeePerGas=20_000_000_000, maxPriorityFeePerGas=1_000_000_000)
        preimage = b"\x02" + rlp.encode(
            [
                31337,
                7,
                1_000_000_000,
                20_000_000_000,
                21000,
                bytes.fromhex(raw["to"][2:]),
                10**18,
                b"",
                [],
            ]
        )
    else:
        preimage = rlp.encode(
            [7, 20_000_000_000, 21000, bytes.fromhex(raw["to"][2:]), 10**18, b"", 31337, 0, 0]
        )
    digest = evm_signing_digest(raw)[1]
    assert digest == keccak(preimage)
    signature = context.private.sign_msg_hash(digest)
    result = {"r": hex(signature.r), "s": hex(signature.s), "recovery_id": signature.v}
    payload, tx_id = assemble_evm_signature(raw, result, context.attempt.from_address)
    signed = Account.sign_transaction(raw, context.private.to_bytes())
    assert bytes.fromhex(payload) == signed.raw_transaction
    assert tx_id == "0x" + keccak(bytes.fromhex(payload)).hex()
    assert Account.recover_transaction(bytes.fromhex(payload)) == context.attempt.from_address


@pytest.mark.parametrize(
    "mutation", ["high_s", "zero_r", "overflow_r", "recovery", "string_recovery", "wrong_digest"]
)
def test_malformed_signature_and_wrong_digest_rejected(context, mutation):
    signature = context.private.sign_msg_hash(bytes(context.session.signing_payload))
    result = {"r": hex(signature.r), "s": hex(signature.s), "recovery_id": signature.v}
    if mutation == "high_s":
        result["s"] = hex(2**255)
    elif mutation == "zero_r":
        result["r"] = "0"
    elif mutation == "overflow_r":
        result["r"] = hex(2**256 - 1)
    elif mutation == "recovery":
        result["recovery_id"] = 2
    elif mutation == "string_recovery":
        result["recovery_id"] = "0"
    else:
        context.attempt.prepared_metadata["nonce"] += 1
    with pytest.raises(ValueError):
        assemble_evm_signature(
            context.attempt.prepared_metadata, result, context.attempt.from_address
        )


def test_completed_signature_is_consumed_once_after_crash(context):
    client = CoordinatorClient(context)
    advance_mpc_signing(context.attempt.pk, client)
    client.complete()
    # Simulate worker death after durable result persistence, before consumption.
    with patch("custody.mpc_signing._consume_completed", side_effect=RuntimeError("crash")):
        with pytest.raises(RuntimeError, match="crash"):
            advance_mpc_signing(context.attempt.pk, client)
    context.session.refresh_from_db()
    assert context.session.status == "COMPLETED" and context.session.signature_consumed_at is None
    advance_mpc_signing(context.attempt.pk, client)
    advance_mpc_signing(context.attempt.pk, client)
    context.attempt.refresh_from_db()
    context.session.refresh_from_db()
    assert context.attempt.status == "SIGNED" and context.session.signature_consumed_at
    assert len(client.executes) == 1
    assert context.session.crypto_execution_id is not None


@pytest.mark.parametrize(
    "mutation",
    ["keyset_id", "crypto_execution_id", "payload_fingerprint", "signature_hex", "y_parity"],
)
def test_completed_signature_conflicting_metadata_rejected(context, mutation):
    client = CoordinatorClient(context)
    advance_mpc_signing(context.attempt.pk, client)
    client.complete()
    client.signature[mutation] = "bad"
    advance_mpc_signing(context.attempt.pk, client)
    context.attempt.refresh_from_db()
    assert (
        context.attempt.status == "RECONCILIATION_REQUIRED" and not context.attempt.signed_payload
    )


def test_ambiguous_coordinator_timeout_resumes_without_new_execution(context):
    client = CoordinatorClient(context)
    original = client.execute_signing_session

    def timeout(session_id):
        original(session_id)
        raise TimeoutError("ambiguous execute response")

    with patch.object(client, "execute_signing_session", side_effect=timeout):
        advance_mpc_signing(context.attempt.pk, client)
    context.attempt.refresh_from_db()
    assert context.attempt.status == "RECONCILIATION_REQUIRED"
    client.complete()
    client.state = "RECONCILIATION_REQUIRED"
    advance_mpc_signing(context.attempt.pk, client)
    context.attempt.refresh_from_db()
    assert context.attempt.status == "SIGNED"
    assert len(client.creates) == len(client.executes) == len(client.reconciles) == 1


def test_crash_after_signed_persistence_and_ambiguous_broadcast_preserves_reservation(context):
    client = CoordinatorClient(context)
    advance_mpc_signing(context.attempt.pk, client)
    client.complete()
    advance_mpc_signing(context.attempt.pk, client)
    context.attempt.refresh_from_db()
    payload = context.attempt.signed_payload
    with patch("custody.outbound._executor") as executor:
        executor.return_value.transport.rpc.return_value = "0x7a69"
        executor.return_value.broadcast.side_effect = AmbiguousBroadcast("response lost")
        with pytest.raises(AmbiguousBroadcast):
            execute_attempt(context.attempt.pk, "worker")
        execute_attempt(context.attempt.pk, "worker")
        assert executor.return_value.broadcast.call_count == 1
        assert executor.return_value.broadcast.call_args.args[1] == bytes.fromhex(payload)
    assert user_balances("phase6e", "ETH")["reserved"] == Decimal(1)
    with patch("custody.reconciliation._executor") as executor:
        executor.return_value.reconcile.return_value = ReconciliationResult(
            ReconciliationState.CONFIRMED, {}
        )
        reconcile_attempt(context.attempt.pk)
        reconcile_attempt(context.attempt.pk)
    assert user_balances("phase6e", "ETH")["reserved"] == 0
    assert (
        LedgerTransaction.objects.filter(
            event_key=f"withdrawal:{context.withdrawal.pk}:settle"
        ).count()
        == 1
    )
    assert len(client.executes) == 1


def test_sweep_and_gas_topup_policy_and_independent_source(context):
    deposit_private = keys.PrivateKey(bytes.fromhex("04".rjust(64, "0")))
    deposit_keyset = MpcKeyset.objects.create(
        keyset_id=uuid.uuid4(),
        algorithm="CGGMP24_ECDSA",
        curve="secp256k1",
        scope="EVM",
        derivation_version="cggmp_hd_v1",
        participant_identities=PARTIES,
        status="ACTIVE",
        public_key=deposit_private.public_key.to_compressed_bytes().hex(),
        dkg_execution_id=uuid.uuid4(),
        dkg_result_fingerprint="34" * 32,
    )
    wallet = UserWallet.objects.create(
        user_id="depositor",
        chain_id="ETH",
        asset_key="ETH",
        deposit_address=deposit_private.public_key.to_checksum_address(),
        derivation_path=f"keyset:{deposit_keyset.keyset_id}",
        derivation_version="mpc_root_v1",
        mpc_keyset=deposit_keyset,
    )
    job = SweepJob.objects.create(
        user_wallet=wallet,
        asset_key="ETH",
        balance_snapshot=Decimal(2),
        status="SWEEP_PROCESSING",
        idempotency_key="root-sweep",
    )
    sweep = copy.copy(context.attempt)
    sweep.operation_type, sweep.operation_id = "SWEEP", job.pk
    sweep.from_address = wallet.deposit_address
    sweep.to_address = context.attempt.from_address
    validate_custody_intent(sweep)
    assert local_root_keyset(sweep).pk == deposit_keyset.pk
    wallet.derivation_path = "m/unsupported"
    wallet.save()
    with pytest.raises(UnsupportedMpcDerivation):
        local_root_keyset(sweep)
    sweep.to_address = "0x" + "77" * 20
    with pytest.raises(MpcBindingError):
        validate_custody_intent(sweep)
    gas = GasTopupIntent.objects.create(
        chain_id="ETH",
        to_address=wallet.deposit_address,
        amount=Decimal("0.005"),
        status="PROCESSING",
        actor_id="system:gas_station",
        idempotency_key="gas",
    )
    topup = copy.copy(context.attempt)
    topup.operation_type, topup.operation_id = "GAS_TOPUP", gas.pk
    topup.to_address, topup.amount, topup.base_unit_amount = gas.to_address, gas.amount, 5 * 10**15
    validate_custody_intent(topup)
    gas.amount = Decimal(1)
    gas.save()
    with pytest.raises(MpcBindingError):
        validate_custody_intent(topup)


@pytest.mark.django_db(transaction=True)
def test_concurrent_advancement_has_one_execution_owner(context):
    assert connection.vendor == "postgresql", "Phase 6E concurrency gate requires PostgreSQL"
    client = CoordinatorClient(context)
    entered, release = threading.Event(), threading.Event()
    original = client.execute_signing_session

    def blocked(session_id):
        entered.set()
        assert release.wait(10)
        return original(session_id)

    def worker():
        close_old_connections()
        try:
            return advance_mpc_signing(context.attempt.pk, client).status
        finally:
            close_old_connections()

    with patch.object(client, "execute_signing_session", side_effect=blocked):
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(worker)
            assert entered.wait(10)
            second = pool.submit(worker)
            assert second.result(timeout=10) == "SIGNING"
            release.set()
            assert first.result(timeout=10) == "SIGNING"
    assert len(client.executes) == len(client.creates) == 1


def test_digest_created_after_allocated_nonce_and_duplicate_preparation(context):
    from custody.models import SourceAccountSequence
    from custody.native_tx import PreparedNativeTransaction

    context.session.delete()
    context.attempt.status = "PREPARING"
    context.attempt.prepared_metadata = {}
    context.attempt.sequence = None
    context.attempt.save()
    SourceAccountSequence.objects.create(
        chain_id="ETH", address=context.attempt.from_address.lower(), next_sequence=12
    )
    raw = dict(context.session.transaction_identity["unsigned_transaction"])
    prepared = PreparedNativeTransaction(
        "ETH",
        "ETH",
        context.attempt.from_address,
        context.attempt.to_address,
        Decimal(1),
        10**18,
        b"",
        raw,
        {},
        sequence=7,
    )
    client = CoordinatorClient(context)
    with (
        patch("custody.outbound._executor") as executor,
        patch("custody.signer_adapter.get_adapter", return_value=client),
    ):
        executor.return_value.prepare.return_value = prepared
        executor.return_value.transport.rpc.return_value = "0x7a69"
        execute_attempt(context.attempt.pk, "reviewer")
        execute_attempt(context.attempt.pk, "reviewer")
        assert executor.return_value.prepare.call_count == 1
    context.attempt.refresh_from_db()
    session = MpcSigningSession.objects.get(attempt=context.attempt)
    assert context.attempt.sequence == context.attempt.prepared_metadata["nonce"] == 12
    assert (
        bytes(session.signing_payload) == evm_signing_digest(context.attempt.prepared_metadata)[1]
    )
    assert bytes(session.signing_payload) != evm_signing_digest(dict(raw, nonce=7))[1]
    assert len(client.executes) == len(client.creates) == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("MPC_EVM_INTEGRATION_ENABLED", False),
        ("MPC_INTEGRATION_ENVIRONMENT", "production"),
        ("MPC_CLIENT_CERT", ""),
        ("CUSTODY_DEMO_MODE", True),
        ("CUSTODY_TX_MODE", "stub"),
    ],
)
def test_integration_guards_fail_closed(context, settings, field, value):
    from custody.signer_adapter import assert_mpc_backend_runtime_safe

    setattr(settings, field, value)
    with pytest.raises((RuntimeError, OSError, ValueError)):
        assert_mpc_backend_runtime_safe("ETH")


@pytest.mark.parametrize("chain_id", ["TRX", "SOL", "TON"])
def test_non_evm_production_signing_remains_disabled(context, chain_id):
    from custody.signer_adapter import assert_mpc_backend_runtime_safe

    with pytest.raises(ValueError, match="isolated EVM test chains only"):
        assert_mpc_backend_runtime_safe(chain_id)


def test_mainnet_and_local_signer_production_guards(context, settings):
    from custody.signer_adapter import assert_mpc_backend_runtime_safe, get_adapter

    Chain.objects.filter(chain_id="ETH").update(evm_chain_id=1, is_testnet=True)
    with pytest.raises(ValueError, match="testnet allowlist"):
        assert_mpc_backend_runtime_safe("ETH")
    settings.MPC_SIGNER_BACKEND = "local_key"
    with pytest.raises(RuntimeError, match="demo mode"):
        get_adapter()
    with pytest.raises(RuntimeError, match="demo mode"):
        assert_mpc_backend_runtime_safe("ETH")


def test_integration_requires_postgresql(context):
    from custody.signer_adapter import assert_mpc_backend_runtime_safe

    with patch.object(connection, "vendor", "sqlite"):
        with pytest.raises(RuntimeError, match="requires PostgreSQL"):
            assert_mpc_backend_runtime_safe("ETH")


def test_missing_reservation_and_changed_approval_prevent_signing(context):
    from custody.models import AdminActionLog

    AdminActionLog.objects.filter(
        action_type="WITHDRAWAL_APPROVE", entity_id=str(context.withdrawal.pk)
    ).update(metadata={"to": "0x" + "55" * 20, "amount": "1"})
    client = CoordinatorClient(context)
    advance_mpc_signing(context.attempt.pk, client)
    context.attempt.refresh_from_db()
    assert context.attempt.status == "RECONCILIATION_REQUIRED" and not client.creates
    assert user_balances("phase6e", "ETH")["reserved"] == 1


def test_crash_during_broadcast_requires_reconciliation_without_resubmission(context):
    context.attempt.status = "BROADCASTING"
    context.attempt.save()
    with patch("custody.outbound._executor") as executor:
        assert execute_attempt(context.attempt.pk, "worker").status == "RECONCILIATION_REQUIRED"
        assert execute_attempt(context.attempt.pk, "worker").status == "RECONCILIATION_REQUIRED"
        executor.return_value.broadcast.assert_not_called()


def test_signed_payload_tampering_rejected_before_rpc(context):
    client = CoordinatorClient(context)
    advance_mpc_signing(context.attempt.pk, client)
    client.complete()
    advance_mpc_signing(context.attempt.pk, client)
    OnchainTransactionAttempt.objects.filter(pk=context.attempt.pk).update(
        signed_payload="deadbeef"
    )
    with patch("custody.outbound._executor") as executor:
        assert execute_attempt(context.attempt.pk, "worker").status == "RECONCILIATION_REQUIRED"
        executor.return_value.broadcast.assert_not_called()
    assert user_balances("phase6e", "ETH")["reserved"] == 1


def test_approved_legacy_withdrawal_without_reservation_never_requests_signature(context):
    from custody.models import WithdrawalRequest

    legacy = WithdrawalRequest.objects.create(
        user_id="phase6e",
        chain_id="ETH",
        asset_key="ETH",
        to_address=context.attempt.to_address,
        amount=Decimal(1),
        idempotency_key="legacy-no-reserve",
    )
    approve("reviewer", legacy.pk)
    context.attempt.operation_id = legacy.pk
    context.attempt.save()
    client = CoordinatorClient(context)
    advance_mpc_signing(context.attempt.pk, client)
    context.attempt.refresh_from_db()
    assert context.attempt.status == "RECONCILIATION_REQUIRED" and not client.creates


def test_proven_prebroadcast_rejection_reuses_signed_bytes(context):
    from custody.native_tx import SafePreBroadcastRejection

    client = CoordinatorClient(context)
    advance_mpc_signing(context.attempt.pk, client)
    client.complete()
    advance_mpc_signing(context.attempt.pk, client)
    context.attempt.refresh_from_db()
    signed, nonce = context.attempt.signed_payload, context.attempt.sequence
    with patch("custody.outbound._executor") as executor:
        executor.return_value.transport.rpc.return_value = "0x7a69"
        executor.return_value.broadcast.side_effect = SafePreBroadcastRejection(
            "proven non-acceptance"
        )
        with pytest.raises(SafePreBroadcastRejection):
            execute_attempt(context.attempt.pk, "worker")
        context.attempt.refresh_from_db()
        assert context.attempt.status == "SIGNED" and context.attempt.signed_payload == signed
        executor.return_value.broadcast.side_effect = None
        execute_attempt(context.attempt.pk, "worker")
        assert all(
            c.args[1] == bytes.fromhex(signed)
            for c in executor.return_value.broadcast.call_args_list
        )
    context.attempt.refresh_from_db()
    assert context.attempt.sequence == nonce
    assert MpcSigningSession.objects.filter(attempt=context.attempt).count() == 1
    assert len(client.executes) == 1


def test_wrong_rpc_chain_is_rejected_before_nonce_or_signature(context):
    from custody.models import SourceAccountSequence

    context.session.delete()
    context.attempt.status = "PREPARING"
    context.attempt.sequence = None
    context.attempt.prepared_metadata = {}
    context.attempt.save()
    with patch("custody.outbound._executor") as executor:
        executor.return_value.transport.rpc.return_value = "0x1"
        with pytest.raises(ValueError, match="RPC chain ID"):
            execute_attempt(context.attempt.pk, "reviewer")
        executor.return_value.prepare.assert_not_called()
    assert not MpcSigningSession.objects.filter(attempt=context.attempt).exists()
    assert not SourceAccountSequence.objects.filter(chain_id="ETH").exists()
