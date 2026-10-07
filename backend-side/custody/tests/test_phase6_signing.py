import hashlib
import uuid
from decimal import Decimal

import pytest

from custody.models import HotWallet, MpcKeyset, MpcSigningSession, OnchainTransactionAttempt
from custody.mpc_signing import advance_mpc_signing
from custody.signer_adapter import CoordinatorSessionNotFound


class CoordinatorClient:
    def __init__(self):
        self.creates = []
        self.gets = []

    def create_signing_session(self, request):
        self.creates.append(request)
        return {**request, "status": "IN_PROGRESS", "crypto_execution_id": str(uuid.uuid4())}

    def get_signing_session(self, session_id):
        self.gets.append(session_id)
        request = self.creates[0]
        return {**request, "status": "IN_PROGRESS", "crypto_execution_id": str(uuid.uuid4())}


class MissingThenCreateClient(CoordinatorClient):
    def get_signing_session(self, session_id):
        self.gets.append(session_id)
        raise CoordinatorSessionNotFound(session_id)


@pytest.mark.django_db
def test_advancement_sends_exact_persisted_bytes_and_reuses_session():
    keyset = MpcKeyset.objects.create(
        keyset_id=uuid.uuid4(),
        algorithm="CGGMP24_ECDSA",
        curve="secp256k1",
        scope="EVM",
        threshold=2,
        party_count=3,
        derivation_version="cggmp_hd_v1",
    )
    HotWallet.objects.update_or_create(
        chain_id="ETH",
        defaults=dict(
            address="0x" + "11" * 20,
            signing_key_ref="cggmp_hd_v1/1/0/0",
            mpc_keyset=keyset,
        ),
    )
    attempt = OnchainTransactionAttempt.objects.create(
        operation_type="WITHDRAWAL",
        operation_id=9,
        chain_id="ETH",
        asset_key="ETH",
        from_address="0x" + "11" * 20,
        to_address="0x" + "22" * 20,
        amount=Decimal("1"),
        base_unit_amount=10**18,
        status="SIGNING",
        sequence=4,
    )
    payload = bytes.fromhex("ab" * 32)
    session = MpcSigningSession.objects.create(
        attempt=attempt,
        session_id=uuid.uuid4(),
        keyset=keyset,
        algorithm=keyset.algorithm,
        message_fingerprint=hashlib.sha256(payload).hexdigest(),
        payload_type="EVM_LEGACY_DIGEST",
        signing_payload=payload,
    )
    client = CoordinatorClient()

    advance_mpc_signing(attempt.pk, client)
    session.refresh_from_db()
    assert session.status == "IN_PROGRESS"
    assert client.creates[0]["payload_hex"] == payload.hex()
    assert client.creates[0]["attempt_id"] == attempt.pk
    assert client.creates[0]["keyset_id"] == str(keyset.keyset_id)

    advance_mpc_signing(attempt.pk, client)
    assert client.gets == [str(session.session_id)]
    assert len(client.creates) == 1


@pytest.mark.django_db
def test_advancement_rejects_persisted_payload_fingerprint_mismatch():
    keyset = MpcKeyset.objects.create(
        keyset_id=uuid.uuid4(),
        algorithm="FROST_ED25519",
        curve="ed25519",
        scope="SOLANA",
        threshold=2,
        party_count=3,
        derivation_version="frost_keyset_v1",
    )
    HotWallet.objects.update_or_create(
        chain_id="SOL",
        defaults=dict(
            address="11111111111111111111111111111111",
            signing_key_ref="keyset",
            mpc_keyset=keyset,
        ),
    )
    attempt = OnchainTransactionAttempt.objects.create(
        operation_type="GAS_TOPUP",
        operation_id=2,
        chain_id="SOL",
        asset_key="SOL",
        from_address="11111111111111111111111111111111",
        to_address="11111111111111111111111111111111",
        amount=Decimal("1"),
        base_unit_amount=1,
        status="SIGNING",
    )
    MpcSigningSession.objects.create(
        attempt=attempt,
        session_id=uuid.uuid4(),
        keyset=keyset,
        algorithm=keyset.algorithm,
        message_fingerprint="00" * 32,
        payload_type="SOLANA_MESSAGE",
        signing_payload=b"message",
    )
    with pytest.raises(ValueError, match="fingerprint mismatch"):
        advance_mpc_signing(attempt.pk, CoordinatorClient())


@pytest.mark.django_db
def test_starting_missing_at_coordinator_reposts_same_session():
    keyset, attempt, session = _signing_fixture("STARTING")
    client = MissingThenCreateClient()
    advance_mpc_signing(attempt.pk, client)
    assert client.gets == [str(session.session_id)]
    assert len(client.creates) == 1
    assert client.creates[0]["session_id"] == str(session.session_id)
    assert MpcSigningSession.objects.filter(attempt=attempt).count() == 1


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("field", "value"),
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
    ],
)
def test_coordinator_response_identity_mismatch_requires_reconciliation(field, value):
    _, attempt, session = _signing_fixture("IN_PROGRESS")

    class MismatchClient(CoordinatorClient):
        def get_signing_session(self, session_id):
            from custody.mpc_signing import coordinator_request

            result = coordinator_request(attempt, session)
            result[field] = value
            return {**result, "status": "COMPLETED", "signature": {"r": "1", "s": "1"}}

    advance_mpc_signing(attempt.pk, MismatchClient())
    session.refresh_from_db()
    attempt.refresh_from_db()
    assert session.status == "RECONCILIATION_REQUIRED"
    assert session.error_code == "COORDINATOR_IDENTITY_MISMATCH"
    assert attempt.status == "SIGNING"


@pytest.mark.django_db
def test_completed_signature_is_consumed_once_after_crash():
    _, attempt, session = _signing_fixture("COMPLETED")
    session.signature_result = {"r": "11" * 32, "s": "22" * 32, "recovery_id": 0}
    session.save(update_fields=["signature_result"])
    calls = []

    def consumer(locked_attempt, locked_session):
        calls.append(locked_session.session_id)
        return "deadbeef", "0xabc"

    advance_mpc_signing(attempt.pk, CoordinatorClient(), consumer)
    advance_mpc_signing(attempt.pk, CoordinatorClient(), consumer)
    attempt.refresh_from_db()
    session.refresh_from_db()
    assert attempt.status == "SIGNED"
    assert attempt.signed_payload == "deadbeef"
    assert session.signature_consumed_at is not None
    assert calls == [session.session_id]
    assert MpcSigningSession.objects.filter(attempt=attempt).count() == 1


def _signing_fixture(status):
    keyset = MpcKeyset.objects.create(
        keyset_id=uuid.uuid4(),
        algorithm="CGGMP24_ECDSA",
        curve="secp256k1",
        scope="EVM",
        threshold=2,
        party_count=3,
        derivation_version="cggmp_hd_v1",
    )
    HotWallet.objects.update_or_create(
        chain_id="ETH",
        defaults={
            "address": "0x" + "11" * 20,
            "signing_key_ref": "cggmp_hd_v1/1/0/0",
            "mpc_keyset": keyset,
        },
    )
    attempt = OnchainTransactionAttempt.objects.create(
        operation_type="WITHDRAWAL",
        operation_id=99,
        chain_id="ETH",
        asset_key="ETH",
        from_address="0x" + "11" * 20,
        to_address="0x" + "22" * 20,
        amount=Decimal("1"),
        base_unit_amount=10**18,
        status="SIGNING",
        sequence=7,
    )
    payload = bytes.fromhex("cd" * 32)
    session = MpcSigningSession.objects.create(
        attempt=attempt,
        session_id=uuid.uuid4(),
        keyset=keyset,
        algorithm=keyset.algorithm,
        message_fingerprint=hashlib.sha256(payload).hexdigest(),
        payload_type="EVM_LEGACY_DIGEST",
        signing_payload=payload,
        status=status,
    )
    return keyset, attempt, session


@pytest.mark.django_db
def test_completed_evm_signature_is_verified_and_assembled_locally():
    from eth_account import Account
    from eth_keys import keys

    from custody.mpc_payload import evm_signing_digest

    keyset, attempt, session = _signing_fixture("COMPLETED")
    private = keys.PrivateKey(bytes.fromhex("03".rjust(64, "0")))
    transaction = {
        "nonce": 7,
        "gasPrice": 20_000_000_000,
        "gas": 21_000,
        "to": "0x" + "22" * 20,
        "value": 10**18,
        "data": "0x",
        "chainId": 1,
    }
    _, digest = evm_signing_digest(transaction)
    signature = private.sign_msg_hash(digest)
    attempt.from_address = Account.from_key(private.to_bytes()).address
    attempt.prepared_metadata = transaction
    attempt.save(update_fields=["from_address", "prepared_metadata"])
    session.signing_payload = digest
    session.message_fingerprint = hashlib.sha256(digest).hexdigest()
    session.signature_result = {
        "r": hex(signature.r),
        "s": hex(signature.s),
        "recovery_id": signature.v,
    }
    session.save(update_fields=["signing_payload", "message_fingerprint", "signature_result"])

    advance_mpc_signing(attempt.pk, CoordinatorClient())

    attempt.refresh_from_db()
    session.refresh_from_db()
    assert attempt.status == "SIGNED"
    assert (
        Account.recover_transaction(bytes.fromhex(attempt.signed_payload)) == attempt.from_address
    )
    assert session.signature_consumed_at is not None
    assert session.keyset == keyset
