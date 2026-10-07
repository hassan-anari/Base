import hashlib
import uuid
from decimal import Decimal

import pytest

from custody.models import HotWallet, MpcKeyset, MpcSigningSession, OnchainTransactionAttempt
from custody.mpc_signing import advance_mpc_signing


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
