"""Custody machine authorization contracts; these fixtures are not MPC evidence."""

import copy
import importlib.util
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.hashes import SHA256
from django.db import DatabaseError, connection, transaction

from custody.mpc_request_auth import (
    APPROVAL_DOMAIN,
    authorization_message,
    authorize_child_approval,
    authorize_child_request,
)
from custody.tests.test_evm_gas_deposits import grant as grant_fixture

grant = grant_fixture


@pytest.fixture
def pki():
    path = Path(__file__).resolve().parents[3] / "mpc-side/integration/environment.py"
    spec = importlib.util.spec_from_file_location("phase6gb_pki", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def identity(tmp_path, pki):
    pki.issue(tmp_path, "custody", pki.ca())
    return tmp_path


def test_original_request_commits_every_field_and_keeps_public_credentials(identity):
    request = {"session_id": "original", "child_authorization": {"path": "m/0/1"}, "digest": "01"}
    grant = authorize_child_request(request, identity / "tls.crt", identity / "tls.key")
    certificate = x509.load_der_x509_certificate(
        bytes.fromhex(grant["certificate_chain_der_hex"][0])
    )
    request["custody_authorization"] = grant
    signature = bytes.fromhex(grant["signature_der_hex"])
    certificate.public_key().verify(signature, authorization_message(request), ec.ECDSA(SHA256()))
    for field in ("session_id", "child_authorization", "digest"):
        modified = copy.deepcopy(request)
        modified[field] = "substituted"
        with pytest.raises(InvalidSignature):
            certificate.public_key().verify(
                signature, authorization_message(modified), ec.ECDSA(SHA256())
            )
    with pytest.raises(ValueError, match="unsigned"):
        authorize_child_request(request, identity / "tls.crt", identity / "tls.key")


def test_wrong_key_or_role_cannot_issue_original_grant(identity, tmp_path, pki):
    other = tmp_path / "other"
    pki.issue(other, "coordinator", pki.ca())
    request = {"child_authorization": {"path": "m/0/1"}}
    with pytest.raises(ValueError, match="identity required"):
        authorize_child_request(request, other / "tls.crt", other / "tls.key")
    with pytest.raises(ValueError, match="matching P-256"):
        authorize_child_request(request, identity / "tls.crt", other / "tls.key")
    key = ec.generate_private_key(ec.SECP384R1())
    (other / "tls.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises(ValueError, match="matching P-256"):
        authorize_child_request(request, identity / "tls.crt", other / "tls.key")


def test_public_approval_is_domain_separated_from_private_signing(identity):
    import json

    request = {"root": "original", "reservation_id": "original", "derivation_path": "m/0/1"}
    grant = authorize_child_approval(request, identity / "tls.crt", identity / "tls.key")
    key = x509.load_pem_x509_certificate((identity / "tls.crt").read_bytes()).public_key()
    message = APPROVAL_DOMAIN + json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
    signature = bytes.fromhex(grant["signature_der_hex"])
    key.verify(signature, message, ec.ECDSA(SHA256()))
    with pytest.raises(InvalidSignature):
        key.verify(signature, authorization_message(request), ec.ECDSA(SHA256()))


def test_unsupported_approval_identity_is_rejected_before_rpc(settings, tmp_path, pki):
    from unittest.mock import patch

    from custody.signer_adapter import SelfHostedMpcAdapter

    pki.issue(tmp_path, "coordinator", pki.ca())
    settings.MPC_CLIENT_CERT = str(tmp_path / "tls.crt")
    settings.MPC_CLIENT_KEY = str(tmp_path / "tls.key")
    with patch.object(SelfHostedMpcAdapter, "_request") as rpc:
        with pytest.raises(ValueError, match="custody identity required"):
            SelfHostedMpcAdapter().approve_child("original", {"reservation_id": "original"})
        rpc.assert_not_called()


@pytest.mark.parametrize("profile", ["rsa", "p384"])
def test_matching_but_unsupported_approval_key_is_rejected(settings, tmp_path, pki, profile):
    from datetime import datetime, timedelta, timezone
    from unittest.mock import patch

    from custody.signer_adapter import SelfHostedMpcAdapter

    issuer = pki.ca()
    pki.issue(tmp_path, "custody", issuer)
    original = x509.load_pem_x509_certificate((tmp_path / "tls.crt").read_bytes())
    key = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if profile == "rsa"
        else ec.generate_private_key(ec.SECP384R1())
    )
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(original.subject)
        .issuer_name(issuer[1].subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
    )
    for extension in original.extensions:
        builder = builder.add_extension(extension.value, extension.critical)
    (tmp_path / "tls.crt").write_bytes(
        builder.sign(issuer[0], SHA256()).public_bytes(serialization.Encoding.PEM)
    )
    (tmp_path / "tls.key").write_bytes(pki.private_key_bytes(key))
    settings.MPC_CLIENT_CERT = str(tmp_path / "tls.crt")
    settings.MPC_CLIENT_KEY = str(tmp_path / "tls.key")
    with patch.object(SelfHostedMpcAdapter, "_request") as rpc:
        with pytest.raises(ValueError, match="matching P-256"):
            SelfHostedMpcAdapter().approve_child("original", {"reservation_id": "original"})
        rpc.assert_not_called()


@pytest.mark.django_db
def test_authorization_is_once_only_and_not_retroactive(grant):
    session = grant[-1]
    with pytest.raises(DatabaseError, match="retrospectively"), transaction.atomic():
        session.custody_authorization = {"fixture": "public"}
        session.save(update_fields=["custody_authorization"])
    session.status = "CREATED"
    session.signature_consumed_at = None
    session.save(update_fields=["status", "signature_consumed_at"])
    session.save(update_fields=["custody_authorization"])
    for sql in (
        "UPDATE custody_mpcsigningsession SET custody_authorization = '{}'::jsonb WHERE id = %s",
        "DELETE FROM custody_mpcsigningsession WHERE id = %s",
    ):
        with (
            pytest.raises(DatabaseError, match="original custody"),
            transaction.atomic(),
            connection.cursor() as cursor,
        ):
            cursor.execute(sql, [session.pk])
    session.refresh_from_db()
    assert session.custody_authorization == {"fixture": "public"}
