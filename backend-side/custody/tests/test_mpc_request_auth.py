"""Custody machine authorization contracts; these fixtures are not MPC evidence."""

import copy
import importlib.util
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256
from django.db import DatabaseError, connection, transaction

from custody.mpc_request_auth import authorization_message, authorize_child_request
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
