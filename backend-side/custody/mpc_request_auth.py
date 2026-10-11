"""End-to-end original custody machine identity, using its existing mTLS key."""

import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

DOMAIN = b"Wallet-MPC/CUSTODY_CHILD_SIGNING_AUTH_V1\0"
APPROVAL_DOMAIN = b"Wallet-MPC/CUSTODY_CHILD_APPROVAL_V1\0"


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def authorization_message(request):
    unsigned = {k: v for k, v in request.items() if k != "custody_authorization"}
    return DOMAIN + _canonical(unsigned)


def authorize_child_request(request, certificate_path, key_path):
    if not request.get("child_authorization") or request.get("custody_authorization"):
        raise ValueError("only an unsigned approved child request can be authorized")
    return _authorize_message(authorization_message(request), certificate_path, key_path)


def authorize_child_approval(request, certificate_path, key_path):
    """Public approval proves that every issuing signer accepts spending credentials."""
    return _authorize_message(APPROVAL_DOMAIN + _canonical(request), certificate_path, key_path)


def _authorize_message(message, certificate_path, key_path):
    certificates = x509.load_pem_x509_certificates(Path(certificate_path).read_bytes())
    if not 1 <= len(certificates) <= 5:
        raise ValueError("invalid custody certificate chain")
    leaf = certificates[0]
    identities = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    if identities.value.get_values_for_type(x509.UniformResourceIdentifier) != [
        "spiffe://wallet-mpc/custody"
    ]:
        raise ValueError("custody identity required")
    key = serialization.load_pem_private_key(Path(key_path).read_bytes(), password=None)
    if (
        not isinstance(key, ec.EllipticCurvePrivateKey)
        or not isinstance(key.curve, ec.SECP256R1)
        or key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        != leaf.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ):
        raise ValueError("matching P-256 custody identity key required")
    return {
        "certificate_chain_der_hex": [
            cert.public_bytes(serialization.Encoding.DER).hex() for cert in certificates
        ],
        "signature_der_hex": key.sign(message, ec.ECDSA(hashes.SHA256())).hex(),
    }
