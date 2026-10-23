"""Signer-origin verification with operator-pinned identities, never RPC trust material.

The pins are archival public P-256 certificates provisioned independently of the
coordinator. Receipt validity outlives transport certificate expiry; replacing a
pin is a separately reviewed lifecycle operation, not automatic TLS renewal.
"""

import json
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.conf import settings

from .mpc_binding import PARTICIPANTS, MpcBindingError

DOMAINS = {
    "root": b"Wallet-MPC/SIGNER_HD_ROOT_RECEIPT_V1\0",
    "child": b"Wallet-MPC/SIGNER_CHILD_RECEIPT_V1\0",
}


def receipt_message(kind, statement):
    return (
        DOMAINS[kind]
        + json.dumps(
            statement, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode()
    )


def verify_receipts(kind, identity, reports):
    try:
        pins = settings.MPC_HD_SIGNER_CERTIFICATES
        if set(pins) != set(PARTICIPANTS) or len(reports) != 3:
            raise ValueError("three independent signer pins required")
        keys = {}
        for party in PARTICIPANTS:
            cert = x509.load_pem_x509_certificate(Path(pins[party]).read_bytes())
            uris = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.UniformResourceIdentifier)
            key = cert.public_key()
            if (
                uris != [f"spiffe://wallet-mpc/{party}"]
                or not isinstance(key, ec.EllipticCurvePublicKey)
                or not isinstance(key.curve, ec.SECP256R1)
            ):
                raise ValueError("pinned signer P-256 identity required")
            keys[party] = key
        encoded = {
            k.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            for k in keys.values()
        }
        if len(encoded) != 3:
            raise ValueError("signers must have independent identity keys")
        for party, report in zip(PARTICIPANTS, reports, strict=True):
            statement = {kind: identity, "party_id": party, "durable": True}
            if (
                set(report) != {*statement, "signer_signature"}
                or any(report[k] != v for k, v in statement.items())
                or report["durable"] is not True
            ):
                raise ValueError("signer statement mismatch")
            signature = bytes.fromhex(report["signer_signature"])
            if not 8 <= len(signature) <= 80:
                raise ValueError("invalid receipt signature bounds")
            keys[party].verify(
                signature, receipt_message(kind, statement), ec.ECDSA(hashes.SHA256())
            )
    except (OSError, KeyError, TypeError, ValueError, InvalidSignature, x509.ExtensionNotFound):
        raise MpcBindingError(
            "unverifiable independent signer-origin receipt; quarantine evidence"
        ) from None
