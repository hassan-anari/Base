"""
Cryptographic helpers for the local "MPC stand-in" vault.

SECURITY BOUNDARY NOTE
----------------------
In production the master seed and all key material live INSIDE the external
separately deployed self-hosted MPC signer nodes. Django core
never imports or touches this module. `LocalVault` below is a *dev/demo*
implementation of that trust boundary: it stands in for the signer cluster so the
whole flow runs end-to-end on public testnets. To go to production you swap
`signer_adapter.get_adapter()` to the self-hosted adapter without
changing any business logic.

Deterministic derivation:
  secret_key(network, path) = HMAC-SHA512(seed, "network:path")[:32]
  seed = SHA-256(LOCAL_KEY_ENCRYPTION_PASSPHRASE)
This is deterministic and *stateless* (no key blobs stored in the DB), which
keeps the demo simple while still producing real, controllable EOAs.
"""

from __future__ import annotations

import base64
import hashlib
import hmac

from cryptography.fernet import Fernet


def master_seed_from_passphrase(passphrase: str) -> bytes:
    """32-byte master seed derived from the operator passphrase."""
    return hashlib.sha256(passphrase.encode("utf-8")).digest()


def derive_scalar(network: str, path: str, seed: bytes) -> bytes:
    """Deterministic 32-byte secret scalar for (network, path).

    For EVM/TRX this is used as a secp256k1 private key; for SOL/TON as the
    ed25519 seed. Never returned outside the vault.
    """
    msg = f"{network}:{path}".encode("utf-8")
    return hmac.new(seed, msg, hashlib.sha512).digest()[:32]


def fernet_key(passphrase: str) -> bytes:
    """Derive a 32-url-safe-byte Fernet key (for encrypting seed at rest)."""
    return base64.urlsafe_b64encode(master_seed_from_passphrase(passphrase))


def encrypt_secret(plaintext: bytes, passphrase: str) -> bytes:
    return Fernet(fernet_key(passphrase)).encrypt(plaintext)


def decrypt_secret(token: bytes, passphrase: str) -> bytes:
    return Fernet(fernet_key(passphrase)).decrypt(token)
