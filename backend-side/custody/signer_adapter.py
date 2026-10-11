"""
Signer adapter layer — the concrete implementation behind `MpcSigner`.

This module owns local-development key material. `LocalVault` is explicitly a
demo signer: it derives complete keys deterministically from a passphrase
and produces local demo addresses/signatures for ETH/BSC/TRX/SOL. TON
requires the separately scoped FROST keyset and reviewed V5R1 contract boundary;
its legacy deterministic address and local signing placeholders are rejected.

Production uses the separately deployed self-hosted MPC coordinator.
"""

from __future__ import annotations

import base64
import hashlib
import logging
from typing import Any, Optional

from .chain_registry import ChainKind, get_chain_spec
from .crypto_utils import derive_scalar

logger = logging.getLogger("custody.vault")

SELF_HOSTED_MPC_DISABLED_MESSAGE = (
    "self_hosted_mpc requires explicit isolated EVM, TRON or Solana integration enablement; "
    "production activation is disabled"
)


def assert_mpc_backend_runtime_safe(chain_id=None) -> None:
    """Defense-in-depth guard used before any signing or outbound side effect."""
    from django.conf import settings

    if settings.MPC_SIGNER_BACKEND == "local_key" and not settings.CUSTODY_DEMO_MODE:
        raise RuntimeError("local_key signer is restricted to demo mode")
    if settings.MPC_SIGNER_BACKEND == "self_hosted_mpc":
        if (
            not (
                settings.MPC_EVM_INTEGRATION_ENABLED
                or settings.MPC_TRON_INTEGRATION_ENABLED
                or settings.MPC_SOLANA_INTEGRATION_ENABLED
                or settings.MPC_TON_INTEGRATION_ENABLED
            )
            or settings.MPC_INTEGRATION_ENVIRONMENT not in {"development", "testnet"}
            or settings.CUSTODY_DEMO_MODE
            or settings.CUSTODY_TX_MODE != "live"
        ):
            raise RuntimeError(SELF_HOSTED_MPC_DISABLED_MESSAGE)
        from django.db import connection

        if connection.vendor != "postgresql":
            raise RuntimeError("Phase 6E MPC integration requires PostgreSQL execution ownership")
        from .mpc_transport import coordinator_tls_context

        coordinator_tls_context()
        if chain_id is not None:
            from .mpc_evm_network import authorize_evm_network
            from .mpc_tron_network import authorize_tron_network

            if get_chain_spec(chain_id).kind is ChainKind.TRON:
                authorize_tron_network(chain_id)
            elif get_chain_spec(chain_id).kind is ChainKind.SOLANA:
                from .mpc_solana_network import authorize_solana_network

                authorize_solana_network(chain_id)
                if settings.CUSTODY_INDEXER_MODE != "live":
                    raise RuntimeError("Solana MPC requires genuine live deposit indexing")
            elif get_chain_spec(chain_id).kind is ChainKind.TON:
                from .mpc_ton_network import authorize_ton_network

                authorize_ton_network(chain_id)
            elif (
                get_chain_spec(chain_id).kind is ChainKind.EVM
                and settings.MPC_EVM_INTEGRATION_ENABLED
            ):
                authorize_evm_network(chain_id)
            else:
                raise RuntimeError(SELF_HOSTED_MPC_DISABLED_MESSAGE)


class CoordinatorSessionNotFound(RuntimeError):
    pass


def _seed() -> bytes:
    # NOTE: decouple config is NOT exported to os.environ, so read the backend
    # selection from Django settings (which is the single source of truth).
    try:
        from django.conf import settings

        passphrase = getattr(settings, "LOCAL_KEY_ENCRYPTION_PASSPHRASE", "")
    except Exception:
        passphrase = ""
    if not passphrase.strip():
        raise RuntimeError("LOCAL_KEY_ENCRYPTION_PASSPHRASE must be non-empty")
    return hashlib.sha256(passphrase.encode("utf-8")).digest()


def _trx_address(pub_hex: str) -> str:
    """Convert an uncompressed secp256k1 pubkey hex to a TRX base58 T-address."""
    from tronpy.keys import PublicKey

    clean = pub_hex[2:] if pub_hex.startswith("0x") else pub_hex
    return PublicKey(bytes.fromhex(clean)).to_base58check_address()


class LocalVault:
    """Derives EOAs + signs locally. NEVER used in production custody."""

    # TON has no local/demo custody signing path.
    def get_derived_address(self, network: str, path: str) -> str:
        kind = get_chain_spec(network).kind
        scalar = derive_scalar(network, path, _seed())
        if kind in (ChainKind.EVM, ChainKind.TRON):
            from eth_keys import keys

            priv = keys.PrivateKey(scalar)
            if kind is ChainKind.TRON:
                return _trx_address(priv.public_key.to_hex())
            return priv.public_key.to_checksum_address()
        if kind is ChainKind.SOLANA:
            from solders.keypair import Keypair

            kp = Keypair.from_seed(scalar)
            return str(kp.pubkey())
        if kind is ChainKind.TON:
            raise ValueError("TON demo address placeholder is not a custody contract")
        raise NotImplementedError("Unknown network for address derivation")

    def sign(self, network: str, raw: dict, path: str, idempotency_key: str) -> str:
        kind = get_chain_spec(network).kind
        scalar = derive_scalar(network, path, _seed())
        if kind is ChainKind.EVM:
            from eth_account import Account

            # STUB BROADCAST PATH: when no real (nonce/chainId/gas) fields are
            # present we return a deterministic signed ref instead of invoking
            # the live chain builder. With a real RPC/nonce, Account.sign_transaction
            # would be called with the fully-populated `raw` transaction dict.
            if not raw:
                return (
                    "signed:"
                    + hashlib.sha256(f"{network}:{path}:{idempotency_key}".encode()).hexdigest()
                )
            acct = Account.from_key(scalar)
            signed = acct.sign_transaction(raw)
            return "signed:" + signed.raw_transaction.hex()
        if kind is ChainKind.TRON:
            from tronpy.keys import PrivateKey as TronPrivateKey

            pk = TronPrivateKey(scalar)
            tx_id = raw.get("txID", raw.get("tx_id", b""))
            tx_id_hex = tx_id.hex() if isinstance(tx_id, bytes) else str(tx_id)
            return "signed:" + pk.sign_msg_hash(bytes.fromhex(tx_id_hex)).hex()
        if kind is ChainKind.SOLANA:
            from solders.keypair import Keypair

            kp = Keypair.from_seed(scalar)
            msg = raw.get("message", b"")
            if isinstance(msg, str):
                msg = base64.b64decode(msg)
            sig = kp.sign_message(msg)
            # solders returns a Signature object; convert to bytes
            sig_bytes = bytes(sig) if not isinstance(sig, bytes) else sig
            return "signed:" + base64.b64encode(sig_bytes).decode()
        if kind is ChainKind.TON:
            # STUB: production TON outbound is disabled.
            raise ValueError("TON local placeholder signing is unsupported")
        raise NotImplementedError("Unknown network for signing")

    def broadcast(self, network: str, signed_ref: str) -> str:
        from django.conf import settings

        if not settings.CUSTODY_DEMO_MODE or settings.CUSTODY_TX_MODE != "stub":
            raise RuntimeError("synthetic broadcast is restricted to demo mode and stub transport")
        # Explicit demo-only synthetic transaction reference; no RPC is called.
        if signed_ref.startswith("signed:ton:"):
            return "0x" + hashlib.sha256(signed_ref.encode()).hexdigest()[:40]
        return "0x" + hashlib.sha256(signed_ref.encode()).hexdigest()[:40]


class SelfHostedMpcAdapter:
    """Client for our mTLS-only coordinator; it never handles private material."""

    def _request(self, method: str, path: str, **kwargs):
        from .mpc_transport import coordinator_request

        return coordinator_request(
            method, path, json_payload=kwargs.get("json"), params=kwargs.get("params")
        )

    def get_derived_address(self, network: str, path: str) -> str:
        del network, path
        from .mpc_binding import UnsupportedMpcDerivation

        raise UnsupportedMpcDerivation("MPC child derivation is unsupported; bind a root keyset")

    def get_keyset(self, keyset_id: str) -> dict:
        return self._request("GET", f"/v1/keysets/{keyset_id}")

    def attest_hd(self, keyset_id: str, scope: dict) -> dict:
        return self._request("POST", f"/v1/keysets/{keyset_id}/hd-attestation", json=scope)

    def approve_child(self, keyset_id: str, request: dict) -> dict:
        return self._request("POST", f"/v1/keysets/{keyset_id}/children", json=request)

    def create_signing_session(self, payload: dict) -> dict:
        """Idempotently create the durable coordinator operation."""
        return self._request("POST", "/v1/sign-sessions", json=payload)

    def get_signing_session(self, session_id: str) -> dict:
        return self._request("GET", f"/v1/sign-sessions/{session_id}")

    def execute_signing_session(self, session_id: str) -> dict:
        return self._request("POST", f"/v1/sign-sessions/{session_id}/execute")

    def reconcile_signing_session(self, session_id: str) -> dict:
        return self._request("POST", f"/v1/sign-sessions/{session_id}/reconcile")

    def sign(self, network: str, raw: dict, path: str, idempotency_key: str) -> str:
        del network, raw, path, idempotency_key
        raise RuntimeError("self_hosted_mpc requires durable exact-payload signing advancement")

    def broadcast(self, network: str, signed_ref: str) -> str:
        del network, signed_ref
        raise RuntimeError("MPC coordinator never broadcasts transactions")


_ADAPTER: Optional[Any] = None


def get_adapter():
    """Returns the active signer adapter (LocalVault in demo, self-hosted MPC in production)."""
    global _ADAPTER
    from django.conf import settings

    if settings.MPC_SIGNER_BACKEND == "self_hosted_mpc":
        assert_mpc_backend_runtime_safe()
        return SelfHostedMpcAdapter()
    if settings.MPC_SIGNER_BACKEND != "local_key" or not settings.CUSTODY_DEMO_MODE:
        raise RuntimeError("local_key signer is restricted to demo mode")
    if _ADAPTER is None:
        # Read from Django settings (single source of truth for config).
        try:
            from django.conf import settings

            backend = getattr(settings, "MPC_SIGNER_BACKEND", "")
        except Exception:
            backend = ""
        if backend == "self_hosted_mpc":
            assert_mpc_backend_runtime_safe()
        if backend != "local_key":
            raise RuntimeError(f"unsupported signer backend: {backend!r}")
        if not settings.CUSTODY_DEMO_MODE:
            raise RuntimeError("local_key signer is restricted to demo mode")
        _ADAPTER = LocalVault()
        logger.info("signer adapter backend=%s", backend)
    return _ADAPTER
