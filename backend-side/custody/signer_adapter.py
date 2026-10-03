"""
Signer adapter layer — the concrete implementation behind `MpcSigner`.

This module owns local-development key material. `LocalVault` is explicitly a
demo signer: it derives complete keys deterministically from a passphrase
and produces real EOA addresses + real signatures for ETH/BSC/TRX/SOL. For TON
it produces a deterministic raw EOA address and a stubbed signature so the full
flow (including memo attribution) can be demonstrated end-to-end on testnets;
production TON signing should be delegated to a vendor (see `VendorSignerAdapter`)
because TON key custody is typically outsourced.

SWAP POINT: to go to production, set MPC_SIGNER_BACKEND=mpc_vendor and implement
`VendorSignerAdapter` against Fireblocks/Turnkey/Lit. No business logic in
mpc_signer.py / sweeper.py / withdrawals.py changes.
"""

from __future__ import annotations

import base64
import hashlib
import logging
from typing import Any, Optional

from .config import Network
from .crypto_utils import derive_scalar

logger = logging.getLogger("custody.vault")


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


def _ton_raw_address(scalar: bytes) -> str:
    """Deterministic TON raw EOA: '0:' + 64 hex of the scalar.

    A real deployment derives this from the vendor MPC root key; this stand-in
    keeps TON deposit-address generation runnable for the demo. The user is
    still attributed via the TON memo, never via a contract address.
    """
    return "0:" + scalar.hex()


def _trx_address(pub_hex: str) -> str:
    """Convert an uncompressed secp256k1 pubkey hex to a TRX base58 T-address."""
    from tronpy.keys import PublicKey

    clean = pub_hex[2:] if pub_hex.startswith("0x") else pub_hex
    return PublicKey(bytes.fromhex(clean)).to_base58check_address()


class LocalVault:
    """Derives EOAs + signs locally. NEVER used in production custody."""

    # ---- TON produces a deterministic EOA + stubbed signature ----
    def get_derived_address(self, network: str, path: str) -> str:
        net = Network(network)
        scalar = derive_scalar(network, path, _seed())
        if net in (Network.ETH, Network.BSC, Network.TRX):
            from eth_keys import keys

            priv = keys.PrivateKey(scalar)
            if net is Network.TRX:
                return _trx_address(priv.public_key.to_hex())
            return priv.public_key.to_checksum_address()
        if net is Network.SOL:
            from solders.keypair import Keypair

            kp = Keypair.from_seed(scalar)
            return str(kp.pubkey())
        if net is Network.TON:
            return _ton_raw_address(scalar)
        raise NotImplementedError("Unknown network for address derivation")

    def sign(self, network: str, raw: dict, path: str, idempotency_key: str) -> str:
        net = Network(network)
        scalar = derive_scalar(network, path, _seed())
        if net in (Network.ETH, Network.BSC):
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
        if net is Network.TRX:
            from tronpy.keys import PrivateKey as TronPrivateKey

            pk = TronPrivateKey(scalar)
            tx_id = raw.get("tx_id", b"")
            tx_id_hex = tx_id.hex() if isinstance(tx_id, bytes) else str(tx_id)
            return "signed:" + pk.sign_msg(tx_id_hex)
        if net is Network.SOL:
            from solders.keypair import Keypair

            kp = Keypair.from_seed(scalar)
            msg = raw.get("message", b"")
            if isinstance(msg, str):
                msg = msg.encode()
            sig = kp.sign_message(msg)
            # solders returns a Signature object; convert to bytes
            sig_bytes = bytes(sig) if not isinstance(sig, bytes) else sig
            return "signed:" + base64.b64encode(sig_bytes).decode()
        if net is Network.TON:
            # STUB: production delegates TON signing to the MPC vendor.
            return "signed:ton:" + hashlib.sha256(f"{path}:{idempotency_key}".encode()).hexdigest()
        raise NotImplementedError("Unknown network for signing")

    def broadcast(self, network: str, signed_ref: str) -> str:
        from django.conf import settings

        if not settings.CUSTODY_DEMO_MODE:
            raise RuntimeError("synthetic broadcast is restricted to demo mode")
        # Explicit demo-only synthetic transaction reference; no RPC is called.
        if signed_ref.startswith("signed:ton:"):
            return "0x" + hashlib.sha256(signed_ref.encode()).hexdigest()[:40]
        return "0x" + hashlib.sha256(signed_ref.encode()).hexdigest()[:40]


class VendorSignerAdapter:
    """Production stub. Wire to Fireblocks/Turnkey/Lit here.

    The interface mirrors LocalVault so MpcSigner is agnostic:
        get_derived_address(network, path) -> EOA string
        sign(network, raw, path, idempotency_key) -> signed payload ref
        broadcast(network, signed_ref) -> tx_hash
    """

    def get_derived_address(self, network: str, path: str) -> str:
        raise NotImplementedError("Vendor MPC get_derived_address not configured")

    def sign(self, network: str, raw: dict, path: str, idempotency_key: str) -> str:
        raise NotImplementedError("Vendor MPC sign not configured")

    def broadcast(self, network: str, signed_ref: str) -> str:
        raise NotImplementedError("Vendor MPC broadcast not configured")


_ADAPTER: Optional[Any] = None


def get_adapter():
    """Returns the active signer adapter (LocalVault in dev, Vendor in prod)."""
    global _ADAPTER
    if _ADAPTER is None:
        # Read from Django settings (single source of truth for config).
        try:
            from django.conf import settings

            backend = getattr(settings, "MPC_SIGNER_BACKEND", "")
        except Exception:
            backend = ""
        if backend == "mpc_vendor":
            raise RuntimeError("mpc_vendor adapter is not implemented")
        if backend != "local_key":
            raise RuntimeError(f"unsupported signer backend: {backend!r}")
        if not settings.CUSTODY_DEMO_MODE:
            raise RuntimeError("local_key signer is restricted to demo mode")
        _ADAPTER = LocalVault()
        logger.info("signer adapter backend=%s", backend)
    return _ADAPTER
