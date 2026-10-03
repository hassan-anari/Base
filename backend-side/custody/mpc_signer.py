"""
MPC Signer abstraction + policy enforcement.

SECURITY BOUNDARY
-----------------
- Django NEVER handles raw MPC key material. It only sends *unsigned
  transaction descriptors* + a *policy* to a signing service adapter.
- Every signing request must be (a) authorized, (b) validated, (c) rate-limited,
  and (d) audited. See the guard points below.
- We never log secrets. Signing responses (tx_hash) are safe to log; raw
  signed payloads / key handles are NOT logged.

POLICIES
--------
- SWEEPER: only forward from user deposit EOA -> hot wallet; only when the
  balance-check threshold condition was met; idempotency required.
- WITHDRAWAL: only after manual admin approval (status == APPROVED).

Guard points (stubbed but documented):
  1. authorize_request()    -> JWT/role check (caller allowed to sign?)
  2. validate_transaction() -> amount>0, dest format valid, min/dust checks
  3. enforce_rate_limit()   -> per (actor, action) token bucket (Redis stub)
  4. audit_sign_request()   -> write AdminActionLog for every signing request
  5. simulate()             -> optional pre-sign simulation hook
  6. sign()                 -> call vendor adapter (never returns raw key)
  7. broadcast()            -> send signed tx to network; store tx_hash
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Optional

from .audit import AuditAction, write_audit_log
from .config import Network, get_chain, ensure_hot_wallet
from .rate_limit import RateLimitExceeded, rate_limiter

logger = logging.getLogger("custody.signer")
# Never log secrets: configure structured logging that redacts payloads.
logging.getLogger("custody.signer").addFilter(lambda r: r)  # placeholder


class SignPolicy(StrEnum):
    SWEEPER = "SWEEPER"
    WITHDRAWAL = "WITHDRAWAL"
    GAS_TOPUP = "GAS_TOPUP"


class SignerError(RuntimeError):
    pass


@dataclass
class UnsignedTx:
    """Network-agnostic unsigned transaction descriptor.

    Django builds this; the MPC adapter serializes it for the vault.
    No private key material is ever placed here.
    """
    network: Network
    from_address: str          # custody-side EOA (user deposit EOA or hot wallet)
    to_address: str            # destination EOA (hot wallet or user receiver)
    amount: float
    derivation_path: str       # path the vault should sign with
    chain_id: str = ""         # config registry key (e.g. "ETH")
    asset_key: str = ""        # asset/token key (e.g. "USDT-BSC")
    memo: Optional[str] = None  # TON memo attribution (kept in plaintext, not secret)
    raw: dict[str, Any] = None  # network-specific extras (nonce, gas, etc.)


@dataclass
class SignResult:
    tx_hash: str
    signed_payload_ref: str = ""  # opaque ref to signed payload (NOT the key)


class MpcSigner:
    """Vendor-agnostic MPC signing adapter wrapper.

    In production, ``adapter`` is a thin client to Fireblocks / Turnkey /
    Lit / custom MPC nodes. We stub it here.
    """

    def __init__(self, adapter=None):
        self._adapter = adapter

    # ---- Guard point 1: authorization ----
    def authorize_request(self, actor_id: str, policy: SignPolicy) -> None:
        """Verify the caller/role is allowed to initiate this policy.

        In production this checks JWT claims + RBAC (admin vs user).
        Sweeper/GasTopup are system-initiated (service token); Withdrawal
        requires an approved record tied to an admin action.
        """
        # Stub: defer to RBAC module. Raise PermissionError if not allowed.
        if policy is SignPolicy.WITHDRAWAL and actor_id == "anonymous":
            raise PermissionError("Withdrawal signing requires authorized admin")

    # ---- Guard point 2: validation ----
    def validate_transaction(self, tx: UnsignedTx, policy: SignPolicy) -> None:
        """Sanity checks: amount>0, destination format, dust/mins."""
        if tx.amount <= 0:
            raise SignerError("amount must be > 0")
        cfg = get_chain(tx.chain_id)
        self._check_destination_format(tx.network, tx.to_address)
        # Dust guard: do not sweep/withdraw below a sane floor.
        min_amount = (cfg.deposit_threshold or 0) * 0.1
        if tx.amount < min_amount:
            raise SignerError(f"amount below dust floor {min_amount}")
        # Policy routing: sweeper MUST go to the chain hot wallet.
        if policy is SignPolicy.SWEEPER and tx.to_address != ensure_hot_wallet(tx.chain_id):
            raise SignerError("sweeper destination must be the hot wallet")

    @staticmethod
    def _check_destination_format(network: Network, address: str) -> None:
        if network in (Network.ETH, Network.BSC) and not address.startswith("0x"):
            raise SignerError("invalid EVM destination")
        if network is Network.TRX and not (address.startswith("T") or address.startswith("0x")):
            raise SignerError("invalid TRX destination")
        if network is Network.SOL and len(address) < 32:
            raise SignerError("invalid SOL destination")
        if network is Network.TON and not address:
            raise SignerError("invalid TON destination")

    # ---- Guard point 3: rate limiting ----
    def enforce_rate_limit(self, actor_id: str, policy: SignPolicy) -> None:
        key = f"sign:{actor_id}:{policy.value}"
        try:
            rate_limiter.consume(key, limit=20, window_seconds=60)
        except RateLimitExceeded:
            logger.warning("rate limit hit for %s", key)
            raise

    # ---- Guard point 4 + 6/7: audit + sign + broadcast ----
    def sign_and_broadcast(
        self,
        actor_id: str,
        tx: UnsignedTx,
        policy: SignPolicy,
        *,
        idempotency_key: str,
    ) -> SignResult:
        """Authorized, validated, rate-limited, audited sign+broadcast.

        Returns SignResult with tx_hash. Raises on any guard failure.
        """
        # 1. authorize
        self.authorize_request(actor_id, policy)
        # 2. validate
        self.validate_transaction(tx, policy)
        # 3. rate limit
        self.enforce_rate_limit(actor_id, policy)
        # 4. audit (request start) -- never include secret material
        write_audit_log(
            actor_id=actor_id,
            action=AuditAction.SIGN_REQUEST,
            entity_type="UnsignedTx",
            entity_id=idempotency_key,
            metadata={
                "network": tx.network.value,
                "policy": policy.value,
                "from": tx.from_address,
                "to": tx.to_address,
                "amount": tx.amount,
                "memo": tx.memo,
            },
        )
        # 5. simulate (optional stub)
        self._simulate(tx)
        # 6. sign (adapter call; never returns raw key)
        signed_ref = self._sign(tx, idempotency_key)
        # 7. broadcast
        tx_hash = self._broadcast(tx, signed_ref)
        # audit (broadcast)
        write_audit_log(
            actor_id=actor_id,
            action=AuditAction.BROADCAST,
            entity_type="Tx",
            entity_id=tx_hash,
            metadata={"network": tx.network.value, "policy": policy.value},
        )
        logger.info("broadcasted %s policy=%s tx=%s", tx.network.value, policy.value, tx_hash)
        return SignResult(tx_hash=tx_hash, signed_payload_ref=signed_ref)

    # ---- Optional simulation hook ----
    def _simulate(self, tx: UnsignedTx) -> None:
        """STUB: pre-sign simulation (estimate gas / dry-run) for safety."""
        # e.g. adapter.simulate(network, tx.raw)
        return None

    def _sign(self, tx: UnsignedTx, idempotency_key: str) -> str:
        """Call MPC vault to sign. Returns opaque signed-payload ref.

        The adapter owns the key material; we only hand it the unsigned
        descriptor (network + raw tx + derivation path). Never returns a key.
        """
        adapter = self._adapter or _get_adapter()
        return adapter.sign(tx.network.value, tx.raw or {}, tx.derivation_path,
                            idempotency_key)

    def _broadcast(self, tx: UnsignedTx, signed_ref: str) -> str:
        """Broadcast signed tx via the adapter; returns tx_hash."""
        adapter = self._adapter or _get_adapter()
        return adapter.broadcast(tx.network.value, signed_ref)


def _get_adapter():
    from .signer_adapter import get_adapter
    return get_adapter()


# Singleton-ish convenience
_default_signer: Optional[MpcSigner] = None


def get_signer() -> MpcSigner:
    global _default_signer
    if _default_signer is None:
        _default_signer = MpcSigner()
    return _default_signer