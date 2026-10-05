"""
MPC Signer abstraction + policy enforcement.

SECURITY BOUNDARY
-----------------
- A future vendor adapter must keep MPC key material outside Django and accept
  only unsigned descriptors. The explicit local demo adapter is an exception:
  it derives complete private keys in-process and is not production MPC.
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
from dataclasses import dataclass, field
from decimal import Decimal
from enum import StrEnum
from typing import Any, Callable, Optional

from .audit import AuditAction, write_audit_log
from .chain_adapters import get_adapter
from .config import ensure_hot_wallet, get_chain
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

    chain_id: str
    asset_key: str
    from_address: str  # custody-side EOA (user deposit EOA or hot wallet)
    to_address: str  # destination EOA (hot wallet or user receiver)
    amount: Decimal
    derivation_path: str  # path the vault should sign with
    memo: Optional[str] = None  # TON memo attribution (kept in plaintext, not secret)
    raw: dict[str, Any] = field(default_factory=dict)


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
        try:
            get_adapter(tx.chain_id).validate_address(tx.to_address)
        except ValueError as exc:
            raise SignerError(str(exc)) from exc
        from .config import get_asset

        asset = get_asset(tx.asset_key)
        if asset.chain_id != tx.chain_id:
            raise SignerError("signing asset does not belong to transaction chain")
        # Native dust policy remains in native units. Tokens already passed
        # exact positive/base-unit validation; never compare them to native units.
        if asset.is_native:
            min_amount = (cfg.deposit_threshold or Decimal("0")) * Decimal("0.1")
            if tx.amount < min_amount:
                raise SignerError(f"amount below dust floor {min_amount}")
        # Policy routing: sweeper MUST go to the chain hot wallet.
        if policy is SignPolicy.SWEEPER and tx.to_address != ensure_hot_wallet(tx.chain_id):
            raise SignerError("sweeper destination must be the hot wallet")

    # ---- Guard point 3: rate limiting ----
    def enforce_rate_limit(self, actor_id: str, policy: SignPolicy) -> None:
        key = f"sign:{actor_id}:{policy.value}"
        try:
            rate_limiter.consume(key, limit=20, window_seconds=60)
        except RateLimitExceeded:
            logger.warning("rate limit hit for %s", key)
            raise

    def sign(
        self,
        actor_id: str,
        tx: UnsignedTx,
        policy: SignPolicy,
        *,
        idempotency_key: str,
    ) -> str:
        """Authorize and sign prepared bytes; broadcasting belongs to the executor."""
        self.authorize_request(actor_id, policy)
        self.validate_transaction(tx, policy)
        self.enforce_rate_limit(actor_id, policy)
        adapter = self._adapter or _get_adapter()
        derived = adapter.get_derived_address(tx.chain_id, tx.derivation_path)
        if not _addresses_equal(tx.chain_id, derived, tx.from_address):
            raise SignerError("signing key reference does not control source address")
        write_audit_log(
            actor_id=actor_id,
            action=AuditAction.SIGN_REQUEST,
            entity_type="PreparedNativeTransaction",
            entity_id=idempotency_key,
            metadata={
                "chain_id": tx.chain_id,
                "asset_key": tx.asset_key,
                "policy": policy.value,
                "from": tx.from_address,
                "to": tx.to_address,
                "amount": str(tx.amount),
            },
        )
        return self._sign(tx, idempotency_key)

    # ---- Guard point 4 + 6/7: audit + sign + broadcast ----
    def sign_and_broadcast(
        self,
        actor_id: str,
        tx: UnsignedTx,
        policy: SignPolicy,
        *,
        idempotency_key: str,
        before_sign: Callable[[], None] | None = None,
    ) -> SignResult:
        """Authorized, validated, rate-limited, audited sign+broadcast.

        Returns SignResult with tx_hash. Raises on any guard failure.
        """
        from django.conf import settings

        if settings.CUSTODY_TX_MODE != "stub":
            raise SignerError("legacy sign_and_broadcast is restricted to stub transport mode")
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
                "chain_id": tx.chain_id,
                "asset_key": tx.asset_key,
                "policy": policy.value,
                "from": tx.from_address,
                "to": tx.to_address,
                "amount": str(tx.amount),
                "memo": tx.memo,
            },
        )
        # 5. simulate (optional stub)
        self._simulate(tx)
        if before_sign:
            before_sign()
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
            metadata={
                "chain_id": tx.chain_id,
                "asset_key": tx.asset_key,
                "amount": str(tx.amount),
                "policy": policy.value,
            },
        )
        logger.info("broadcasted %s policy=%s tx=%s", tx.chain_id, policy.value, tx_hash)
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
        return adapter.sign(tx.chain_id, tx.raw, tx.derivation_path, idempotency_key)

    def _broadcast(self, tx: UnsignedTx, signed_ref: str) -> str:
        """Broadcast signed tx via the adapter; returns tx_hash."""
        adapter = self._adapter or _get_adapter()
        return adapter.broadcast(tx.chain_id, signed_ref)


def _get_adapter():
    from .signer_adapter import get_adapter

    return get_adapter()


def _addresses_equal(chain_id: str, derived: str, expected: str) -> bool:
    """Use family-correct address equivalence (Base58 is case-sensitive)."""
    from .chain_registry import ChainKind, get_chain_spec

    if get_chain_spec(chain_id).kind is ChainKind.EVM:
        try:
            from eth_utils import to_checksum_address

            return to_checksum_address(derived) == to_checksum_address(expected)
        except ValueError:
            return False
    return derived == expected


# Singleton-ish convenience
_default_signer: Optional[MpcSigner] = None


def get_signer() -> MpcSigner:
    global _default_signer
    if _default_signer is None:
        _default_signer = MpcSigner()
    return _default_signer
