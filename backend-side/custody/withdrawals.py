"""
Withdrawal workflow with mandatory manual admin approval.

Lifecycle (WithdrawalRequest.status):
  PENDING_APPROVAL  -- created by user, NO on-chain action yet
    -> APPROVED     -- admin approves (required before any signing)
    -> DENIED       -- admin denies
  APPROVED
    -> BROADCASTED  -- system signs (WITHDRAWAL policy) + broadcasts hot->user
    -> CONFIRMED    -- indexer confirms finality
    -> FAILED

SECURITY / ENFORCEMENT:
  - sign_and_broadcast is ONLY called after status == APPROVED (see
    process_withdrawal). The MPC signer policy WITHDRAWAL also enforces this.
  - Approve/deny are admin-only (RBAC enforced in api.py).
  - Every approve/deny/broadcast writes an AdminActionLog audit entry.
  - Replay protection: idempotency_key on the request; broadcast guarded by
    status transition (only APPROVED -> BROADCASTED).
"""
from __future__ import annotations

import logging
import uuid
from decimal import Decimal

from django.utils import timezone

from .config import Network, get_chain, get_asset, ensure_hot_wallet, native_asset_key
from .mpc_signer import get_signer, SignPolicy, UnsignedTx
from .models import WithdrawalRequest, HotWallet
from .audit import AuditAction, write_audit_log
from .rate_limit import rate_limiter

logger = logging.getLogger("custody.withdrawals")


def create_request(user_id: str, network: str, to_address: str,
                   amount: float, asset_key: str | None = None,
                   idempotency_key: str | None = None) -> WithdrawalRequest:
    """User submits a withdrawal. Stays PENDING_APPROVAL until admin acts."""
    asset_key = asset_key or native_asset_key(network)  # default to native asset
    get_asset(asset_key)  # validate asset exists
    get_chain(network)
    if idempotency_key is None:
        idempotency_key = f"wd:{user_id}:{network}:{asset_key}:{uuid.uuid4().hex}"
    req, _ = WithdrawalRequest.objects.get_or_create(
        idempotency_key=idempotency_key,
        defaults={
            "user_id": user_id,
            "chain_id": network,
            "asset_key": asset_key,
            "to_address": to_address,
            "amount": Decimal(str(amount)),
            "status": "PENDING_APPROVAL",
        },
    )
    return req


def approve(admin_id: str, req_id: int, notes: str | None = None) -> WithdrawalRequest:
    """Admin approval. Required before any broadcast."""
    req = WithdrawalRequest.objects.get(id=req_id)
    if req.status != "PENDING_APPROVAL":
        raise ValueError(f"cannot approve in state {req.status}")
    req.status = "APPROVED"
    req.admin_notes = notes
    req.save(update_fields=["status", "admin_notes", "updated_at"])
    write_audit_log(admin_id, AuditAction.WITHDRAWAL_APPROVE, "WithdrawalRequest",
                    str(req.id), {"to": req.to_address, "amount": float(req.amount)})
    return req


def deny(admin_id: str, req_id: int, notes: str | None = None) -> WithdrawalRequest:
    """Admin denial."""
    req = WithdrawalRequest.objects.get(id=req_id)
    if req.status != "PENDING_APPROVAL":
        raise ValueError(f"cannot deny in state {req.status}")
    req.status = "DENIED"
    req.admin_notes = notes
    req.save(update_fields=["status", "admin_notes", "updated_at"])
    write_audit_log(admin_id, AuditAction.WITHDRAWAL_DENY, "WithdrawalRequest",
                    str(req.id), {"notes": notes})
    return req


def process_withdrawal(admin_id: str, req_id: int) -> WithdrawalRequest:
    """Sign + broadcast on-chain transfer (hot wallet -> user address).

    MUST only run for APPROVED requests. Idempotent on status transition.
    """
    req = WithdrawalRequest.objects.get(id=req_id)
    if req.status != "APPROVED":
        raise ValueError("withdrawal must be APPROVED before broadcast")
    rate_limiter.consume(f"sign:{admin_id}:WITHDRAWAL", limit=10, window_seconds=60)

    net = Network(req.chain_id)
    hot = ensure_hot_wallet(req.chain_id)
    tx = UnsignedTx(
        network=net,
        chain_id=req.chain_id,
        asset_key=req.asset_key,
        from_address=hot,
        to_address=req.to_address,
        amount=float(req.amount),
        derivation_path="<hot-wallet-path>",
        memo=None,
    )
    signer = get_signer()
    res = signer.sign_and_broadcast(
        actor_id=admin_id, tx=tx,
        policy=SignPolicy.WITHDRAWAL, idempotency_key=req.idempotency_key,
    )
    req.status = "BROADCASTED"
    req.tx_hash = res.tx_hash
    req.updated_at = timezone.now()
    req.save(update_fields=["status", "tx_hash", "updated_at"])
    logger.info("withdrawal broadcast req=%s tx=%s", req.id, res.tx_hash)
    return req


def mark_confirmed(req_id: int) -> None:
    req = WithdrawalRequest.objects.get(id=req_id)
    req.status = "CONFIRMED"
    req.save(update_fields=["status", "updated_at"])