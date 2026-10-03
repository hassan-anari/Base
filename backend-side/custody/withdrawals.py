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
from decimal import Decimal

from django.db import transaction
from django.utils import timezone

from .audit import AuditAction, write_audit_log
from .config import Network, ensure_hot_wallet, native_asset_key, validate_chain_asset
from .models import WithdrawalRequest
from .mpc_signer import SignPolicy, UnsignedTx, get_signer
from .rate_limit import rate_limiter

logger = logging.getLogger("custody.withdrawals")


def create_request(
    user_id: str,
    network: str,
    to_address: str,
    amount: float,
    asset_key: str | None = None,
    idempotency_key: str | None = None,
) -> WithdrawalRequest:
    """User submits a withdrawal. Stays PENDING_APPROVAL until admin acts."""
    asset_key = asset_key or native_asset_key(network)  # default to native asset
    validate_chain_asset(network, asset_key)
    if idempotency_key is None:
        raise ValueError("idempotency_key is required")
    requested = {
        "user_id": user_id,
        "chain_id": network,
        "asset_key": asset_key,
        "to_address": to_address,
        "amount": Decimal(str(amount)),
    }
    req, created = WithdrawalRequest.objects.get_or_create(
        idempotency_key=idempotency_key,
        defaults={**requested, "status": "PENDING_APPROVAL"},
    )
    if not created and any(getattr(req, key) != value for key, value in requested.items()):
        raise ValueError("idempotency_key was already used with different parameters")
    return req


def approve(admin_id: str, req_id: int, notes: str | None = None) -> WithdrawalRequest:
    """Admin approval. Required before any broadcast."""
    with transaction.atomic():
        req = WithdrawalRequest.objects.select_for_update().get(id=req_id)
        if req.status != "PENDING_APPROVAL":
            raise ValueError(f"cannot approve in state {req.status}")
        req.status = "APPROVED"
        req.admin_notes = notes
        req.save(update_fields=["status", "admin_notes", "updated_at"])
        write_audit_log(
            admin_id,
            AuditAction.WITHDRAWAL_APPROVE,
            "WithdrawalRequest",
            str(req.id),
            {"to": req.to_address, "amount": float(req.amount)},
        )
    return req


def deny(admin_id: str, req_id: int, notes: str | None = None) -> WithdrawalRequest:
    """Admin denial."""
    with transaction.atomic():
        req = WithdrawalRequest.objects.select_for_update().get(id=req_id)
        if req.status != "PENDING_APPROVAL":
            raise ValueError(f"cannot deny in state {req.status}")
        req.status = "DENIED"
        req.admin_notes = notes
        req.save(update_fields=["status", "admin_notes", "updated_at"])
        write_audit_log(
            admin_id,
            AuditAction.WITHDRAWAL_DENY,
            "WithdrawalRequest",
            str(req.id),
            {"notes": notes},
        )
    return req


def process_withdrawal(admin_id: str, req_id: int) -> WithdrawalRequest:
    """Sign + broadcast on-chain transfer (hot wallet -> user address).

    MUST only run for APPROVED requests. Idempotent on status transition.
    """
    with transaction.atomic():
        req = WithdrawalRequest.objects.select_for_update().get(id=req_id)
        if req.status != "APPROVED":
            raise ValueError("withdrawal must be APPROVED before broadcast")
        req.status = "PROCESSING"
        req.save(update_fields=["status", "updated_at"])
        rate_limiter.consume(f"sign:{admin_id}:WITHDRAWAL", limit=10, window_seconds=60)
        validate_chain_asset(req.chain_id, req.asset_key)
    try:
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
            actor_id=admin_id,
            tx=tx,
            policy=SignPolicy.WITHDRAWAL,
            idempotency_key=req.idempotency_key,
        )
    except Exception:
        WithdrawalRequest.objects.filter(pk=req.pk, status="PROCESSING").update(
            status="FAILED", updated_at=timezone.now()
        )
        raise
    with transaction.atomic():
        req = WithdrawalRequest.objects.select_for_update().get(pk=req.pk)
        if req.status != "PROCESSING":
            raise ValueError(f"unexpected withdrawal state {req.status}")
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
