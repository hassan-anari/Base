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

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from .audit import AuditAction, write_audit_log
from .config import ensure_hot_wallet, native_asset_key, validate_chain_asset
from .ledger import release_withdrawal, reserve_withdrawal, settle_withdrawal
from .models import HotWallet, WithdrawalRequest
from .mpc_signer import SignPolicy, UnsignedTx, get_signer

logger = logging.getLogger("custody.withdrawals")


def create_request(
    user_id: str,
    network: str,
    to_address: str,
    amount: Decimal,
    asset_key: str | None = None,
    idempotency_key: str | None = None,
) -> WithdrawalRequest:
    """User submits a withdrawal. Stays PENDING_APPROVAL until admin acts."""
    asset_key = asset_key or native_asset_key(network)  # default to native asset
    validate_chain_asset(network, asset_key, "withdrawal")
    if idempotency_key is None:
        raise ValueError("idempotency_key is required")
    decimal_amount = Decimal(str(amount))
    if decimal_amount <= 0:
        raise ValueError("amount must be greater than zero")
    requested = {
        "user_id": user_id,
        "chain_id": network,
        "asset_key": asset_key,
        "to_address": to_address,
        "amount": decimal_amount,
    }
    with transaction.atomic():
        try:
            # The unique key is the arbitration boundary. The savepoint keeps
            # the outer transaction usable when a concurrent creator wins.
            with transaction.atomic():
                req = WithdrawalRequest.objects.create(
                    idempotency_key=idempotency_key, **requested, status="PENDING_APPROVAL"
                )
            created = True
        except IntegrityError:
            req = WithdrawalRequest.objects.select_for_update().get(idempotency_key=idempotency_key)
            created = False
        if any(getattr(req, key) != value for key, value in requested.items()):
            raise ValueError("idempotency_key was already used with different parameters")
        if created:
            reserve_withdrawal(req)
        return req


def approve(admin_id: str, req_id: int, notes: str | None = None) -> WithdrawalRequest:
    """Admin approval. Required before any broadcast."""
    with transaction.atomic():
        req = WithdrawalRequest.objects.select_for_update().get(id=req_id)
        if req.status in {
            "APPROVED",
            "PROCESSING",
            "BROADCASTED",
            "CONFIRMED",
            "RECONCILIATION_REQUIRED",
        }:
            return req
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
            {"to": req.to_address, "amount": str(req.amount)},
        )
    return req


def deny(admin_id: str, req_id: int, notes: str | None = None) -> WithdrawalRequest:
    """Admin denial."""
    with transaction.atomic():
        req = WithdrawalRequest.objects.select_for_update().get(id=req_id)
        if req.status == "DENIED":
            return req
        if req.status != "PENDING_APPROVAL":
            raise ValueError(f"cannot deny in state {req.status}")
        release_withdrawal(req)
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
    req = WithdrawalRequest.objects.get(id=req_id)
    if req.status != "APPROVED":
        raise ValueError("withdrawal must be APPROVED before broadcast")
    validate_chain_asset(req.chain_id, req.asset_key, "withdrawal")

    claimed_by_this_call = False

    def claim_after_guards():
        nonlocal claimed_by_this_call
        with transaction.atomic():
            claimed = WithdrawalRequest.objects.select_for_update().get(id=req_id)
            if claimed.status != "APPROVED":
                raise ValueError("withdrawal must be APPROVED before broadcast")
            claimed.status = "PROCESSING"
            claimed.save(update_fields=["status", "updated_at"])
            claimed_by_this_call = True

    try:
        hot = ensure_hot_wallet(req.chain_id)
        key_ref = HotWallet.objects.get(chain_id=req.chain_id).signing_key_ref
        if not key_ref:
            raise ValueError("hot wallet signing_key_ref is not configured")
        if settings.CUSTODY_TX_MODE == "live":
            from .native_tx import AmbiguousBroadcast
            from .outbound import create_attempt, execute_attempt

            claim_after_guards()
            attempt = create_attempt(
                operation_type="WITHDRAWAL",
                operation_id=req.pk,
                chain_id=req.chain_id,
                asset_key=req.asset_key,
                source=hot,
                destination=req.to_address,
                amount=req.amount,
            )
            try:
                attempt = execute_attempt(attempt.pk, admin_id)
            except AmbiguousBroadcast:
                WithdrawalRequest.objects.filter(pk=req.pk).update(
                    status="RECONCILIATION_REQUIRED", updated_at=timezone.now()
                )
                raise
            except Exception:
                # No ambiguous external effect: preparation/signing failures
                # remain safely retryable from the approved business intent.
                state = type(attempt).objects.get(pk=attempt.pk).status
                if state == "FAILED":
                    WithdrawalRequest.objects.filter(pk=req.pk, status="PROCESSING").update(
                        status="APPROVED", updated_at=timezone.now()
                    )
                    claimed_by_this_call = False
                raise
            WithdrawalRequest.objects.filter(pk=req.pk, status="PROCESSING").update(
                status="BROADCASTED",
                tx_hash=attempt.network_tx_id,
                updated_at=timezone.now(),
            )
            return WithdrawalRequest.objects.get(pk=req.pk)
        tx = UnsignedTx(
            chain_id=req.chain_id,
            asset_key=req.asset_key,
            from_address=hot,
            to_address=req.to_address,
            amount=req.amount,
            derivation_path=key_ref,
            memo=None,
        )
        signer = get_signer()
        res = signer.sign_and_broadcast(
            actor_id=admin_id,
            tx=tx,
            policy=SignPolicy.WITHDRAWAL,
            idempotency_key=req.idempotency_key,
            before_sign=claim_after_guards,
        )
    except Exception:
        if claimed_by_this_call:
            WithdrawalRequest.objects.filter(pk=req.pk, status="PROCESSING").update(
                status="RECONCILIATION_REQUIRED", updated_at=timezone.now()
            )
        raise
    # Persist a safe non-retryable state before recording the successful
    # external response. A failed final write therefore cannot expose the
    # withdrawal as APPROVED/retryable.
    WithdrawalRequest.objects.filter(pk=req.pk, status="PROCESSING").update(
        status="RECONCILIATION_REQUIRED", updated_at=timezone.now()
    )
    try:
        with transaction.atomic():
            req = WithdrawalRequest.objects.select_for_update().get(pk=req.pk)
            if req.status != "RECONCILIATION_REQUIRED":
                raise ValueError(f"unexpected withdrawal state {req.status}")
            req.status = "BROADCASTED"
            req.tx_hash = res.tx_hash
            req.updated_at = timezone.now()
            req.save(update_fields=["status", "tx_hash", "updated_at"])
    except Exception:
        WithdrawalRequest.objects.filter(pk=req.pk).exclude(status="BROADCASTED").update(
            status="RECONCILIATION_REQUIRED", updated_at=timezone.now()
        )
        raise
    logger.info("withdrawal broadcast req=%s tx=%s", req.id, res.tx_hash)
    return req


def mark_confirmed(req_id: int) -> WithdrawalRequest:
    """Atomically settle a final on-chain withdrawal exactly once."""
    with transaction.atomic():
        req = WithdrawalRequest.objects.select_for_update().get(id=req_id)
        if req.status == "CONFIRMED":
            return req
        if req.status != "BROADCASTED":
            raise ValueError(f"cannot confirm withdrawal in state {req.status}")
        settle_withdrawal(req)
        req.status = "CONFIRMED"
        req.save(update_fields=["status", "updated_at"])
        return req
