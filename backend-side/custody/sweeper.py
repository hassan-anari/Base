"""
Sweeper workflow: user deposit EOA -> hot wallet.

Triggered ONLY by a user "Check Balance" action (balance check endpoint),
and ONLY when confirmed balance > deposit_threshold. Runs automatically to
completion once started.

STATE MACHINE (SweepJob.status):
  CREATED
    -> GAS_TOPUP_REQUIRED        (if deposit EOA needs gas to broadcast)
       -> GAS_TOPUP_BROADCASTED  (gas topup signed+broadcast)
    -> SWEEP_BROADCASTED         (sweep signed+broadcast EOA -> hot wallet)
    -> CONFIRMED | FAILED

IDEMPOTENCY (prevent double-sweep):
  - UniqueConstraint(user_wallet, sweep_round): one job per rounded sweep.
  - While ANY sweep for the wallet is in-flight (not CONFIRMED/FAILED),
    repeated "Check Balance" calls return the existing job rather than
    creating a new one (double-sweep prevention).
  - A wallet-scoped Redis lock `sweep:{user_wallet_id}` guards concurrent runs.
  - Idempotency key = f"sweep:{user_wallet_id}:{round}" passed to signer so
    the MPC vault also de-dupes.

POLICY ENFORCEMENT (see mpc_signer):
  - Sweeper policy requires balance-check trigger + threshold met (checked in
    trigger_sweep) and destination == hot wallet (checked in signer.validate).
"""

from __future__ import annotations

import logging
from decimal import Decimal

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .audit import AuditAction, write_audit_log
from .config import (
    effective_deposit_threshold,
    ensure_hot_wallet,
    get_chain,
    is_memo_required,
    validate_chain_asset,
)
from .deposits import ingest_event
from .gas_station import AmbiguousBroadcastError, ensure_gas
from .indexer.factory import get_indexer
from .models import SweepJob, UserWallet
from .mpc_signer import SignPolicy, UnsignedTx, get_signer
from .native_tx import SafePreBroadcastRejection
from .rate_limit import rate_limiter

logger = logging.getLogger("custody.sweeper")


def _current_round(user_wallet_id: int) -> int:
    """Next sweep round = (max existing round) + 1, else 1."""
    last = SweepJob.objects.filter(user_wallet_id=user_wallet_id).order_by("-sweep_round").first()
    return (last.sweep_round + 1) if last else 1


def _inflight_job(user_wallet: UserWallet):
    """Return an unfinished (in-flight) sweep job for this wallet, if any."""
    return (
        SweepJob.objects.filter(user_wallet=user_wallet)
        .exclude(status__in=("CONFIRMED", "FAILED"))
        .order_by("-sweep_round")
        .first()
    )


def trigger_sweep(
    user_wallet: UserWallet, actor_id: str, balance_result=None
) -> tuple[bool, int | None, str]:
    """Entry point from balance-check. Returns (triggered, sweep_job_id, reason).

    Called by the balance-check endpoint AFTER confirming balance > threshold.
    Implements idempotency + double-sweep prevention:
      - If an in-flight sweep exists for the wallet, repeated "Check Balance"
        calls return that existing job instead of creating a new one.
      - A new sweep round is only started once the previous round is
        CONFIRMED or FAILED.
    """
    cfg = get_chain(user_wallet.chain_id)
    asset = validate_chain_asset(user_wallet.chain_id, user_wallet.asset_key, "sweep")
    threshold = effective_deposit_threshold(asset, cfg)

    # Idempotency: if a sweep is already in flight, do not start another.
    inflight = _inflight_job(user_wallet)
    if inflight:
        return (True, inflight.id, "already running")

    # Guard point: lock is wallet-scoped (only one in-flight sweep at a time).
    lock_key = f"sweep:{user_wallet.id}"
    if not rate_limiter.acquire_lock(lock_key, ttl=120):
        inflight = _inflight_job(user_wallet)
        return (inflight is not None, inflight.id if inflight else None, "already running")

    try:
        # Re-check after acquiring the lock (race-safe).
        inflight = _inflight_job(user_wallet)
        if inflight:
            return (True, inflight.id, "already running")

        # Pull confirmed balance + deposit events from indexer.
        bal = balance_result
        if bal is None:
            indexer = get_indexer(user_wallet.chain_id)
            bal = indexer.get_balance(
                user_wallet.deposit_address,
                memo=user_wallet.memo if is_memo_required(user_wallet.chain_id) else None,
            )
        for event in bal.deposit_events:
            ingest_event(user_wallet, event)
        confirmed = Decimal(str(bal.confirmed_balance))
        if confirmed <= Decimal(str(threshold)):
            return (False, None, "balance below threshold")

        round_no = _current_round(user_wallet.id)

        # Persist deposit events (idempotent via unique constraint) + create job.
        with transaction.atomic():
            job = SweepJob.objects.create(
                user_wallet=user_wallet,
                asset_key=user_wallet.asset_key,
                sweep_round=round_no,
                balance_snapshot=confirmed,
                status="CREATED",
                idempotency_key=f"sweep:{user_wallet.id}:{round_no}",
            )
            write_audit_log(
                actor_id,
                AuditAction.SWEEP_TRIGGER,
                "SweepJob",
                str(job.id),
                {"round": round_no, "balance": str(confirmed)},
            )

        # Gas top-up step (if needed) -> then sweep. Run in background in prod.
        try:
            _run_sweep(job, actor_id)
        except AmbiguousBroadcastError:
            SweepJob.objects.filter(pk=job.pk).update(status="RECONCILIATION_REQUIRED")
            raise
        except SafePreBroadcastRejection:
            raise
        except Exception:
            SweepJob.objects.filter(pk=job.pk).update(status="FAILED", completed_at=timezone.now())
            raise
        return (True, job.id, "sweep started")
    finally:
        rate_limiter.release_lock(lock_key)


def _run_sweep(job: SweepJob, actor_id: str) -> None:
    """Advance the sweep state machine. In prod, enqueue as Celery task."""
    cfg = get_chain(job.user_wallet.chain_id)
    hot = ensure_hot_wallet(job.user_wallet.chain_id)
    amount = job.balance_snapshot

    if settings.CUSTODY_TX_MODE == "live":
        from .native_tx import AmbiguousBroadcast, SafePreBroadcastRejection
        from .outbound import create_attempt, execute_attempt

        attempt = create_attempt(
            operation_type="SWEEP",
            operation_id=job.pk,
            chain_id=job.user_wallet.chain_id,
            asset_key=job.asset_key,
            source=job.user_wallet.deposit_address,
            destination=hot,
            amount=amount,
        )
        try:
            attempt = execute_attempt(attempt.pk, actor_id)
        except AmbiguousBroadcast as exc:
            job.status = "RECONCILIATION_REQUIRED"
            job.save(update_fields=["status"])
            raise AmbiguousBroadcastError(str(exc)) from exc
        except SafePreBroadcastRejection:
            job.status = "CREATED"
            job.tx_hash = None
            job.save(update_fields=["status", "tx_hash"])
            raise
        job.status = (
            "RECONCILIATION_REQUIRED"
            if attempt.status == "RECONCILIATION_REQUIRED"
            else "SWEEP_BROADCASTED"
        )
        job.tx_hash = attempt.network_tx_id
        job.save(update_fields=["status", "tx_hash"])
        return

    # Step A: optional gas top-up of the deposit EOA.
    if cfg.kind.value in ("evm", "tron"):
        # STUB gas check; assume needed for skeleton.
        job.status = "GAS_TOPUP_REQUIRED"
        job.save(update_fields=["status"])
        ensure_gas(job.user_wallet, idempotency_key=f"gas_topup:sweep:{job.id}")
        job.status = "GAS_TOPUP_BROADCASTED"
        job.save(update_fields=["status"])

    # Step B: build + sign + broadcast the sweep (EOA -> hot wallet).
    tx = UnsignedTx(
        chain_id=job.user_wallet.chain_id,
        asset_key=job.user_wallet.asset_key,
        from_address=job.user_wallet.deposit_address,
        to_address=hot,
        amount=amount,
        derivation_path=job.user_wallet.derivation_path,
        memo=job.user_wallet.memo if is_memo_required(job.user_wallet.chain_id) else None,
    )
    signer = get_signer()
    try:
        res = signer.sign_and_broadcast(
            actor_id=actor_id,
            tx=tx,
            policy=SignPolicy.SWEEPER,
            idempotency_key=job.idempotency_key,
        )
    except Exception as exc:
        raise AmbiguousBroadcastError("sweep outcome is unknown; reconcile before retry") from exc
    # Cross the external-effect boundary fail-closed: persist an uncertain,
    # non-retryable state before attempting to record the successful response.
    # If the final DB write fails, reconciliation remains required.
    try:
        job.status = "RECONCILIATION_REQUIRED"
        job.save(update_fields=["status"])
        job.status = "SWEEP_BROADCASTED"
        job.tx_hash = res.tx_hash
        job.save(update_fields=["status", "tx_hash"])
    except Exception as exc:
        raise AmbiguousBroadcastError(
            "sweep was broadcast but its result could not be persisted"
        ) from exc
    logger.info("sweep broadcast job=%s tx=%s", job.id, res.tx_hash)
    # Confirmation monitoring is indexer-driven (separate task/worker).


def mark_confirmed(job_id: int) -> None:
    raise RuntimeError("sweeps may only be confirmed by attempt reconciliation")
