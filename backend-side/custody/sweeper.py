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

from django.db import transaction
from django.utils import timezone

from .config import Network, get_chain, get_asset, effective_deposit_threshold, is_memo_required, ensure_hot_wallet
from .mpc_signer import SignPolicy, UnsignedTx, get_signer
from .models import UserWallet, SweepJob, Deposit
from .indexer.factory import get_indexer
from .gas_station import ensure_gas
from .rate_limit import rate_limiter
from .audit import AuditAction, write_audit_log

logger = logging.getLogger("custody.sweeper")


def _current_round(user_wallet_id: int) -> int:
    """Next sweep round = (max existing round) + 1, else 1."""
    last = (
        SweepJob.objects.filter(user_wallet_id=user_wallet_id)
        .order_by("-sweep_round")
        .first()
    )
    return (last.sweep_round + 1) if last else 1


def _inflight_job(user_wallet: UserWallet):
    """Return an unfinished (in-flight) sweep job for this wallet, if any."""
    return (
        SweepJob.objects.filter(user_wallet=user_wallet)
        .exclude(status__in=("CONFIRMED", "FAILED"))
        .order_by("-sweep_round")
        .first()
    )


def trigger_sweep(user_wallet: UserWallet, actor_id: str) -> tuple[bool, int | None, str]:
    """Entry point from balance-check. Returns (triggered, sweep_job_id, reason).

    Called by the balance-check endpoint AFTER confirming balance > threshold.
    Implements idempotency + double-sweep prevention:
      - If an in-flight sweep exists for the wallet, repeated "Check Balance"
        calls return that existing job instead of creating a new one.
      - A new sweep round is only started once the previous round is
        CONFIRMED or FAILED.
    """
    net = Network(user_wallet.chain_id)
    cfg = get_chain(user_wallet.chain_id)
    asset = get_asset(user_wallet.asset_key)
    threshold = effective_deposit_threshold(asset, cfg)

    # Idempotency: if a sweep is already in flight, do not start another.
    inflight = _inflight_job(user_wallet)
    if inflight:
        return (True, inflight.id, "already running")

    # Guard point: lock is wallet-scoped (only one in-flight sweep at a time).
    lock_key = f"sweep:{user_wallet.id}"
    if not rate_limiter.acquire_lock(lock_key, ttl=120):
        inflight = _inflight_job(user_wallet)
        return (inflight is not None, inflight.id if inflight else None,
                "already running")

    try:
        # Re-check after acquiring the lock (race-safe).
        inflight = _inflight_job(user_wallet)
        if inflight:
            return (True, inflight.id, "already running")

        # Pull confirmed balance + deposit events from indexer.
        indexer = get_indexer(net)
        bal = indexer.get_balance(
            user_wallet.deposit_address,
            memo=user_wallet.memo if is_memo_required(net) else None,
        )
        confirmed = Decimal(str(bal.confirmed_balance))
        if confirmed <= Decimal(str(threshold)):
            return (False, None, "balance below threshold")

        round_no = _current_round(user_wallet.id)

        # Persist deposit events (idempotent via unique constraint) + create job.
        with transaction.atomic():
            job = SweepJob.objects.create(
                user_wallet=user_wallet,
                sweep_round=round_no,
                balance_snapshot=confirmed,
                status="CREATED",
                idempotency_key=f"sweep:{user_wallet.id}:{round_no}",
            )
            for ev in bal.deposit_events:
                Deposit.objects.get_or_create(
                    user_wallet=user_wallet, tx_hash=ev.tx_hash,
                    asset_key=user_wallet.asset_key,
                    defaults={
                        "amount": Decimal(str(ev.amount)),
                        "block": ev.block,
                        "confirmations": ev.confirmations,
                        "memo": ev.memo,
                    },
                )
            write_audit_log(actor_id, AuditAction.SWEEP_TRIGGER, "SweepJob",
                            str(job.id), {"round": round_no, "balance": float(confirmed)})

        # Gas top-up step (if needed) -> then sweep. Run in background in prod.
        _run_sweep(job, actor_id)
        return (True, job.id, "sweep started")
    finally:
        rate_limiter.release_lock(lock_key)


def _run_sweep(job: SweepJob, actor_id: str) -> None:
    """Advance the sweep state machine. In prod, enqueue as Celery task."""
    net = Network(job.user_wallet.chain_id)
    cfg = get_chain(job.user_wallet.chain_id)
    hot = ensure_hot_wallet(job.user_wallet.chain_id)
    amount = float(job.balance_snapshot)

    # Step A: optional gas top-up of the deposit EOA.
    if cfg.kind in ("EVM", "TRON"):
        # STUB gas check; assume needed for skeleton.
        job.status = "GAS_TOPUP_REQUIRED"
        job.save(update_fields=["status"])
        if ensure_gas(job.user_wallet):
            job.status = "GAS_TOPUP_BROADCASTED"
            job.save(update_fields=["status"])

    # Step B: build + sign + broadcast the sweep (EOA -> hot wallet).
    tx = UnsignedTx(
        network=net,
        chain_id=job.user_wallet.chain_id,
        asset_key=job.user_wallet.asset_key,
        from_address=job.user_wallet.deposit_address,
        to_address=hot,
        amount=amount,
        derivation_path=job.user_wallet.derivation_path,
        memo=job.user_wallet.memo if is_memo_required(net) else None,
    )
    signer = get_signer()
    res = signer.sign_and_broadcast(
        actor_id=actor_id, tx=tx,
        policy=SignPolicy.SWEEPER, idempotency_key=job.idempotency_key,
    )
    job.status = "SWEEP_BROADCASTED"
    job.tx_hash = res.tx_hash
    job.save(update_fields=["status", "tx_hash"])
    logger.info("sweep broadcast job=%s tx=%s", job.id, res.tx_hash)
    # Confirmation monitoring is indexer-driven (separate task/worker).


def mark_confirmed(job_id: int) -> None:
    """Called by indexer confirmation monitor once finality reached."""
    job = SweepJob.objects.get(id=job_id)
    job.status = "CONFIRMED"
    job.completed_at = timezone.now()
    job.save(update_fields=["status", "completed_at"])