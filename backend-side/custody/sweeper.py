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
from contextlib import contextmanager
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
from .gas_station import (
    AmbiguousBroadcastError,
    ensure_gas,
    execute_gas_intent,
    get_or_create_gas_intent,
)
from .indexer.factory import get_indexer
from .models import Asset, GasTopupIntent, OnchainTransactionAttempt, SweepJob, UserWallet
from .mpc_signer import SignPolicy, UnsignedTx, get_signer
from .native_tx import SafePreBroadcastRejection
from .rate_limit import rate_limiter

logger = logging.getLogger("custody.sweeper")


@contextmanager
def _sweep_execution_lock(job_id: int):
    """Session-level PostgreSQL lock; released automatically if the worker dies."""
    from django.db import connection

    if connection.vendor != "postgresql":
        key = f"advance-sweep:{job_id}"
        acquired = rate_limiter.acquire_lock(key, ttl=300)
        try:
            yield acquired
        finally:
            if acquired:
                rate_limiter.release_lock(key)
        return
    lock_id = 0x5357454550000000 + int(job_id)
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_try_advisory_lock(%s)", [lock_id])
        acquired = bool(cursor.fetchone()[0])
    try:
        yield acquired
    finally:
        if acquired:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_unlock(%s)", [lock_id])


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


def _record_sweep_error(job_id: int) -> SweepJob:
    """An exception is not evidence that an external operation failed."""
    with transaction.atomic():
        job = SweepJob.objects.select_for_update().get(pk=job_id)
        if job.status in {"CONFIRMED", "FAILED"}:
            return job
        # Do not lock attempt rows after the parent: reconciliation locks the
        # attempt first, then this row, and commits both terminal states together.
        sweep_states = list(
            OnchainTransactionAttempt.objects.filter(
                operation_type="SWEEP", operation_id=job.pk
            ).values_list("status", flat=True)
        )
        gas_failed = False
        gas_resolved = True
        intent = (
            GasTopupIntent.objects.get(pk=job.gas_topup_intent_id)
            if job.gas_topup_intent_id
            else GasTopupIntent.objects.filter(idempotency_key=f"gas_topup:sweep:{job.pk}").first()
        )
        if intent is not None:
            gas_states = list(
                OnchainTransactionAttempt.objects.filter(
                    operation_type="GAS_TOPUP", operation_id=intent.pk
                ).values_list("status", flat=True)
            )
            gas_failed = intent.status == "FAILED" and all(s == "FAILED" for s in gas_states)
            gas_resolved = gas_failed or (
                intent.status == "CONFIRMED"
                and all(s in {"CONFIRMED", "FAILED"} for s in gas_states)
            )
        # The legacy demo path can fail gas configuration before an intent is
        # created and before invoking the sweep signer. Preserve that proven
        # pre-effect failure, but never infer it for a live custody execution.
        demo_preflight_failed = (
            settings.CUSTODY_TX_MODE == "stub"
            and job.status == "GAS_TOPUP_REQUIRED"
            and not sweep_states
            and intent is None
        )
        failed = demo_preflight_failed or (
            gas_resolved
            and (
                (bool(sweep_states) and all(s == "FAILED" for s in sweep_states))
                or (not sweep_states and gas_failed)
            )
        )
        job.status = "FAILED" if failed else "RECONCILIATION_REQUIRED"
        job.completed_at = timezone.now() if failed else None
        job.save(update_fields=["status", "completed_at"])
        return job


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
        if not asset.is_native:
            inflight = advance_sweep(inflight.pk, actor_id)
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
            if not asset.is_native:
                inflight = advance_sweep(inflight.pk, actor_id)
            return (True, inflight.id, "already running")

        # Pull confirmed balance + deposit events from indexer.
        bal = balance_result
        if bal is None:
            indexer = get_indexer(user_wallet.chain_id)
            bal = indexer.get_balance(
                user_wallet.deposit_address,
                asset_key=user_wallet.asset_key,
                after_block=user_wallet.last_scanned_block,
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
            if asset.is_native:
                _run_sweep(job, actor_id)
            else:
                advance_sweep(job.pk, actor_id)
        except AmbiguousBroadcastError:
            _record_sweep_error(job.pk)
            raise
        except SafePreBroadcastRejection:
            raise
        except Exception:
            _record_sweep_error(job.pk)
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
        from .native_tx import AmbiguousBroadcast
        from .outbound import create_attempt

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
            _execute_claimed_sweep(job.pk, attempt, actor_id)
        except AmbiguousBroadcast as exc:
            raise AmbiguousBroadcastError(str(exc)) from exc
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


def _token_native_requirement(job: SweepJob) -> Decimal:
    """Return a conservative reviewed native-fee requirement in human units."""
    cfg = get_chain(job.user_wallet.chain_id)
    settings = cfg.gas_settings
    if cfg.kind.value == "evm":
        gas_limit = int(settings["max_gas_limit"])
        fee_cap = settings.get("max_fee_per_gas")
        if fee_cap is None:
            fee_cap = settings.get("max_legacy_gas_price")
        if fee_cap is None:
            raise ValueError("reviewed EVM token gas price cap is required")
        units = gas_limit * int(fee_cap)
    elif cfg.kind.value == "tron":
        units = int(settings["max_trc20_fee_limit"])
        from django.conf import settings as django_settings

        if django_settings.MPC_SIGNER_BACKEND == "self_hosted_mpc":
            units += int(settings["max_bandwidth_bytes"]) * int(settings["max_bandwidth_price_sun"])
    elif cfg.kind.value == "solana":
        units = int(settings["max_fee_lamports"]) + int(settings["max_ata_rent_lamports"])
    elif cfg.kind.value == "ton":
        units = 130_000_000
    else:
        raise ValueError("token gas policy is unsupported for this chain")
    return Decimal(units) / (Decimal(10) ** cfg.native_decimals)


def advance_sweep(job_id: int, actor_id: str = "system:sweep-advancer") -> SweepJob:
    with _sweep_execution_lock(job_id) as acquired:
        if not acquired:
            return SweepJob.objects.get(pk=job_id)
        return _advance_sweep(job_id, actor_id)


def _advance_sweep(job_id: int, actor_id: str) -> SweepJob:
    """Idempotently advance a token sweep only after durable gas confirmation."""
    # Phase 1: inspect only durable state while locking only the non-nullable job row.
    with transaction.atomic():
        job = SweepJob.objects.select_for_update().select_related("user_wallet").get(pk=job_id)
        asset = Asset.objects.get(asset_key=job.asset_key, chain_id=job.user_wallet.chain_id)
        if asset.is_native or job.status in {
            "CONFIRMED",
            "FAILED",
            "SWEEP_BROADCASTED",
            "RECONCILIATION_REQUIRED",
        }:
            return job
        if asset.token_standard == "SPL":
            from .spl import derive_ata

            expected = derive_ata(job.user_wallet.deposit_address, asset.contract_address)
            if job.user_wallet.asset_account_address != expected:
                raise ValueError("SPL sweep source is not the canonical ATA")
        wallet = job.user_wallet
        intent_id = job.gas_topup_intent_id
        recovering_attempt = None
        if job.status == "SWEEP_PROCESSING":
            from .models import OnchainTransactionAttempt

            recovering_attempt = (
                OnchainTransactionAttempt.objects.filter(
                    operation_type="SWEEP", operation_id=job.pk
                )
                .order_by("-attempt_number")
                .first()
            )
            if recovering_attempt is None:
                job.status = "CREATED"
                job.save(update_fields=["status"])

    if recovering_attempt is not None:
        if recovering_attempt.status == "CONFIRMED":
            SweepJob.objects.filter(pk=job_id).exclude(status__in={"CONFIRMED", "FAILED"}).update(
                status="CONFIRMED",
                tx_hash=recovering_attempt.network_tx_id,
                completed_at=timezone.now(),
            )
            return SweepJob.objects.get(pk=job_id)
        if recovering_attempt.status == "FAILED":
            return _record_sweep_error(job_id)
        if recovering_attempt.status == "BROADCASTED":
            SweepJob.objects.filter(pk=job_id).exclude(status__in={"CONFIRMED", "FAILED"}).update(
                status="SWEEP_BROADCASTED", tx_hash=recovering_attempt.network_tx_id
            )
            return SweepJob.objects.get(pk=job_id)
        if recovering_attempt.status == "RECONCILIATION_REQUIRED":
            SweepJob.objects.filter(pk=job_id).exclude(status__in={"CONFIRMED", "FAILED"}).update(
                status="RECONCILIATION_REQUIRED", tx_hash=recovering_attempt.network_tx_id
            )
            return SweepJob.objects.get(pk=job_id)
        attempt = recovering_attempt
        return _execute_claimed_sweep(job_id, attempt, actor_id)

    # Recover an already-durable gas operation before any fresh sweep preflight.
    # It may own a nonce and must not be stranded by changed policy or RPC health.
    if intent_id:
        intent = GasTopupIntent.objects.get(pk=intent_id)
        if intent.status == "FAILED":
            return _record_sweep_error(job_id)
        if intent.status in {"CREATED", "PROCESSING"}:
            execute_gas_intent(intent.pk)
            intent.refresh_from_db()
        if intent.status in {"CREATED", "PROCESSING", "BROADCASTED"}:
            status = (
                "GAS_TOPUP_BROADCASTED" if intent.status == "BROADCASTED" else "GAS_TOPUP_REQUIRED"
            )
            SweepJob.objects.filter(pk=job_id).update(status=status)
            return SweepJob.objects.get(pk=job_id)
        if intent.status == "RECONCILIATION_REQUIRED":
            SweepJob.objects.filter(pk=job_id).update(status="GAS_TOPUP_REQUIRED")
            return SweepJob.objects.get(pk=job_id)
        if intent.status != "CONFIRMED":
            raise ValueError(f"unsupported gas intent state {intent.status}")
        # Confirmation is not a balance assertion. Only after synchronizing the
        # durable operation do we apply current balance and fee policy.
        native_key = get_chain(wallet.chain_id).native_asset_key
        required = _token_native_requirement(job)
        native_balance = Decimal(
            str(
                get_indexer(wallet.chain_id)
                .get_balance(wallet.deposit_address, asset_key=native_key)
                .confirmed_balance
            )
        )
        if native_balance < required:
            SweepJob.objects.filter(pk=job_id).update(status="RECONCILIATION_REQUIRED")
            return SweepJob.objects.get(pk=job_id)
    else:
        # No durable gas operation exists: fresh preflight may decide whether
        # one must be created and linked before external execution.
        native_key = get_chain(wallet.chain_id).native_asset_key
        required = _token_native_requirement(job)
        native_balance = Decimal(
            str(
                get_indexer(wallet.chain_id)
                .get_balance(wallet.deposit_address, asset_key=native_key)
                .confirmed_balance
            )
        )
    if not intent_id and native_balance < required:
        grant = get_chain(wallet.chain_id).gas_topup_amount
        if native_balance + grant < required:
            raise ValueError("configured gas top-up cannot satisfy reviewed token fee requirement")
        # Phase 2: create and link the intent durably, then commit before execution.
        with transaction.atomic():
            locked = (
                SweepJob.objects.select_for_update().select_related("user_wallet").get(pk=job_id)
            )
            if locked.gas_topup_intent_id:
                intent_id = locked.gas_topup_intent_id
            else:
                intent = get_or_create_gas_intent(
                    locked.user_wallet, idempotency_key=f"gas_topup:sweep:{locked.pk}"
                )
                locked.gas_topup_intent_id = intent.pk
                locked.status = "GAS_TOPUP_REQUIRED"
                locked.save(update_fields=["gas_topup_intent", "status"])
                intent_id = intent.pk
        # Phase 3: claim/sign/broadcast only after the durable link committed.
        execute_gas_intent(intent_id)
        intent = GasTopupIntent.objects.get(pk=intent_id)
        SweepJob.objects.filter(pk=job_id).update(
            status=(
                "GAS_TOPUP_BROADCASTED" if intent.status == "BROADCASTED" else "GAS_TOPUP_REQUIRED"
            )
        )
        return SweepJob.objects.get(pk=job_id)

    # Claim token execution under the job lock. Concurrent workers observe PROCESSING.
    with transaction.atomic():
        job = SweepJob.objects.select_for_update().get(pk=job_id)
        if job.status in {
            "SWEEP_PROCESSING",
            "SWEEP_BROADCASTED",
            "CONFIRMED",
            "FAILED",
            "RECONCILIATION_REQUIRED",
        }:
            return job
        job.status = "SWEEP_PROCESSING"
        job.save(update_fields=["status"])
        from .outbound import create_attempt

        attempt = create_attempt(
            operation_type="SWEEP",
            operation_id=job.pk,
            chain_id=wallet.chain_id,
            asset_key=job.asset_key,
            source=wallet.deposit_address,
            destination=ensure_hot_wallet(wallet.chain_id),
            amount=job.balance_snapshot,
        )
    return _execute_claimed_sweep(job_id, attempt, actor_id)


def _execute_claimed_sweep(job_id, attempt, actor_id):
    from .native_tx import SafePreBroadcastRejection
    from .outbound import execute_attempt

    try:
        attempt = execute_attempt(attempt.pk, actor_id)
    except SafePreBroadcastRejection:
        job = SweepJob.objects.select_related("gas_topup_intent").get(pk=job_id)
        retry_status = "GAS_TOPUP_CONFIRMED" if job.gas_topup_intent_id else "CREATED"
        SweepJob.objects.filter(pk=job_id).exclude(
            status__in={"CONFIRMED", "FAILED", "RECONCILIATION_REQUIRED"}
        ).update(status=retry_status, tx_hash=None)
        raise
    except Exception:
        _record_sweep_error(job_id)
        raise
    with transaction.atomic():
        job = SweepJob.objects.select_for_update().get(pk=job_id)
        if job.status in {"CONFIRMED", "FAILED"}:
            return job
        attempt.refresh_from_db()
        job.tx_hash = attempt.network_tx_id
        job.status = (
            "RECONCILIATION_REQUIRED"
            if attempt.status == "RECONCILIATION_REQUIRED"
            else ("SWEEP_BROADCASTED" if attempt.status == "BROADCASTED" else "SWEEP_PROCESSING")
        )
        job.save(update_fields=["status", "tx_hash"])
        return job


def advance_pending_sweeps(*, limit: int = 100) -> list[SweepJob]:
    results = []
    ids = (
        SweepJob.objects.filter(
            status__in=[
                "CREATED",
                "GAS_TOPUP_REQUIRED",
                "GAS_TOPUP_BROADCASTED",
                "GAS_TOPUP_CONFIRMED",
                "SWEEP_PROCESSING",
            ]
        )
        .order_by("created_at")
        .values_list("id", flat=True)[:limit]
    )
    for job_id in ids:
        try:
            results.append(advance_sweep(job_id))
        except Exception:
            logger.exception("could not advance sweep %s", job_id)
    return results
