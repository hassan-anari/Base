"""Idempotent confirmation monitor for concrete outbound attempts."""

from __future__ import annotations

from django.db import transaction
from django.utils import timezone

from .ledger import release_withdrawal, settle_withdrawal
from .models import GasTopupIntent, OnchainTransactionAttempt, SweepJob, WithdrawalRequest
from .native_tx import PreparedNativeTransaction, ReconciliationState, get_native_executor


def _prepared(attempt: OnchainTransactionAttempt) -> PreparedNativeTransaction:
    return PreparedNativeTransaction(
        chain_id=attempt.chain_id,
        asset_key=attempt.asset_key,
        from_address=attempt.from_address,
        to_address=attempt.to_address,
        amount=attempt.amount,
        base_unit_amount=int(attempt.base_unit_amount),
        signing_payload=b"",
        unsigned_payload=attempt.prepared_metadata,
        fee_metadata=attempt.fee_metadata,
        sequence=attempt.sequence,
        expected_tx_id=attempt.network_tx_id,
        last_valid_block=attempt.last_valid_block,
    )


def reconcile_attempt(attempt_id: int):
    snapshot = OnchainTransactionAttempt.objects.get(pk=attempt_id)
    if snapshot.status in {"CONFIRMED", "FAILED"}:
        return snapshot
    if not snapshot.network_tx_id:
        return snapshot
    result = get_native_executor(snapshot.chain_id).reconcile(
        _prepared(snapshot), snapshot.network_tx_id
    )
    if result.state not in {ReconciliationState.CONFIRMED, ReconciliationState.FAILED}:
        OnchainTransactionAttempt.objects.filter(pk=attempt_id).update(
            confirmation_metadata={"state": result.state.value, **result.evidence}
        )
        return OnchainTransactionAttempt.objects.get(pk=attempt_id)
    with transaction.atomic():
        attempt = OnchainTransactionAttempt.objects.select_for_update().get(pk=attempt_id)
        if attempt.status in {"CONFIRMED", "FAILED"}:
            return attempt
        if attempt.operation_type == "WITHDRAWAL":
            operation = WithdrawalRequest.objects.select_for_update().get(pk=attempt.operation_id)
            if result.state is ReconciliationState.CONFIRMED:
                settle_withdrawal(operation)
                operation.status = "CONFIRMED"
            else:
                release_withdrawal(operation)
                operation.status = "FAILED"
            operation.tx_hash = attempt.network_tx_id
            operation.save(update_fields=["status", "tx_hash", "updated_at"])
        elif attempt.operation_type == "SWEEP":
            operation = SweepJob.objects.select_for_update().get(pk=attempt.operation_id)
            operation.status = (
                "CONFIRMED" if result.state is ReconciliationState.CONFIRMED else "FAILED"
            )
            operation.completed_at = timezone.now()
            operation.tx_hash = attempt.network_tx_id
            operation.save(update_fields=["status", "completed_at", "tx_hash"])
        else:
            operation = GasTopupIntent.objects.select_for_update().get(pk=attempt.operation_id)
            operation.status = (
                "CONFIRMED" if result.state is ReconciliationState.CONFIRMED else "FAILED"
            )
            operation.tx_hash = attempt.network_tx_id
            operation.save(update_fields=["status", "tx_hash", "updated_at"])
        attempt.status = "CONFIRMED" if result.state is ReconciliationState.CONFIRMED else "FAILED"
        attempt.confirmation_metadata = {"state": result.state.value, **result.evidence}
        attempt.save(update_fields=["status", "confirmation_metadata", "updated_at"])
        return attempt


def reconcile_pending_attempts(*, limit: int = 100) -> list[OnchainTransactionAttempt]:
    ids = list(
        OnchainTransactionAttempt.objects.filter(
            status__in=["BROADCASTED", "RECONCILIATION_REQUIRED"]
        )
        .order_by("created_at")
        .values_list("id", flat=True)[:limit]
    )
    return [reconcile_attempt(attempt_id) for attempt_id in ids]
