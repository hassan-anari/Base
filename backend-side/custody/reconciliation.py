"""Idempotent confirmation monitor for concrete outbound attempts."""

from __future__ import annotations

from django.db import transaction
from django.utils import timezone

from .ledger import release_withdrawal, settle_withdrawal
from .models import GasTopupIntent, OnchainTransactionAttempt, SweepJob, WithdrawalRequest
from .native_tx import PreparedNativeTransaction, ReconciliationState, get_native_executor
from .token_tx import get_transfer_executor


def _executor(chain_id: str, asset_key: str):
    from .models import Asset

    asset = Asset.objects.get(asset_key=asset_key, chain_id=chain_id)
    return (
        get_native_executor(chain_id)
        if asset.is_native
        else get_transfer_executor(chain_id, asset_key)
    )


def _prepared(attempt: OnchainTransactionAttempt) -> PreparedNativeTransaction:
    return PreparedNativeTransaction(
        chain_id=attempt.chain_id,
        asset_key=attempt.asset_key,
        from_address=attempt.from_address,
        to_address=attempt.to_address,
        amount=attempt.amount,
        base_unit_amount=int(attempt.base_unit_amount),
        signing_payload=b"",
        unsigned_payload={
            **attempt.prepared_metadata,
            **(
                {
                    "_ton_reconciliation_progress": attempt.confirmation_metadata.get(
                        "ton_progress", {}
                    )
                }
                if attempt.chain_id == "TON"
                else {}
            ),
        },
        fee_metadata=attempt.fee_metadata,
        sequence=attempt.sequence,
        expected_tx_id=attempt.network_tx_id,
        expires_at_ms=attempt.prepared_metadata.get("raw_data", {}).get("expiration"),
        last_valid_block=attempt.last_valid_block,
    )


def reconcile_attempt(attempt_id: int):
    from .mpc_signing import attempt_execution_lock

    with attempt_execution_lock(attempt_id) as acquired:
        if not acquired:
            return OnchainTransactionAttempt.objects.get(pk=attempt_id)
        try:
            return _reconcile_attempt(attempt_id)
        except Exception:
            from django.conf import settings

            from .outbound import sync_parent_state

            snapshot = OnchainTransactionAttempt.objects.get(pk=attempt_id)
            if settings.MPC_SIGNER_BACKEND == "self_hosted_mpc" and snapshot.chain_id in {
                "TRX",
                "SOL",
                "TON",
            }:
                OnchainTransactionAttempt.objects.filter(pk=attempt_id).exclude(
                    status__in=["CONFIRMED", "FAILED"]
                ).update(
                    status="RECONCILIATION_REQUIRED",
                    error_code=f"{snapshot.chain_id}_EVIDENCE_UNVERIFIED",
                )
                sync_parent_state(OnchainTransactionAttempt.objects.get(pk=attempt_id))
            raise


def _reconcile_attempt(attempt_id: int):
    snapshot = OnchainTransactionAttempt.objects.get(pk=attempt_id)
    if snapshot.status in {"CONFIRMED", "FAILED"}:
        return snapshot
    if not snapshot.network_tx_id:
        return snapshot
    from django.conf import settings

    from .chain_registry import ChainKind, get_chain_spec

    if settings.MPC_SIGNER_BACKEND == "self_hosted_mpc" and get_chain_spec(
        snapshot.chain_id
    ).kind in {ChainKind.TRON, ChainKind.SOLANA, ChainKind.TON}:
        from .models import MpcSigningSession
        from .mpc_signing import _default_consumer

        if not snapshot.signed_payload:
            return snapshot  # An unsigned txID cannot authorize financial settlement.
        with transaction.atomic():
            session = MpcSigningSession.objects.select_related("keyset").get(attempt=snapshot)
            if session.status != "COMPLETED" or not session.signature_consumed_at:
                raise ValueError("TRON reconciliation lacks consumed MPC completion")
            if _default_consumer(snapshot, session) != (
                snapshot.signed_payload,
                snapshot.network_tx_id,
            ):
                raise ValueError("TRON reconciliation signed identity mismatch")
    result = _executor(snapshot.chain_id, snapshot.asset_key).reconcile(
        _prepared(snapshot), snapshot.network_tx_id
    )
    if (
        get_chain_spec(snapshot.chain_id).kind in {ChainKind.SOLANA, ChainKind.TON}
        and result.state is ReconciliationState.EXPIRED
    ):
        from .native_tx import ReconciliationResult

        result = ReconciliationResult(
            ReconciliationState.RECONCILIATION_REQUIRED,
            {**result.evidence, "error": "SOLANA_NON_INCLUSION_UNPROVEN"},
        )
    if result.state not in {
        ReconciliationState.CONFIRMED,
        ReconciliationState.FAILED,
        ReconciliationState.EXPIRED,
    }:
        updates = {"confirmation_metadata": {"state": result.state.value, **result.evidence}}
        if result.state is ReconciliationState.RECONCILIATION_REQUIRED:
            updates.update(
                status="RECONCILIATION_REQUIRED",
                error_code=result.evidence.get("error", "TOKEN_EFFECT_MISMATCH"),
            )
            if snapshot.operation_type == "WITHDRAWAL":
                WithdrawalRequest.objects.filter(pk=snapshot.operation_id).update(
                    status="RECONCILIATION_REQUIRED"
                )
            elif snapshot.operation_type == "SWEEP":
                SweepJob.objects.filter(pk=snapshot.operation_id).update(
                    status="RECONCILIATION_REQUIRED"
                )
            else:
                GasTopupIntent.objects.filter(pk=snapshot.operation_id).update(
                    status="RECONCILIATION_REQUIRED"
                )
        OnchainTransactionAttempt.objects.filter(pk=attempt_id).update(**updates)
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
        if (
            get_chain_spec(attempt.chain_id).kind is ChainKind.SOLANA
            and settings.MPC_SIGNER_BACKEND == "self_hosted_mpc"
        ):
            from .solana_costs import post_execution_costs

            post_execution_costs(attempt, result.evidence)
        if attempt.chain_id == "TON":
            from .ton_costs import post_execution_costs

            post_execution_costs(attempt, result.evidence)
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
    reconciled = []
    for attempt_id in ids:
        try:
            reconciled.append(reconcile_attempt(attempt_id))
        except Exception as exc:
            OnchainTransactionAttempt.objects.filter(pk=attempt_id).update(
                error_code="RECONCILIATION_CHECK_FAILED", error_message=str(exc)[:512]
            )
    return reconciled
