"""Durable orchestration of native transaction attempts."""

from __future__ import annotations

import hashlib
from decimal import Decimal

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .models import HotWallet, OnchainTransactionAttempt
from .mpc_signer import MpcSigner, SignPolicy, UnsignedTx, get_signer
from .native_tx import (
    AmbiguousBroadcast,
    get_native_executor,
    to_base_units,
)


def _signing_ref(operation_type: str, operation_id: int, chain_id: str) -> str:
    if operation_type == "SWEEP":
        from .models import SweepJob

        return (
            SweepJob.objects.select_related("user_wallet")
            .get(pk=operation_id)
            .user_wallet.derivation_path
        )
    hot = HotWallet.objects.get(chain_id=chain_id)
    if not hot.signing_key_ref:
        raise ValueError("hot wallet signing_key_ref is not configured")
    return hot.signing_key_ref


def create_attempt(
    *,
    operation_type: str,
    operation_id: int,
    chain_id: str,
    asset_key: str,
    source: str,
    destination: str,
    amount: Decimal,
) -> OnchainTransactionAttempt:
    from .models import Asset

    asset = Asset.objects.get(asset_key=asset_key, chain_id=chain_id, is_native=True, enabled=True)
    units = to_base_units(amount, asset.decimals)
    with transaction.atomic():
        existing = (
            OnchainTransactionAttempt.objects.select_for_update()
            .filter(operation_type=operation_type, operation_id=operation_id)
            .order_by("-attempt_number")
            .first()
        )
        if existing and existing.status not in {"FAILED"}:
            return existing
        number = existing.attempt_number + 1 if existing else 1
        return OnchainTransactionAttempt.objects.create(
            operation_type=operation_type,
            operation_id=operation_id,
            attempt_number=number,
            chain_id=chain_id,
            asset_key=asset_key,
            from_address=source,
            to_address=destination,
            amount=amount,
            base_unit_amount=units,
        )


def execute_attempt(attempt_id: int, actor_id: str, signer: MpcSigner | None = None):
    """Prepare/sign/broadcast once; uncertainty is always non-retryable."""
    signer = signer or get_signer()
    with transaction.atomic():
        attempt = OnchainTransactionAttempt.objects.select_for_update().get(pk=attempt_id)
        if attempt.status != "PREPARING":
            return attempt
        executor = get_native_executor(attempt.chain_id)
        prepared = executor.prepare(
            attempt.chain_id,
            attempt.asset_key,
            attempt.from_address,
            attempt.to_address,
            attempt.amount,
        )
        attempt.sequence = prepared.sequence
        attempt.prepared_metadata = prepared.unsigned_payload
        attempt.fee_metadata = prepared.fee_metadata
        attempt.network_tx_id = prepared.expected_tx_id
        attempt.last_valid_block = prepared.last_valid_block
        attempt.status = "PREPARED"
        attempt.save()
    ref = _signing_ref(attempt.operation_type, attempt.operation_id, attempt.chain_id)
    policy = SignPolicy(attempt.operation_type if attempt.operation_type != "SWEEP" else "SWEEPER")
    with transaction.atomic():
        attempt = OnchainTransactionAttempt.objects.select_for_update().get(pk=attempt_id)
        attempt.status = "SIGNING"
        attempt.save(update_fields=["status", "updated_at"])
    tx = UnsignedTx(
        chain_id=attempt.chain_id,
        asset_key=attempt.asset_key,
        from_address=attempt.from_address,
        to_address=attempt.to_address,
        amount=attempt.amount,
        derivation_path=ref,
        raw=prepared.unsigned_payload,
    )
    try:
        signed_ref = signer.sign(actor_id, tx, policy, idempotency_key=f"attempt:{attempt.pk}")
        signed = executor.assemble(prepared, signed_ref)
        if isinstance(signed, bytes):
            payload = signed.hex()
            tx_id = executor.transaction_id(signed)
        else:
            import json

            payload = json.dumps(signed, separators=(",", ":"), sort_keys=True)
            tx_id = prepared.expected_tx_id or hashlib.sha256(payload.encode()).hexdigest()
        with transaction.atomic():
            attempt = OnchainTransactionAttempt.objects.select_for_update().get(pk=attempt_id)
            attempt.signed_payload = payload
            attempt.network_tx_id = tx_id
            attempt.status = "SIGNED"
            attempt.save()
        with transaction.atomic():
            attempt = OnchainTransactionAttempt.objects.select_for_update().get(pk=attempt_id)
            attempt.status = "BROADCASTING"
            attempt.broadcast_started_at = timezone.now()
            attempt.save(update_fields=["status", "broadcast_started_at", "updated_at"])
        executor.broadcast(attempt.chain_id, signed, tx_id)
    except AmbiguousBroadcast as exc:
        OnchainTransactionAttempt.objects.filter(pk=attempt_id).update(
            status="RECONCILIATION_REQUIRED",
            error_code="AMBIGUOUS_BROADCAST",
            error_message=str(exc)[:512],
        )
        raise
    except Exception as exc:
        # Once BROADCASTING was persisted, an untyped transport failure is
        # conservatively ambiguous. Earlier failures are definitively safe.
        current = OnchainTransactionAttempt.objects.get(pk=attempt_id)
        status = "RECONCILIATION_REQUIRED" if current.status == "BROADCASTING" else "FAILED"
        OnchainTransactionAttempt.objects.filter(pk=attempt_id).update(
            status=status, error_code=type(exc).__name__, error_message=str(exc)[:512]
        )
        raise
    OnchainTransactionAttempt.objects.filter(pk=attempt_id).update(
        status="BROADCASTED", broadcast_at=timezone.now()
    )
    return OnchainTransactionAttempt.objects.get(pk=attempt_id)


def assert_transport_configuration() -> None:
    if settings.CUSTODY_TX_MODE == "stub" and not settings.CUSTODY_DEMO_MODE:
        raise RuntimeError("stub transaction transport requires CUSTODY_DEMO_MODE=true")
