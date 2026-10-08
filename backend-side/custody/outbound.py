"""Durable orchestration of native transaction attempts."""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from decimal import Decimal

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .models import HotWallet, MpcSigningSession, OnchainTransactionAttempt
from .mpc_payload import exact_signing_payload
from .mpc_signer import MpcSigner, SignPolicy, UnsignedTx, get_signer
from .native_tx import (
    AmbiguousBroadcast,
    DeterministicBroadcastRejection,
    PreparedNativeTransaction,
    SafePreBroadcastRejection,
    allocate_evm_nonce,
    get_native_executor,
    to_base_units,
)
from .token_tx import get_transfer_executor


def _executor(chain_id: str, asset_key: str):
    from .models import Asset

    asset = Asset.objects.get(asset_key=asset_key, chain_id=chain_id)
    return (
        get_native_executor(chain_id)
        if asset.is_native
        else get_transfer_executor(chain_id, asset_key)
    )


def _restore(attempt: OnchainTransactionAttempt) -> PreparedNativeTransaction:
    raw = attempt.prepared_metadata
    signing = b""
    if "message" in raw:
        signing = base64.b64decode(raw["message"])
    elif "txID" in raw:
        signing = bytes.fromhex(raw["txID"])
    return PreparedNativeTransaction(
        attempt.chain_id,
        attempt.asset_key,
        attempt.from_address,
        attempt.to_address,
        attempt.amount,
        int(attempt.base_unit_amount),
        signing,
        raw,
        attempt.fee_metadata,
        sequence=attempt.sequence,
        expected_tx_id=attempt.network_tx_id,
        expires_at_ms=raw.get("raw_data", {}).get("expiration"),
        last_valid_block=attempt.last_valid_block,
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


def _signing_keyset(attempt: OnchainTransactionAttempt):
    if attempt.operation_type == "SWEEP":
        from .models import SweepJob

        return (
            SweepJob.objects.select_related("user_wallet__mpc_keyset")
            .get(pk=attempt.operation_id)
            .user_wallet.mpc_keyset
        )
    return HotWallet.objects.select_related("mpc_keyset").get(chain_id=attempt.chain_id).mpc_keyset


def _message_fingerprint(prepared: PreparedNativeTransaction) -> str:
    """Fingerprint the exact immutable input (bytes when available, canonical payload otherwise)."""
    content = (
        prepared.signing_payload
        or json.dumps(prepared.unsigned_payload, sort_keys=True, separators=(",", ":")).encode()
    )
    return hashlib.sha256(content).hexdigest()


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
    from .config import validate_chain_asset
    from .models import Asset

    validate_chain_asset(chain_id, asset_key)
    asset = Asset.objects.get(asset_key=asset_key, chain_id=chain_id, enabled=True)
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
    from .signer_adapter import assert_mpc_backend_runtime_safe

    assert_mpc_backend_runtime_safe()
    signer = signer or get_signer()
    attempt = OnchainTransactionAttempt.objects.get(pk=attempt_id)
    executor = _executor(attempt.chain_id, attempt.asset_key)
    if attempt.status == "BROADCASTING":
        OnchainTransactionAttempt.objects.filter(pk=attempt_id).update(
            status="RECONCILIATION_REQUIRED", error_code="CRASH_DURING_BROADCAST"
        )
        return OnchainTransactionAttempt.objects.get(pk=attempt_id)
    if attempt.status in {"BROADCASTED", "RECONCILIATION_REQUIRED", "CONFIRMED", "FAILED"}:
        return attempt
    if attempt.status == "SIGNING":
        # Retrying continues the durable coordinator session below. It must never
        # allocate another network nonce or another logical signing session.
        prepared = _restore(attempt)
    if attempt.status == "PREPARING":
        try:
            method = (
                executor.prepare_sweep
                if attempt.operation_type == "SWEEP" and hasattr(executor, "prepare_sweep")
                else executor.prepare
            )
            prepared = method(
                attempt.chain_id,
                attempt.asset_key,
                attempt.from_address,
                attempt.to_address,
                attempt.amount,
            )
        except Exception as exc:
            OnchainTransactionAttempt.objects.filter(pk=attempt_id).update(
                status="FAILED", error_code="PREPARATION_FAILED", error_message=str(exc)[:512]
            )
            raise
        with transaction.atomic():
            attempt = OnchainTransactionAttempt.objects.select_for_update().get(pk=attempt_id)
            if "chainId" in prepared.unsigned_payload:
                owned_nonce = allocate_evm_nonce(
                    attempt.chain_id, attempt.from_address, prepared.sequence or 0
                )
                prepared.unsigned_payload["nonce"] = owned_nonce
                prepared = PreparedNativeTransaction(
                    prepared.chain_id,
                    prepared.asset_key,
                    prepared.from_address,
                    prepared.to_address,
                    prepared.amount,
                    prepared.base_unit_amount,
                    prepared.signing_payload,
                    prepared.unsigned_payload,
                    prepared.fee_metadata,
                    sequence=owned_nonce,
                    expected_tx_id=prepared.expected_tx_id,
                    expires_at_ms=prepared.expires_at_ms,
                    last_valid_block=prepared.last_valid_block,
                )
            attempt.sequence = prepared.sequence
            attempt.prepared_metadata = prepared.unsigned_payload
            attempt.fee_metadata = prepared.fee_metadata
            attempt.network_tx_id = prepared.expected_tx_id
            attempt.last_valid_block = prepared.last_valid_block
            if int(attempt.base_unit_amount) != prepared.base_unit_amount:
                from .models import Asset

                decimals = Asset.objects.get(asset_key=attempt.asset_key).decimals
                attempt.base_unit_amount = prepared.base_unit_amount
                attempt.amount = Decimal(prepared.base_unit_amount) / (Decimal(10) ** decimals)
            attempt.status = "PREPARED"
            attempt.save()
    else:
        prepared = _restore(attempt)
    if attempt.status == "SIGNED":
        signed = (
            json.loads(attempt.signed_payload)
            if attempt.prepared_metadata.get("txID")
            else bytes.fromhex(attempt.signed_payload)
        )
        tx_id = attempt.network_tx_id
    else:
        ref = _signing_ref(attempt.operation_type, attempt.operation_id, attempt.chain_id)
        policy = SignPolicy(
            attempt.operation_type if attempt.operation_type != "SWEEP" else "SWEEPER"
        )
        with transaction.atomic():
            attempt = OnchainTransactionAttempt.objects.select_for_update().get(pk=attempt_id)
            keyset = _signing_keyset(attempt)
            if settings.MPC_SIGNER_BACKEND == "self_hosted_mpc" and keyset is None:
                raise ValueError("production signing requires an explicit MPC keyset binding")
            session = None
            if keyset is not None:
                payload_type, signing_payload = exact_signing_payload(
                    prepared.chain_id, prepared.unsigned_payload, prepared.signing_payload
                )
                session = (
                    MpcSigningSession.objects.filter(
                        attempt=attempt, status__in=["CREATED", "STARTING", "IN_PROGRESS"]
                    )
                    .order_by("-session_number")
                    .first()
                )
                if session is None:
                    previous = (
                        MpcSigningSession.objects.filter(attempt=attempt)
                        .order_by("-session_number")
                        .first()
                    )
                    if previous and previous.status != "DEFINITIVE_NO_SIGNATURE_FAILURE":
                        raise ValueError("previous MPC session is not authoritatively retryable")
                    session = MpcSigningSession.objects.create(
                        attempt=attempt,
                        session_number=(previous.session_number + 1 if previous else 1),
                        session_id=uuid.uuid4(),
                        keyset=keyset,
                        algorithm=keyset.algorithm,
                        message_fingerprint=hashlib.sha256(signing_payload).hexdigest(),
                        payload_type=payload_type,
                        signing_payload=signing_payload,
                    )
                if session.message_fingerprint != hashlib.sha256(signing_payload).hexdigest():
                    raise ValueError("prepared signing content changed after MPC session creation")
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
        signing_id = str(session.session_id) if session else f"attempt:{attempt.pk}"
        if settings.MPC_SIGNER_BACKEND == "self_hosted_mpc":
            from .mpc_signing import advance_mpc_signing

            return advance_mpc_signing(attempt.pk)
        if session:
            MpcSigningSession.objects.filter(pk=session.pk).update(
                status="IN_PROGRESS", started_at=timezone.now()
            )
        signed_ref = signer.sign(actor_id, tx, policy, idempotency_key=signing_id)
        signed = executor.assemble(prepared, signed_ref)
        if isinstance(signed, bytes):
            payload = signed.hex()
            tx_id = executor.transaction_id(signed)
        else:
            payload = json.dumps(signed, separators=(",", ":"), sort_keys=True)
            tx_id = prepared.expected_tx_id or hashlib.sha256(payload.encode()).hexdigest()
        OnchainTransactionAttempt.objects.filter(pk=attempt_id).update(
            signed_payload=payload, network_tx_id=tx_id, status="SIGNED"
        )
        if session:
            MpcSigningSession.objects.filter(pk=session.pk).update(
                status="COMPLETED", completed_at=timezone.now()
            )
    try:
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
    except SafePreBroadcastRejection as exc:
        # Preserve the owned nonce and prepared transaction. A safe retry must
        # fill this nonce rather than allocating a higher one.
        OnchainTransactionAttempt.objects.filter(pk=attempt_id).update(
            status="PREPARED",
            signed_payload="",
            network_tx_id=prepared.expected_tx_id,
            error_code="BROADCAST_REJECTED",
            error_message=str(exc)[:512],
        )
        raise
    except DeterministicBroadcastRejection as exc:
        # Rejections such as nonce-too-low are not safe proof of non-acceptance.
        OnchainTransactionAttempt.objects.filter(pk=attempt_id).update(
            status="RECONCILIATION_REQUIRED",
            error_code="BROADCAST_REJECTION_REQUIRES_RECONCILIATION",
            error_message=str(exc)[:512],
        )
        raise
    except Exception as exc:
        OnchainTransactionAttempt.objects.filter(pk=attempt_id).update(
            status="RECONCILIATION_REQUIRED",
            error_code=type(exc).__name__,
            error_message=str(exc)[:512],
        )
        raise
    OnchainTransactionAttempt.objects.filter(pk=attempt_id).update(
        status="BROADCASTED", broadcast_at=timezone.now()
    )
    return OnchainTransactionAttempt.objects.get(pk=attempt_id)


def assert_transport_configuration() -> None:
    if settings.CUSTODY_TX_MODE == "stub" and not settings.CUSTODY_DEMO_MODE:
        raise RuntimeError("stub transaction transport requires CUSTODY_DEMO_MODE=true")
