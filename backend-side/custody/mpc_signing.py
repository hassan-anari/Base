"""Asynchronous, idempotent advancement of durable self-hosted MPC sessions."""

from __future__ import annotations

import hashlib

from django.db import transaction
from django.utils import timezone

from .models import MpcSigningSession, OnchainTransactionAttempt

ACTIVE = {"CREATED", "STARTING", "IN_PROGRESS"}


def coordinator_request(attempt, session) -> dict:
    payload = bytes(session.signing_payload)
    fingerprint = hashlib.sha256(payload).hexdigest()
    if fingerprint != session.message_fingerprint:
        raise ValueError("persisted MPC signing payload fingerprint mismatch")
    return {
        "session_id": str(session.session_id),
        "attempt_id": attempt.pk,
        "keyset_id": str(session.keyset.keyset_id),
        "algorithm": session.algorithm,
        "payload_type": session.payload_type,
        "payload_hex": payload.hex(),
        "message_fingerprint": fingerprint,
        "operation_type": attempt.operation_type,
        "chain": attempt.chain_id,
        "asset": attempt.asset_key,
        "expected_source": attempt.from_address,
        "derivation_reference": _derivation_reference(attempt),
    }


def _derivation_reference(attempt):
    from .outbound import _signing_ref

    return _signing_ref(attempt.operation_type, attempt.operation_id, attempt.chain_id)


def _consume_completed(attempt_id, session_id, consumer):
    with transaction.atomic():
        attempt = OnchainTransactionAttempt.objects.select_for_update().get(pk=attempt_id)
        session = MpcSigningSession.objects.select_for_update().get(pk=session_id)
        if attempt.status == "SIGNED" and session.signature_consumed_at:
            return attempt
        if session.status != "COMPLETED" or not session.signature_result:
            raise ValueError("completed MPC session has no signature result")
        if consumer is None:
            consumer = _default_consumer
        signed_payload, network_tx_id = consumer(attempt, session)
        attempt.signed_payload = signed_payload
        attempt.network_tx_id = network_tx_id
        attempt.status = "SIGNED"
        attempt.save(update_fields=["signed_payload", "network_tx_id", "status", "updated_at"])
        session.signature_consumed_at = timezone.now()
        session.save(update_fields=["signature_consumed_at"])
        return attempt


def _default_consumer(attempt, session):
    if session.payload_type not in {"EVM_LEGACY_DIGEST", "EVM_EIP1559_DIGEST"}:
        raise ValueError("chain-specific MPC signature consumer is not implemented")
    from .mpc_payload import assemble_evm_signature

    return assemble_evm_signature(
        attempt.prepared_metadata, session.signature_result, attempt.from_address
    )


def advance_mpc_signing(attempt_id: int, client=None, consumer=None):
    """Start/query one logical session without waiting for protocol completion."""
    if client is None:
        from .signer_adapter import get_adapter

        client = get_adapter()
    with transaction.atomic():
        attempt = OnchainTransactionAttempt.objects.select_for_update().get(pk=attempt_id)
        if attempt.status not in {"SIGNING", "SIGNED"}:
            raise ValueError("MPC advancement requires a SIGNING attempt")
        if attempt.status == "SIGNED":
            return attempt
        session = (
            MpcSigningSession.objects.select_for_update()
            .select_related("keyset")
            .filter(attempt=attempt, status__in=ACTIVE | {"COMPLETED"})
            .order_by("-session_number")
            .first()
        )
        if session is None:
            raise ValueError("SIGNING attempt has no active MPC session")
        was_starting = session.status == "STARTING"
        if session.status == "COMPLETED":
            completed_id = session.pk
            request = None
            should_create = False
        else:
            completed_id = None
            request = coordinator_request(attempt, session)
        should_create = session.status == "CREATED"
        if should_create:
            session.status = "STARTING"
            session.started_at = session.started_at or timezone.now()
            session.save(update_fields=["status", "started_at"])

    if completed_id:
        return _consume_completed(attempt_id, completed_id, consumer)
    # The local DB transaction is committed before this external effect.
    from .signer_adapter import CoordinatorSessionNotFound

    if was_starting:
        try:
            result = client.get_signing_session(str(session.session_id))
        except CoordinatorSessionNotFound:
            result = client.create_signing_session(request)
    else:
        result = (
            client.create_signing_session(request)
            if should_create
            else client.get_signing_session(str(session.session_id))
        )
    with transaction.atomic():
        attempt = OnchainTransactionAttempt.objects.select_for_update().get(pk=attempt_id)
        session = MpcSigningSession.objects.select_for_update().get(pk=session.pk)
        if result.get("request", result).get("session_id") != str(session.session_id):
            session.status = "RECONCILIATION_REQUIRED"
            session.error_code = "COORDINATOR_SESSION_MISMATCH"
        elif result["status"] in {"CREATED", "STARTING", "IN_PROGRESS"}:
            session.status = "IN_PROGRESS"
            session.crypto_execution_id = result.get("crypto_execution_id")
        elif result["status"] == "DEFINITIVE_NO_SIGNATURE_FAILURE":
            session.status = "DEFINITIVE_NO_SIGNATURE_FAILURE"
            session.error_code = result.get("error_code", "MPC_DEFINITIVE_FAILURE")
        elif result["status"] == "COMPLETED":
            # Assembly/cryptographic verification is chain-specific. Persisting
            # the result first closes the crash window without claiming SIGNED.
            session.signature_result = result.get("signature") or {}
            session.status = "COMPLETED"
            session.completed_at = timezone.now()
        else:
            session.status = "RECONCILIATION_REQUIRED"
            session.error_code = "COORDINATOR_STATE_UNKNOWN"
        session.save()
    if session.status == "COMPLETED":
        return _consume_completed(attempt_id, session.pk, consumer)
    return attempt
