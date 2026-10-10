"""Resumable advancement of one owned CGGMP/FROST execution for custody."""

from __future__ import annotations

import hashlib
import uuid
from contextlib import contextmanager

import requests
from django.db import IntegrityError, connection, transaction
from django.utils import timezone
from eth_keys.exceptions import BadSignature
from eth_utils.exceptions import ValidationError

from .chain_registry import ChainKind, get_chain_spec
from .models import MpcSigningSession, OnchainTransactionAttempt
from .mpc_binding import (
    identity_fingerprint,
    local_root_keyset,
    transaction_identity,
    validate_custody_intent,
    verify_coordinator_keyset,
)
from .mpc_payload import exact_signing_payload

ACTIVE = {"CREATED", "STARTING", "IN_PROGRESS"}


@contextmanager
def attempt_execution_lock(attempt_id):
    """Nonblocking PostgreSQL ownership; released automatically on worker death."""
    if connection.vendor != "postgresql":
        yield True
        return
    lock_id = 0x4D50430000000000 + int(attempt_id)
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_try_advisory_lock(%s)", [lock_id])
        acquired = cursor.fetchone()[0]
    try:
        yield acquired
    finally:
        if acquired:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_unlock(%s)", [lock_id])


def coordinator_request(attempt, session) -> dict:
    payload = bytes(session.signing_payload)
    fingerprint = hashlib.sha256(payload).hexdigest()
    if fingerprint != session.message_fingerprint:
        raise ValueError("persisted MPC signing payload fingerprint mismatch")
    keyset = local_root_keyset(attempt)
    if keyset.pk != session.keyset_id or session.algorithm != keyset.algorithm:
        raise ValueError("persisted session/keyset binding mismatch")
    validate_custody_intent(attempt)
    identity = transaction_identity(attempt, keyset)
    payload_type, digest = exact_signing_payload(attempt.chain_id, attempt.prepared_metadata, b"")
    if (
        (
            not 0 < len(payload) <= 1167
            if keyset.algorithm == "FROST_ED25519"
            else len(payload) != 32
        )
        or digest != payload
        or payload_type != session.payload_type
        or identity != session.transaction_identity
        or identity_fingerprint(identity) != session.coordinator_request_id
    ):
        raise ValueError("immutable MPC transaction identity or digest mismatch")
    request = {
        "session_id": str(session.session_id),
        "attempt_id": attempt.pk,
        "keyset_id": str(session.keyset.keyset_id),
        "algorithm": session.algorithm,
        "payload_type": session.payload_type,
        "payload_hex": payload.hex(),
        "message_fingerprint": fingerprint,
        "operation_type": attempt.operation_type,
        "chain": "TRON"
        if get_chain_spec(attempt.chain_id).kind is ChainKind.TRON
        else attempt.chain_id,
        "asset": attempt.asset_key,
        "expected_source": attempt.from_address
        if session.payload_type in {"TRON_TXID", "SOLANA_MESSAGE"}
        else attempt.from_address.lower(),
        "derivation_reference": None,
    }
    if session.payload_type == "TON_V5R1_CELL_HASH":
        request["ton_authorization"] = attempt.prepared_metadata["ton_authorization"]
    return request


def _coordinator_identity_matches(expected: dict, result: dict) -> bool:
    actual = result.get("request", result)
    return all(field in actual and actual[field] == value for field, value in expected.items())


def _execution_identity_matches(session, result: dict) -> bool:
    execution = result.get("crypto_execution_id")
    try:
        execution = uuid.UUID(str(execution))
    except (ValueError, TypeError, AttributeError):
        return False
    if (
        execution.int == 0
        or execution == session.keyset.dkg_execution_id
        or session.crypto_execution_id not in {None, execution}
    ):
        return False
    signers = result.get("selected_signers")
    if not isinstance(signers, list) or any(not isinstance(p, str) for p in signers):
        return False
    if session.selected_signers and session.selected_signers != signers:
        return False
    if result.get("status") == "CREATED":
        return not signers and not session.selected_signers
    if result.get("status") in {"STARTING", "RECONCILIATION_REQUIRED"} and not signers:
        return not session.selected_signers
    return (
        len(signers) == 2
        and signers == sorted(set(signers))
        and set(signers).issubset(set(session.keyset.participant_identities))
    )


def mark_signing_uncertain(attempt_id, code):
    from .outbound import sync_parent_state

    with transaction.atomic():
        attempt = OnchainTransactionAttempt.objects.select_for_update().get(pk=attempt_id)
        if attempt.status not in {"SIGNING", "RECONCILIATION_REQUIRED"}:
            return attempt
        MpcSigningSession.objects.filter(
            attempt=attempt, signature_consumed_at__isnull=True
        ).update(status="RECONCILIATION_REQUIRED", error_code=code)
        attempt.status = "RECONCILIATION_REQUIRED"
        attempt.error_code = code
        attempt.save(update_fields=["status", "error_code", "updated_at"])
        sync_parent_state(attempt)
        return attempt


def _default_consumer(attempt, session):
    from eth_keys import keys

    from .mpc_payload import assemble_evm_signature

    coordinator_request(attempt, session)
    result = session.signature_result
    expected = {
        "logical_session_id": str(session.session_id),
        "crypto_execution_id": str(session.crypto_execution_id),
        "keyset_id": str(session.keyset.keyset_id),
        "selected_signers": session.selected_signers,
        "algorithm": session.algorithm,
        "payload_fingerprint": session.message_fingerprint,
        "verified": True,
    }
    if (
        result.get("verified") is not True
        or any(result.get(k) != v for k, v in expected.items())
        or not _execution_identity_matches(
            session,
            {
                "status": "COMPLETED",
                "crypto_execution_id": str(session.crypto_execution_id),
                "selected_signers": session.selected_signers,
            },
        )
    ):
        raise ValueError("completed signature identity mismatch")
    if session.algorithm == "FROST_ED25519":
        from .solana_wire import assemble_signature

        if session.payload_type not in {"SOLANA_MESSAGE", "TON_V5R1_CELL_HASH"} or set(
            result
        ) != set(expected) | {"signature_hex"}:
            raise ValueError("invalid FROST output contract")
        if session.payload_type == "TON_V5R1_CELL_HASH":
            from .ton_wire import assemble_signature as assemble_ton_signature

            return assemble_ton_signature(
                attempt.prepared_metadata["ton_authorization"],
                session.keyset.public_key,
                result["signature_hex"],
            )
        return assemble_signature(
            attempt.prepared_metadata["message"], session.keyset.public_key, result["signature_hex"]
        )
    if (
        type(result.get("recovery_id")) is not int
        or result.get("y_parity") != result.get("recovery_id")
        or len(result.get("r", "")) != 64
        or len(result.get("s", "")) != 64
        or result.get("signature_hex") != result["r"] + result["s"]
    ):
        raise ValueError("completed signature identity/encoding mismatch")
    if session.payload_type == "TRON_TXID":
        from .tron_policy import assemble_tron_signature

        signed_payload, tx_id = assemble_tron_signature(attempt.prepared_metadata, result)
    else:
        signed_payload, tx_id = assemble_evm_signature(
            attempt.prepared_metadata, result, attempt.from_address
        )
    signature = keys.Signature(
        vrs=(result["recovery_id"], int(result["r"], 16), int(result["s"], 16))
    )
    public = signature.recover_public_key_from_msg_hash(bytes(session.signing_payload))
    if (
        public.to_compressed_bytes().hex() != session.keyset.public_key
        or not signature.verify_msg_hash(bytes(session.signing_payload), public)
    ):
        raise ValueError("signature does not recover the persisted DKG public key")
    return signed_payload, tx_id


def _consume_completed(attempt_id, session_id):
    with transaction.atomic():
        attempt = OnchainTransactionAttempt.objects.select_for_update().get(pk=attempt_id)
        session = (
            MpcSigningSession.objects.select_for_update()
            .select_related("keyset")
            .get(pk=session_id)
        )
        if session.signature_consumed_at:
            return attempt
        if attempt.status not in {"SIGNING", "RECONCILIATION_REQUIRED"}:
            raise ValueError("signature cannot be consumed in current attempt state")
        if session.status != "COMPLETED" or not session.signature_result:
            raise ValueError("completed MPC session has no signature result")
        signed_payload, tx_id = _default_consumer(attempt, session)
        attempt.signed_payload, attempt.network_tx_id, attempt.status = (
            signed_payload,
            tx_id,
            "SIGNED",
        )
        attempt.error_code = ""
        attempt.save(
            update_fields=["signed_payload", "network_tx_id", "status", "error_code", "updated_at"]
        )
        session.signature_consumed_at = timezone.now()
        session.save(update_fields=["signature_consumed_at"])
        return attempt


def _persist_result(attempt_id, session_id, request, result):
    with transaction.atomic():
        attempt = OnchainTransactionAttempt.objects.select_for_update().get(pk=attempt_id)
        session = (
            MpcSigningSession.objects.select_for_update()
            .select_related("keyset")
            .get(pk=session_id)
        )
        if not _coordinator_identity_matches(request, result) or not _execution_identity_matches(
            session, result
        ):
            raise ValueError("COORDINATOR_IDENTITY_MISMATCH")
        status = result.get("status")
        if status not in ACTIVE | {"COMPLETED", "RECONCILIATION_REQUIRED"}:
            raise ValueError("COORDINATOR_STATE_UNKNOWN")
        if session.status == "COMPLETED":
            if result.get("signature") != session.signature_result:
                raise ValueError("conflicting completed coordinator result")
            return session
        session.crypto_execution_id = uuid.UUID(result["crypto_execution_id"])
        session.selected_signers = result["selected_signers"]
        session.status = status
        if status == "COMPLETED":
            if not result.get("signature"):
                raise ValueError("missing completed signature")
            session.signature_result = result["signature"]
            session.completed_at = timezone.now()
        session.save()
        if status != "RECONCILIATION_REQUIRED":
            attempt.status = "SIGNING"
            attempt.save(update_fields=["status", "updated_at"])
        return session


def advance_mpc_signing(attempt_id: int, client=None):
    """Create/execute/read/reconcile the SAME execution; no interactive protocol wait."""
    from .signer_adapter import assert_mpc_backend_runtime_safe, get_adapter

    snapshot = OnchainTransactionAttempt.objects.get(pk=attempt_id)
    assert_mpc_backend_runtime_safe(snapshot.chain_id)
    with attempt_execution_lock(attempt_id) as acquired:
        if not acquired:
            return OnchainTransactionAttempt.objects.get(pk=attempt_id)
        if snapshot.status not in {"SIGNING", "RECONCILIATION_REQUIRED"}:
            return snapshot
        client = client or get_adapter()
        sessions = list(
            MpcSigningSession.objects.select_related("keyset").filter(attempt_id=attempt_id)[:2]
        )
        if len(sessions) != 1:
            return mark_signing_uncertain(attempt_id, "MPC_SESSION_OWNERSHIP_MISMATCH")
        session = sessions[0]
        try:
            with transaction.atomic():
                request = coordinator_request(snapshot, session)
            from .mpc_tron_network import verify_mpc_rpc_endpoints
            from .native_tx import RequestsTransport

            verify_mpc_rpc_endpoints(snapshot.chain_id, RequestsTransport())
            verify_coordinator_keyset(
                session.keyset, client.get_keyset(str(session.keyset.keyset_id))
            )
            if session.status == "COMPLETED":
                return _consume_completed(attempt_id, session.pk)
            from .signer_adapter import CoordinatorSessionNotFound

            if session.status == "CREATED":
                _require_solana_fresh(snapshot, session)
                if session.payload_type == "TRON_TXID":
                    from .tron_policy import require_fresh

                    require_fresh(snapshot.prepared_metadata, signing=True)
                MpcSigningSession.objects.filter(pk=session.pk).update(
                    status="STARTING", started_at=timezone.now()
                )
                result = client.create_signing_session(request)
            else:
                try:
                    result = client.get_signing_session(str(session.session_id))
                except CoordinatorSessionNotFound:
                    if session.crypto_execution_id is not None:
                        raise ValueError("coordinator lost a known execution") from None
                    if session.payload_type == "TRON_TXID":
                        from .tron_policy import require_fresh

                        require_fresh(snapshot.prepared_metadata, signing=True)
                    _require_solana_fresh(snapshot, session)
                    result = client.create_signing_session(request)
            session = _persist_result(attempt_id, session.pk, request, result)
            if session.status == "CREATED":
                _require_solana_fresh(snapshot, session)
                if session.payload_type == "TRON_TXID":
                    from .tron_policy import require_fresh

                    require_fresh(snapshot.prepared_metadata, signing=True)
                result = client.execute_signing_session(str(session.session_id))
                session = _persist_result(attempt_id, session.pk, request, result)
            elif session.status == "RECONCILIATION_REQUIRED":
                result = client.reconcile_signing_session(str(session.session_id))
                session = _persist_result(attempt_id, session.pk, request, result)
            if session.status == "COMPLETED":
                return _consume_completed(attempt_id, session.pk)
            if session.status == "RECONCILIATION_REQUIRED":
                return mark_signing_uncertain(attempt_id, "COORDINATOR_SIGNING_UNCERTAIN")
        except (
            OSError,
            requests.RequestException,
            ValueError,
            KeyError,
            TypeError,
            BadSignature,
            ValidationError,
            IntegrityError,
        ):
            # A timeout or invalid result cannot establish nonce non-consumption.
            # Do not persist external payload/error details in logs or error_message.
            return mark_signing_uncertain(attempt_id, "MPC_RECONCILIATION_REQUIRED")
        return OnchainTransactionAttempt.objects.get(pk=attempt_id)


def _require_solana_fresh(attempt, session):
    if session.payload_type == "TON_V5R1_CELL_HASH":
        from .ton_policy import require_fresh_authorization

        require_fresh_authorization(attempt)

    if session.payload_type == "SOLANA_MESSAGE":
        from .mpc_solana_network import require_fresh
        from .native_tx import RequestsTransport

        require_fresh(
            attempt.chain_id,
            attempt.last_valid_block,
            RequestsTransport(),
            blockhash=attempt.prepared_metadata["recentBlockhash"],
        )
