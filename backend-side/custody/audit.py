"""
Audit logging helper.

Every signing request and broadcast action is recorded in AdminActionLog
(models). This is the single audit-write entrypoint used across the service.
Integrity note: in production, consider append-only storage / WORM or a
tamper-evident log (e.g., hash-chaining) for forensic value.

Pluggable compliance hooks (AML/KYC) can subscribe to audit writes; see the
`AML_KYC_HOOK` integration point near the bottom of this module.
"""
from __future__ import annotations

import logging
from enum import StrEnum
from typing import Any, Optional

logger = logging.getLogger("custody.audit")


class AuditAction(StrEnum):
    SIGN_REQUEST = "SIGN_REQUEST"
    BROADCAST = "BROADCAST"
    WITHDRAWAL_APPROVE = "WITHDRAWAL_APPROVE"
    WITHDRAWAL_DENY = "WITHDRAWAL_DENY"
    SWEEP_TRIGGER = "SWEEP_TRIGGER"
    GAS_TOPUP = "GAS_TOPUP"
    DEPOSIT_DETECTED = "DEPOSIT_DETECTED"
    INDEXER_SCAN = "INDEXER_SCAN"
    ADDRESS_CREATED = "ADDRESS_CREATED"
    ADDRESS_RETIRED = "ADDRESS_RETIRED"
    ADDRESS_RESOLVE = "ADDRESS_RESOLVE"
    ALERT_ACK = "ALERT_ACK"
    ASSET_ADD = "ASSET_ADD"
    ASSET_UPDATE = "ASSET_UPDATE"
    NODE_ADD = "NODE_ADD"
    NODE_UPDATE = "NODE_UPDATE"
    CHAIN_CREATE = "CHAIN_CREATE"
    CHAIN_UPDATE = "CHAIN_UPDATE"
    BLOCKLIST_ADD = "BLOCKLIST_ADD"
    BLOCKLIST_UPDATE = "BLOCKLIST_UPDATE"


# ---------------------------------------------------------------------------
# AML / KYC integration point (pluggable).
# ---------------------------------------------------------------------------
# Assign a callable here at startup (e.g. from waas.services) to run
# screening on high-risk actions (deposit address creation, withdrawals,
# blocklist hits). The hook receives (action, entity_type, entity_id, metadata)
# and should be NON-BLOCKING / best-effort so it never breaks the primary flow.
AML_KYC_HOOK = None


def register_aml_kyc_hook(hook) -> None:
    """Register an external screening hook (e.g. Chainalysis, Elliptic)."""
    global AML_KYC_HOOK
    AML_KYC_HOOK = hook


def write_audit_log(
    actor_id: str,
    action: AuditAction,
    entity_type: str,
    entity_id: str,
    metadata: Optional[dict[str, Any]] = None,
) -> None:
    """Persist an audit entry. Safe to call from any workflow.

    SECURITY: metadata MUST NOT contain secrets (no signed payloads, keys).
    """
    from .models import AdminActionLog

    # Accept either an AuditAction enum or a plain string (defensive).
    action_value = action.value if isinstance(action, AuditAction) else str(action)

    try:
        AdminActionLog.objects.create(
            actor_id=actor_id,
            action_type=action_value,
            entity_type=entity_type,
            entity_id=str(entity_id),
            metadata=metadata or {},
        )
    except Exception:  # pragma: no cover - audit must never crash primary flow
        logger.exception("failed to write audit log for %s", action_value)

    # Compliance fan-out (best effort).
    if AML_KYC_HOOK is not None:
        try:
            AML_KYC_HOOK(action_value, entity_type, str(entity_id), metadata or {})
        except Exception:
            logger.exception("aml/kyc hook failed for %s", action_value)