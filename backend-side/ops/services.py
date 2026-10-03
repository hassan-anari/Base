"""
Ops service layer: all read/write business logic for the operations platform.

Responsibilities:
  * Asset/chain registry (config-driven onboarding, no code change)
  * Node health monitoring (RPC/Indexer reachability, block height, latency)
  - Balance snapshots (current + historical) for any address
  * Operator activity tracking + audit integration
  * Alert creation/acknowledgement

This layer is deliberately DB/integration-light (no live RPC calls in the
skeleton) but shows exactly where to plug real monitoring.
"""
from __future__ import annotations

import logging
from decimal import Decimal
from typing import Optional

from django.utils import timezone

from . import models as M
from custody.audit import write_audit_log, AuditAction

logger = logging.getLogger("ops.services")


# ---------------------------------------------------------------------------
# Asset / Chain registry
# ---------------------------------------------------------------------------
def seed_defaults() -> None:
    """Idempotently seed built-in chains/assets/nodes from custody config.

    Call from a management command or on startup (idempotent).
    """
    from custody.config import (chain_ids, get_chain, get_asset, native_asset_key,
                                get_assets, effective_deposit_threshold,
                                get_indexer_base_url)
    ASSETS = get_assets()
    for cid in chain_ids():
        cfg = get_chain(cid)
        M.Chain.objects.update_or_create(
            chain_id=cid,
            defaults=dict(
                display_name=cfg.display_name,
                kind=cfg.kind.value if hasattr(cfg.kind, "value") else str(cfg.kind),
                evm_chain_id=cfg.chain_id_int,
                native_asset_key=native_asset_key(cid),
                is_testnet=cfg.enabled,
                min_confirmations=cfg.confirmations,
                sweep_threshold=Decimal(str(cfg.deposit_threshold)),
                memo_required=cfg.memo_required,
                enabled=cfg.enabled,
            ),
        )
    for ak in ASSETS:
        a = get_asset(ak)
        thr = effective_deposit_threshold(a)
        M.Asset.objects.update_or_create(
            asset_key=ak,
            defaults=dict(
                chain_id=a.chain_id, symbol=a.symbol, name="",
                contract_address=a.contract_address or "",
                decimals=a.decimals, is_native=a.is_native,
                deposit_threshold=Decimal(str(thr)),
                withdraw_enabled=True, enabled=a.enabled,
            ),
        )
    # Seed default node endpoints (rpc + indexer) per chain so the ops
    # dashboard + chain token page have real rows to monitor / edit.
    idx_base = get_indexer_base_url()
    for cid in chain_ids():
        cfg = get_chain(cid)
        # RPC node (primary)
        M.NodeEndpoint.objects.update_or_create(
            chain_id=cid, kind="rpc", name=f"{cid} RPC (default)",
            url=cfg.rpc_url,
            defaults=dict(priority=10, is_primary=True, enabled=True),
        )
        # Indexer node (default)
        M.NodeEndpoint.objects.update_or_create(
            chain_id=cid, kind="indexer", name=f"{cid} Indexer (default)",
            url=idx_base,
            defaults=dict(priority=10, is_primary=True, enabled=True),
        )


def add_asset(actor_id: str, *, asset_key: str, chain_id: str, symbol: str,
              name: str = "", contract_address: str = "", decimals: int = 18,
              is_native: bool = False, deposit_threshold: str = "0.0",
              withdraw_enabled: bool = True) -> M.Asset:
    """Admin/operator adds a new token (onboarding). No code change needed.

    RBAC (operator+) is enforced at the API boundary; this layer only
    attributes the action to ``actor_id`` for audit.
    """
    obj, created = M.Asset.objects.update_or_create(
        asset_key=asset_key,
        defaults=dict(chain_id=chain_id, symbol=symbol, name=name,
                      contract_address=contract_address, decimals=decimals,
                      is_native=is_native,
                      deposit_threshold=Decimal(deposit_threshold),
                      withdraw_enabled=withdraw_enabled, enabled=True),
    )
    write_audit_log(actor_id, "ASSET_ADD" if created else "ASSET_UPDATE",
                   "Asset", asset_key,
                   {"chain_id": chain_id, "symbol": symbol,
                    "contract": contract_address})
    return obj


def add_node(actor_id: str, *, chain_id: str, name: str, url: str,
             kind: str = "rpc", priority: int = 10,
             is_primary: bool = False) -> M.NodeEndpoint:
    obj = M.NodeEndpoint.objects.create(
        chain_id=chain_id, name=name, url=url, kind=kind,
        priority=priority, is_primary=is_primary, enabled=True,
    )
    write_audit_log(actor_id, "NODE_ADD", "NodeEndpoint", obj.id,
                   {"chain_id": chain_id, "url": url, "kind": kind})
    return obj


class NodeNoChange(Exception):
    pass


def ops_update_node(actor_id: str, *, node_id: str, url: Optional[str] = None,
                    name: Optional[str] = None, kind: Optional[str] = None,
                    priority: Optional[int] = None,
                    is_primary: Optional[bool] = None,
                    enabled: Optional[bool] = None) -> M.NodeEndpoint:
    """Operator/auditor edits a node endpoint (e.g. rotate RPC URL).

    RBAC (operator+) is enforced at the API boundary. Records a NODE_UPDATE
    audit entry. Raises NodeNoChange if the request would not modify any field.
    """
    try:
        node = M.NodeEndpoint.objects.get(id=node_id)
    except M.NodeEndpoint.DoesNotExist:
        raise ValueError("node_not_found")
    changed = {}
    if url is not None and url != node.url:
        node.url = url; changed["url"] = url
    if name is not None and name != node.name:
        node.name = name; changed["name"] = name
    if kind is not None and kind != node.kind:
        node.kind = kind; changed["kind"] = kind
    if priority is not None and priority != node.priority:
        node.priority = priority; changed["priority"] = priority
    if is_primary is not None and is_primary != node.is_primary:
        node.is_primary = is_primary; changed["is_primary"] = is_primary
    if enabled is not None and enabled != node.enabled:
        node.enabled = enabled; changed["enabled"] = enabled
    if not changed:
        raise NodeNoChange()
    node.save()
    write_audit_log(actor_id, AuditAction.NODE_UPDATE, "NodeEndpoint", node.id,
                   {"chain_id": node.chain_id, "changes": changed})
    return node


# ---------------------------------------------------------------------------
# Node health monitoring
# ---------------------------------------------------------------------------
def record_node_health(node_id: str, *, healthy: bool, latency_ms: Optional[int] = None,
                       block_height: Optional[int] = None, sync_status: str = "",
                       last_error: str = "") -> None:
    """Persist a node health probe result.

    In production this is called by a Celery beat task that pings each
    NodeEndpoint.url. Here it is a pure DB write (testable, no network).
    """
    try:
        node = M.NodeEndpoint.objects.get(id=node_id)
    except M.NodeEndpoint.DoesNotExist:
        return
    node.healthy = healthy
    node.latency_ms = latency_ms
    node.block_height = block_height
    node.sync_status = sync_status
    node.last_error = last_error
    node.last_checked = timezone.now()
    node.save(update_fields=["healthy", "latency_ms", "block_height",
                             "sync_status", "last_error", "last_checked"])
    if not healthy:
        maybe_alert(node.chain_id, "node_health", "warning",
                    f"Node {node.name} unhealthy", last_error)


def maybe_alert(chain_id: str, category: str, severity: str,
                title: str, detail: str = "") -> None:
    """Create an unresolved alert (deduped on open title+chain)."""
    existing = M.Alert.objects.filter(
        chain_id=chain_id, category=category, title=title, resolved=False
    ).first()
    if existing:
        return
    M.Alert.objects.create(chain_id=chain_id, category=category,
                           severity=severity, title=title, detail=detail)


# ---------------------------------------------------------------------------
# Balance snapshots
# ---------------------------------------------------------------------------
def record_balance(*, chain_id: str, asset_key: str, address: str,
                   owner_type: str = "user_deposit", owner_ref: str = "",
                   confirmed_balance: str = "0", pending_balance: Optional[str] = None,
                   source: str = "indexer") -> M.AddressBalance:
    """Persist a point-in-time balance observation."""
    return M.AddressBalance.objects.create(
        chain_id=chain_id, asset_key=asset_key, address=address,
        owner_type=owner_type, owner_ref=owner_ref,
        confirmed_balance=Decimal(confirmed_balance),
        pending_balance=Decimal(pending_balance) if pending_balance is not None else None,
        source=source,
    )


def log_tx(*, tx_type: str, chain_id: str, asset_key: str, tx_hash: str = "",
           from_address: str = "", to_address: str = "",
           amount: str = "0", memo: str = "", block: Optional[int] = None,
           confirmations: int = 0, status: str = "pending",
           ref_type: str = "", ref_id: str = "") -> M.TransactionLog:
    return M.TransactionLog.objects.create(
        tx_type=tx_type, chain_id=chain_id, asset_key=asset_key, tx_hash=tx_hash,
        from_address=from_address, to_address=to_address,
        amount=Decimal(amount), memo=memo, block=block,
        confirmations=confirmations, status=status,
        ref_type=ref_type, ref_id=ref_id,
    )


# ---------------------------------------------------------------------------
# Operator activity + session tracking
# ---------------------------------------------------------------------------
def track_activity(actor_id: str, role: str, action: str,
                   target: str = "", meta: Optional[dict] = None) -> None:
    M.OperatorActivity.objects.create(
        actor_id=actor_id, role=role, action=action, target=target,
        meta=meta or {},
    )
