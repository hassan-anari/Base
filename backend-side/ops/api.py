"""
Ops platform REST API (asset/chain registry, node health, balances,
transactions, alerts, operator activity + audit).

RBAC:
  * read-only endpoints  : read_only, auditor, operator, admin
  * mutating config      : operator, admin   (require_operator)
  * alert acknowledgement: operator, admin
  * no user/custody secrets are exposed here; deposit addresses of users are
    NOT listed by ops (privacy boundary). Ops sees aggregates + own addresses.
"""
from __future__ import annotations

import logging
from typing import Optional

from django.db.models import Count, Sum
from django.utils import timezone
from ninja import Router, Header, Schema
from ninja.errors import HttpError

from . import models as M
from . import services as S
from .schemas import (
    ChainDTO, AssetDTO, AddAssetRequest, AddNodeRequest, NodeHealthDTO,
    NodeUpdateRequest, AddressBalanceDTO, TransactionDTO, AlertDTO, AckAlertRequest,
    OperatorActivityDTO, EmptyResponse, SummaryDTO,
    AddChainRequest, ChainUpdateRequest, BlocklistDTO, AddBlocklistRequest,
    BlocklistUpdateRequest,
)
from custody.auth import decode_token
from custody.api import require_admin, require_operator, require_auditor
from custody.rate_limit import RateLimitExceeded, rate_limiter
from custody.audit import write_audit_log, AuditAction

logger = logging.getLogger("ops.api")
api = Router()


def _current_user(authorization: Optional[str],
                  x_user_id: Optional[str], x_role: Optional[str]):
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        decoded = decode_token(token)
        if decoded:
            return decoded
        raise HttpError(401, "invalid or expired token")
    # Backward-compat stub headers (dev-only; disabled in production).
    from django.conf import settings
    if getattr(settings, "ALLOW_DEV_STUB_AUTH", False) and x_user_id:
        return (x_user_id, x_role or "read_only")
    # SECURITY: never serve unauthenticated read/mutating ops requests.
    raise HttpError(401, "authentication required")


def _rate(key: str, limit: int, window: int):
    try:
        rate_limiter.consume(key, limit, window)
    except RateLimitExceeded:
        raise HttpError(429, "rate limited")


def _dt(o) -> str:
    return str(o) if o else ""


# ---------------------------------------------------------------------------
# Chains & Assets (registry)
# ---------------------------------------------------------------------------
@api.get("/ops/chains", response=list[ChainDTO])
def list_chains(request, authorization: Optional[str] = Header(None),
                x_user_id: Optional[str] = Header(None),
                x_role: Optional[str] = Header(None)):
    _current_user(authorization, x_user_id, x_role)
    out = []
    for c in M.Chain.objects.all():
        out.append(ChainDTO(
            chain_id=c.chain_id, display_name=c.display_name, kind=c.kind,
            native_asset_key=c.native_asset_key, evm_chain_id=c.evm_chain_id,
            is_testnet=c.is_testnet, min_confirmations=c.min_confirmations,
            sweep_threshold=float(c.sweep_threshold), memo_required=c.memo_required,
            enabled=c.enabled,
        ))
    return out


@api.post("/ops/chains", response=ChainDTO)
def create_chain(request, payload: AddChainRequest,
                 authorization: Optional[str] = Header(None),
                 x_user_id: Optional[str] = Header(None),
                 x_role: Optional[str] = Header(None)):
    actor_id, role = _current_user(authorization, x_user_id, x_role)
    require_operator(role)
    _rate(f"ops-chain:{actor_id}", 10, 60)
    from decimal import Decimal
    c, created = M.Chain.objects.get_or_create(
        chain_id=payload.chain_id,
        defaults=dict(
            display_name=payload.display_name, kind=payload.kind,
            evm_chain_id=payload.evm_chain_id, native_asset_key=payload.native_asset_key,
            is_testnet=payload.is_testnet, min_confirmations=payload.min_confirmations,
            sweep_threshold=Decimal(str(payload.sweep_threshold)),
            memo_required=payload.memo_required,
            explorer_tx_url=payload.explorer_tx_url,
            explorer_address_url=payload.explorer_address_url,
            gas_settings=payload.gas_settings, enabled=payload.enabled,
        ),
    )
    if not created:
        raise HttpError(409, "chain already exists")
    write_audit_log(actor_id, AuditAction.CHAIN_CREATE, "Chain", c.chain_id,
                   {"kind": c.kind})
    return ChainDTO(
        chain_id=c.chain_id, display_name=c.display_name, kind=c.kind,
        native_asset_key=c.native_asset_key, evm_chain_id=c.evm_chain_id,
        is_testnet=c.is_testnet, min_confirmations=c.min_confirmations,
        sweep_threshold=float(c.sweep_threshold), memo_required=c.memo_required,
        enabled=c.enabled,
    )


@api.patch("/ops/chains/{chain_id}", response=ChainDTO)
def update_chain(request, chain_id: str, payload: ChainUpdateRequest,
                authorization: Optional[str] = Header(None),
                x_user_id: Optional[str] = Header(None),
                x_role: Optional[str] = Header(None)):
    actor_id, role = _current_user(authorization, x_user_id, x_role)
    require_operator(role)
    _rate(f"ops-chain-upd:{actor_id}", 20, 60)
    try:
        c = M.Chain.objects.get(chain_id=chain_id)
    except M.Chain.DoesNotExist:
        raise HttpError(404, "chain not found")
    data = payload.dict(exclude_unset=True)
    from decimal import Decimal
    if "sweep_threshold" in data:
        data["sweep_threshold"] = Decimal(str(data["sweep_threshold"]))
    for k, v in data.items():
        setattr(c, k, v)
    c.save()
    write_audit_log(actor_id, AuditAction.CHAIN_UPDATE, "Chain", c.chain_id,
                   {"changed": list(data.keys())})
    return ChainDTO(
        chain_id=c.chain_id, display_name=c.display_name, kind=c.kind,
        native_asset_key=c.native_asset_key, evm_chain_id=c.evm_chain_id,
        is_testnet=c.is_testnet, min_confirmations=c.min_confirmations,
        sweep_threshold=float(c.sweep_threshold), memo_required=c.memo_required,
        enabled=c.enabled,
    )


@api.post("/ops/assets", response=AssetDTO)
def create_asset(request, payload: AddAssetRequest,
                 authorization: Optional[str] = Header(None),
                 x_user_id: Optional[str] = Header(None),
                 x_role: Optional[str] = Header(None)):
    actor_id, role = _current_user(authorization, x_user_id, x_role)
    require_operator(role)
    _rate(f"ops-asset:{actor_id}", 10, 60)
    obj = S.add_asset(actor_id, **payload.dict())
    return AssetDTO(
        asset_key=obj.asset_key, chain_id=obj.chain_id, symbol=obj.symbol,
        name=obj.name, contract_address=obj.contract_address,
        decimals=obj.decimals, is_native=obj.is_native,
        deposit_threshold=float(obj.deposit_threshold),
        withdraw_enabled=obj.withdraw_enabled, enabled=obj.enabled,
    )


@api.post("/ops/nodes", response=EmptyResponse)
def create_node(request, payload: AddNodeRequest,
                authorization: Optional[str] = Header(None),
                x_user_id: Optional[str] = Header(None),
                x_role: Optional[str] = Header(None)):
    actor_id, role = _current_user(authorization, x_user_id, x_role)
    require_operator(role)
    S.add_node(actor_id, **payload.dict())
    return EmptyResponse(message="node registered")


@api.patch("/ops/nodes/{node_id}", response=NodeHealthDTO)
def update_node(request, node_id: str, payload: NodeUpdateRequest,
                authorization: Optional[str] = Header(None),
                x_user_id: Optional[str] = Header(None),
                x_role: Optional[str] = Header(None)):
    """Edit an existing node/RPC endpoint (e.g. rotate the RPC URL, reprioritise).

    Delegates to the ops service layer (single source of truth) which enforces
    RBAC, computes the field diff, writes the NODE_UPDATE audit entry, and
    returns a clear 400 when the request would change nothing.
    """
    actor_id, role = _current_user(authorization, x_user_id, x_role)
    require_operator(role)
    _rate(f"ops-node-upd:{actor_id}", 20, 60)
    try:
        n = S.ops_update_node(
            actor_id, node_id=node_id,
            url=payload.url, name=payload.name, kind=payload.kind,
            priority=payload.priority, is_primary=payload.is_primary,
            enabled=payload.enabled,
        )
    except S.NodeNoChange:
        raise HttpError(400, "no fields to update")
    except ValueError as e:
        if str(e) == "node_not_found":
            raise HttpError(404, "node not found")
        raise
    return _node_dto(n)


# ---------------------------------------------------------------------------
# Blocklist (deposit / withdrawal address screening)
# ---------------------------------------------------------------------------
@api.get("/ops/blocklist", response=list[BlocklistDTO])
def list_blocklist(request, scope: Optional[str] = None,
                   enabled: Optional[bool] = None,
                   authorization: Optional[str] = Header(None),
                   x_user_id: Optional[str] = Header(None),
                   x_role: Optional[str] = Header(None)):
    _current_user(authorization, x_user_id, x_role)
    qs = M.Blocklist.objects.all().order_by("-id")
    if scope:
        qs = qs.filter(scope=scope)
    if enabled is not None:
        qs = qs.filter(enabled=enabled)
    out = []
    for b in qs[:500]:
        out.append(BlocklistDTO(
            id=b.id, scope=b.scope, value=b.value, chain_id=b.chain_id,
            asset_key=b.asset_key, reason=b.reason, note=b.note,
            enabled=b.enabled, created_by=b.created_by,
            created_at=_dt(b.created_at),
        ))
    return out


@api.post("/ops/blocklist", response=BlocklistDTO)
def create_blocklist(request, payload: AddBlocklistRequest,
                     authorization: Optional[str] = Header(None),
                     x_user_id: Optional[str] = Header(None),
                     x_role: Optional[str] = Header(None)):
    actor_id, role = _current_user(authorization, x_user_id, x_role)
    # SECURITY: blocklist is an AML/sanctions control -> admin only.
    require_admin(role)
    _rate(f"ops-block:{actor_id}", 20, 60)
    if payload.scope not in ("DEPOSIT_ADDRESS", "WITHDRAW_ADDRESS", "CHAIN_ASSET"):
        raise HttpError(400, "invalid scope")
    if payload.scope == "CHAIN_ASSET" and not (payload.chain_id and payload.asset_key):
        raise HttpError(400, "CHAIN_ASSET scope requires chain_id + asset_key")
    b = M.Blocklist.objects.create(
        scope=payload.scope, value=payload.value, chain_id=payload.chain_id,
        asset_key=payload.asset_key, reason=payload.reason, note=payload.note,
        created_by=actor_id,
    )
    write_audit_log(actor_id, AuditAction.BLOCKLIST_ADD, "Blocklist", b.id,
                   {"scope": b.scope, "value": b.value,
                    "chain_id": b.chain_id, "asset_key": b.asset_key})
    return BlocklistDTO(
        id=b.id, scope=b.scope, value=b.value, chain_id=b.chain_id,
        asset_key=b.asset_key, reason=b.reason, note=b.note,
        enabled=b.enabled, created_by=b.created_by, created_at=_dt(b.created_at),
    )


@api.patch("/ops/blocklist/{block_id}", response=BlocklistDTO)
def update_blocklist(request, block_id: str, payload: BlocklistUpdateRequest,
                     authorization: Optional[str] = Header(None),
                     x_user_id: Optional[str] = Header(None),
                     x_role: Optional[str] = Header(None)):
    actor_id, role = _current_user(authorization, x_user_id, x_role)
    # SECURITY: blocklist is an AML/sanctions control -> admin only.
    require_admin(role)
    try:
        b = M.Blocklist.objects.get(id=block_id)
    except M.Blocklist.DoesNotExist:
        raise HttpError(404, "entry not found")
    data = payload.dict(exclude_unset=True)
    for k, v in data.items():
        setattr(b, k, v)
    b.save()
    write_audit_log(actor_id, AuditAction.BLOCKLIST_UPDATE, "Blocklist", b.id,
                   {"changed": list(data.keys()), "enabled": b.enabled})
    return BlocklistDTO(
        id=b.id, scope=b.scope, value=b.value, chain_id=b.chain_id,
        asset_key=b.asset_key, reason=b.reason, note=b.note,
        enabled=b.enabled, created_by=b.created_by, created_at=_dt(b.created_at),
    )


# ---------------------------------------------------------------------------
# Node health
# ---------------------------------------------------------------------------
def _node_dto(n: M.NodeEndpoint) -> NodeHealthDTO:
    return NodeHealthDTO(
        id=n.id, chain_id=n.chain_id, name=n.name, url=n.url, kind=n.kind,
        priority=n.priority, is_primary=n.is_primary, enabled=n.enabled,
        healthy=n.healthy, latency_ms=n.latency_ms,
        block_height=n.block_height, sync_status=n.sync_status,
        last_error=n.last_error, last_checked=_dt(n.last_checked),
    )


@api.get("/ops/nodes", response=list[NodeHealthDTO])
def list_nodes(request, chain_id: Optional[str] = None,
               authorization: Optional[str] = Header(None),
               x_user_id: Optional[str] = Header(None),
               x_role: Optional[str] = Header(None)):
    """List all registered nodes/RPC endpoints (optionally per chain)."""
    _current_user(authorization, x_user_id, x_role)
    qs = M.NodeEndpoint.objects.all().order_by("chain_id", "priority", "name")
    if chain_id:
        qs = qs.filter(chain_id=chain_id)
    return [_node_dto(n) for n in qs]


@api.get("/ops/nodes/health", response=list[NodeHealthDTO])
def node_health(request, authorization: Optional[str] = Header(None),
                x_user_id: Optional[str] = Header(None),
                x_role: Optional[str] = Header(None)):
    _current_user(authorization, x_user_id, x_role)
    return [_node_dto(n)
            for n in M.NodeEndpoint.objects.all().order_by("chain_id", "priority")]


@api.post("/ops/nodes/{node_id}/probe", response=NodeHealthDTO)
def probe_node_endpoint(request, node_id: str,
                        authorization: Optional[str] = Header(None),
                        x_user_id: Optional[str] = Header(None),
                        x_role: Optional[str] = Header(None)):
    """Live-probe one node's RPC URL and persist the health result.

    Operator-only (it performs an outbound network call). The probe is
    chain-family aware (EVM/TRON/SOLANA/TON) and never raises: failures are
    recorded as unhealthy with the error message.
    """
    actor_id, role = _current_user(authorization, x_user_id, x_role)
    require_operator(role)
    _rate(f"ops-node-probe:{actor_id}", 30, 60)
    try:
        node = M.NodeEndpoint.objects.get(id=node_id)
    except M.NodeEndpoint.DoesNotExist:
        raise HttpError(404, f"node {node_id} not found")
    from custody.indexer.rpc_nodes import probe_node
    res = probe_node(node.url, node.chain_id)
    S.record_node_health(node.id, **res)
    node.refresh_from_db()
    return _node_dto(node)


# ---------------------------------------------------------------------------
# Balances (exchange-owned addresses; never user deposit privacy dump)
# ---------------------------------------------------------------------------
@api.get("/ops/balances", response=list[AddressBalanceDTO])
def list_balances(request, chain_id: Optional[str] = None,
                  owner_type: Optional[str] = None,
                  authorization: Optional[str] = Header(None),
                  x_user_id: Optional[str] = Header(None),
                  x_role: Optional[str] = Header(None)):
    actor_id, role = _current_user(authorization, x_user_id, x_role)
    require_auditor(role)
    qs = M.AddressBalance.objects.all().order_by("-id")
    if chain_id:
        qs = qs.filter(chain_id=chain_id)
    if owner_type:
        qs = qs.filter(owner_type=owner_type)
    out = []
    for b in qs[:500]:
        out.append(AddressBalanceDTO(
            id=b.id, chain_id=b.chain_id, asset_key=b.asset_key, address=b.address,
            owner_type=b.owner_type, owner_ref=b.owner_ref,
            confirmed_balance=float(b.confirmed_balance),
            pending_balance=float(b.pending_balance) if b.pending_balance is not None else None,
            source=b.source, created_at=_dt(b.created_at),
        ))
    return out


# ---------------------------------------------------------------------------
# Transactions (exchange ledger of on-chain activity)
# ---------------------------------------------------------------------------
@api.get("/ops/transactions", response=list[TransactionDTO])
def list_transactions(request, chain_id: Optional[str] = None,
                      tx_type: Optional[str] = None,
                      authorization: Optional[str] = Header(None),
                      x_user_id: Optional[str] = Header(None),
                      x_role: Optional[str] = Header(None)):
    actor_id, role = _current_user(authorization, x_user_id, x_role)
    require_auditor(role)
    qs = M.TransactionLog.objects.all().order_by("-id")
    if chain_id:
        qs = qs.filter(chain_id=chain_id)
    if tx_type:
        qs = qs.filter(tx_type=tx_type)
    out = []
    for t in qs[:500]:
        out.append(TransactionDTO(
            id=t.id, tx_type=t.tx_type, chain_id=t.chain_id, asset_key=t.asset_key,
            tx_hash=t.tx_hash, from_address=t.from_address, to_address=t.to_address,
            amount=float(t.amount), memo=t.memo, block=t.block,
            confirmations=t.confirmations, status=t.status,
            ref_type=t.ref_type, ref_id=t.ref_id, created_at=_dt(t.created_at),
        ))
    return out


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------
@api.get("/ops/alerts", response=list[AlertDTO])
def list_alerts(request, resolved: Optional[bool] = None,
                authorization: Optional[str] = Header(None),
                x_user_id: Optional[str] = Header(None),
                x_role: Optional[str] = Header(None)):
    _current_user(authorization, x_user_id, x_role)
    qs = M.Alert.objects.all().order_by("-id")
    if resolved is not None:
        qs = qs.filter(resolved=resolved)
    out = []
    for a in qs[:500]:
        out.append(AlertDTO(
            id=a.id, chain_id=a.chain_id, category=a.category, severity=a.severity,
            title=a.title, detail=a.detail, resolved=a.resolved,
            acknowledged_by=a.acknowledged_by, created_at=_dt(a.created_at),
        ))
    return out


@api.post("/ops/alerts/{alert_id}/ack", response=EmptyResponse)
def ack_alert(request, alert_id: int, payload: AckAlertRequest,
              authorization: Optional[str] = Header(None),
              x_user_id: Optional[str] = Header(None),
              x_role: Optional[str] = Header(None)):
    actor_id, role = _current_user(authorization, x_user_id, x_role)
    require_operator(role)
    try:
        a = M.Alert.objects.get(id=alert_id)
    except M.Alert.DoesNotExist:
        raise HttpError(404, "alert not found")
    a.resolved = True
    a.acknowledged_by = actor_id
    a.save(update_fields=["resolved", "acknowledged_by"])
    write_audit_log(actor_id, AuditAction.ALERT_ACK, "Alert", str(alert_id),
                   {"note": payload.note})
    return EmptyResponse(message="alert acknowledged")


# ---------------------------------------------------------------------------
# Operator activity / audit feed (read-only for auditors)
# ---------------------------------------------------------------------------
@api.get("/ops/activity", response=list[OperatorActivityDTO])
def list_activity(request, authorization: Optional[str] = Header(None),
                  x_user_id: Optional[str] = Header(None),
                  x_role: Optional[str] = Header(None)):
    actor_id, role = _current_user(authorization, x_user_id, x_role)
    require_auditor(role)
    out = []
    for r in M.OperatorActivity.objects.all().order_by("-id")[:500]:
        out.append(OperatorActivityDTO(
            id=r.id, actor_id=r.actor_id, role=r.role, action=r.action,
            target=r.target, meta=r.meta, created_at=_dt(r.created_at),
        ))
    return out


# ---------------------------------------------------------------------------
# Aggregate summary (single call for the ops dashboard)
# ---------------------------------------------------------------------------
@api.get("/ops/summary", response=SummaryDTO)
def summary(request, authorization: Optional[str] = Header(None),
            x_user_id: Optional[str] = Header(None),
            x_role: Optional[str] = Header(None)):
    _current_user(authorization, x_user_id, x_role)
    chains_total = M.Chain.objects.count()
    assets_total = M.Asset.objects.count()
    nodes_total = M.NodeEndpoint.objects.count()
    nodes_unhealthy = M.NodeEndpoint.objects.filter(healthy=False).count()
    balances = M.AddressBalance.objects.all()
    balances_total = balances.count()
    balances_confirmed_sum = float(balances.aggregate(s=Sum("confirmed_balance"))["s"] or 0)
    txs = M.TransactionLog.objects.all()
    transactions_total = txs.count()
    by_status: dict = {}
    for row in txs.values("status").annotate(c=Count("id")):
        by_status[row["status"]] = row["c"]
    alerts_open = M.Alert.objects.filter(resolved=False).count()
    alerts_critical = M.Alert.objects.filter(resolved=False, severity="critical").count()
    activity_recent = M.OperatorActivity.objects.count()
    return SummaryDTO(
        generated_at=_dt(timezone.now()),
        chains_total=chains_total, assets_total=assets_total,
        nodes_total=nodes_total, nodes_unhealthy=nodes_unhealthy,
        balances_total=balances_total,
        balances_confirmed_sum=balances_confirmed_sum,
        transactions_total=transactions_total,
        transactions_by_status=by_status,
        alerts_open=alerts_open, alerts_critical=alerts_critical,
        activity_recent=activity_recent,
    )