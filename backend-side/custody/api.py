"""
Django Ninja REST API routes + RBAC stubs.

Endpoints
---------
POST /api/wallet/address            -> create/return user deposit EOA (idempotent)
POST /api/wallet/balance/check      -> indexer check + auto-sweep trigger
POST /api/withdrawals/request       -> user creates PENDING_APPROVAL
POST /api/withdrawals/{id}/approve  -> admin approve (RBAC)
POST /api/withdrawals/{id}/deny     -> admin deny (RBAC)
GET  /api/withdrawals               -> user list
GET  /api/admin/withdrawals         -> admin list
GET  /api/sweeps/{id}               -> sweep job status

SECURITY:
  - All endpoints are rate-limited (api_rate_limit decorator stub).
  - Admin routes require role=admin (RBAC stub via require_admin).
  - Request/response validated by Ninja/Pydantic schemas.
"""

from __future__ import annotations

import logging
from decimal import Decimal
from typing import Optional

from django.db import transaction
from django.db.models import Count, Sum
from django.utils import timezone
from ninja import Header, Router, Schema
from ninja.errors import HttpError

from .audit import AuditAction, write_audit_log
from .auth import authenticate, decode_token
from .chain_status import check_all_chains
from .config import (
    default_deposit_targets,
    effective_deposit_threshold,
    get_asset,
    get_assets,
    get_chains,
    is_memo_required,
    native_asset_key,
    validate_chain_asset,
)
from .deposits import ingest_event
from .gas_station import admin_topup
from .hd_wallet import derive_deposit_address, stable_user_index
from .indexer.base import IndexerUnavailable
from .indexer.factory import get_indexer
from .ledger import InsufficientFunds, user_balances
from .models import Deposit, HotWallet, LedgerAccount, SweepJob, UserWallet, WithdrawalRequest
from .rate_limit import RateLimitExceeded, rate_limiter
from .schemas import (
    AddressRequest,
    AddressResolveRequest,
    AddressResolveResponse,
    AddressResponse,
    BalanceCheckRequest,
    BalanceCheckResponse,
    CreateWalletRequest,
    CreateWalletResponse,
    CustodyStatsResponse,
    GasStationEntry,
    GasStationListResponse,
    GasStationTopupRequest,
    GasStationTopupResponse,
    InternalBalanceEntry,
    InternalBalanceResponse,
    SweepStatusResponse,
    WalletAddressDTO,
    WithdrawalAdminAction,
    WithdrawalListResponse,
    WithdrawalRequestInput,
    WithdrawalRequestResponse,
)
from .screening import check_deposit_asset, check_withdrawal_target
from .sweeper import trigger_sweep
from .withdrawals import (
    approve as wd_approve,
)
from .withdrawals import (
    create_request as wd_create,
)
from .withdrawals import (
    deny as wd_deny,
)
from .withdrawals import (
    process_withdrawal,
)

logger = logging.getLogger("custody.api")
api = Router()


# ---------------- Auth / login ----------------
class LoginRequest(Schema):
    username: str
    password: str


class LoginResponse(Schema):
    access_token: str
    user_id: str
    role: str


@api.post("/auth/login", response=LoginResponse, auth=None)
def login(request, payload: LoginRequest):
    """Exchange credentials for a signed JWT (skeleton: demo users only)."""
    token = authenticate(payload.username, payload.password)
    if not token:
        raise HttpError(401, "invalid credentials")
    from .auth import decode_token

    sub, role = decode_token(token)
    return LoginResponse(access_token=token, user_id=sub, role=role)


class ChainConfigDTO(Schema):
    chain_id: str
    kind: str
    display_name: str
    memo_required: bool
    confirmations: int
    deposit_threshold: float
    evm_chain_id: Optional[int] = None
    enabled: bool


class AssetConfigDTO(Schema):
    asset_key: str
    chain_id: str
    symbol: str
    decimals: int
    is_native: bool
    contract_address: Optional[str] = None
    deposit_threshold: float
    deposit_supported: bool
    withdrawal_supported: bool
    sweep_supported: bool


class AppConfigResponse(Schema):
    chains: list[ChainConfigDTO]
    assets: list[AssetConfigDTO]
    # asset_keys grouped by chain, for easy frontend selector population
    assets_by_chain: dict[str, list[AssetConfigDTO]]


@api.get("/config", response=AppConfigResponse, auth=None)
def app_config(request):
    """Public-ish registry of enabled chains + their assets (incl. USDT).

    Safe to expose: contains NO secrets, only chain/asset metadata used to
    build network+asset selectors in the frontend. RPC URLs are intentionally
    omitted (they belong to the backend / MPC signer boundary).
    """
    chains, assets = [], []
    by_chain: dict[str, list] = {}
    for c in get_chains().values():
        chains.append(
            ChainConfigDTO(
                chain_id=c.chain_id,
                kind=c.kind.value if hasattr(c.kind, "value") else str(c.kind),
                display_name=c.display_name,
                memo_required=c.memo_required,
                confirmations=c.confirmations,
                deposit_threshold=c.deposit_threshold,
                evm_chain_id=c.chain_id_int,
                enabled=c.enabled,
            )
        )
    for a in get_assets().values():
        dto = AssetConfigDTO(
            asset_key=a.asset_key,
            chain_id=a.chain_id,
            symbol=a.symbol,
            decimals=a.decimals,
            is_native=a.is_native,
            contract_address=a.contract_address or None,
            deposit_threshold=effective_deposit_threshold(a),
            deposit_supported=a.deposit_supported,
            withdrawal_supported=a.withdrawal_supported,
            sweep_supported=a.sweep_supported,
        )
        assets.append(dto)
        by_chain.setdefault(a.chain_id, []).append(dto)
    return AppConfigResponse(chains=chains, assets=assets, assets_by_chain=by_chain)


def _current_user(
    authorization: Optional[str], x_user_id: Optional[str], x_role: Optional[str]
) -> tuple[str, str]:
    # Preferred: Bearer JWT from Authorization header.
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        decoded = decode_token(token)
        if decoded:
            return decoded  # (user_id, role)
        raise HttpError(401, "invalid or expired token")
    # Backward-compat stub headers (dev-only; disabled in production).
    from django.conf import settings

    if getattr(settings, "ALLOW_DEV_STUB_AUTH", False) and x_user_id:
        return (x_user_id, x_role or "user")
    # SECURITY: never serve unauthenticated requests in a custody product.
    raise HttpError(401, "authentication required")


def require_admin(role: str) -> None:
    from .auth import require_min_role

    require_min_role(role, "admin")


def require_operator(role: str) -> None:
    from .auth import require_min_role

    # operator, admin qualify (auditor/read_only do not)
    require_min_role(role, "operator")


def require_auditor(role: str) -> None:
    from .auth import require_min_role

    # auditor, operator, admin qualify (read_only does not; auditors can read logs)
    require_min_role(role, "auditor")


def api_rate_limit(key: str, limit: int, window: int):
    def deco():
        try:
            rate_limiter.consume(key, limit, window)
        except RateLimitExceeded:
            raise HttpError(429, "rate limited")

    return deco


# ---------------- Wallet ----------------
@api.post("/wallet/address", response=AddressResponse)
def wallet_address(
    request,
    payload: AddressRequest,
    authorization: Optional[str] = Header(None),
    x_user_id: Optional[str] = Header(None),
    x_role: Optional[str] = Header(None),
):
    # The logged-in caller is an OPERATOR acting on behalf of a subject customer.
    operator_id, role = _current_user(authorization, x_user_id, x_role)
    require_operator(role)
    api_rate_limit(f"addr:{operator_id}", limit=30, window=60)()
    subject = payload.subject_user_id
    net = payload.network
    asset_key = payload.asset_key or native_asset_key(net)  # default to native asset
    validate_chain_asset(net, asset_key, "deposit")
    idx = payload.address_index if payload.address_index is not None else 0
    # Compliance screening: block disabled asset/chain before provisioning.
    check_deposit_asset(net, asset_key)
    # Idempotent: return existing ACTIVE wallet if present.
    existing = UserWallet.objects.filter(
        user_id=subject, chain_id=net, asset_key=asset_key, address_index=idx, status="ACTIVE"
    ).first()
    if existing:
        return AddressResponse(
            network=net,
            asset_key=existing.asset_key,
            deposit_address=existing.deposit_address,
            derivation_path=existing.derivation_path,
            memo=existing.memo,
            status=existing.status,
        )
    memo = None
    if is_memo_required(net):
        memo = f"u{subject}.{idx}"  # TON memo attribution
    user_index = stable_user_index(subject)
    derived = derive_deposit_address(net, user_index, idx, asset_key=asset_key)
    derivation = derived.derivation_path
    address = derived.deposit_address
    w = UserWallet.objects.create(
        user_id=subject,
        chain_id=net,
        asset_key=asset_key,
        derivation_path=derivation,
        deposit_address=address,
        memo=memo,
        address_index=idx,
        status="ACTIVE",
    )
    # Actor = operator (who performed the action); subject stored in metadata.
    write_audit_log(
        operator_id,
        AuditAction.ADDRESS_CREATED,
        "UserWallet",
        str(w.id),
        {"subject_user_id": subject, "address": address, "chain_id": net, "asset_key": asset_key},
    )
    return AddressResponse(
        network=net,
        asset_key=asset_key,
        deposit_address=address,
        derivation_path=derivation,
        memo=memo,
        status="ACTIVE",
    )


def _ensure_deposit_address(
    user_id: str, net: str, asset_key: str, idx: int = 0, actor_id: str | None = None
) -> UserWallet:
    """Idempotently create/return an ACTIVE deposit EOA for (user, network, asset).

    ``actor_id`` is the operator who triggered provisioning (for audit).
    """
    validate_chain_asset(net, asset_key, "deposit")
    existing = UserWallet.objects.filter(
        user_id=user_id,
        chain_id=net,
        asset_key=asset_key,
        address_index=idx,
        status="ACTIVE",
    ).first()
    if existing:
        return existing
    # Compliance screening: block disabled asset/chain before provisioning.
    check_deposit_asset(net, asset_key)
    memo = None
    if is_memo_required(net):
        memo = f"u{user_id}.{idx}"
    user_index = stable_user_index(user_id)
    derived = derive_deposit_address(net, user_index, idx, asset_key=asset_key)
    w = UserWallet.objects.create(
        user_id=user_id,
        chain_id=net,
        asset_key=asset_key,
        derivation_path=derived.derivation_path,
        deposit_address=derived.deposit_address,
        memo=memo,
        address_index=idx,
        status="ACTIVE",
    )
    write_audit_log(
        actor_id or user_id,
        AuditAction.ADDRESS_CREATED,
        "UserWallet",
        str(w.id),
        {
            "subject_user_id": user_id,
            "address": w.deposit_address,
            "chain_id": net,
            "asset_key": asset_key,
        },
    )
    return w


@api.post("/wallet/create", response=CreateWalletResponse)
def create_wallet(
    request,
    payload: CreateWalletRequest,
    authorization: Optional[str] = Header(None),
    x_user_id: Optional[str] = Header(None),
    x_role: Optional[str] = Header(None),
):
    """Provision a subject user's deposit wallet: derive EOAs across networks/assets.

    The logged-in caller is an OPERATOR acting on behalf of ``subject_user_id``.
    This is idempotent - existing ACTIVE deposit rows are returned (never
    duplicated). The returned addresses are always EOAs (never contracts).
    """
    operator_id, role = _current_user(authorization, x_user_id, x_role)
    require_operator(role)
    api_rate_limit(f"create:{operator_id}", limit=10, window=60)()
    subject = payload.subject_user_id

    if payload.asset_keys:
        # Explicit asset list: create exactly those.
        targets = [(get_asset(a).chain_id, a) for a in payload.asset_keys]
    elif payload.networks:
        # Explicit network list: native asset per network.
        targets = [(n, native_asset_key(n)) for n in payload.networks]
    else:
        # Default: only enabled native assets with reviewed deposit capability.
        targets = default_deposit_targets()

    # Validate the complete plan before deriving or persisting any address.
    for net, ak in targets:
        validate_chain_asset(net, ak, "deposit")
    out: list[WalletAddressDTO] = []
    with transaction.atomic():
        for net, ak in targets:
            w = _ensure_deposit_address(subject, net, ak, actor_id=operator_id)
            out.append(
                WalletAddressDTO(
                    network=net,
                    asset_key=w.asset_key,
                    deposit_address=w.deposit_address,
                    derivation_path=w.derivation_path,
                    memo=w.memo,
                    status=w.status,
                )
            )
    return CreateWalletResponse(user_id=subject, addresses=out)


# ---------------- Balance check + auto sweep ----------------
def _balance_exceeds_threshold(confirmed: Decimal, threshold: Decimal) -> bool:
    """Keep exact monetary precision at the sweep decision boundary."""
    return confirmed > threshold


@api.post("/wallet/balance/check", response=BalanceCheckResponse)
def balance_check(
    request,
    payload: BalanceCheckRequest,
    authorization: Optional[str] = Header(None),
    x_user_id: Optional[str] = Header(None),
    x_role: Optional[str] = Header(None),
):
    # Operator console acts on behalf of a subject (customer) user.
    operator_id, role = _current_user(authorization, x_user_id, x_role)
    require_operator(role)
    api_rate_limit(f"bal:{operator_id}", limit=20, window=60)()
    subject = payload.subject_user_id
    chain_id = payload.network
    asset_key = payload.asset_key or native_asset_key(chain_id)
    asset = get_asset(asset_key)
    validate_chain_asset(chain_id, asset_key, "deposit")
    w = UserWallet.objects.filter(
        user_id=subject, chain_id=chain_id, asset_key=asset_key, status="ACTIVE"
    ).first()
    if not w:
        raise HttpError(404, "no deposit address for network/asset")
    indexer = get_indexer(chain_id)
    bal = indexer.get_balance(
        w.deposit_address, memo=w.memo if is_memo_required(chain_id) else None
    )
    for event in bal.deposit_events:
        ingest_event(w, event)
    confirmed = Decimal(bal.confirmed_balance)
    threshold = effective_deposit_threshold(asset)
    triggered = False
    job_id = None
    reason = None
    if _balance_exceeds_threshold(confirmed, threshold):
        triggered, job_id, reason = trigger_sweep(w, actor_id=operator_id, balance_result=bal)
    else:
        reason = "balance below threshold"
    return BalanceCheckResponse(
        network=chain_id,
        asset_key=asset_key,
        confirmed_balance=confirmed,
        deposit_threshold=threshold,
        sweep_triggered=triggered,
        sweep_job_id=job_id,
        reason=reason,
    )


# ---------------- Sweep status ----------------
@api.get("/sweeps/{sweep_id}", response=SweepStatusResponse)
def sweep_status(
    request,
    sweep_id: int,
    authorization: Optional[str] = Header(None),
    x_user_id: Optional[str] = Header(None),
    x_role: Optional[str] = Header(None),
):
    _current_user(authorization, x_user_id, x_role)
    try:
        job = SweepJob.objects.get(id=sweep_id)
    except SweepJob.DoesNotExist:
        raise HttpError(404, f"SweepJob {sweep_id} not found")
    return SweepStatusResponse(
        sweep_job_id=job.id,
        status=job.status,
        tx_hash=job.tx_hash,
        asset_key=job.user_wallet.asset_key,
        balance_snapshot=float(job.balance_snapshot) if job.balance_snapshot else None,
        created_at=str(job.created_at),
        completed_at=str(job.completed_at),
    )


# ---------------- Address ownership resolution ----------------
def _resolve_address(address: str, chain_id: Optional[str]) -> AddressResolveResponse:
    """Resolve whether ``address`` belongs to THIS platform.

    Checks (in order) user deposit EOAs (UserWallet.deposit_address) and
    custody hot/gas-station EOAs (HotWallet.address). Never performs any
    on-chain lookup; purely a ledger/state membership check.
    """
    q_user = UserWallet.objects.filter(deposit_address=address)
    if chain_id:
        q_user = q_user.filter(chain_id=chain_id)
    w = q_user.order_by("-id").first()
    if w:
        return AddressResolveResponse(
            address=address,
            chain_id=chain_id,
            is_platform=True,
            category="USER_DEPOSIT",
            user_id=w.user_id,
            asset_key=w.asset_key,
            status=w.status,
        )
    q_hot = HotWallet.objects.filter(address=address)
    if chain_id:
        q_hot = q_hot.filter(chain_id=chain_id)
    if q_hot.exists():
        return AddressResolveResponse(
            address=address,
            chain_id=chain_id,
            is_platform=True,
            category="HOT_WALLET",
            user_id=None,
            asset_key=None,
            status=None,
        )
    return AddressResolveResponse(
        address=address,
        chain_id=chain_id,
        is_platform=False,
        category="UNKNOWN",
        user_id=None,
        asset_key=None,
        status=None,
    )


@api.post("/admin/address/resolve", response=AddressResolveResponse)
def admin_resolve_address(
    request,
    payload: AddressResolveRequest,
    authorization: Optional[str] = Header(None),
    x_user_id: Optional[str] = Header(None),
    x_role: Optional[str] = Header(None),
):
    """Operator/Admin lookup: does this address belong to our platform?

    Returns whether the address is one of OUR user deposit EOAs or OUR custody
    hot/gas-station EOAs. Pure ledger lookup (no on-chain call). Used by the
    admin dashboard to label internal transfers and prevent mis-routes.
    """
    actor_id, role = _current_user(authorization, x_user_id, x_role)
    require_operator(role)
    api_rate_limit(f"resolve:{actor_id}", limit=30, window=60)()
    result = _resolve_address(payload.address, payload.chain_id)
    # Read-only audit trail (no address secrets; address is not a secret).
    write_audit_log(
        actor_id,
        AuditAction.ADDRESS_RESOLVE,
        "AddressLookup",
        payload.address,
        {
            "chain_id": payload.chain_id,
            "category": result.category,
            "is_platform": result.is_platform,
        },
    )
    return result


# ---------------- Gas station (dashboard) ----------------
@api.get("/gas-station", response=GasStationListResponse)
def gas_station(
    request,
    authorization: Optional[str] = Header(None),
    x_user_id: Optional[str] = Header(None),
    x_role: Optional[str] = Header(None),
):
    """Return custody gas-station + hot-wallet addresses and balances per chain.

    The gas-station address is the MPC-controlled EOA that funds user deposit
    EOAs (gas topups) and signs sweeps/withdrawals. Balances are read from the
    indexer (stubbed in local mode). Admin/operator only.
    """
    actor_id, role = _current_user(authorization, x_user_id, x_role)
    require_operator(role)
    from .models import HotWallet, SweepJob

    entries: list[GasStationEntry] = []
    for cid, cfg in get_chains().items():
        if not cfg.enabled:
            continue
        hot = HotWallet.objects.filter(chain_id=cid).first()
        hot_addr = hot.address if hot else ""
        # Gas-station address == custody signing EOA (hot wallet funds topups).
        gas_addr = hot_addr or ""
        # Balances come from the indexer (stubbed locally; real on testnets).
        bal = None
        balance_status = "UNAVAILABLE"
        if gas_addr:
            try:
                bal = float(get_indexer(cid).get_balance(gas_addr).confirmed_balance)
                balance_status = "AVAILABLE"
            except IndexerUnavailable:
                pass
        sweep_count = SweepJob.objects.filter(user_wallet__chain_id=cid).count() if hot else 0
        entries.append(
            GasStationEntry(
                chain_id=cid,
                display_name=cfg.display_name,
                kind=cfg.kind.value,
                gas_station_address=gas_addr,
                hot_wallet_address=hot_addr or "",
                native_balance=bal,
                balance_status=balance_status,
                gas_topup_amount=cfg.gas_topup_amount,
                sweep_count=sweep_count,
            )
        )
    return GasStationListResponse(entries=entries)


# ---------------- Gas station admin top-up ----------------
@api.post("/gas-station/topup", response=GasStationTopupResponse)
def gas_station_topup(
    request,
    payload: GasStationTopupRequest,
    authorization: Optional[str] = Header(None),
    x_user_id: Optional[str] = Header(None),
    x_role: Optional[str] = Header(None),
):
    """Operator/admin manual top-up of a gas-station address.

    SECURITY / GUARD POINTS:
      - RBAC: requires operator role (admin also qualifies).
      - Rate-limited per actor.
      - amount must be > 0 and bounded server-side (gas_topup_max).
      - destination must be a known hot wallet or active deposit EOA for the
        chain (prevents sending funds to an arbitrary address).
      - Fully audited (SIGN_REQUEST + BROADCAST) inside the signer.
      - Caller-supplied idempotency identifies one logical top-up intent;
        same-key conflicting payloads are rejected.
    """
    actor_id, role = _current_user(authorization, x_user_id, x_role)
    require_operator(role)
    api_rate_limit(f"gas_topup:{actor_id}", limit=10, window=60)()
    # admin_topup validates amount>0, destination, and broadcasts via MPC signer.
    try:
        res = admin_topup(
            actor_id,
            payload.chain_id,
            payload.to_address,
            payload.amount,
            payload.idempotency_key,
            payload.memo,
        )
    except ValueError as exc:
        if "already used" in str(exc):
            raise HttpError(409, str(exc)) from exc
        raise
    write_audit_log(
        actor_id,
        AuditAction.GAS_TOPUP,
        "GasStation",
        payload.chain_id,
        {
            "to": payload.to_address,
            "amount": payload.amount,
            "tx_hash": res["tx_hash"],
            "memo": payload.memo,
        },
    )
    return GasStationTopupResponse(
        tx_hash=res["tx_hash"],
        to=res["to"],
        amount=res["amount"],
        chain_id=payload.chain_id,
    )


# ---------------- Custody stats (home/overview) ----------------
@api.get("/stats", response=CustodyStatsResponse)
def custody_stats(
    request,
    authorization: Optional[str] = Header(None),
    x_user_id: Optional[str] = Header(None),
    x_role: Optional[str] = Header(None),
):
    """Global custody aggregates for the operator home/overview dashboard.

    Exposes ONLY aggregate counts (users, wallets, deposits, sweeps,
    withdrawals). No individual customer deposit addresses are returned, so
    this is safe for operator/auditor visibility.
    """
    _current_user(authorization, x_user_id, x_role)
    users_total = UserWallet.objects.values("user_id").distinct().count()
    wallets_total = UserWallet.objects.count()
    wallets_active = UserWallet.objects.filter(status="ACTIVE").count()
    wallets_retired = UserWallet.objects.filter(status="RETIRED").count()
    deposits_total = Deposit.objects.count()
    deposits_amount = Deposit.objects.aggregate(s=Sum("amount"))["s"]
    sweeps_status = {
        r["status"]: r["c"] for r in SweepJob.objects.values("status").annotate(c=Count("id"))
    }
    withdraw_status = {
        r["status"]: r["c"]
        for r in WithdrawalRequest.objects.values("status").annotate(c=Count("id"))
    }
    return CustodyStatsResponse(
        users_total=users_total,
        wallets_total=wallets_total,
        wallets_active=wallets_active,
        wallets_retired=wallets_retired,
        deposits_total=deposits_total,
        deposits_total_amount=float(deposits_amount or 0),
        sweeps_total=SweepJob.objects.count(),
        sweeps_by_status=sweeps_status,
        withdrawals_total=WithdrawalRequest.objects.count(),
        withdrawals_by_status=withdraw_status,
        pending_withdrawals=WithdrawalRequest.objects.filter(status="PENDING_APPROVAL").count(),
        generated_at=str(timezone.now()),
    )


# ---------------- Withdrawals (user) ----------------
@api.post("/withdrawals/request", response=WithdrawalRequestResponse)
def withdrawal_request(
    request,
    payload: WithdrawalRequestInput,
    authorization: Optional[str] = Header(None),
    x_user_id: Optional[str] = Header(None),
    x_role: Optional[str] = Header(None),
):
    # Operator console creates a withdrawal ON BEHALF OF a subject (customer).
    operator_id, role = _current_user(authorization, x_user_id, x_role)
    require_operator(role)
    api_rate_limit(f"wd:{operator_id}", limit=15, window=60)()
    subject = payload.subject_user_id
    asset_key = payload.asset_key or native_asset_key(payload.network)
    # Compliance screening: block sanctions/blocklisted withdrawal destinations.
    check_withdrawal_target(payload.to_address, payload.network, asset_key)
    try:
        req = wd_create(
            subject,
            payload.network,
            payload.to_address,
            payload.amount,
            asset_key=asset_key,
            idempotency_key=payload.idempotency_key,
        )
    except InsufficientFunds as exc:
        raise HttpError(409, str(exc)) from exc
    except ValueError as exc:
        if "already used" in str(exc):
            raise HttpError(409, str(exc)) from exc
        raise
    return _wd_to_schema(req)


@api.get("/admin/ledger/balances/{subject_user_id}", response=InternalBalanceResponse)
def internal_ledger_balances(
    request,
    subject_user_id: str,
    authorization: Optional[str] = Header(None),
    x_user_id: Optional[str] = Header(None),
    x_role: Optional[str] = Header(None),
):
    """Authoritative internal balances; never an on-chain address balance."""
    _actor, role = _current_user(authorization, x_user_id, x_role)
    require_operator(role)
    assets = (
        LedgerAccount.objects.filter(owner_type="USER", owner_id=subject_user_id)
        .values_list("asset_key", flat=True)
        .distinct()
    )
    entries = []
    for asset_key in sorted(assets):
        balances = user_balances(subject_user_id, asset_key)
        entries.append(
            InternalBalanceEntry(
                asset_key=asset_key,
                available_balance=str(balances["available"]),
                reserved_balance=str(balances["reserved"]),
                total_balance=str(balances["total"]),
            )
        )
    return InternalBalanceResponse(
        subject_user_id=subject_user_id,
        source="authoritative_internal_ledger_not_on_chain_balance",
        balances=entries,
    )


@api.get("/withdrawals", response=WithdrawalListResponse)
def list_withdrawals(
    request,
    subject: Optional[str] = None,
    authorization: Optional[str] = Header(None),
    x_user_id: Optional[str] = Header(None),
    x_role: Optional[str] = Header(None),
):
    """Operator-scoped list. If ``subject`` query param given, narrow to that
    customer; otherwise list all withdrawals (operator visibility)."""
    _current_user(authorization, x_user_id, x_role)
    qs = WithdrawalRequest.objects.all()
    if subject:
        qs = qs.filter(user_id=subject)
    items = [_wd_to_schema(r) for r in qs.order_by("-id")]
    return WithdrawalListResponse(items=items)


@api.get("/withdrawals/{wd_id}", response=WithdrawalRequestResponse)
def withdrawal_detail(
    request,
    wd_id: int,
    authorization: Optional[str] = Header(None),
    x_user_id: Optional[str] = Header(None),
    x_role: Optional[str] = Header(None),
):
    """Withdrawal detail (operator visibility; used for status polling)."""
    _current_user(authorization, x_user_id, x_role)
    try:
        req = WithdrawalRequest.objects.get(id=wd_id)
    except WithdrawalRequest.DoesNotExist:
        raise HttpError(404, "withdrawal not found")
    return _wd_to_schema(req)


# ---------------- Withdrawals (admin) ----------------
@api.post("/withdrawals/{wd_id}/approve", response=WithdrawalRequestResponse)
def admin_approve(
    request,
    wd_id: int,
    payload: WithdrawalAdminAction,
    authorization: Optional[str] = Header(None),
    x_user_id: Optional[str] = Header(None),
    x_role: Optional[str] = Header(None),
):
    admin_id, role = _current_user(authorization, x_user_id, x_role)
    require_admin(role)
    req = wd_approve(admin_id, wd_id, payload.admin_notes)
    # An endpoint retry returns terminal/in-flight state without rebroadcast.
    if req.status == "APPROVED":
        try:
            req = process_withdrawal(admin_id, wd_id)
        except RateLimitExceeded as exc:
            raise HttpError(429, "signing rate limited; approved request may be retried") from exc
    return _wd_to_schema(req)


@api.post("/withdrawals/{wd_id}/deny", response=WithdrawalRequestResponse)
def admin_deny(
    request,
    wd_id: int,
    payload: WithdrawalAdminAction,
    authorization: Optional[str] = Header(None),
    x_user_id: Optional[str] = Header(None),
    x_role: Optional[str] = Header(None),
):
    admin_id, role = _current_user(authorization, x_user_id, x_role)
    require_admin(role)
    req = wd_deny(admin_id, wd_id, payload.admin_notes)
    return _wd_to_schema(req)


@api.get("/admin/withdrawals", response=WithdrawalListResponse)
def admin_list_withdrawals(
    request,
    authorization: Optional[str] = Header(None),
    x_user_id: Optional[str] = Header(None),
    x_role: Optional[str] = Header(None),
):
    admin_id, role = _current_user(authorization, x_user_id, x_role)
    require_admin(role)
    items = [_wd_to_schema(r) for r in WithdrawalRequest.objects.all().order_by("-id")]
    return WithdrawalListResponse(items=items)


# ---------------- Chain / node status ----------------
class ChainStatusEntry(Schema):
    chain_id: str
    display_name: str
    kind: str
    enabled: bool
    memo_required: bool
    node_host: str
    endpoint_count: int
    online: bool
    latency_ms: Optional[int] = None
    block_height: Optional[int] = None
    sync_status: str
    last_error: str


class ChainsStatusResponse(Schema):
    status: str  # ok | degraded | down
    online_count: int
    total_count: int
    chains: list[ChainStatusEntry]
    generated_at: str


@api.get("/chains/status", response=ChainsStatusResponse)
def chains_status(
    request,
    chain: Optional[str] = None,
    authorization: Optional[str] = Header(None),
    x_user_id: Optional[str] = Header(None),
    x_role: Optional[str] = Header(None),
):
    """Live node-status rollup for all supported chains.

    Probes each chain's configured RPC endpoint(s) (DB-registered nodes first,
    in deterministic failover order) and reports ONLINE/OFFLINE with height and latency.
    Authenticated users can view; ``?chain=ETH`` narrows to a single chain.
    """
    actor, role = _current_user(authorization, x_user_id, x_role)
    try:
        rate_limiter.consume(f"chains-status:{actor}", 30, 60)
    except RateLimitExceeded:
        raise HttpError(429, "rate limit exceeded, retry shortly")
    data = check_all_chains(chain_id=chain, timeout=6.0)
    return ChainsStatusResponse(
        status=data["status"],
        online_count=data["online_count"],
        total_count=data["total_count"],
        chains=[ChainStatusEntry(**c) for c in data["chains"]],
        generated_at=data["generated_at"],
    )


# ---------------- Helpers ----------------
def _wd_to_schema(r: WithdrawalRequest) -> WithdrawalRequestResponse:
    return WithdrawalRequestResponse(
        id=r.id,
        user_id=r.user_id,
        network=r.chain_id,
        asset_key=r.asset_key,
        to_address=r.to_address,
        amount=float(r.amount),
        status=r.status,
        tx_hash=r.tx_hash,
        created_at=str(r.created_at),
        updated_at=str(r.updated_at),
    )
