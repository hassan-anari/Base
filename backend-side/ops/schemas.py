"""Pydantic/Ninja DTOs for the ops platform."""
from __future__ import annotations

from typing import Optional

from ninja import Schema


# ---- Chain / Asset registry ----
class ChainDTO(Schema):
    chain_id: str
    display_name: str
    kind: str
    native_asset_key: str
    evm_chain_id: Optional[int]
    is_testnet: bool
    min_confirmations: int
    sweep_threshold: float
    memo_required: bool
    enabled: bool


class AssetDTO(Schema):
    asset_key: str
    chain_id: str
    symbol: str
    name: str = ""
    contract_address: str = ""
    decimals: int
    is_native: bool
    deposit_threshold: float
    withdraw_enabled: bool
    enabled: bool


class AddAssetRequest(Schema):
    asset_key: str
    chain_id: str
    symbol: str
    name: str = ""
    contract_address: str = ""
    decimals: int = 18
    is_native: bool = False
    deposit_threshold: str = "0.0"
    withdraw_enabled: bool = True


class AddNodeRequest(Schema):
    chain_id: str
    name: str
    url: str
    kind: str = "rpc"
    priority: int = 10
    is_primary: bool = False


# ---- Chain create / update ----
class AddChainRequest(Schema):
    chain_id: str
    display_name: str
    kind: str = "evm"
    evm_chain_id: Optional[int] = None
    native_asset_key: str
    is_testnet: bool = True
    min_confirmations: int = 12
    sweep_threshold: str = "0.01"
    memo_required: bool = False
    explorer_tx_url: str = ""
    explorer_address_url: str = ""
    gas_settings: dict = {}
    enabled: bool = True


class ChainUpdateRequest(Schema):
    display_name: Optional[str] = None
    kind: Optional[str] = None
    evm_chain_id: Optional[int] = None
    native_asset_key: Optional[str] = None
    is_testnet: Optional[bool] = None
    min_confirmations: Optional[int] = None
    sweep_threshold: Optional[str] = None
    memo_required: Optional[bool] = None
    explorer_tx_url: Optional[str] = None
    explorer_address_url: Optional[str] = None
    gas_settings: Optional[dict] = None
    enabled: Optional[bool] = None


# ---- Blocklist ----
class BlocklistDTO(Schema):
    id: str
    scope: str
    value: str
    chain_id: str
    asset_key: str
    reason: str
    note: str
    enabled: bool
    created_by: str
    created_at: str


class AddBlocklistRequest(Schema):
    scope: str
    value: str = "-"
    chain_id: str = ""
    asset_key: str = ""
    reason: str = "compliance"
    note: str = ""


class BlocklistUpdateRequest(Schema):
    enabled: Optional[bool] = None
    reason: Optional[str] = None
    note: Optional[str] = None


# ---- Node health ----
class NodeHealthDTO(Schema):
    id: str
    chain_id: str
    name: str
    url: str
    kind: str
    priority: int = 10
    is_primary: bool = False
    enabled: bool = True
    healthy: Optional[bool] = None
    latency_ms: Optional[int] = None
    block_height: Optional[int] = None
    sync_status: str = ""
    last_error: str = ""
    last_checked: Optional[str] = None


class NodeUpdateRequest(Schema):
    """Edit an existing node/RPC endpoint (e.g. rotate RPC URL, reprioritise)."""
    name: Optional[str] = None
    url: Optional[str] = None
    kind: Optional[str] = None
    priority: Optional[int] = None
    is_primary: Optional[bool] = None
    enabled: Optional[bool] = None


# ---- Balances ----
class AddressBalanceDTO(Schema):
    id: int
    chain_id: str
    asset_key: str
    address: str
    owner_type: str
    owner_ref: str
    confirmed_balance: float
    pending_balance: Optional[float]
    source: str
    created_at: str


# ---- Transactions is above (keep ordering) ----
class TransactionDTO(Schema):
    id: int
    tx_type: str
    chain_id: str
    asset_key: str
    tx_hash: str
    from_address: str
    to_address: str
    amount: float
    memo: str
    block: Optional[int]
    confirmations: int
    status: str
    ref_type: str
    ref_id: str
    created_at: str


# ---- Alerts ----
class AlertDTO(Schema):
    id: int
    chain_id: str
    category: str
    severity: str
    title: str
    detail: str
    resolved: bool
    acknowledged_by: Optional[str]
    created_at: str


class AckAlertRequest(Schema):
    note: str = ""


# ---- Operator activity ----
class OperatorActivityDTO(Schema):
    id: int
    actor_id: str
    role: str
    action: str
    target: str
    meta: dict
    created_at: str


# ---- Summary ----
class SummaryDTO(Schema):
    generated_at: str
    # registry
    chains_total: int
    assets_total: int
    nodes_total: int
    nodes_unhealthy: int
    # balances (exchange-owned addresses only; never a user privacy dump)
    balances_total: int
    balances_confirmed_sum: float
    # transactions
    transactions_total: int
    transactions_by_status: dict
    # alerts
    alerts_open: int
    alerts_critical: int
    # operator activity (recent actions)
    activity_recent: int


# ---- Generic ----
class EmptyResponse(Schema):
    ok: bool = True
    message: str = ""