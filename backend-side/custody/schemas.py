"""
Ninja / Pydantic DTO schemas for the REST API.

Typed request/response models used by custody/api.py. Validation is enforced
at the boundary (Ninja/Pydantic) before any business logic runs.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Optional

from ninja import Schema
from pydantic import Field, field_validator, model_validator

from .chain_registry import ChainRegistryError
from .config import chain_ids, get_asset, native_asset_key, validate_chain_asset


def _validated_native_asset_key(chain_id: str) -> str:
    """Translate fail-closed registry errors into an API validation error."""
    try:
        return native_asset_key(chain_id)
    except ChainRegistryError as exc:
        raise ValueError(str(exc)) from exc


# ---------------- Wallet ----------------
class AddressRequest(Schema):
    # The operator console acts ON BEHALF OF a subject (customer) user.
    subject_user_id: str = Field(
        min_length=1, description="customer user the operator is servicing"
    )
    # chain_id selects the chain/network; asset_key selects native or a token
    # (e.g. "ETH" or "USDT-BSC"). Defaults to the chain's native asset.
    network: str = Field(description="chain id, e.g. ETH/BSC/TRX/SOL/TON")
    asset_key: Optional[str] = None
    # Optional explicit address index for rotation; defaults to next available.
    address_index: Optional[int] = None

    @model_validator(mode="after")
    def _check_chain(self):
        validate_chain_asset(
            self.network, self.asset_key or _validated_native_asset_key(self.network), "deposit"
        )
        return self


class AddressResponse(Schema):
    network: str
    asset_key: str
    deposit_address: str  # EOA
    derivation_path: str
    memo: Optional[str] = None
    asset_account_address: Optional[str] = None
    status: str


class WalletAddressDTO(Schema):
    """A single derived deposit EOA for one (network, asset)."""

    network: str
    asset_key: str
    deposit_address: str  # EOA
    derivation_path: str
    memo: Optional[str] = None
    asset_account_address: Optional[str] = None
    status: str


class CreateWalletRequest(Schema):
    """Provision a subject user's deposit wallet across one or more networks/assets.

    The operator console acts ON BEHALF OF ``subject_user_id`` (a customer).
    If ``networks`` is omitted, the wallet is created for every enabled chain
    using its native asset. ``asset_keys`` narrows the assets created (when
    provided, each entry selects a specific token/native asset on its chain).
    Idempotent: existing ACTIVE deposit rows are returned, not duplicated.
    """

    subject_user_id: str = Field(
        min_length=1, description="customer user the operator is servicing"
    )
    networks: Optional[list[str]] = None
    asset_keys: Optional[list[str]] = None

    @model_validator(mode="after")
    def _check(self):
        if self.networks:
            for n in self.networks:
                validate_chain_asset(n, _validated_native_asset_key(n), "deposit")
        if self.asset_keys:
            for a in self.asset_keys:
                try:
                    asset = get_asset(a)
                except KeyError as exc:
                    raise ValueError(f"unknown asset {a}") from exc
                validate_chain_asset(asset.chain_id, a, "deposit")
        return self


class CreateWalletResponse(Schema):
    user_id: str
    addresses: list[WalletAddressDTO]


# ---------------- Balance check / sweep trigger ----------------
class BalanceCheckRequest(Schema):
    # Operator console acts on behalf of a subject (customer) user.
    subject_user_id: str = Field(
        min_length=1, description="customer user the operator is servicing"
    )
    network: str
    asset_key: Optional[str] = None

    @model_validator(mode="after")
    def _check_asset(self):
        validate_chain_asset(
            self.network, self.asset_key or _validated_native_asset_key(self.network), "deposit"
        )
        return self


class BalanceCheckResponse(Schema):
    network: str
    asset_key: str
    confirmed_balance: float
    deposit_threshold: float
    sweep_triggered: bool
    sweep_job_id: Optional[int] = None
    reason: Optional[str] = None


# ---------------- Sweep status ----------------
class SweepStatusResponse(Schema):
    sweep_job_id: int
    status: str
    asset_key: str
    tx_hash: Optional[str] = None
    balance_snapshot: Optional[float] = None
    created_at: Optional[str] = None
    completed_at: Optional[str] = None


# ---------------- Withdrawals ----------------
class WithdrawalRequestInput(Schema):
    # Operator console creates a withdrawal ON BEHALF OF a subject (customer) user.
    subject_user_id: str = Field(
        min_length=1, description="customer user the operator is servicing"
    )
    network: str
    asset_key: Optional[str] = None
    to_address: str = Field(min_length=1, max_length=128)
    amount: Decimal = Field(gt=0)
    idempotency_key: str = Field(min_length=8, max_length=64)

    @field_validator("amount")
    @classmethod
    def _positive(cls, v: Decimal) -> Decimal:
        if v <= 0:
            raise ValueError("amount must be > 0")
        return v

    @model_validator(mode="after")
    def _check_asset(self):
        ak = self.asset_key or _validated_native_asset_key(self.network)
        validate_chain_asset(self.network, ak, "withdrawal")
        return self


class WithdrawalRequestResponse(Schema):
    id: int
    user_id: str
    network: str
    asset_key: str
    to_address: str
    amount: float
    status: str
    tx_hash: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class WithdrawalAdminAction(Schema):
    admin_notes: Optional[str] = None


class WithdrawalListResponse(Schema):
    items: list[WithdrawalRequestResponse]


class InternalBalanceEntry(Schema):
    asset_key: str
    available_balance: str
    reserved_balance: str
    total_balance: str


class InternalBalanceResponse(Schema):
    subject_user_id: str
    source: str
    balances: list[InternalBalanceEntry]


# ---------------- Gas station ----------------
class GasStationEntry(Schema):
    chain_id: str
    display_name: str
    kind: str
    gas_station_address: str  # MPC-controlled EOA that pays gas/topups
    hot_wallet_address: str  # sweep/withdrawal target (also an EOA)
    native_balance: Optional[float]  # null when infrastructure is unavailable
    balance_status: str  # AVAILABLE | UNAVAILABLE
    gas_topup_amount: float  # per-topup grant configured
    sweep_count: int  # number of sweeps funded from this station
    last_topup_at: Optional[str] = None


class GasStationListResponse(Schema):
    entries: list[GasStationEntry]


# ---------------- Gas station admin top-up ----------------
class GasStationTopupRequest(Schema):
    """Operator/admin manual top-up of a gas-station address.

    SECURITY: amount is bounded server-side (gas_topup_max); destination must be
    a known hot wallet or active deposit EOA for the chain. Fully audited.
    """

    chain_id: str = Field(description="chain id, e.g. ETH/BSC/TRX/SOL/TON")
    to_address: str = Field(
        min_length=1, max_length=128, description="destination EOA (hot wallet or deposit EOA)"
    )
    amount: float = Field(gt=0, description="top-up amount in native asset")
    idempotency_key: str = Field(min_length=8, max_length=64)
    memo: Optional[str] = Field(None, description="TON memo attribution (if required)")

    @model_validator(mode="after")
    def _check_chain(self):
        if self.chain_id not in chain_ids():
            raise ValueError(f"unknown network {self.chain_id}")
        return self


class GasStationTopupResponse(Schema):
    tx_hash: str
    to: str
    amount: float
    chain_id: str


# ---------------- Custody stats (home overview) ----------------
class CustodyStatsResponse(Schema):
    """Global custody aggregates for the operator home/overview dashboard.

    Aggregates ONLY (no individual customer deposit addresses are exposed).
    """

    users_total: int
    wallets_total: int
    wallets_active: int
    wallets_retired: int
    deposits_total: int
    deposits_total_amount: float
    sweeps_total: int
    sweeps_by_status: dict[str, int]
    withdrawals_total: int
    withdrawals_by_status: dict[str, int]
    pending_withdrawals: int
    generated_at: str


# ---------------- Address resolution (platform ownership) ----------------
class AddressResolveRequest(Schema):
    address: str  # the address to check
    chain_id: Optional[str] = None  # optional network scope


class AddressResolveResponse(Schema):
    """Tells the operator whether an address belongs to THIS platform.

    ``is_platform`` is True if the address matches a platform-controlled EOA:
      - a user deposit EOA (UserWallet.deposit_address), or
      - a custody hot/gas-station EOA (HotWallet.address).
    ``category`` disambiguates the role. This is a read-only lookup used by
    the admin dashboard to confirm a counterparty address is ours before
    acting (e.g. labelling internal transfers, preventing mis-routes).
    """

    address: str
    chain_id: Optional[str] = None
    is_platform: bool
    category: str  # USER_DEPOSIT | HOT_WALLET | UNKNOWN
    user_id: Optional[str] = None  # populated when category==USER_DEPOSIT
    asset_key: Optional[str] = None
    status: Optional[str] = None  # ACTIVE/RETIRED for user deposits


# ---------------- Generic errors ----------------
class ErrorResponse(Schema):
    detail: str
    code: Optional[str] = None
