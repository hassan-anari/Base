"""Authoritative, uncached runtime view of the operator chain registry."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum


class ChainKind(StrEnum):
    EVM = "evm"
    TRON = "tron"
    SOLANA = "solana"
    TON = "ton"


class ChainRegistryError(RuntimeError):
    """Base class for fail-closed chain resolution failures."""


class UnknownChain(ChainRegistryError):
    pass


class ChainDisabled(ChainRegistryError):
    pass


class UnsupportedChainKind(ChainRegistryError):
    pass


class ChainUnavailable(ChainRegistryError):
    """The chain is configured but has no usable runtime infrastructure."""


@dataclass(frozen=True)
class ChainSpec:
    chain_id: str
    kind: ChainKind
    display_name: str
    enabled: bool
    is_testnet: bool
    native_asset_key: str
    native_decimals: int
    evm_chain_id: int | None
    confirmations: int
    sweep_threshold: Decimal
    memo_required: bool
    explorer_tx_url: str
    explorer_address_url: str
    gas_settings: dict

    @property
    def deposit_threshold(self) -> Decimal:
        return self.sweep_threshold

    @property
    def chain_id_int(self) -> int | None:
        return self.evm_chain_id

    @property
    def gas_topup_amount(self) -> Decimal:
        return Decimal(str(self.gas_settings.get("topup_amount", "0")))


def get_chain_spec(chain_id: str, *, require_enabled: bool = True) -> ChainSpec:
    """Read a fresh ChainSpec from DB; bootstrap constants are never a fallback."""
    from ops.models import Chain

    from .models import Asset

    canonical = str(chain_id).strip().upper()
    try:
        row = Chain.objects.get(chain_id=canonical)
    except Chain.DoesNotExist as exc:
        raise UnknownChain(f"unknown runtime chain {canonical!r}") from exc
    if require_enabled and not row.enabled:
        raise ChainDisabled(f"runtime chain {canonical!r} is disabled")
    try:
        kind = ChainKind(row.kind)
    except ValueError as exc:
        raise UnsupportedChainKind(f"unsupported chain kind {row.kind!r}") from exc
    try:
        native = Asset.objects.get(
            asset_key=row.native_asset_key, chain_id=canonical, is_native=True, enabled=True
        )
    except Asset.DoesNotExist as exc:
        raise ChainUnavailable(
            f"enabled native custody asset {row.native_asset_key!r} is unavailable for {canonical}"
        ) from exc
    return ChainSpec(
        chain_id=canonical,
        kind=kind,
        display_name=row.display_name,
        enabled=row.enabled,
        is_testnet=row.is_testnet,
        native_asset_key=row.native_asset_key,
        native_decimals=native.decimals,
        evm_chain_id=row.evm_chain_id,
        confirmations=row.min_confirmations,
        sweep_threshold=Decimal(row.sweep_threshold),
        memo_required=row.memo_required,
        explorer_tx_url=row.explorer_tx_url,
        explorer_address_url=row.explorer_address_url,
        gas_settings=dict(row.gas_settings),
    )


def rpc_urls(chain_id: str) -> list[str]:
    """Return enabled DB RPC endpoints in deterministic failover order."""
    spec = get_chain_spec(chain_id)
    from ops.models import NodeEndpoint

    rows = NodeEndpoint.objects.filter(chain_id=spec.chain_id, kind="rpc", enabled=True).order_by(
        "-is_primary", "priority", "name", "id"
    )
    urls = [row.url for row in rows if row.url]
    if not urls:
        raise ChainUnavailable(f"no enabled RPC endpoint configured for {spec.chain_id}")
    return urls
