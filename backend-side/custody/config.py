"""
Per-chain + per-asset configuration for the currently implemented adapters.

Why config-driven?
-------------------
A real exchange needs to:
  * support custom EVM chains (Polygon, Arbitrum, Base, Avalanche, your own
    L2, etc.) WITHOUT code changes,
  * support multiple assets per chain (native coin + tokens like USDT, USDC),
  * keep deposit thresholds / confirmation rules per (chain, asset),
  * plug each chain/asset into its indexer + MPC signing adapter.

We achieve this with two registries:

  CHAIN_REGISTRY : chain_id (e.g. "ETH", "BSC", "BASE", "MYL2") -> ChainConfig
  ASSET_REGISTRY : asset_key (e.g. "ETH", "USDT-BSC")          -> AssetConfig

Both are seeded from DEFAULT_* dicts and can be extended at runtime by an
admin (DB-backed `ChainConfig` / `AssetConfig` rows loaded on startup).

No secrets live here. MPC key material never touches Django.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache


class ChainKind(StrEnum):
    EVM = "EVM"  # Ethereum-family (ETH, BSC, custom L2s, ...)
    TRON = "TRON"  # TRX / TRC20
    SOLANA = "SOLANA"  # SOL / SPL
    TON = "TON"  # TON / jetton (memo-attributed)


# Networks that require memo-based attribution of deposits/withdrawals.
MEMO_REQUIRED_KINDS = {ChainKind.TON}


@dataclass(frozen=True)
class ChainConfig:
    chain_id: str  # stable key used in all APIs (e.g. "BASE")
    kind: ChainKind  # determines signing/indexer adapter family
    display_name: str
    rpc_url: str
    hot_wallet_address: str  # custody-controlled MPC hot wallet
    deposit_threshold: float  # min confirmed BALANCE to trigger sweep
    confirmations: int  # finality threshold
    memo_required: bool = False
    # EVM-only extras:
    chain_id_int: int | None = None  # EIP-155 chainId for EVM tx signing
    explorer_url: str = ""
    # Optional gas params for the gas-station top-up:
    gas_topup_amount: float = 0.0
    enabled: bool = True


@dataclass(frozen=True)
class AssetConfig:
    asset_key: str  # "ETH", "USDT-BSC", "USDC-BASE" ...
    chain_id: str  # parent chain
    symbol: str  # "USDT"
    decimals: int = 18
    is_native: bool = False  # True for the chain's gas/native coin
    # ERC-20 / TRC-20 / SPL / jetton contract address. None for native.
    contract_address: str | None = None
    deposit_threshold: float | None = None  # overrides chain default if set
    sweep_dust: float = 0.0  # below this we leave it (dust) on EOA
    enabled: bool = True


# ---------------------------------------------------------------------------
# DEFAULT CHAINS (presets: ETH, BSC, TRX, SOL, TON + example custom EVM)
# ---------------------------------------------------------------------------
def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default)


DEFAULT_CHAINS: dict[str, ChainConfig] = {
    "ETH": ChainConfig(
        chain_id="ETH",
        kind=ChainKind.EVM,
        display_name="Ethereum Sepolia",
        rpc_url=_env("RPC_ETH", "https://rpc.sepolia.org"),
        hot_wallet_address=_env("HOT_WALLET_ETH", ""),
        deposit_threshold=float(_env("DEPOSIT_THRESHOLD_ETH", "0.001")),
        confirmations=int(_env("CONFIRMATIONS_ETH", "12")),
        chain_id_int=11155111,
        gas_topup_amount=0.005,
        explorer_url="https://sepolia.etherscan.io",
    ),
    "BSC": ChainConfig(
        chain_id="BSC",
        kind=ChainKind.EVM,
        display_name="BNB Smart Chain Testnet",
        rpc_url=_env("RPC_BSC", "https://data-seed-prebsc-1-s1.bnbchain.org:8545"),
        hot_wallet_address=_env("HOT_WALLET_BSC", ""),
        deposit_threshold=float(_env("DEPOSIT_THRESHOLD_BSC", "0.001")),
        confirmations=int(_env("CONFIRMATIONS_BSC", "15")),
        chain_id_int=97,
        gas_topup_amount=0.01,
        explorer_url="https://testnet.bscscan.com",
    ),
    "TRX": ChainConfig(
        chain_id="TRX",
        kind=ChainKind.TRON,
        display_name="TRON Shasta",
        rpc_url=_env("RPC_TRX", "https://api.shasta.trongrid.io"),
        hot_wallet_address=_env("HOT_WALLET_TRX", ""),
        deposit_threshold=float(_env("DEPOSIT_THRESHOLD_TRX", "1.0")),
        confirmations=int(_env("CONFIRMATIONS_TRX", "19")),
        gas_topup_amount=5.0,
    ),
    "SOL": ChainConfig(
        chain_id="SOL",
        kind=ChainKind.SOLANA,
        display_name="Solana Devnet",
        rpc_url=_env("RPC_SOL", "https://api.devnet.solana.com"),
        hot_wallet_address=_env("HOT_WALLET_SOL", ""),
        deposit_threshold=float(_env("DEPOSIT_THRESHOLD_SOL", "0.01")),
        confirmations=int(_env("CONFIRMATIONS_SOL", "32")),
        gas_topup_amount=0.02,
    ),
    "TON": ChainConfig(
        chain_id="TON",
        kind=ChainKind.TON,
        display_name="TON Testnet",
        rpc_url=_env("RPC_TON", "https://testnet.toncenter.com/api/v2/jsonRPC"),
        hot_wallet_address=_env("HOT_WALLET_TON", ""),
        deposit_threshold=float(_env("DEPOSIT_THRESHOLD_TON", "0.1")),
        confirmations=int(_env("CONFIRMATIONS_TON", "5")),
        memo_required=True,
        gas_topup_amount=0.1,
    ),
    # Example CUSTOM EVM chain added via config only (no code change needed):
    # "BASE": ChainConfig(
    #     chain_id="BASE", kind=ChainKind.EVM, display_name="Base Sepolia",
    #     rpc_url=_env("RPC_BASE", "https://sepolia.base.org"),
    #     hot_wallet_address=_env("HOT_WALLET_BASE", ""),
    #     deposit_threshold=0.001, confirmations=20, chain_id_int=84532,
    # ),
}


# ---------------------------------------------------------------------------
# DEFAULT ASSETS (native + tokens like USDT). Tokens are how you "add any
# token on a chain" (e.g. USDT on BSC / ETH / Tron / your custom EVM).
# ---------------------------------------------------------------------------
DEFAULT_ASSETS: dict[str, AssetConfig] = {
    # native coins
    "ETH": AssetConfig(asset_key="ETH", chain_id="ETH", symbol="ETH", decimals=18, is_native=True),
    "BNB": AssetConfig(asset_key="BNB", chain_id="BSC", symbol="BNB", decimals=18, is_native=True),
    "TRX": AssetConfig(asset_key="TRX", chain_id="TRX", symbol="TRX", decimals=6, is_native=True),
    "SOL": AssetConfig(asset_key="SOL", chain_id="SOL", symbol="SOL", decimals=9, is_native=True),
    "TON": AssetConfig(asset_key="TON", chain_id="TON", symbol="TON", decimals=9, is_native=True),
    # Token metadata presets. End-to-end token transfer support is planned;
    # these entries alone do not imply signing/broadcast support.
    #   ETH  -> USDT on Sepolia
    #   BSC  -> USDT on BNB Chain Testnet (Legacy 18-decimals version)
    #   TRX  -> USDT-TRON on Shasta
    #   SOL  -> USDT-SPL on Devnet
    #   TON  -> USDT jetton master on TON Testnet (deposits attributed via memo)
    "USDT-ETH": AssetConfig(
        asset_key="USDT-ETH",
        chain_id="ETH",
        symbol="USDT",
        decimals=6,
        is_native=False,
        contract_address=_env("USDT_ETH_CONTRACT", "0x07081d8c4c165da3cba3c5c6e3c5c5c5c5c5c5c5c5"),
        deposit_threshold=1.0,
    ),
    "USDT-BSC": AssetConfig(
        asset_key="USDT-BSC",
        chain_id="BSC",
        symbol="USDT",
        decimals=18,
        is_native=False,
        contract_address=_env("USDT_BSC_CONTRACT", "0x337610d27c682E347C9cD60BD4b3b107C9d34dDd"),
        deposit_threshold=1.0,
    ),
    "USDT-TRX": AssetConfig(
        asset_key="USDT-TRX",
        chain_id="TRX",
        symbol="USDT",
        decimals=6,
        is_native=False,
        contract_address=_env("USDT_TRX_CONTRACT", "TG3XXyExBkPp9nzdajDZsozEu4BkaSJozs"),
        deposit_threshold=1.0,
    ),
    "USDT-SOL": AssetConfig(
        asset_key="USDT-SOL",
        chain_id="SOL",
        symbol="USDT",
        decimals=6,
        is_native=False,
        contract_address=_env("USDT_SOL_CONTRACT", "Es9VVM7aGzC8t7k1Z3e2jJ9qB5rF6nT8mY4pL3xN7wQ"),
        deposit_threshold=1.0,
    ),
    "USDT-TON": AssetConfig(
        asset_key="USDT-TON",
        chain_id="TON",
        symbol="USDT",
        decimals=6,
        is_native=False,
        contract_address=_env(
            "USDT_TON_CONTRACT", "EQD2Vuh8jFqW6o1XfF0ywz6t7m9o8n7s6r5t4y3u2i1o0p"
        ),
        deposit_threshold=1.0,
    ),
}


# Backwards-compatible ``Network`` enum shim. New code should prefer the
# config-driven registry (chain_id strings + ChainConfig/AssetConfig), but we
# keep ``Network`` so legacy imports (`from .config import Network`) resolve to
# the preset chain ids (ETH/BSC/TRX/SOL/TON) without touching every module.
Network = StrEnum("Network", {c: c for c in DEFAULT_CHAINS})


def get_network_config(network) -> ChainConfig:
    """Resolve a Network enum/string/chain_id to its ChainConfig."""
    return get_chain(str(network))


@lru_cache(maxsize=1)
def get_chains() -> dict[str, ChainConfig]:
    """Return the active chain registry (defaults + DB overrides)."""
    chains = {k: v for k, v in DEFAULT_CHAINS.items()}
    # (Optional) merge DB-backed ChainConfig rows here for runtime admin edits.
    return chains


@lru_cache(maxsize=1)
def get_assets() -> dict[str, AssetConfig]:
    """Return the active asset registry (defaults + DB overrides)."""
    assets = {k: v for k, v in DEFAULT_ASSETS.items()}
    return assets


def get_chain(chain_id: str) -> ChainConfig:
    try:
        return get_chains()[chain_id]
    except KeyError:
        raise KeyError(f"unknown chain_id '{chain_id}' (not in registry)")


def get_asset(asset_key: str) -> AssetConfig:
    try:
        return get_assets()[asset_key]
    except KeyError:
        raise KeyError(f"unknown asset_key '{asset_key}' (not in registry)")


def chain_ids() -> list[str]:
    return [c.chain_id for c in get_chains().values() if c.enabled]


def asset_keys() -> list[str]:
    return [a.asset_key for a in get_assets().values() if a.enabled]


def get_indexer_base_url() -> str:
    return _env("INDEXER_BASE_URL", "http://localhost:8080")


def is_memo_required(chain_id) -> bool:
    try:
        return get_chain(str(chain_id)).memo_required
    except KeyError:
        return False


def native_asset_key(chain_id: str) -> str:
    """Return the native asset key for a chain (e.g. BSC -> 'BNB').

    Finds the AssetConfig whose chain_id matches and is_native=True. This
    decouples the chain id from its native asset symbol (BSC != BNB).
    Falls back to the chain_id itself when no native asset entry exists.
    """
    for a in get_assets().values():
        if a.chain_id == str(chain_id) and a.is_native:
            return a.asset_key
    return str(chain_id)


def validate_chain_asset(chain_id: str, asset_key: str) -> AssetConfig:
    """Resolve an asset and reject cross-chain operations."""
    get_chain(chain_id)
    asset = get_asset(asset_key)
    if asset.chain_id != chain_id:
        raise ValueError(f"asset {asset_key} belongs to {asset.chain_id}, not {chain_id}")
    return asset


def effective_deposit_threshold(asset: AssetConfig, chain: ChainConfig | None = None) -> float:
    if asset.deposit_threshold is not None:
        return asset.deposit_threshold
    if chain is not None:
        return chain.deposit_threshold
    # Fallback when no chain context is supplied (rare): use the asset's chain.
    try:
        return get_chain(asset.chain_id).deposit_threshold
    except KeyError:
        return 0.0


def get_confirmation_threshold(chain_id: str) -> int:
    """Return the finality/confirmation threshold for a chain."""
    return get_chain(chain_id).confirmations


def ensure_hot_wallet(chain_id: str) -> str:
    """Return the custody hot wallet address for `chain_id`.

    Seeds a HotWallet row from config if one does not exist yet. This is the
    MPC-controlled address that sweeps/withdrawals target (NEVER a user EOA).
    """
    from .models import HotWallet  # local import; safe at call time

    cfg = get_chain(chain_id)
    address = cfg.hot_wallet_address
    if not address:
        existing = HotWallet.objects.filter(chain_id=chain_id).first()
        address = existing.address if existing else ""
    if not address:
        raise RuntimeError(f"no custody hot wallet configured for {chain_id}")
    obj, created = HotWallet.objects.get_or_create(
        chain_id=chain_id,
        defaults={"address": address},
    )
    if not created and not obj.address and cfg.hot_wallet_address:
        obj.address = cfg.hot_wallet_address
        obj.save(update_fields=["address"])
    return obj.address
