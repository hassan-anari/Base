"""Reviewed chain-family behavior selected from the runtime ChainSpec kind."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from decimal import Decimal

from .chain_registry import ChainKind, ChainSpec, UnsupportedChainKind, get_chain_spec


def from_base_units(value: int, decimals: int) -> Decimal:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError("base units must be a non-negative integer")
    if not 0 <= decimals <= 255:
        raise ValueError("invalid asset decimals")
    return Decimal(value) / Decimal(10**decimals)


class ChainAdapter(ABC):
    kind: ChainKind
    derivation_purpose: int

    @abstractmethod
    def validate_address(self, address: str, *, custody_derived: bool = False) -> None: ...

    @abstractmethod
    def build_indexer(self, spec: ChainSpec): ...

    def from_base_units(self, value: int, decimals: int) -> Decimal:
        return from_base_units(value, decimals)


class EvmAdapter(ChainAdapter):
    kind, derivation_purpose = ChainKind.EVM, 44

    def validate_address(self, address: str, *, custody_derived: bool = False) -> None:
        if not re.fullmatch(r"0x[0-9a-fA-F]{40}", address or ""):
            raise ValueError("invalid EVM address")

    def build_indexer(self, spec):
        from .indexer.evm import EvmIndexer

        return EvmIndexer(spec.chain_id)


class TronAdapter(ChainAdapter):
    kind, derivation_purpose = ChainKind.TRON, 44

    def validate_address(self, address: str, *, custody_derived: bool = False) -> None:
        if not (
            re.fullmatch(r"T[1-9A-HJ-NP-Za-km-z]{33}", address or "")
            or re.fullmatch(r"41[0-9a-fA-F]{40}", address or "")
        ):
            raise ValueError("invalid TRON address")

    def build_indexer(self, spec):
        from .indexer.trx import TrxIndexer

        return TrxIndexer(spec.chain_id)


class SolanaAdapter(ChainAdapter):
    kind, derivation_purpose = ChainKind.SOLANA, 501

    def validate_address(self, address: str, *, custody_derived: bool = False) -> None:
        if not re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,44}", address or ""):
            raise ValueError("invalid Solana address")

    def build_indexer(self, spec):
        from .indexer.sol import SolIndexer

        return SolIndexer(spec.chain_id)


class TonAdapter(ChainAdapter):
    kind, derivation_purpose = ChainKind.TON, 396

    def validate_address(self, address: str, *, custody_derived: bool = False) -> None:
        if not (
            re.fullmatch(r"-?\d+:[0-9a-fA-F]{64}", address or "")
            or re.fullmatch(r"[EU]Q[0-9A-Za-z_-]{46}", address or "")
        ):
            raise ValueError("invalid TON address")

    def build_indexer(self, spec):
        from .indexer.ton import TonIndexer

        return TonIndexer(spec.chain_id)


_ADAPTERS = {a.kind: a for a in (EvmAdapter(), TronAdapter(), SolanaAdapter(), TonAdapter())}


def get_adapter(chain_id: str) -> ChainAdapter:
    spec = get_chain_spec(chain_id)
    try:
        return _ADAPTERS[spec.kind]
    except KeyError as exc:
        raise UnsupportedChainKind(f"unsupported chain kind {spec.kind!r}") from exc
