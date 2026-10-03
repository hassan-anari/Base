"""
Indexer client interface + shared result types.

The indexer is our source of truth for on-chain balances and deposit events.
All network clients implement ``IndexerClient``. The Django service NEVER
trusts raw RPC for finality; it defers to the indexer which applies
confirmation thresholds and detects reorgs.

Reorg handling (approach, implemented in comments / stubs):
  - The indexer tracks ``last_scanned_block`` per (network, address).
  - Each returned deposit includes ``block`` and ``confirmations``.
  - If a previously-parsed deposit's block is no longer in the canonical chain
    (detected via reorg callback / re-scan), we UNWIND the ledger entry:
        * mark the Deposit REVERTED and append its exact inverse journal entry,
        * if a sweep already moved funds, escalate to manual review (do NOT
          auto-reverse on-chain; log + alert).
  - Finality = (chain_head - deposit.block) >= network.confirmations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import List, Optional


class IndexerUnavailable(RuntimeError):
    """No authoritative balance could be obtained from indexer infrastructure."""


@dataclass
class DepositEvent:
    tx_hash: str
    amount: Decimal
    block: int
    confirmations: int
    memo: Optional[str] = None


@dataclass
class BalanceResult:
    confirmed_balance: Decimal
    pending_balance: Decimal = Decimal("0")
    last_scanned_block: Optional[int] = None
    deposit_events: List[DepositEvent] = field(default_factory=list)


class IndexerClient:
    """Abstract indexer client. Subclasses implement network specifics."""

    network = "UNKNOWN"

    # Stub mode: simulate a funded deposit address so the sweep flow is
    # observable end-to-end without network access. Controlled by
    # CUSTODY_INDEXER_MODE=stub (smoke tests / offline demo). Default is
    # "live": real testnet RPC calls via the editable node registry.
    stub_funded_balance: float = 1.0

    def get_balance(self, address: str, memo: Optional[str] = None) -> BalanceResult:
        # Base STUB: returns a fixed "funded" balance (above typical thresholds)
        # so the gas-station + auto-sweep path can be demonstrated. Subclasses
        # that wire a real indexer override get_balance and only fall back to
        # this stub when stub mode is enabled.
        return self._stub_balance(memo)

    @staticmethod
    def _stub_enabled() -> bool:
        """True when running in offline stub mode (no real testnet calls).

        Mode resolution:
          CUSTODY_INDEXER_MODE=stub  -> always stub (smoke tests, offline demo)
          CUSTODY_INDEXER_MODE=live  -> always live (default)
          unset                      -> live
        """
        import os

        mode = os.environ.get("CUSTODY_INDEXER_MODE", "live").strip().lower()
        return mode == "stub"

    def _stub_balance(self, memo: Optional[str] = None) -> BalanceResult:
        from custody.config import get_confirmation_threshold

        confirmations = get_confirmation_threshold(str(self.network))
        return BalanceResult(
            confirmed_balance=Decimal(str(self.stub_funded_balance)),
            pending_balance=Decimal("0"),
            last_scanned_block=1_000_000,
            deposit_events=[
                DepositEvent(
                    tx_hash="0xstubdeposit",
                    amount=Decimal(str(self.stub_funded_balance)),
                    block=999_999,
                    confirmations=confirmations,
                    memo=memo,
                )
            ],
        )

    def get_txs(
        self, address: str, after_block: Optional[int] = None, memo: Optional[str] = None
    ) -> List[DepositEvent]:
        raise NotImplementedError

    # ---- Reorg support (stub) ----
    def handle_reorg(
        self, address: str, known_block: int, canonical_block: int
    ) -> List[DepositEvent]:
        """Detect deposits that were reverted between known_block and the
        current canonical chain. Returns events to UNWIND."""
        # Production: query indexer for canonical deposits at/after known_block
        # and diff against local Deposit rows; return those to revert.
        raise NotImplementedError
