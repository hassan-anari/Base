"""ETH (Sepolia) indexer client. EOA deposit addresses only.

LIVE mode (default): real JSON-RPC via the editable node registry
(ops dashboard -> Nodes). STUB mode (CUSTODY_INDEXER_MODE=stub): offline
simulated balance for smoke tests.
"""
from __future__ import annotations

import logging

from .base import BalanceResult, IndexerClient
from .evm_live import evm_get_balance

logger = logging.getLogger("custody.indexer.eth")


class EthIndexer(IndexerClient):
    network = "ETH"

    def get_balance(self, address: str, memo=None) -> BalanceResult:
        if self._stub_enabled():
            return self._stub_balance()
        try:
            return evm_get_balance("ETH", address)
        except Exception as e:  # noqa: BLE001 - degrade to zero, never 500
            logger.error("ETH live balance failed for %s: %s", address, e)
            return BalanceResult(confirmed_balance=0.0, last_scanned_block=0)

    def get_txs(self, address: str, after_block=None, memo=None):
        # Covered by the block scan inside evm_get_balance (deposit_events).
        return []