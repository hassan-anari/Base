"""BSC (testnet) indexer client. Same EVM semantics as ETH.

LIVE mode (default): real JSON-RPC via the editable node registry.
STUB mode (CUSTODY_INDEXER_MODE=stub): offline simulated balance.
"""

from __future__ import annotations

import logging

from .base import BalanceResult, IndexerClient, IndexerUnavailable
from .evm_live import evm_get_balance

logger = logging.getLogger("custody.indexer.bsc")


class BscIndexer(IndexerClient):
    network = "BSC"

    def get_balance(self, address: str, memo=None) -> BalanceResult:
        if self._stub_enabled():
            return self._stub_balance()
        try:
            return evm_get_balance("BSC", address)
        except Exception as e:
            logger.error("BSC live balance failed for %s: %s", address, e)
            raise IndexerUnavailable("BSC balance unavailable") from e

    def get_txs(self, address: str, after_block=None, memo=None):
        return []
