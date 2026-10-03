"""ETH (Sepolia) indexer client. EOA deposit addresses only.

LIVE mode (default): real JSON-RPC via the editable node registry
(ops dashboard -> Nodes). STUB mode (CUSTODY_INDEXER_MODE=stub): offline
simulated balance for smoke tests.
"""

from __future__ import annotations

import logging

from .base import BalanceResult, IndexerClient, IndexerUnavailable
from .evm_live import evm_get_balance

logger = logging.getLogger("custody.indexer.eth")


class EthIndexer(IndexerClient):
    def __init__(self):
        super().__init__("ETH")

    def get_balance(self, address: str, memo=None) -> BalanceResult:
        if self._stub_enabled():
            return self._stub_balance()
        try:
            return evm_get_balance(self.chain_id, address)
        except Exception as e:
            logger.error("ETH live balance failed for %s: %s", address, e)
            raise IndexerUnavailable("ETH balance unavailable") from e

    def get_txs(self, address: str, after_block=None, memo=None):
        # Covered by the block scan inside evm_get_balance (deposit_events).
        return []
