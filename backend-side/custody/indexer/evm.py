"""Generic indexer for every configured EVM chain."""

import logging

from .base import BalanceResult, IndexerClient, IndexerUnavailable
from .evm_live import evm_get_balance

logger = logging.getLogger("custody.indexer.evm")


class EvmIndexer(IndexerClient):
    def __init__(self, chain_id: str):
        super().__init__(chain_id)

    def get_balance(self, address: str, memo=None) -> BalanceResult:
        if self._stub_enabled():
            return self._stub_balance()
        try:
            return evm_get_balance(self.chain_id, address)
        except Exception as exc:
            logger.error("%s live balance failed for %s: %s", self.chain_id, address, exc)
            raise IndexerUnavailable(f"{self.chain_id} balance unavailable") from exc

    def get_txs(self, address, after_block=None, memo=None):
        return []
