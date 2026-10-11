"""Generic indexer for every configured EVM chain."""

import logging
from decimal import Decimal

from ..chain_registry import get_chain_spec, rpc_urls
from ..models import Asset
from .base import BalanceResult, DepositEvent, IndexerClient, IndexerUnavailable
from .evm_live import _call_any, evm_get_balance

logger = logging.getLogger("custody.indexer.evm")


class EvmIndexer(IndexerClient):
    def __init__(self, chain_id: str):
        super().__init__(chain_id)

    def get_balance(
        self, address: str, *, asset_key=None, after_block=None, after_block_hash=None, memo=None
    ) -> BalanceResult:
        if self._stub_enabled():
            return self._stub_balance(asset_key=asset_key)
        try:
            asset = Asset.objects.get(asset_key=asset_key, chain_id=self.chain_id, enabled=True)
            if not asset.is_native:
                return self._token_balance(asset, address, after_block)
            return evm_get_balance(
                self.chain_id, address, after_block=after_block, after_block_hash=after_block_hash
            )
        except Exception as exc:
            logger.error("%s live balance failed for %s: %s", self.chain_id, address, exc)
            raise IndexerUnavailable(f"{self.chain_id} balance unavailable") from exc

    def _token_balance(self, asset, address, after_block):
        from ..token_metadata import assert_verified_token

        assert_verified_token(asset.asset_key)
        urls = rpc_urls(self.chain_id)

        def read(method, params):
            return _call_any(urls, method, params, chain_id=self.chain_id)

        head = int(read("eth_blockNumber", []), 16)
        padded = address.lower().removeprefix("0x").rjust(64, "0")
        raw = read(
            "eth_call",
            [{"to": asset.contract_address, "data": "0x70a08231" + padded}, "latest"],
        )
        units = int(raw, 16)
        divisor = Decimal(10) ** asset.decimals
        settings = get_chain_spec(self.chain_id).gas_settings
        lookback = int(settings.get("token_initial_lookback_blocks", 1000))
        overlap = int(settings.get("token_reorg_overlap_blocks", 12))
        chunk = int(settings.get("token_log_chunk_blocks", 1000))
        start = max(0, (after_block - overlap) if after_block is not None else head - lookback)
        topic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        events = []
        for first in range(start, head + 1, chunk):
            last = min(head, first + chunk - 1)
            logs = (
                read(
                    "eth_getLogs",
                    [
                        {
                            "fromBlock": hex(first),
                            "toBlock": hex(last),
                            "address": asset.contract_address,
                            "topics": [topic, None, "0x" + padded],
                        }
                    ],
                )
                or []
            )
            for log in logs:
                if (
                    log.get("removed")
                    or log.get("address", "").lower() != asset.contract_address.lower()
                ):
                    continue
                topics = log.get("topics") or []
                if len(topics) != 3 or topics[0].lower() != topic:
                    continue
                value = int(log.get("data", "0x0"), 16)
                if value <= 0:
                    continue
                block = int(log["blockNumber"], 16)
                events.append(
                    DepositEvent(
                        tx_hash=log["transactionHash"],
                        amount=Decimal(value) / divisor,
                        block=block,
                        confirmations=max(0, head - block),
                        asset_key=asset.asset_key,
                        event_index=f"log:{int(log['logIndex'], 16)}",
                        block_hash=log.get("blockHash"),
                        contract_address=log["address"],
                    )
                )
        return BalanceResult(
            Decimal(units) / divisor, last_scanned_block=head, deposit_events=events
        )

    def get_txs(self, address, after_block=None, memo=None):
        return []
