"""TRX (Shasta testnet) indexer client. T-address EOA deposits.

LIVE mode (default): real Tron HTTP API via the editable node registry
(ops dashboard -> Nodes). Balance = /wallet/getaccount (SUN -> TRX, 1e6).
Deposit events = TronGrid v1 /v1/accounts/{addr}/transactions (best-effort;
degrades to balance-only if the node does not expose the v1 API).
STUB mode (CUSTODY_INDEXER_MODE=stub): offline simulated balance.
"""

from __future__ import annotations

import logging
from decimal import Decimal
from typing import List

import requests

from .base import BalanceResult, DepositEvent, IndexerClient, IndexerUnavailable
from .rpc_nodes import rpc_urls

logger = logging.getLogger("custody.indexer.trx")

RPC_TIMEOUT = 8.0


def _positive_block_number(value) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


class TrxIndexer(IndexerClient):
    def __init__(self, chain_id: str = "TRX"):
        super().__init__(chain_id)

    def get_balance(self, address: str, memo=None) -> BalanceResult:
        if self._stub_enabled():
            return self._stub_balance()
        urls = rpc_urls(self.chain_id)
        if not urls:
            raise IndexerUnavailable("no RPC node configured for TRX")
        last_err: Exception | None = None
        for u in urls:
            try:
                base = u.rstrip("/")
                r = requests.post(
                    f"{base}/wallet/getaccount",
                    json={"address": address, "visible": True},
                    timeout=RPC_TIMEOUT,
                )
                r.raise_for_status()
                data = r.json()
                balance_sun = int(data.get("balance", 0))
                from ..chain_registry import get_chain_spec

                divisor = Decimal(10 ** get_chain_spec(self.chain_id).native_decimals)
                confirmed = Decimal(balance_sun) / divisor

                head_block = None
                try:
                    rb = requests.post(f"{base}/wallet/getnowblock", json={}, timeout=RPC_TIMEOUT)
                    rb.raise_for_status()
                    head_block = int(
                        rb.json().get("block_header", {}).get("raw_data", {}).get("number", 0)
                    )
                except Exception:  # noqa: BLE001
                    pass

                events: List[DepositEvent] = []
                try:
                    rt = requests.get(
                        f"{base}/v1/accounts/{address}/transactions",
                        params={"limit": 50, "only_to": "true"},
                        timeout=RPC_TIMEOUT,
                    )
                    if rt.ok:
                        for tx in rt.json().get("data", []):
                            raw = tx.get("raw_data", {})
                            for c in raw.get("contract", []):
                                p = c.get("parameter", {}).get("value", {})
                                amount_sun = int(p.get("amount", 0))
                                if c.get("type") == "TransferContract" and amount_sun > 0:
                                    # TronGrid's blockNumber is the mined block. The
                                    # transaction ref block is only an expiration/
                                    # anti-replay reference and is not finality evidence.
                                    block = _positive_block_number(tx.get("blockNumber"))
                                    confirmations = (
                                        max(0, head_block - block + 1)
                                        if head_block is not None and block > 0
                                        else 0
                                    )
                                    events.append(
                                        DepositEvent(
                                            tx_hash=tx.get("txID", ""),
                                            amount=Decimal(amount_sun) / divisor,
                                            block=block,
                                            confirmations=confirmations,
                                        )
                                    )
                except Exception as e:  # noqa: BLE001
                    logger.warning("TRX tx scan failed for %s: %s", address, e)

                return BalanceResult(
                    confirmed_balance=confirmed,
                    pending_balance=Decimal("0"),
                    last_scanned_block=head_block,
                    deposit_events=events,
                )
            except Exception as e:  # noqa: BLE001 - failover to next node
                last_err = e
                logger.warning("trx rpc fail url=%s err=%s", u, e)
        logger.error("TRX live balance failed for %s: %s", address, last_err)
        raise IndexerUnavailable("TRX balance unavailable") from last_err

    def get_txs(self, address: str, after_block=None, memo=None):
        return []
