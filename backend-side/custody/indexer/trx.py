"""TRX (Shasta testnet) indexer client. T-address EOA deposits.

LIVE mode (default): real Tron HTTP API via the editable node registry
(ops dashboard -> Nodes). Balance = /wallet/getaccount (SUN -> TRX, 1e6).
Deposit events = TronGrid v1 /v1/accounts/{addr}/transactions (best-effort;
degrades to balance-only if the node does not expose the v1 API).
STUB mode (CUSTODY_INDEXER_MODE=stub): offline simulated balance.
"""
from __future__ import annotations

import logging
from typing import List

import requests

from .base import BalanceResult, DepositEvent, IndexerClient
from .rpc_nodes import rpc_urls

logger = logging.getLogger("custody.indexer.trx")

RPC_TIMEOUT = 8.0


class TrxIndexer(IndexerClient):
    network = "TRX"

    def get_balance(self, address: str, memo=None) -> BalanceResult:
        if self._stub_enabled():
            return self._stub_balance()
        urls = rpc_urls("TRX")
        if not urls:
            logger.error("no RPC node configured for TRX")
            return BalanceResult(confirmed_balance=0.0)
        last_err: Exception | None = None
        for u in urls:
            try:
                base = u.rstrip("/")
                r = requests.post(f"{base}/wallet/getaccount",
                                  json={"address": address, "visible": True},
                                  timeout=RPC_TIMEOUT)
                r.raise_for_status()
                data = r.json()
                balance_sun = int(data.get("balance", 0))
                confirmed = balance_sun / 1_000_000

                head_block = None
                try:
                    rb = requests.post(f"{base}/wallet/getnowblock", json={},
                                       timeout=RPC_TIMEOUT)
                    rb.raise_for_status()
                    head_block = int(rb.json().get("block_header", {})
                                     .get("raw_data", {}).get("number", 0))
                except Exception:  # noqa: BLE001
                    pass

                events: List[DepositEvent] = []
                try:
                    rt = requests.get(
                        f"{base}/v1/accounts/{address}/transactions",
                        params={"limit": 50, "only_to": "true"},
                        timeout=RPC_TIMEOUT)
                    if rt.ok:
                        for tx in rt.json().get("data", []):
                            raw = tx.get("raw_data", {})
                            for c in raw.get("contract", []):
                                p = c.get("parameter", {}).get("value", {})
                                owner = p.get("owner_address", "")
                                amount_sun = int(p.get("amount", 0))
                                if c.get("type") == "TransferContract" \
                                        and amount_sun > 0:
                                    events.append(DepositEvent(
                                        tx_hash=tx.get("txID", ""),
                                        amount=amount_sun / 1_000_000,
                                        block=int(raw.get(
                                            "ref_block_bytes", "0"), 16)
                                        if raw.get("ref_block_bytes") else 0,
                                        confirmations=10,
                                    ))
                except Exception as e:  # noqa: BLE001
                    logger.warning("TRX tx scan failed for %s: %s", address, e)

                return BalanceResult(confirmed_balance=confirmed,
                                     pending_balance=0.0,
                                     last_scanned_block=head_block,
                                     deposit_events=events)
            except Exception as e:  # noqa: BLE001 - failover to next node
                last_err = e
                logger.warning("trx rpc fail url=%s err=%s", u, e)
        logger.error("TRX live balance failed for %s: %s", address, last_err)
        return BalanceResult(confirmed_balance=0.0, last_scanned_block=0)

    def get_txs(self, address: str, after_block=None, memo=None):
        return []