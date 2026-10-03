"""SOL (devnet) indexer client. System-account EOA deposits.

LIVE mode (default): real Solana JSON-RPC via the editable node registry
(ops dashboard -> Nodes). Balance = getBalance (lamports -> SOL, 1e9).
Deposit events = getSignaturesForAddress + getTransaction (best-effort).
STUB mode (CUSTODY_INDEXER_MODE=stub): offline simulated balance.
"""

from __future__ import annotations

import logging
from decimal import Decimal
from typing import List

import requests

from .base import BalanceResult, DepositEvent, IndexerClient, IndexerUnavailable
from .rpc_nodes import rpc_urls

logger = logging.getLogger("custody.indexer.sol")

RPC_TIMEOUT = 8.0


def _rpc(url: str, method: str, params: list):
    r = requests.post(
        url,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        timeout=RPC_TIMEOUT,
    )
    r.raise_for_status()
    data = r.json()
    if "error" in data:
        raise RuntimeError(f"{method}: {data['error']}")
    return data["result"]


class SolIndexer(IndexerClient):
    def __init__(self, chain_id: str = "SOL"):
        super().__init__(chain_id)

    def get_balance(self, address: str, memo=None) -> BalanceResult:
        if self._stub_enabled():
            return self._stub_balance()
        urls = rpc_urls(self.chain_id)
        if not urls:
            raise IndexerUnavailable("no RPC node configured for SOL")
        last_err: Exception | None = None
        for u in urls:
            try:
                slot = int(_rpc(u, "getSlot", []))
                lamports = int(
                    _rpc(u, "getBalance", [address, {"commitment": "confirmed"}])["value"]
                )
                from ..chain_registry import get_chain_spec

                divisor = Decimal(10 ** get_chain_spec(self.chain_id).native_decimals)
                confirmed = Decimal(lamports) / divisor

                events: List[DepositEvent] = []
                try:
                    sigs = _rpc(u, "getSignaturesForAddress", [address, {"limit": 25}]) or []
                    for s in sigs:
                        if s.get("err"):
                            continue
                        try:
                            tx = _rpc(
                                u,
                                "getTransaction",
                                [
                                    s["signature"],
                                    {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0},
                                ],
                            )
                        except Exception:  # noqa: BLE001
                            continue
                        if not tx:
                            continue
                        meta = tx.get("meta") or {}
                        msg = tx.get("transaction", {}).get("message", {}) or {}
                        accs = msg.get("accountKeys", [])
                        # Find this address's index in the account list.
                        idx = None
                        for i, ak in enumerate(accs):
                            pk = ak.get("pubkey") if isinstance(ak, dict) else ak
                            if pk == address:
                                idx = i
                                break
                        if idx is None:
                            continue
                        pre = (meta.get("preBalances") or [0] * (idx + 1))[idx]
                        post = (meta.get("postBalances") or [0] * (idx + 1))[idx]
                        delta = post - pre
                        if delta > 0:
                            events.append(
                                DepositEvent(
                                    tx_hash=s["signature"],
                                    amount=Decimal(delta) / divisor,
                                    block=int(tx.get("slot", 0)),
                                    confirmations=max(0, slot - int(tx.get("slot", slot))),
                                )
                            )
                except Exception as e:  # noqa: BLE001
                    logger.warning("SOL tx scan failed for %s: %s", address, e)

                return BalanceResult(
                    confirmed_balance=confirmed,
                    pending_balance=Decimal("0"),
                    last_scanned_block=slot,
                    deposit_events=events,
                )
            except Exception as e:  # noqa: BLE001 - failover to next node
                last_err = e
                logger.warning("sol rpc fail url=%s err=%s", u, e)
        logger.error("SOL live balance failed for %s: %s", address, last_err)
        raise IndexerUnavailable("SOL balance unavailable") from last_err

    def get_txs(self, address: str, after_block=None, memo=None):
        return []
