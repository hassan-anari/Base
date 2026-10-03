"""TON (testnet) indexer client. Memo-based user attribution.

TON specifics:
  - Deposit addresses are EOAs (raw workchain-0 wallet).
  - We attribute deposits/withdrawals to the correct user via a MEMO field
    encoded in the internal transfer comment / payload. The indexer maps
    memo -> user_id (looked up from UserWallet.memo).
  - When sweeping, we KEEP the same memo scheme so accounting stays consistent:
    the sweep tx from the user EOA to the hot wallet carries the user's memo,
    and the indexer credits the hot-wallet's internal ledger per memo bucket.

LIVE mode (default): real toncenter v2 HTTP API via the editable node
registry (ops dashboard -> Nodes).
  * balance : GET {base}/getAddressBalance?address=...   (nanotons -> TON 1e9)
  * deposits: GET {base}/getTransactions?address=...&limit=...
              each inbound message's `message` (comment) must EQUAL the
              user's memo to be credited.
STUB mode (CUSTODY_INDEXER_MODE=stub): offline simulated balance.
"""

from __future__ import annotations

import logging
from typing import List

import requests

from .base import BalanceResult, DepositEvent, IndexerClient, IndexerUnavailable
from .rpc_nodes import rpc_urls

logger = logging.getLogger("custody.indexer.ton")

RPC_TIMEOUT = 8.0


class TonIndexer(IndexerClient):
    network = "TON"

    def get_balance(self, address: str, memo: str | None = None) -> BalanceResult:
        if self._stub_enabled():
            return self._stub_balance(memo=memo)
        urls = rpc_urls("TON")
        if not urls:
            raise IndexerUnavailable("no RPC node configured for TON")
        last_err: Exception | None = None
        for u in urls:
            try:
                base = u.rstrip("/")
                r = requests.get(
                    f"{base}/getAddressBalance", params={"address": address}, timeout=RPC_TIMEOUT
                )
                r.raise_for_status()
                data = r.json()
                if not data.get("ok"):
                    raise RuntimeError(f"toncenter error: {data}")
                nanotons = int(data["result"])
                confirmed = nanotons / 1_000_000_000

                # Masterchain seqno as a coarse "last scanned" marker.
                last_block = None
                try:
                    rm = requests.get(f"{base}/getMasterchainInfo", timeout=RPC_TIMEOUT)
                    if rm.ok and rm.json().get("ok"):
                        last_block = int(rm.json()["result"]["last"]["seqno"])
                except Exception:  # noqa: BLE001
                    pass

                events: List[DepositEvent] = []
                try:
                    rt = requests.get(
                        f"{base}/getTransactions",
                        params={"address": address, "limit": 30},
                        timeout=RPC_TIMEOUT,
                    )
                    if rt.ok and rt.json().get("ok"):
                        for tx in rt.json().get("result", []):
                            in_msg = tx.get("in_msg") or {}
                            # Only inbound value transfers.
                            value = int(in_msg.get("value", "0"))
                            if value <= 0:
                                continue
                            comment = (in_msg.get("message") or "").strip()
                            # MEMO ATTRIBUTION: only credit when the comment
                            # matches this user's memo. If no memo is supplied
                            # (e.g. hot-wallet sweep-in accounting) credit all.
                            if memo is not None and comment != memo:
                                continue
                            events.append(
                                DepositEvent(
                                    tx_hash=tx.get("transaction_id", {}).get("hash", ""),
                                    amount=value / 1_000_000_000,
                                    block=int(tx.get("utime", 0)),
                                    confirmations=10,
                                    memo=comment or None,
                                )
                            )
                except Exception as e:  # noqa: BLE001
                    logger.warning("TON tx scan failed for %s: %s", address, e)

                # Memo-filtered balance semantics: the raw address balance is
                # shared across memo buckets; when a memo is given we report
                # the sum of memo-matched deposits as the confirmed amount so
                # per-user accounting stays correct.
                if memo is not None:
                    confirmed = sum(e.amount for e in events)

                return BalanceResult(
                    confirmed_balance=confirmed,
                    pending_balance=0.0,
                    last_scanned_block=last_block,
                    deposit_events=events,
                )
            except Exception as e:  # noqa: BLE001 - failover to next node
                last_err = e
                logger.warning("ton rpc fail url=%s err=%s", u, e)
        logger.error("TON live balance failed for %s: %s", address, last_err)
        raise IndexerUnavailable("TON balance unavailable") from last_err

    def get_txs(self, address: str, after_block=None, memo: str | None = None):
        return []
