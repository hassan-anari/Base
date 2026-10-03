"""
Live EVM testnet balance/tx reader (ETH Sepolia, BSC testnet, any EVM chain).

Uses plain JSON-RPC against enabled ``ops.NodeEndpoint`` rows returned by the
canonical runtime resolver. There is deliberately no static/environment fallback.

Balance semantics:
  * eth_getBalance returns the CURRENT state balance of the EOA.
  * "confirmed" = current balance (state is always post-finality for balance
    display); pending delta is not tracked via RPC-only mode.
  * Deposit events require tx scanning (eth_getLogs can't see native value
    transfers). We scan the last N blocks with eth_getBlockByNumber and pick
    transactions whose `to` == deposit address. For production volume, replace
    this with a dedicated indexer service (the get_indexer_base_url() REST
    path) — the interface is identical.

Reorg handling:
  * Each event carries block + confirmations = head - block.
  * Callers only credit events with confirmations >= chain.confirmations.
  * If a previously credited Deposit's block is orphaned, handle_reorg()
    returns it for ledger UNWIND (see base.py docstring).
"""

from __future__ import annotations

import logging
from decimal import Decimal
from typing import List, Optional

import requests

from ..chain_registry import get_chain_spec
from .base import BalanceResult, DepositEvent
from .rpc_nodes import rpc_urls

logger = logging.getLogger("custody.indexer.evm")

# How many recent blocks to scan for incoming native transfers (RPC-only mode).
SCAN_BLOCKS = 64
RPC_TIMEOUT = 8.0


class EvmLiveError(RuntimeError):
    pass


def _rpc(url: str, method: str, params: list):
    r = requests.post(
        url,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        timeout=RPC_TIMEOUT,
    )
    r.raise_for_status()
    data = r.json()
    if "error" in data:
        raise EvmLiveError(f"{method}: {data['error']}")
    return data["result"]


def _call_any(urls: List[str], method: str, params: list):
    """Try each RPC URL in priority order until one succeeds."""
    last_err: Optional[Exception] = None
    for u in urls:
        try:
            return _rpc(u, method, params)
        except Exception as e:  # noqa: BLE001 - failover to next node
            last_err = e
            logger.warning("evm rpc fail url=%s method=%s err=%s", u, method, e)
    raise EvmLiveError(f"all RPC nodes failed for {method}: {last_err}")


def evm_get_balance(chain_id: str, address: str) -> BalanceResult:
    urls = rpc_urls(chain_id)
    if not urls:
        raise EvmLiveError(f"no RPC node configured for {chain_id}")
    head_hex = _call_any(urls, "eth_blockNumber", [])
    head = int(head_hex, 16)
    bal_hex = _call_any(urls, "eth_getBalance", [address, "latest"])
    balance_wei = int(bal_hex, 16)
    decimals = get_chain_spec(chain_id).native_decimals
    divisor = Decimal(10**decimals)
    confirmed = Decimal(balance_wei) / divisor

    events: List[DepositEvent] = []
    try:
        start = max(0, head - SCAN_BLOCKS)
        for n in range(start, head + 1):
            blk = _call_any(urls, "eth_getBlockByNumber", [hex(n), True])
            if not blk:
                continue
            for tx in blk.get("transactions") or []:
                if (tx.get("to") or "").lower() == address.lower() and int(
                    tx.get("value", "0x0"), 16
                ) > 0:
                    events.append(
                        DepositEvent(
                            tx_hash=tx["hash"],
                            amount=Decimal(int(tx["value"], 16)) / divisor,
                            block=n,
                            confirmations=max(0, head - n),
                        )
                    )
    except Exception as e:  # noqa: BLE001 - balance still valid without events
        logger.warning("evm tx scan failed for %s: %s", address, e)

    return BalanceResult(
        confirmed_balance=confirmed,
        pending_balance=Decimal("0"),
        last_scanned_block=head,
        deposit_events=events,
    )
