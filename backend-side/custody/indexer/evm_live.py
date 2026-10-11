"""
Live EVM testnet balance/tx reader (ETH Sepolia, BSC testnet, any EVM chain).

Uses plain JSON-RPC against enabled ``ops.NodeEndpoint`` rows returned by the
canonical runtime resolver. There is deliberately no static/environment fallback.

Balance semantics:
  * eth_getBalance returns the CURRENT state balance of the EOA.
  * The displayed balance is current state; it is not deposit finality evidence.
  * Native deposits require full blocks and matching execution receipts. Scan
    bounded finalized chunks from genesis or the last verified checkpoint.
    The caller commits events and the height/hash checkpoint atomically.
  * Missing/pruned history, malformed responses, changed checkpoint identity or
    RPC failures abort the chunk. No successful result or advanced cursor is
    returned. Backfill must finish before the background scanner starts a sweep.

Reorg handling:
  * Each event carries block + confirmations = head - block.
  * Callers only credit events with confirmations >= chain.confirmations.
  * If a previously credited Deposit's block is orphaned, handle_reorg()
    returns it for ledger UNWIND (see base.py docstring).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from decimal import Decimal
from typing import List, Optional

import requests

from ..chain_registry import get_chain_spec
from .base import BalanceResult, DepositEvent
from .rpc_nodes import rpc_urls

logger = logging.getLogger("custody.indexer.evm")

# Maximum full historical blocks per request; this is a work bound, not a lookback.
SCAN_BLOCKS = 64
RPC_TIMEOUT = 8.0


class EvmLiveError(RuntimeError):
    pass


def _rpc(url: str, method: str, params: list, *, chain_id=None):
    from django.conf import settings

    if chain_id is not None and settings.MPC_SIGNER_BACKEND == "self_hosted_mpc":
        from ..mpc_evm_network import guarded_evm_rpc
        from ..native_tx import RequestsTransport

        return guarded_evm_rpc(chain_id, url, RequestsTransport(), method, params)
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


def _call_any(urls: List[str], method: str, params: list, *, chain_id=None):
    """Try each RPC URL in priority order until one succeeds."""
    last_err: Optional[Exception] = None
    for u in urls:
        try:
            return _rpc(u, method, params, chain_id=chain_id)
        except Exception as e:  # noqa: BLE001 - failover to next node
            from ..mpc_evm_network import MpcNetworkError

            if isinstance(e, MpcNetworkError):
                raise
            last_err = e
            logger.warning("evm rpc fail url=%s method=%s err=%s", u, method, e)
    raise EvmLiveError(f"all RPC nodes failed for {method}: {last_err}")


@dataclass
class EvmBalanceResult(BalanceResult):
    evm_scan_block_hash: Optional[str] = None
    scan_complete: bool = True
    minimum_confirmations: int = 0


def _quantity(value, label):
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]+", value):
        raise EvmLiveError(f"missing or invalid {label}")
    return int(value, 16)


def _hash(value, label):
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", value):
        raise EvmLiveError(f"missing or invalid {label}")
    return value.lower()


def evm_get_balance(
    chain_id: str, address: str, *, after_block=None, after_block_hash=None
) -> EvmBalanceResult:
    urls = rpc_urls(chain_id)
    if not urls:
        raise EvmLiveError(f"no RPC node configured for {chain_id}")

    def read(method, params):
        return _call_any(urls, method, params, chain_id=chain_id)

    spec = get_chain_spec(chain_id)
    if spec.confirmations < 1:
        raise EvmLiveError("native scan requires a positive confirmation policy")
    head = _quantity(read("eth_blockNumber", []), "chain head")
    balance_wei = _quantity(read("eth_getBalance", [address, "latest"]), "native balance")
    divisor = Decimal(10**spec.native_decimals)
    finalized = head - spec.confirmations
    previous_hash = None
    if after_block is not None:
        if type(after_block) is not int or after_block < 0 or after_block > finalized:
            raise EvmLiveError("durable native checkpoint exceeds available finalized history")
        checkpoint = read("eth_getBlockByNumber", [hex(after_block), False])
        if (
            not isinstance(checkpoint, dict)
            or _quantity(checkpoint.get("number"), "checkpoint block number") != after_block
        ):
            raise EvmLiveError("missing or mismatched native checkpoint block")
        previous_hash = _hash(checkpoint.get("hash"), "checkpoint block hash")
        if after_block_hash is not None and previous_hash != _hash(
            after_block_hash, "durable checkpoint hash"
        ):
            raise EvmLiveError("durable native checkpoint block identity changed")
    elif after_block_hash is not None:
        raise EvmLiveError("native checkpoint hash has no height")

    start = 0 if after_block is None else after_block + 1
    end = min(finalized, start + SCAN_BLOCKS - 1)
    events: List[DepositEvent] = []
    for n in range(start, end + 1):
        blk = read("eth_getBlockByNumber", [hex(n), True])
        if not isinstance(blk, dict) or _quantity(blk.get("number"), "block number") != n:
            raise EvmLiveError(f"missing or mismatched native history block {n}")
        block_hash = _hash(blk.get("hash"), "block hash")
        parent_hash = _hash(blk.get("parentHash"), "parent block hash")
        if previous_hash is not None and parent_hash != previous_hash:
            raise EvmLiveError("native history block ancestry changed")
        transactions = blk.get("transactions")
        if not isinstance(transactions, list):
            raise EvmLiveError("native history requires complete block transactions")
        for tx in transactions:
            if not isinstance(tx, dict) or "to" not in tx:
                raise EvmLiveError("native history requires full transaction objects")
            recipient = tx["to"]
            if recipient is not None and (
                not isinstance(recipient, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", recipient)
            ):
                raise EvmLiveError("invalid native transaction recipient")
            value = _quantity(tx.get("value"), "transaction value")
            tx_hash = _hash(tx.get("hash"), "transaction hash")
            if (recipient or "").lower() != address.lower() or value == 0:
                continue
            receipt = read("eth_getTransactionReceipt", [tx_hash])
            if not isinstance(receipt, dict):
                raise EvmLiveError("missing native execution receipt")
            status = _quantity(receipt.get("status"), "receipt status")
            if (
                status not in (0, 1)
                or _hash(receipt.get("transactionHash"), "receipt transaction hash") != tx_hash
                or _hash(receipt.get("blockHash"), "receipt block hash") != block_hash
                or _quantity(receipt.get("blockNumber"), "receipt block number") != n
            ):
                raise EvmLiveError("native receipt does not match scanned transaction/block")
            if status == 1:
                events.append(
                    DepositEvent(
                        tx_hash=tx_hash,
                        amount=Decimal(value) / divisor,
                        block=n,
                        confirmations=head - n,
                        block_hash=block_hash,
                    )
                )
        previous_hash = block_hash

    return EvmBalanceResult(
        confirmed_balance=Decimal(balance_wei) / divisor,
        last_scanned_block=end if end >= start else after_block,
        deposit_events=events,
        evm_scan_block_hash=previous_hash,
        scan_complete=end >= finalized,
        minimum_confirmations=spec.confirmations,
    )
