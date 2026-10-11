"""Generic indexer for every configured EVM chain."""

import logging
import re
from decimal import Decimal

import rlp
from eth_utils import keccak
from trie import HexaryTrie

from ..chain_registry import get_chain_spec, rpc_urls
from ..models import Asset
from .base import BalanceResult, DepositEvent, IndexerClient, IndexerUnavailable
from .evm_live import (
    SCAN_BLOCKS,
    EvmBalanceResult,
    EvmLiveError,
    _call_any,
    _hash,
    _quantity,
    evm_get_balance,
)

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
                return self._token_balance(asset, address, after_block, after_block_hash)
            return evm_get_balance(
                self.chain_id, address, after_block=after_block, after_block_hash=after_block_hash
            )
        except Exception as exc:
            logger.error("%s live balance failed for %s: %s", self.chain_id, address, exc)
            raise IndexerUnavailable(f"{self.chain_id} balance unavailable") from exc

    def _token_balance(self, asset, address, after_block, after_block_hash=None):
        from ..token_metadata import _hex_uint, assert_verified_token

        assert_verified_token(asset.asset_key)
        if not re.fullmatch(r"0x[0-9a-fA-F]{40}", address):
            raise EvmLiveError("invalid ERC-20 deposit address")
        urls = rpc_urls(self.chain_id)

        def read(method, params):
            return _call_any(urls, method, params, chain_id=self.chain_id)

        spec = get_chain_spec(self.chain_id)
        if spec.confirmations < 1:
            raise EvmLiveError("ERC-20 scan requires a positive confirmation policy")
        head = _quantity(read("eth_blockNumber", []), "chain head")
        padded = address.lower()[2:].rjust(64, "0")
        units = _hex_uint(
            read(
                "eth_call",
                [{"to": asset.contract_address, "data": "0x70a08231" + padded}, "latest"],
            )
        )
        divisor = Decimal(10) ** asset.decimals
        finalized = head - spec.confirmations
        overlap = int(spec.gas_settings.get("token_reorg_overlap_blocks", 12))
        chunk = min(SCAN_BLOCKS, int(spec.gas_settings.get("token_log_chunk_blocks", 1000)))
        if not 0 <= overlap <= SCAN_BLOCKS or chunk < 1:
            raise EvmLiveError("invalid bounded ERC-20 history policy")
        if after_block is not None:
            if type(after_block) is not int or not 0 <= after_block <= finalized:
                raise EvmLiveError("ERC-20 checkpoint exceeds available finalized history")
            if after_block_hash is None:
                raise EvmLiveError("ERC-20 checkpoint is missing its original verified hash")
            durable_hash = _hash(after_block_hash, "durable ERC-20 checkpoint hash")
            if verified_block(read, after_block, False)["hash"].lower() != durable_hash:
                raise EvmLiveError("durable ERC-20 checkpoint block identity changed")
        elif after_block_hash is not None:
            raise EvmLiveError("ERC-20 checkpoint hash has no height")
        # The former initial lookback/head cursor could permanently lose deposits.
        # Genesis is the only trustworthy starting point for an unverified cursor.
        next_block = 0 if after_block is None else after_block + 1
        start = max(0, next_block - overlap) if after_block is not None else 0
        end = min(finalized, next_block + SCAN_BLOCKS - 1)
        previous_hash = verified_block(read, start - 1, False)["hash"].lower() if start else None
        expected_logs = {}
        for n in range(start, end + 1):
            block = verified_block(read, n, True)
            block_hash = block["hash"].lower()
            if previous_hash is not None and block["parentHash"].lower() != previous_hash:
                raise EvmLiveError("ERC-20 history ancestry changed")
            if n == after_block and block_hash != durable_hash:
                raise EvmLiveError("ERC-20 overlap no longer reaches the original checkpoint")
            txs = block.get("transactions")
            if not isinstance(txs, list):
                raise EvmLiveError("ERC-20 history requires full block transactions")
            if _quantity(
                read("eth_getBlockTransactionCountByHash", [block_hash]), "block transaction count"
            ) != len(txs):
                raise EvmLiveError("incomplete ERC-20 block transaction list")
            block_bloom = 0
            receipts = HexaryTrie({})
            next_log_index = 0
            seen_txs = set()
            for index, tx in enumerate(txs):
                if not isinstance(tx, dict):
                    raise EvmLiveError("ERC-20 history requires full transaction objects")
                tx_hash = _hash(tx.get("hash"), "transaction hash")
                if tx_hash in seen_txs:
                    raise EvmLiveError("duplicate ERC-20 block transaction")
                seen_txs.add(tx_hash)
                receipt = read("eth_getTransactionReceipt", [tx_hash])
                if not isinstance(receipt, dict):
                    raise EvmLiveError("missing ERC-20 history receipt")
                status = _quantity(receipt.get("status"), "receipt status")
                if (
                    status not in (0, 1)
                    or _hash(receipt.get("transactionHash"), "receipt transaction hash") != tx_hash
                    or _hash(receipt.get("blockHash"), "receipt block hash") != block_hash
                    or _quantity(receipt.get("blockNumber"), "receipt height") != n
                    or _quantity(receipt.get("transactionIndex"), "receipt index") != index
                ):
                    raise EvmLiveError("ERC-20 receipt does not match scanned transaction/block")
                logs = receipt.get("logs")
                if not isinstance(logs, list) or (status == 0 and logs):
                    raise EvmLiveError("incomplete or invalid ERC-20 receipt logs")
                receipt_bloom = 0
                for log in logs:
                    record = canonical_log(log)
                    if record[:5] != (n, block_hash, tx_hash, index, next_log_index):
                        raise EvmLiveError("receipt log identity/order does not match history")
                    next_log_index += 1
                    receipt_bloom |= log_bloom(record)
                    if (
                        record[5] == asset.contract_address.lower()
                        and record[6]
                        and record[6][0] == TRANSFER_TOPIC
                    ):
                        if len(record[6]) != 3 or len(record[7]) != 66:
                            raise EvmLiveError("invalid allowlisted ERC-20 Transfer encoding")
                        if record[6][2] == "0x" + padded:
                            expected_logs[record[:5]] = record
                if receipt_bloom != bloom_value(receipt.get("logsBloom")):
                    raise EvmLiveError("incomplete receipt logs: bloom mismatch")
                receipts[rlp.encode(index)] = receipt_encoding(receipt)
                block_bloom |= receipt_bloom
            if block_bloom != bloom_value(block.get("logsBloom")):
                raise EvmLiveError("incomplete block receipts: bloom mismatch")
            if receipts.root_hash.hex() != _hash(block.get("receiptsRoot"), "receipt root")[2:]:
                raise EvmLiveError("incomplete or mismatched history: receipt trie root mismatch")
            previous_hash = block_hash
        returned_logs = {}
        for first in range(start, end + 1, chunk):
            logs = read(
                "eth_getLogs",
                [
                    {
                        "fromBlock": hex(first),
                        "toBlock": hex(min(end, first + chunk - 1)),
                        "address": asset.contract_address,
                        "topics": [TRANSFER_TOPIC, None, "0x" + padded],
                    }
                ],
            )
            if not isinstance(logs, list):
                raise EvmLiveError("missing or invalid ERC-20 log response")
            for log in logs:
                record = canonical_log(log)
                if (
                    not first <= record[0] <= min(end, first + chunk - 1)
                    or record[:5] in returned_logs
                ):
                    raise EvmLiveError("duplicate or out-of-range ERC-20 log response")
                returned_logs[record[:5]] = record
        # [] is evidence of absence only after exhaustive block/receipt corroboration.
        if returned_logs != expected_logs:
            raise EvmLiveError("ERC-20 log response disagrees with complete block receipts")
        if end >= start and verified_block(read, end, False)["hash"].lower() != previous_hash:
            raise EvmLiveError("ERC-20 history changed before checkpoint commit")
        events = [
            DepositEvent(
                tx_hash=record[2],
                amount=Decimal(int(record[7], 16)) / divisor,
                block=record[0],
                confirmations=head - record[0],
                asset_key=asset.asset_key,
                event_index=f"log:{record[4]}",
                block_hash=record[1],
                contract_address=record[5],
            )
            for record in expected_logs.values()
            if int(record[7], 16) > 0
        ]
        return EvmBalanceResult(
            confirmed_balance=Decimal(units) / divisor,
            last_scanned_block=end if end >= start else after_block,
            evm_scan_block_hash=previous_hash if end >= start else after_block_hash,
            deposit_events=events,
            scan_complete=finalized >= 0 and end >= finalized,
            minimum_confirmations=spec.confirmations,
        )

    def get_txs(self, address, after_block=None, memo=None):
        return []


TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


def verified_block(read, height, full):
    block = read("eth_getBlockByNumber", [hex(height), full])
    if not isinstance(block, dict) or _quantity(block.get("number"), "block number") != height:
        raise EvmLiveError("missing or mismatched ERC-20 history block")
    _hash(block.get("hash"), "block hash")
    _hash(block.get("parentHash"), "parent hash")
    return block


def bloom_value(value):
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{512}", value):
        raise EvmLiveError("missing or invalid history logs bloom")
    return int(value, 16)


def canonical_log(log):
    if not isinstance(log, dict) or log.get("removed") is not False:
        raise EvmLiveError("missing or removed ERC-20 history log")
    address = log.get("address")
    topics = log.get("topics")
    data = log.get("data")
    if (
        not isinstance(address, str)
        or not re.fullmatch(r"0x[0-9a-fA-F]{40}", address)
        or not isinstance(topics, list)
        or len(topics) > 4
        or not isinstance(data, str)
        or not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", data)
    ):
        raise EvmLiveError("invalid ERC-20 receipt log encoding")
    return (
        _quantity(log.get("blockNumber"), "log block number"),
        _hash(log.get("blockHash"), "log block hash"),
        _hash(log.get("transactionHash"), "log transaction hash"),
        _quantity(log.get("transactionIndex"), "log transaction index"),
        _quantity(log.get("logIndex"), "log index"),
        address.lower(),
        tuple(_hash(topic, "log topic") for topic in topics),
        data.lower(),
    )


def log_bloom(record):
    result = 0
    for value in (record[5], *record[6]):
        hashed = keccak(bytes.fromhex(value[2:]))
        for offset in (0, 2, 4):
            result |= 1 << (int.from_bytes(hashed[offset : offset + 2], "big") & 2047)
    return result


def receipt_encoding(receipt):
    """Canonical EIP-2718 receipt bytes for the existing EVM execution boundary."""
    kind = _quantity(receipt.get("type"), "receipt type")
    if kind not in (0, 1, 2, 3, 4):
        raise EvmLiveError("unsupported EVM receipt type")
    encoded = rlp.encode(
        [
            _quantity(receipt.get("status"), "receipt status"),
            _quantity(receipt.get("cumulativeGasUsed"), "receipt cumulative gas"),
            bytes.fromhex(receipt["logsBloom"][2:]),
            [
                [
                    bytes.fromhex(log["address"][2:]),
                    [bytes.fromhex(topic[2:]) for topic in log["topics"]],
                    bytes.fromhex(log["data"][2:]),
                ]
                for log in receipt["logs"]
            ],
        ]
    )
    return encoded if kind == 0 else bytes([kind]) + encoded
