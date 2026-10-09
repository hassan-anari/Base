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
TRANSFER_TOPIC = "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


def _positive_block_number(value) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


class TrxIndexer(IndexerClient):
    def __init__(self, chain_id: str = "TRX"):
        super().__init__(chain_id)

    def get_balance(
        self, address: str, *, asset_key=None, after_block=None, memo=None
    ) -> BalanceResult:
        from django.conf import settings

        if self._stub_enabled():
            if settings.MPC_SIGNER_BACKEND == "self_hosted_mpc":
                raise IndexerUnavailable("TRON MPC indexing forbids simulated balances")
            return self._stub_balance(asset_key=asset_key)
        from ..models import Asset

        asset = Asset.objects.filter(
            asset_key=asset_key, chain_id=self.chain_id, enabled=True
        ).first()
        if settings.MPC_SIGNER_BACKEND == "self_hosted_mpc":
            if asset is None:
                raise IndexerUnavailable("explicit verified TRON balance asset required")
            return self._mpc_balance(asset, address, after_block)
        if asset and not asset.is_native:
            return self._token_balance(asset, address, after_block)
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

    def _token_balance(self, asset, address, after_block):
        from ..chain_registry import get_chain_spec
        from ..token_metadata import assert_verified_token, tron_address_hex

        assert_verified_token(asset.asset_key)
        settings = get_chain_spec(self.chain_id).gas_settings
        lookback = int(settings.get("token_initial_lookback_blocks", 1000))
        overlap = int(settings.get("token_reorg_overlap_blocks", 20))
        chunk = int(settings.get("token_log_chunk_blocks", 100))
        contract_hex = tron_address_hex(asset.contract_address)
        owner_hex = tron_address_hex(address)
        parameter = owner_hex.removeprefix("41").rjust(64, "0")
        last_error = None
        for url in rpc_urls(self.chain_id):
            try:
                base = url.rstrip("/")
                call = requests.post(
                    base + "/wallet/triggerconstantcontract",
                    json={
                        "owner_address": address,
                        "contract_address": asset.contract_address,
                        "function_selector": "balanceOf(address)",
                        "parameter": parameter,
                        "visible": True,
                    },
                    timeout=RPC_TIMEOUT,
                )
                call.raise_for_status()
                units = int(call.json()["constant_result"][0], 16)
                head_resp = requests.post(
                    base + "/walletsolidity/getnowblock", json={}, timeout=RPC_TIMEOUT
                )
                head_resp.raise_for_status()
                head_body = head_resp.json()
                head = int(head_body["block_header"]["raw_data"]["number"])
                start = max(
                    0, after_block - overlap if after_block is not None else head - lookback
                )
                events = []
                for first in range(start, head + 1, chunk):
                    for number in range(first, min(head, first + chunk - 1) + 1):
                        block_resp = requests.post(
                            base + "/walletsolidity/getblockbynum",
                            json={"num": number},
                            timeout=RPC_TIMEOUT,
                        )
                        block_resp.raise_for_status()
                        block = block_resp.json()
                        block_hash = block.get("blockID")
                        for tx in block.get("transactions", []):
                            contracts = tx.get("raw_data", {}).get("contract", [])
                            if not any(c.get("type") == "TriggerSmartContract" for c in contracts):
                                continue
                            txid = tx.get("txID")
                            info_resp = requests.post(
                                base + "/walletsolidity/gettransactioninfobyid",
                                json={"value": txid},
                                timeout=RPC_TIMEOUT,
                            )
                            info_resp.raise_for_status()
                            info = info_resp.json()
                            if not info or info.get("blockNumber") is None:
                                raise IndexerUnavailable(
                                    "solidified TRC20 TransactionInfo is unavailable"
                                )
                            result = info.get("receipt", {}).get("result")
                            if result is None:
                                raise IndexerUnavailable(
                                    "solidified TRC20 execution status is unavailable"
                                )
                            if str(result).upper() != "SUCCESS" or info.get("result") == "FAILED":
                                continue
                            for idx, log in enumerate(info.get("log", [])):
                                topics = log.get("topics") or []
                                emitting = str(log.get("address", "")).lower().removeprefix("0x")
                                if emitting.startswith("41"):
                                    emitting = emitting[2:]
                                if (
                                    len(topics) != 3
                                    or topics[0].lower().removeprefix("0x") != TRANSFER_TOPIC
                                ):
                                    continue
                                if emitting != contract_hex[2:].lower():
                                    continue
                                destination = topics[2].lower().removeprefix("0x")[-40:]
                                if destination != owner_hex[2:].lower():
                                    continue
                                amount = int(str(log.get("data", "0")), 16)
                                if amount <= 0:
                                    continue
                                events.append(
                                    DepositEvent(
                                        tx_hash=txid,
                                        amount=Decimal(amount) / (Decimal(10) ** asset.decimals),
                                        block=number,
                                        confirmations=max(0, head - number + 1),
                                        asset_key=asset.asset_key,
                                        event_index=f"log:{idx}",
                                        block_hash=block_hash,
                                        contract_address=asset.contract_address,
                                    )
                                )
                return BalanceResult(
                    Decimal(units) / (Decimal(10) ** asset.decimals),
                    last_scanned_block=head,
                    deposit_events=events,
                )
            except Exception as exc:
                last_error = exc
        raise IndexerUnavailable("TRC20 solidified scan unavailable") from last_error

    def _mpc_balance(self, asset, address, after_block):
        """Bounded solidified backfill; balance observations alone never credit the ledger."""
        import hashlib

        from ..chain_registry import get_chain_spec
        from ..mpc_tron_network import guarded_tron_post, verify_tron_rpc_endpoints
        from ..native_tx import RequestsTransport
        from ..token_metadata import assert_verified_token
        from ..tron_wire import address_bytes, block_identity, integer, serialize_raw

        spec = get_chain_spec(self.chain_id)
        transport = RequestsTransport()
        verify_tron_rpc_endpoints(self.chain_id, transport)
        owner = address_bytes(address)

        def amount(units):
            integer(units, maximum=2**256 - 1)
            # Decimal division uses ambient precision and may round a token integer.
            return Decimal(f"{units}e-{asset.decimals}")

        if not asset.is_native:
            asset = assert_verified_token(asset.asset_key)
        caps = spec.gas_settings
        lookback = int(caps.get("token_initial_lookback_blocks", 1000))
        overlap = int(caps.get("token_reorg_overlap_blocks", 20))
        chunk = int(caps.get("token_log_chunk_blocks", 100))
        if not 0 <= overlap <= 100 or not 1 <= lookback <= 10000 or not overlap + 1 < chunk <= 1000:
            raise IndexerUnavailable("TRON scan bounds outside reviewed policy")
        last_error = None
        for url in rpc_urls(self.chain_id):
            try:

                def post(path, body):
                    return guarded_tron_post(self.chain_id, url, transport, path, body)

                if asset.is_native:
                    account = post(
                        "/walletsolidity/getaccount", {"address": address, "visible": True}
                    )
                    if account and address_bytes(account.get("address")) != owner:
                        raise ValueError("solidified TRON account mismatch")
                    units = integer(account.get("balance", 0))
                else:
                    balance = post(
                        "/walletsolidity/triggerconstantcontract",
                        {
                            "owner_address": address,
                            "contract_address": asset.contract_address,
                            "function_selector": "balanceOf(address)",
                            "parameter": owner[1:].hex().rjust(64, "0"),
                            "visible": True,
                        },
                    )
                    if (
                        balance.get("result", {}).get("result") is not True
                        or len(bytes.fromhex(balance["constant_result"][0])) != 32
                    ):
                        raise ValueError("solidified TRC20 balance evidence mismatch")
                    units = int(balance["constant_result"][0], 16)
                head, _, _ = block_identity(post("/walletsolidity/getnowblock", {}))
                # Genesis allocations are not incoming, signed deposit transfers.
                start = max(
                    1, after_block - overlap if after_block is not None else head - lookback
                )
                end = min(head, start + chunk - 1)
                events = []
                for number in range(start, end + 1):
                    block = post("/walletsolidity/getblockbynum", {"num": number})
                    height, block_hash, timestamp = block_identity(block)
                    if height != number:
                        raise ValueError("TRON scan block number mismatch")
                    for tx in block.get("transactions", []):
                        contracts = tx.get("raw_data", {}).get("contract", [])
                        if not contracts or contracts[0].get("type") != (
                            "TransferContract" if asset.is_native else "TriggerSmartContract"
                        ):
                            continue
                        txid = tx["txID"]
                        raw = serialize_raw(tx["raw_data"])
                        if (
                            hashlib.sha256(raw).hexdigest() != txid
                            or tx.get("raw_data_hex") != raw.hex()
                        ):
                            raise ValueError("TRON deposit txID mismatch")
                        info = post("/walletsolidity/gettransactioninfobyid", {"value": txid})
                        if (
                            info.get("id") != txid
                            or info.get("blockNumber") != number
                            or info.get("blockTimeStamp") != timestamp
                        ):
                            raise ValueError("TRON deposit inclusion mismatch")
                        if not (
                            len(tx.get("ret", [])) == 1
                            and tx["ret"][0].get("contractRet") == "SUCCESS"
                        ):
                            continue
                        if info.get("result") == "FAILED":
                            raise ValueError("TRON deposit execution evidence disagreement")
                        effects = []
                        if asset.is_native:
                            value = contracts[0]["parameter"]["value"]
                            if address_bytes(value["to_address"]) == owner:
                                effects.append(("contract:0", value["amount"]))
                        else:
                            if (
                                info.get("receipt", {}).get("result") != "SUCCESS"
                                or info.get("result") == "FAILED"
                            ):
                                continue
                            for index, log in enumerate(info.get("log", [])):
                                topics = log.get("topics", [])
                                if (
                                    log.get("address")
                                    == address_bytes(asset.contract_address)[1:].hex()
                                    and len(topics) == 3
                                    and topics[0] == TRANSFER_TOPIC
                                    and len(bytes.fromhex(topics[1])) == 32
                                    and topics[1][:24] == "0" * 24
                                    and topics[2] == owner[1:].hex().rjust(64, "0")
                                    and len(bytes.fromhex(log["data"])) == 32
                                ):
                                    effects.append((f"log:{index}", int(log["data"], 16)))
                        for event_index, effect_units in effects:
                            if effect_units > 0:
                                events.append(
                                    DepositEvent(
                                        tx_hash=txid,
                                        amount=amount(effect_units),
                                        block=number,
                                        confirmations=head - number + 1,
                                        asset_key=asset.asset_key,
                                        event_index=event_index,
                                        block_hash=block_hash,
                                        contract_address=asset.contract_address,
                                    )
                                )
                return BalanceResult(
                    amount(units),
                    last_scanned_block=end,
                    deposit_events=events,
                )
            except Exception as exc:
                last_error = exc
        raise IndexerUnavailable("TRON pinned solidified scan unavailable") from last_error

    def get_txs(self, address: str, after_block=None, memo=None):
        return []
