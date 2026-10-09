"""Deterministic RPC emulator only. It does not establish TRON network acceptance."""

import copy
import hashlib
import time

from eth_keys import keys

from custody.mpc_tron_network import ISOLATED_PARENT
from custody.tron_wire import _bytes, _uint, address_bytes, serialize_raw

CAPS = {
    "mpc_validity_seconds": 600,
    "max_bandwidth_bytes": 1000,
    "max_bandwidth_price_sun": 1000,
    "max_energy_price_sun": 500,
    "max_energy_units": 100000,
    "max_trc20_fee_limit": 50000000,
    "max_total_fee_sun": 51000000,
    "topup_amount": "60",
    "token_initial_lookback_blocks": 10,
    "token_reorg_overlap_blocks": 1,
    "token_log_chunk_blocks": 10,
}


def block(number, timestamp, *, transactions=(), parent=None):
    raw = {
        "timestamp": timestamp,
        "number": number,
        "parentHash": parent or "aa" * 32,
        "txTrieRoot": "bb" * 32,
        "witness_address": "41" + "cc" * 20,
        "version": 1,
    }
    encoded = (
        _uint(1, timestamp)
        + _bytes(2, bytes.fromhex(raw["txTrieRoot"]))
        + _bytes(3, bytes.fromhex(raw["parentHash"]))
        + _uint(7, number)
        + _bytes(9, bytes.fromhex(raw["witness_address"]))
        + _uint(10, 1)
    )
    return {
        "blockID": (number.to_bytes(8, "big") + hashlib.sha256(encoded).digest()[8:]).hex(),
        "block_header": {"raw_data": raw},
        "transactions": list(transactions),
    }


def transaction(source, destination, units, *, token=None, fee_limit=50000000, reference=None):
    now = int(time.time() * 1000)
    ref = reference or block(2, now)
    name = "TriggerSmartContract" if token else "TransferContract"
    value = {"owner_address": address_bytes(source).hex()}
    if token:
        value.update(
            contract_address=address_bytes(token).hex(),
            data="a9059cbb"
            + address_bytes(destination)[1:].hex().rjust(64, "0")
            + units.to_bytes(32, "big").hex(),
        )
    else:
        value.update(to_address=address_bytes(destination).hex(), amount=units)
    raw = {
        "ref_block_bytes": ref["blockID"][12:16],
        "ref_block_hash": ref["blockID"][16:32],
        "timestamp": now,
        "expiration": now + 60000,
        "contract": [
            {
                "type": name,
                "parameter": {"type_url": "type.googleapis.com/protocol." + name, "value": value},
            }
        ],
    }
    if token:
        raw["fee_limit"] = fee_limit
    encoded = serialize_raw(raw)
    return {
        "txID": hashlib.sha256(encoded).hexdigest(),
        "raw_data": raw,
        "raw_data_hex": encoded.hex(),
        "visible": False,
    }


class RpcEmulator:
    def __init__(self, source, destination, token):
        self.source, self.destination, self.token = source, destination, token
        self.submissions, self.transactions, self.receipts = [], {}, {}
        self.anchor = block(0, 0, parent=ISOLATED_PARENT)
        self.checkpoint = block(1, 1000)
        self.head = block(2, int(time.time() * 1000))
        self.blocks = {2: copy.deepcopy(self.head)}
        self.balance = 2000000000
        self.failure = None

    def policy(self, url="http://127.0.0.1:18809"):
        return {
            "network": "isolated-v1",
            "genesis_block_id": self.anchor["blockID"],
            "checkpoint_height": 1,
            "checkpoint_block_id": self.checkpoint["blockID"],
            "trusted_endpoints": [url],
        }

    def post(self, url, path, body):
        if path.endswith("getblockbynum"):
            number = body["num"]
            if number == self.head["block_header"]["raw_data"]["number"]:
                return copy.deepcopy(self.head)
            return copy.deepcopy(
                {0: self.anchor, 1: self.checkpoint, **self.blocks}.get(number, self.head)
            )
        if path.endswith("getnowblock"):
            return copy.deepcopy(self.head)
        if path.endswith("getchainparameters"):
            values = {
                "getTransactionFee": 1000,
                "getEnergyFee": 420,
                "getCreateAccountFee": 100000,
                "getCreateNewAccountFeeInSystemContract": 1000000,
            }
            return {"chainParameter": [{"key": k, "value": v} for k, v in values.items()]}
        if path.endswith("getaccountresource"):
            return {"EnergyLimit": 0, "freeNetLimit": 600}
        if path.endswith("getaccount"):
            return {"address": address_bytes(body["address"]).hex(), "balance": self.balance}
        if path.endswith("getcontract"):
            return {"contract_address": address_bytes(body["value"]).hex(), "bytecode": "6000"}
        if path.endswith("triggerconstantcontract"):
            value = 6 if body["function_selector"] == "decimals()" else 1000000000
            return {"result": {"result": True}, "constant_result": [f"{value:064x}"]}
        if path.endswith("estimateenergy"):
            return {"result": {"result": True}, "energy_required": 30000}
        if path.endswith("createtransaction"):
            return transaction(
                body["owner_address"], body["to_address"], body["amount"], reference=self.head
            )
        if path.endswith("triggersmartcontract"):
            data = body["parameter"]
            tx = transaction(
                body["owner_address"],
                "41" + data[24:64],
                int(data[64:], 16),
                token=body["contract_address"],
                fee_limit=body["fee_limit"],
                reference=self.head,
            )
            return {"result": {"result": True}, "transaction": tx}
        if path.endswith("broadcasttransaction"):
            self.submissions.append(copy.deepcopy(body))
            self.include(body)
            if self.failure:
                raise self.failure
            return {"result": True, "txid": body["txID"]}
        if path.endswith("gettransactioninfobyid"):
            return copy.deepcopy(self.receipts.get(body["value"], {}))
        if path.endswith("gettransactionbyid"):
            return copy.deepcopy(self.transactions.get(body["value"], {}))
        raise AssertionError(path)

    def include(self, signed):
        tx = copy.deepcopy(signed)
        raw = bytes.fromhex(tx["signature"][0])
        signature = keys.Signature(raw)
        public = signature.recover_public_key_from_msg_hash(bytes.fromhex(tx["txID"]))
        value = tx["raw_data"]["contract"][0]["parameter"]["value"]
        assert public.to_canonical_address() == address_bytes(value["owner_address"])[1:]
        tx["ret"] = [{"contractRet": "SUCCESS"}]
        self.transactions[tx["txID"]] = tx
        self.head = block(3, int(time.time() * 1000), transactions=[tx])
        info = {
            "id": tx["txID"],
            "blockNumber": 3,
            "blockTimeStamp": self.head["block_header"]["raw_data"]["timestamp"],
            "receipt": {},
        }
        if "data" in value:
            data = value["data"]
            info["receipt"]["result"] = "SUCCESS"
            info["log"] = [
                {
                    "address": address_bytes(self.token)[1:].hex(),
                    "topics": [
                        "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                        address_bytes(self.source)[1:].hex().rjust(64, "0"),
                        data[8:72],
                    ],
                    "data": data[72:],
                }
            ]
        self.receipts[tx["txID"]] = info
