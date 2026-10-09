"""Strict protobuf serialization for reviewed TRON custody shapes.

Field numbers are from tronprotocol/protocol core/Tron.proto and
core/contract/{balance,smart_contract}.proto. Unknown fields, permissions,
multi-contract transactions and attached TRX/token values fail closed.
This is a small allowlisted serializer, not a general protobuf decoder.
"""

import hashlib

import base58


def integer(value, *, maximum=2**63 - 1):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("invalid TRON integer")
    return value


def hex_bytes(value, size=None):
    if not isinstance(value, str) or value != value.lower():
        raise ValueError("noncanonical TRON hex")
    raw = bytes.fromhex(value)
    if raw.hex() != value or (size is not None and len(raw) != size):
        raise ValueError("invalid TRON hex length")
    return raw


def address_bytes(value):
    if isinstance(value, str) and len(value) == 42:
        raw = hex_bytes(value, 21)
    else:
        raw = base58.b58decode_check(value)
        if base58.b58encode_check(raw).decode() != value:
            raise ValueError("noncanonical TRON address")
    if len(raw) != 21 or raw[0] != 0x41:
        raise ValueError("invalid TRON address prefix")
    return raw


def _shape(body, allowed, required=()):
    if not isinstance(body, dict) or set(body) - set(allowed) or set(required) - set(body):
        raise ValueError("unsupported TRON protobuf fields")


def _varint(value):
    value = integer(value)
    out = bytearray()
    while value > 127:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def _uint(field, value):
    value = integer(value)
    return _varint(field << 3) + _varint(value) if value else b""


def _bytes(field, value):
    return _varint(field << 3 | 2) + _varint(len(value)) + value if value else b""


def serialize_raw(raw):
    _shape(
        raw,
        {"ref_block_bytes", "ref_block_hash", "expiration", "contract", "timestamp", "fee_limit"},
        {"ref_block_bytes", "ref_block_hash", "expiration", "contract", "timestamp"},
    )
    contracts = raw["contract"]
    if not isinstance(contracts, list) or len(contracts) != 1:
        raise ValueError("exactly one TRON contract is required")
    contract = contracts[0]
    _shape(contract, {"type", "parameter", "Permission_id"}, {"type", "parameter"})
    if integer(contract.get("Permission_id", 0)) != 0:
        raise ValueError("custom TRON permissions are unsupported")
    parameter = contract["parameter"]
    _shape(parameter, {"type_url", "value"}, {"type_url", "value"})
    name = contract["type"]
    if parameter["type_url"] != "type.googleapis.com/protocol." + name:
        raise ValueError("TRON Any contract type mismatch")
    value = parameter["value"]
    if name == "TransferContract":
        _shape(
            value,
            {"owner_address", "to_address", "amount"},
            {"owner_address", "to_address", "amount"},
        )
        number = 1
        encoded = (
            _bytes(1, address_bytes(value["owner_address"]))
            + _bytes(2, address_bytes(value["to_address"]))
            + _uint(3, value["amount"])
        )
    elif name == "TriggerSmartContract":
        _shape(
            value,
            {
                "owner_address",
                "contract_address",
                "data",
                "call_value",
                "call_token_value",
                "token_id",
            },
            {"owner_address", "contract_address", "data"},
        )
        if any(integer(value.get(k, 0)) for k in ("call_value", "call_token_value", "token_id")):
            raise ValueError("attached contract values are unsupported")
        number = 31
        encoded = (
            _bytes(1, address_bytes(value["owner_address"]))
            + _bytes(2, address_bytes(value["contract_address"]))
            + _bytes(4, hex_bytes(value["data"]))
        )
    else:
        raise ValueError("unsupported TRON contract type")
    any_message = _bytes(1, parameter["type_url"].encode()) + _bytes(2, encoded)
    contract_message = _uint(1, number) + _bytes(2, any_message)
    return (
        _bytes(1, hex_bytes(raw["ref_block_bytes"], 2))
        + _bytes(4, hex_bytes(raw["ref_block_hash"], 8))
        + _uint(8, raw["expiration"])
        + _bytes(11, contract_message)
        + _uint(14, raw["timestamp"])
        + _uint(18, raw.get("fee_limit", 0))
    )


def validate_wire(tx):
    _shape(
        tx, {"raw_data", "raw_data_hex", "txID", "visible"}, {"raw_data", "raw_data_hex", "txID"}
    )
    if "visible" in tx and type(tx["visible"]) is not bool:
        raise ValueError("invalid TRON visibility")
    raw = serialize_raw(tx["raw_data"])
    if raw != hex_bytes(tx["raw_data_hex"]) or hashlib.sha256(raw).hexdigest() != tx["txID"]:
        raise ValueError("TRON raw_data protobuf / txID mismatch")
    return bytes.fromhex(tx["txID"])


def block_identity(block):
    """Independently recompute BlockId = height || SHA256(BlockHeader.raw)[8:]."""
    raw = block["block_header"]["raw_data"]
    _shape(
        raw,
        {
            "timestamp",
            "txTrieRoot",
            "parentHash",
            "number",
            "witness_id",
            "witness_address",
            "version",
            "accountStateRoot",
        },
    )
    height = integer(raw.get("number", 0))
    encoded = (
        _uint(1, raw.get("timestamp", 0))
        + _bytes(2, hex_bytes(raw.get("txTrieRoot", "")))
        + _bytes(3, hex_bytes(raw.get("parentHash", "")))
        + _uint(7, height)
        + _uint(8, raw.get("witness_id", 0))
        + _bytes(9, hex_bytes(raw.get("witness_address", "")))
        + _uint(10, raw.get("version", 0))
        + _bytes(11, hex_bytes(raw.get("accountStateRoot", "")))
    )
    expected = (height.to_bytes(8, "big") + hashlib.sha256(encoded).digest()[8:]).hex()
    if block.get("blockID") != expected:
        raise ValueError("TRON block header / blockID mismatch")
    return height, expected, raw.get("timestamp", 0)
