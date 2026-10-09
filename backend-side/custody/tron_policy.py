"""TRON preparation and immutable transfer identity for the existing executors."""

import copy
import hashlib
import json
import time

from .chain_registry import get_chain_spec
from .native_tx import FeePolicyError, InsufficientBalance, _cap
from .tron_wire import address_bytes, block_identity, integer, serialize_raw, validate_wire


def transfer_data(destination, units):
    return (
        "a9059cbb"
        + address_bytes(destination)[1:].hex().rjust(64, "0")
        + units.to_bytes(32, "big").hex()
    )


def validate_transfer(tx, source, destination, units, *, contract=None, fee_limit=None):
    digest = validate_wire(tx)
    raw = tx["raw_data"]
    item = raw["contract"][0]
    value = item["parameter"]["value"]
    if address_bytes(value["owner_address"]) != address_bytes(source):
        raise ValueError("TRON source mismatch")
    if contract is None:
        if (
            item["type"] != "TransferContract"
            or value.get("amount") != units
            or address_bytes(value.get("to_address")) != address_bytes(destination)
            or raw.get("fee_limit", 0) != 0
        ):
            raise ValueError("TRON native intent mismatch")
    elif (
        item["type"] != "TriggerSmartContract"
        or address_bytes(value.get("contract_address")) != address_bytes(contract)
        or value.get("data") != transfer_data(destination, units)
        or raw.get("fee_limit") != fee_limit
    ):
        raise ValueError("TRC20 intent or fee limit mismatch")
    return digest


def validity_window(chain_id):
    seconds = _cap(get_chain_spec(chain_id).gas_settings, "mpc_validity_seconds")
    # TRON's protocol maximum is 24 hours. This reviewed policy is much narrower.
    if not 300 <= seconds <= 900:
        raise FeePolicyError("TRON MPC validity must be between 300 and 900 seconds")
    return seconds * 1000


def require_fresh(tx, *, signing=False):
    raw = tx["raw_data"]
    remaining = integer(raw["expiration"]) - int(time.time() * 1000)
    if remaining <= (180_000 if signing else 5_000):
        raise ValueError("TRON transaction is stale; original attempt requires reconciliation")


def freeze_transaction(chain_id, tx, post):
    """Extend expiry ONCE before signing identity exists; never reuse a changed digest."""
    original = validate_wire(tx).hex()
    tx = copy.deepcopy(tx)
    raw = tx["raw_data"]
    now = int(time.time() * 1000)
    timestamp = integer(raw["timestamp"])
    if abs(timestamp - now) > 30_000 or raw["expiration"] <= now:
        raise FeePolicyError("TRON node prepared stale transaction time")
    head = post("/wallet/getnowblock", {})
    height, _, head_time = block_identity(head)
    if abs(head_time - now) > 30_000:
        raise FeePolicyError("TRON head is stale")
    ref = int(raw["ref_block_bytes"], 16)
    ref_height = (height & ~65535) | ref
    if ref_height > height:
        ref_height -= 65536
    if ref_height < 0 or height - ref_height > 2000:
        raise FeePolicyError("TRON TAPOS reference outside reviewed range")
    reference = post("/wallet/getblockbynum", {"num": ref_height})
    number, block_id, _ = block_identity(reference)
    if number != ref_height or bytes.fromhex(block_id)[8:16].hex() != raw["ref_block_hash"]:
        raise ValueError("TRON TAPOS block evidence mismatch")
    raw["expiration"] = timestamp + validity_window(chain_id)
    encoded = serialize_raw(raw)
    # raw_data field framing plus one 65-byte signature, with bounded varint framing.
    if len(encoded) + 80 > _cap(get_chain_spec(chain_id).gas_settings, "max_bandwidth_bytes"):
        raise FeePolicyError("TRON signed transaction exceeds reviewed bandwidth budget")
    tx["raw_data_hex"], tx["txID"] = encoded.hex(), hashlib.sha256(encoded).hexdigest()
    validate_wire(tx)
    require_fresh(tx, signing=True)
    return tx, {
        "node_original_txid": original,
        "tapos_height": number,
        "tapos_block_id": block_id,
        "timestamp_ms": timestamp,
        "expiration_ms": raw["expiration"],
    }


def resource_budget(chain_id, source, destination, post, *, token=False, estimate=None):
    """Conservative full-burn TRX budget; delegated/free resources never justify a grant."""
    caps = get_chain_spec(chain_id).gas_settings
    response = post("/wallet/getchainparameters", {})
    parameters = {p["key"]: integer(p.get("value", 0)) for p in response["chainParameter"]}
    price = parameters["getTransactionFee"]
    if not 0 < price <= _cap(caps, "max_bandwidth_price_sun"):
        raise FeePolicyError("TRON bandwidth price outside reviewed budget")
    bandwidth = _cap(caps, "max_bandwidth_bytes")
    if bandwidth > 4096:
        raise FeePolicyError("TRON bandwidth budget exceeds reviewed transaction shape")
    bandwidth_fee = bandwidth * price
    account = post("/wallet/getaccount", {"address": source, "visible": True})
    if address_bytes(account.get("address")) != address_bytes(source):
        raise ValueError("TRON account identity mismatch")
    owner = account.get("owner_permission")
    if owner is not None and (
        owner.get("threshold") != 1
        or len(owner.get("keys", [])) != 1
        or owner["keys"][0].get("weight") != 1
        or address_bytes(owner["keys"][0].get("address")) != address_bytes(source)
    ):
        raise ValueError("unsupported TRON owner permissions")
    resources = post("/wallet/getaccountresource", {"address": source, "visible": True})
    budget = bandwidth_fee
    if token:
        energy = parameters["getEnergyFee"]
        if not 0 < energy <= _cap(caps, "max_energy_price_sun"):
            raise FeePolicyError("TRON energy price outside reviewed budget")
        required = integer(estimate["energy_required"])
        if estimate.get("result", {}).get("result") is not True or not 0 < required <= _cap(
            caps, "max_energy_units"
        ):
            raise FeePolicyError("TRC20 energy estimate unavailable or outside policy")
        fee_limit = _cap(caps, "max_trc20_fee_limit")
        if fee_limit > 1_000_000_000 or required * energy > fee_limit:
            raise FeePolicyError("TRC20 energy burn exceeds reviewed fee limit")
        budget += fee_limit
    else:
        recipient = post("/wallet/getaccount", {"address": destination, "visible": True})
        if recipient and address_bytes(recipient.get("address")) != address_bytes(destination):
            raise ValueError("TRON recipient account mismatch")
        if not recipient:
            budget += (
                parameters["getCreateAccountFee"]
                + parameters["getCreateNewAccountFeeInSystemContract"]
            )
    if budget > _cap(caps, "max_total_fee_sun"):
        raise FeePolicyError("TRON total fee budget exceeds reviewed maximum")
    balance = integer(account.get("balance", 0))
    if balance < budget:
        raise InsufficientBalance("source TRX cannot fund conservative resource budget")
    return (
        balance,
        budget,
        {
            "worst_case_base_units": str(budget),
            "bandwidth_bytes": str(bandwidth),
            "bandwidth_price_sun": str(price),
            "resource_observation": resources,
            "energy_estimate": estimate or {},
        },
    )


def tron_transaction_identity(attempt, keyset):
    from .models import Asset
    from .mpc_tron_network import network_identity
    from .token_metadata import assert_verified_token

    spec = get_chain_spec(attempt.chain_id)
    asset = Asset.objects.get(asset_key=attempt.asset_key)
    if asset.is_native and (asset.asset_key != spec.native_asset_key or asset.decimals != 6):
        raise ValueError("TRX native asset identity mismatch")
    if not asset.is_native:
        asset = assert_verified_token(asset.asset_key)
        if asset.token_standard != "TRC20" or asset.chain_id != attempt.chain_id:
            raise ValueError("TRC20 asset identity mismatch")
    contract = None if asset.is_native else asset.contract_address
    limit = None if asset.is_native else _cap(spec.gas_settings, "max_trc20_fee_limit")
    validate_transfer(
        attempt.prepared_metadata,
        attempt.from_address,
        attempt.to_address,
        int(attempt.base_unit_amount),
        contract=contract,
        fee_limit=limit,
    )
    raw = attempt.prepared_metadata["raw_data"]
    if raw["expiration"] - raw["timestamp"] != validity_window(attempt.chain_id):
        raise ValueError("persisted TRON validity policy mismatch")
    if attempt.network_tx_id != attempt.prepared_metadata["txID"] or attempt.sequence is not None:
        raise ValueError("TRON attempt identity mismatch")
    if attempt.fee_metadata.get("network") != network_identity(attempt.chain_id):
        raise ValueError("TRON frozen network evidence mismatch")
    if (
        attempt.fee_metadata.get("expiration_ms") != raw["expiration"]
        or attempt.fee_metadata.get("timestamp_ms") != raw["timestamp"]
    ):
        raise ValueError("TRON frozen validity evidence mismatch")
    return {
        "attempt_id": attempt.pk,
        "operation_type": attempt.operation_type,
        "operation_id": attempt.operation_id,
        "chain": attempt.chain_id,
        "asset": attempt.asset_key,
        "token_contract": contract,
        "source": attempt.from_address,
        "destination": attempt.to_address,
        "base_unit_amount": str(int(attempt.base_unit_amount)),
        "unsigned_transaction": attempt.prepared_metadata,
        "fees": attempt.fee_metadata,
        "keyset_id": str(keyset.keyset_id),
        "public_key": keyset.public_key,
        "dkg_fingerprint": keyset.dkg_result_fingerprint,
    }


def assemble_tron_signature(tx, signature):
    validate_wire(tx)
    r, s, v = int(signature["r"], 16), int(signature["s"], 16), signature["recovery_id"]
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    if type(v) is not int or v not in (0, 1) or not 0 < r < order or not 0 < s <= order // 2:
        raise ValueError("noncanonical TRON ECDSA signature")
    signed = copy.deepcopy(tx)
    signed["signature"] = [
        r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex() + bytes([v]).hex()
    ]
    return json.dumps(signed, sort_keys=True, separators=(",", ":")), tx["txID"]
