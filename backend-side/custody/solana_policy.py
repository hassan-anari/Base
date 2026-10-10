"""Reviewed SOL/Classic SPL preparation and immutable custody transaction policy."""

import base64
import hashlib
import struct

from .chain_registry import get_chain_spec, rpc_urls
from .models import Asset
from .mpc_solana_network import guarded_solana_rpc, network_identity, require_fresh
from .native_tx import (
    FeePolicyError,
    InsufficientBalance,
    PreparedNativeTransaction,
    _cap,
    to_base_units,
)
from .solana_wire import SYSTEM_PROGRAM, U64_MAX, build_message, uint, validate_message
from .spl import derive_ata
from .token_metadata import CLASSIC_TOKEN_PROGRAM, assert_verified_token


def account_data(account, owner, size):
    if (
        not isinstance(account, dict)
        or account.get("owner") != owner
        or account.get("executable") is not False
    ):
        raise ValueError("Solana account program owner/executable mismatch")
    value = account["data"]
    if not isinstance(value, list) or len(value) != 2 or value[1] != "base64":
        raise ValueError("canonical binary Solana account data required")
    data = base64.b64decode(value[0], validate=True)
    if len(data) != size:
        raise ValueError("unsupported Solana account size/extensions")
    uint(account["lamports"])
    return data


def validate_mint(account, decimals):
    data = account_data(account, CLASSIC_TOKEN_PROGRAM, 82)
    if data[44] != decimals or data[45] != 1:
        raise ValueError("SPL mint is uninitialized or has wrong decimals")
    if struct.unpack_from("<I", data, 0)[0] not in {0, 1} or struct.unpack_from("<I", data, 46)[
        0
    ] not in {0, 1}:
        raise ValueError("noncanonical SPL mint authority")


def validate_token_account(account, owner, mint, decimals):
    from solders.pubkey import Pubkey

    data = account_data(account, CLASSIC_TOKEN_PROGRAM, 165)
    if (
        data[:32] != bytes(Pubkey.from_string(mint))
        or data[32:64] != bytes(Pubkey.from_string(owner))
        or data[108] != 1
        or struct.unpack_from("<I", data, 72)[0] != 0
        or struct.unpack_from("<I", data, 109)[0] != 0
        or struct.unpack_from("<Q", data, 121)[0] != 0
        or struct.unpack_from("<I", data, 129)[0] != 0
    ):
        raise ValueError("SPL ATA mint/authority/state/delegate/native/close-authority mismatch")
    return struct.unpack_from("<Q", data, 64)[0]


def prepare_solana(transport, chain_id, asset_key, source, destination, amount, *, sweep=False):
    spec = get_chain_spec(chain_id)
    network = network_identity(chain_id)
    asset = Asset.objects.get(asset_key=asset_key, chain_id=chain_id, enabled=True)
    url = rpc_urls(chain_id)[0]

    def rpc(method, params):
        return guarded_solana_rpc(chain_id, url, transport, method, params)

    def account(address):
        return rpc("getAccountInfo", [address, {"encoding": "base64", "commitment": "finalized"}])[
            "value"
        ]

    units = to_base_units(amount, asset.decimals, maximum=U64_MAX)
    source_info = account(source)
    account_data(source_info, SYSTEM_PROGRAM, 0)
    balance = uint(source_info["lamports"])
    system_rent = uint(rpc("getMinimumBalanceForRentExemption", [0]))
    destination_info = None
    rent = 0
    create = False
    token = {}
    raw = {"from": source, "to": destination, "version": "legacy", "feePayer": source}
    if asset.is_native:
        if asset.asset_key != spec.native_asset_key or asset.decimals != 9:
            raise ValueError("SOL native asset identity mismatch")
        destination_info = account(destination)
        if destination_info is not None:
            account_data(destination_info, SYSTEM_PROGRAM, 0)
        elif units < system_rent:
            raise InsufficientBalance(
                "native recipient transfer is below system-account rent minimum"
            )
    else:
        asset = assert_verified_token(asset_key)
        validate_mint(account(asset.contract_address), asset.decimals)
        source_ata = derive_ata(source, asset.contract_address)
        destination_ata = derive_ata(destination, asset.contract_address)
        source_account = account(source_ata)
        token_balance = validate_token_account(
            source_account, source, asset.contract_address, asset.decimals
        )
        if token_balance < units:
            raise InsufficientBalance("SPL source ATA cannot fund exact transfer")
        destination_info = account(destination_ata)
        create = destination_info is None
        if create:
            rent = uint(rpc("getMinimumBalanceForRentExemption", [165]), positive=True)
            if rent > _cap(spec.gas_settings, "max_ata_rent_lamports"):
                raise FeePolicyError("ATA creation exceeds reviewed rent cap")
        else:
            validate_token_account(
                destination_info, destination, asset.contract_address, asset.decimals
            )
        token = {"mint": asset.contract_address, "decimals": asset.decimals, "create_ata": create}
        raw.update(
            {
                "mint": asset.contract_address,
                "sourceAta": source_ata,
                "destinationAta": destination_ata,
                "destinationOwner": destination,
                "tokenAmount": str(units),
                "createDestinationAta": create,
                "tokenMetadataFingerprint": asset.metadata_fingerprint,
            }
        )
    block_response = rpc("getLatestBlockhash", [{"commitment": "finalized"}])
    block = block_response["value"]
    last_valid = uint(block["lastValidBlockHeight"], positive=True)
    require_fresh(chain_id, last_valid, transport, blockhash=block["blockhash"])
    raw.update(
        {
            "recentBlockhash": block["blockhash"],
            "lastValidBlockHeight": last_valid,
            "blockhashContextSlot": uint(block_response["context"]["slot"]),
            "network": network,
        }
    )
    reserve = uint(spec.gas_settings.get("native_reserve_lamports", "0")) if asset.is_native else 0
    fee = 0
    for _ in range(3):
        if sweep and asset.is_native:
            units = min(
                to_base_units(amount, asset.decimals, maximum=U64_MAX), balance - fee - reserve
            )
            remainder = balance - fee - units
            if 0 < remainder < system_rent:
                units = min(units, balance - fee - max(reserve, system_rent))
            if units <= 0:
                raise InsufficientBalance("source cannot fund safe native sweep")
        message = build_message(source, destination, units, block["blockhash"], **token)
        encoded = base64.b64encode(message).decode()
        final_fee = uint(
            rpc("getFeeForMessage", [encoded, {"commitment": "finalized"}])["value"], positive=True
        )
        if final_fee > _cap(spec.gas_settings, "max_fee_lamports"):
            raise FeePolicyError("Solana network fee exceeds reviewed cap")
        if not sweep or not asset.is_native or fee == final_fee:
            fee = final_fee
            break
        fee = final_fee
    else:
        raise FeePolicyError("Solana sweep fee did not converge")
    if balance < (units if asset.is_native else 0) + fee + rent + reserve:
        raise InsufficientBalance("source cannot fund transfer, fee, rent and reserve")
    remainder = balance - (units if asset.is_native else 0) - fee - rent
    if remainder and remainder < system_rent:
        raise InsufficientBalance("source remainder is below system-account rent minimum")
    if asset.is_native:
        raw["lamports"] = units
    raw["message"] = encoded
    validate_message(encoded, source, destination, units, block["blockhash"], **token)
    fees = {
        "fee_lamports": str(fee),
        "ata_rent_lamports": str(rent),
        "reserve_lamports": str(reserve),
        "source_rent_minimum_lamports": str(system_rent),
        "compute_budget": "none",
        "policy": dict(spec.gas_settings),
        "network": network,
        "source_account_fingerprint": hashlib.sha256(str(source_info).encode()).hexdigest(),
    }
    return PreparedNativeTransaction(
        chain_id,
        asset_key,
        source,
        destination,
        amount,
        units,
        message,
        raw,
        fees,
        last_valid_block=last_valid,
    )


def solana_transaction_identity(attempt, keyset):
    raw, fees = attempt.prepared_metadata, attempt.fee_metadata
    spec = get_chain_spec(attempt.chain_id)
    asset = Asset.objects.get(asset_key=attempt.asset_key, chain_id=attempt.chain_id, enabled=True)
    network = network_identity(attempt.chain_id)
    units = uint(str(attempt.base_unit_amount), positive=True)
    if (
        raw.get("network") != network
        or fees.get("network") != network
        or raw.get("from") != attempt.from_address
        or raw.get("to") != attempt.to_address
        or raw.get("feePayer") != attempt.from_address
        or raw.get("version") != "legacy"
        or raw.get("lastValidBlockHeight") != attempt.last_valid_block
        or fees.get("policy") != spec.gas_settings
        or fees.get("compute_budget") != "none"
        or uint(fees["fee_lamports"], positive=True) > _cap(spec.gas_settings, "max_fee_lamports")
    ):
        raise ValueError("Solana immutable source/network/validity/fee policy mismatch")
    uint(raw["blockhashContextSlot"])
    uint(attempt.last_valid_block, positive=True)
    token = {}
    rent = uint(fees["ata_rent_lamports"])
    if asset.is_native:
        if (
            raw.get("lamports") != units
            or asset.asset_key != spec.native_asset_key
            or asset.decimals != 9
            or rent != 0
        ):
            raise ValueError("native SOL amount/asset/rent mismatch")
    else:
        asset = assert_verified_token(attempt.asset_key)
        create = raw.get("createDestinationAta")
        if (
            type(create) is not bool
            or raw.get("mint") != asset.contract_address
            or raw.get("sourceAta") != derive_ata(attempt.from_address, asset.contract_address)
            or raw.get("destinationAta") != derive_ata(attempt.to_address, asset.contract_address)
            or raw.get("destinationOwner") != attempt.to_address
            or raw.get("tokenAmount") != str(units)
            or raw.get("tokenMetadataFingerprint") != asset.metadata_fingerprint
            or (create and not 0 < rent <= _cap(spec.gas_settings, "max_ata_rent_lamports"))
            or (not create and rent != 0)
        ):
            raise ValueError("SPL mint/ATA/amount/rent metadata mismatch")
        token = {"mint": asset.contract_address, "decimals": asset.decimals, "create_ata": create}
    message, decoded = validate_message(
        raw["message"],
        attempt.from_address,
        attempt.to_address,
        units,
        raw["recentBlockhash"],
        **token,
    )
    return {
        "attempt_id": attempt.pk,
        "operation_id": attempt.operation_id,
        "operation_type": attempt.operation_type,
        "chain": attempt.chain_id,
        "network": network,
        "asset": asset.asset_key,
        "mint": None if asset.is_native else asset.contract_address,
        "decimals": asset.decimals,
        "source": attempt.from_address,
        "destination": attempt.to_address,
        "base_unit_amount": str(units),
        "fee_payer": attempt.from_address,
        "signers": [keyset.public_key],
        "version": "legacy",
        "message_hex": message.hex(),
        "instructions": decoded,
        "unsigned_transaction": dict(raw),
        "fees": dict(fees),
        "keyset_id": str(keyset.keyset_id),
        "public_key": keyset.public_key,
        "dkg_fingerprint": keyset.dkg_result_fingerprint,
    }
