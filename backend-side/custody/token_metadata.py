"""Reviewed token allow-list verification.

Verification is deliberately separate from activation.  It reads current runtime
RPC endpoints and binds chain, address, standard, decimals and program identity
in a SHA-256 fingerprint. Money-moving code recomputes that fingerprint.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import base58
from django.db import transaction
from django.utils import timezone
from eth_utils import is_address, to_checksum_address

from .chain_registry import ChainKind, get_chain_spec, rpc_urls
from .models import Asset
from .native_tx import RequestsTransport

CLASSIC_TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"


class TokenVerificationError(ValueError):
    pass


def tron_address_hex(value: str) -> str:
    """Return TRON's canonical 21-byte 41-prefixed hexadecimal address."""
    value = str(value).strip()
    if len(value) == 42 and value.lower().startswith("41"):
        bytes.fromhex(value)
        return value.lower()
    try:
        raw = base58.b58decode_check(value)
    except Exception as exc:
        raise TokenVerificationError("invalid TRON address") from exc
    if len(raw) != 21 or raw[0] != 0x41:
        raise TokenVerificationError("invalid TRON address")
    return raw.hex()


def canonical_contract(kind: ChainKind, value: str) -> str:
    value = (value or "").strip()
    if kind is ChainKind.EVM:
        if not is_address(value):
            raise TokenVerificationError("invalid EVM token contract")
        return to_checksum_address(value)
    if kind in {ChainKind.TRON, ChainKind.SOLANA}:
        try:
            raw = (
                base58.b58decode_check(value) if kind is ChainKind.TRON else base58.b58decode(value)
            )
        except Exception as exc:
            raise TokenVerificationError(f"invalid {kind.value} token address") from exc
        expected = 21 if kind is ChainKind.TRON else 32
        if len(raw) != expected:
            raise TokenVerificationError(f"invalid {kind.value} token address")
        return value
    raise TokenVerificationError("tokens are not supported on this chain family")


def expected_standard(kind: ChainKind) -> str:
    try:
        return {ChainKind.EVM: "ERC20", ChainKind.TRON: "TRC20", ChainKind.SOLANA: "SPL"}[kind]
    except KeyError as exc:
        raise TokenVerificationError("tokens are not supported on this chain family") from exc


def metadata_fingerprint(asset: Asset | Any, *, program: str = "") -> str:
    spec = get_chain_spec(asset.chain_id)
    contract = canonical_contract(spec.kind, asset.contract_address)
    if spec.kind is ChainKind.EVM:
        contract = contract.lower()
    body = {
        "chain_id": spec.chain_id,
        "contract": contract,
        "decimals": int(asset.decimals),
        "standard": asset.token_standard,
        "program": program or (CLASSIC_TOKEN_PROGRAM if asset.token_standard == "SPL" else ""),
    }
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def assert_verified_token(asset_key: str) -> Asset:
    try:
        asset = Asset.objects.get(asset_key=asset_key, enabled=True, is_native=False)
    except Asset.DoesNotExist as exc:
        raise ValueError(f"token asset {asset_key} is unavailable") from exc
    spec = get_chain_spec(asset.chain_id)
    if asset.token_standard != expected_standard(spec.kind):
        raise ValueError("token standard does not match chain family")
    if not asset.metadata_verified_at or not asset.metadata_fingerprint:
        raise ValueError(f"non-native asset {asset_key} has not been verified")
    if asset.metadata_fingerprint != metadata_fingerprint(asset):
        raise ValueError(f"token asset {asset_key} verification is stale")
    return asset


def _hex_uint(value: Any) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise TokenVerificationError("contract call did not return ABI uint256")
    raw = bytes.fromhex(value[2:])
    if len(raw) != 32:
        raise TokenVerificationError("contract call returned invalid ABI uint256")
    return int.from_bytes(raw, "big")


def _rpc(transport, url: str, method: str, params: list[Any]):
    return transport.rpc(url, method, params)


def verify_token_asset(asset_key: str, *, transport=None) -> Asset:
    """Verify identity metadata without enabling any capability flags."""
    transport = transport or RequestsTransport()
    with transaction.atomic():
        try:
            asset = Asset.objects.select_for_update().get(asset_key=asset_key)
        except Asset.DoesNotExist as exc:
            raise TokenVerificationError("unknown token asset") from exc
        if asset.is_native:
            raise TokenVerificationError("native assets do not use token verification")
        spec = get_chain_spec(asset.chain_id)
        standard = expected_standard(spec.kind)
        if asset.token_standard != standard:
            raise TokenVerificationError(f"{spec.kind.value} requires {standard}")
        asset.contract_address = canonical_contract(spec.kind, asset.contract_address)
        url = rpc_urls(spec.chain_id)[0]
        if standard == "ERC20":
            code = _rpc(transport, url, "eth_getCode", [asset.contract_address, "latest"])
            if not code or code in {"0x", "0x0"}:
                raise TokenVerificationError("token contract has no deployed bytecode")
            decimals = _hex_uint(
                _rpc(
                    transport,
                    url,
                    "eth_call",
                    [{"to": asset.contract_address, "data": "0x313ce567"}, "latest"],
                )
            )
            # balanceOf(address(0)); successful ABI uint proves the reviewed selector is callable.
            _hex_uint(
                _rpc(
                    transport,
                    url,
                    "eth_call",
                    [{"to": asset.contract_address, "data": "0x70a08231" + "0" * 64}, "latest"],
                )
            )
        elif standard == "TRC20":
            zero = "00" * 20
            common = {
                "contract_address": asset.contract_address,
                "owner_address": asset.contract_address,
                "visible": True,
            }
            dec = transport.post(
                url,
                "/wallet/triggerconstantcontract",
                {**common, "function_selector": "decimals()", "parameter": ""},
            )
            bal = transport.post(
                url,
                "/wallet/triggerconstantcontract",
                {
                    **common,
                    "function_selector": "balanceOf(address)",
                    "parameter": zero.rjust(64, "0"),
                },
            )
            try:
                decimals = int((dec["constant_result"][0]), 16)
                int(bal["constant_result"][0], 16)
            except (KeyError, IndexError, TypeError, ValueError) as exc:
                raise TokenVerificationError("TRC20 constant contract call failed") from exc
        else:
            info = _rpc(
                transport,
                url,
                "getAccountInfo",
                [asset.contract_address, {"encoding": "jsonParsed", "commitment": "finalized"}],
            )
            value = (info or {}).get("value")
            if not value:
                raise TokenVerificationError("SPL mint does not exist")
            owner = value.get("owner")
            if owner != CLASSIC_TOKEN_PROGRAM:
                if owner == TOKEN_2022_PROGRAM:
                    raise TokenVerificationError("Token-2022 is unsupported")
                raise TokenVerificationError("mint is not owned by classic Token Program")
            try:
                decimals = int(value["data"]["parsed"]["info"]["decimals"])
            except (KeyError, TypeError, ValueError) as exc:
                raise TokenVerificationError("invalid SPL mint account") from exc
        if decimals != asset.decimals:
            raise TokenVerificationError("configured decimals do not match on-chain decimals")
        if not 0 <= decimals <= 18:
            raise TokenVerificationError("token decimals exceed authoritative ledger precision")
        asset.metadata_fingerprint = metadata_fingerprint(asset)
        asset.metadata_verified_at = timezone.now()
        # This is the sole boundary allowed to bind a changed canonical identity
        # and a fresh fingerprint atomically; Asset.save otherwise invalidates it.
        Asset.objects.filter(pk=asset.pk).update(
            contract_address=asset.contract_address,
            metadata_fingerprint=asset.metadata_fingerprint,
            metadata_verified_at=asset.metadata_verified_at,
        )
        return asset
