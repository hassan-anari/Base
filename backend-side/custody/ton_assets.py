"""Operator master allowlist plus proof-bound, pinned TEP-74 contract states."""

from django.conf import settings

from .ton_wire import (
    JETTON_MASTER_CODE_HASH,
    JETTON_WALLET_CODE_HASH,
    jetton_wallet_address,
    normalize_address,
    verify_jetton_wallet,
)


def verified_master(asset, client, checkpoint):
    master = normalize_address(asset.contract_address).raw
    pins = settings.MPC_TON_NETWORK.get("jetton_masters", {})
    pin = pins.get(master)
    if (
        not pin
        or pin.get("decimals") != asset.decimals
        or pin.get("wallet_code_hash") != JETTON_WALLET_CODE_HASH
        or pin.get("master_code_hash") != JETTON_MASTER_CODE_HASH
        or not pin.get("provenance")
    ):
        raise ValueError("Jetton master requires independently established operator allowlist")
    state = client.account(master, checkpoint)
    if state["status"] != "active" or state["code"].hash.hex() != JETTON_MASTER_CODE_HASH:
        raise ValueError("unknown Jetton master contract")
    s = state["data"].begin_parse()
    s.load_coins()
    s.load_address()
    content = s.load_ref()
    code = s.load_ref()
    if (
        code.hash.hex() != JETTON_WALLET_CODE_HASH
        or content.hash.hex() != pin.get("content_hash")
        or s.remaining_bits
        or s.remaining_refs
    ):
        raise ValueError("Jetton master wallet code/metadata mismatch")
    # The reviewed getter derives exactly this StateInit from owner + master +
    # the pinned wallet code. No symbol or remote getter overrides that identity.
    return master


def verified_asset_wallet(asset, owner, client, checkpoint, *, allow_uninit=False):
    master = verified_master(asset, client, checkpoint)
    address = jetton_wallet_address(owner, master)
    state = client.account(address, checkpoint)
    if state["status"] == "uninit" and allow_uninit:
        return address, 0
    balance = verify_jetton_wallet(address, owner, master, state["code"], state["data"], address)
    client.jetton_getters(owner, master, address, state["data"], balance, checkpoint)
    return address, balance
