"""One pinned V5R1 contract, strict TL-B shapes and public-only Ed25519 assembly.

pytoniq-core serializes cells; Rust independently reconstructs the signing cell.
The representation hash is the signing input, not the BOC or its SHA-256.
"""

import base64
import re
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pytoniq_core import Address, Builder, Cell, ExternalMsgInfo, MessageAny, StateInit
from pytoniq_core.crypto.crc import crc16

WALLET_VERSION = "V5R1"
WALLET_CODE_HASH = "20834b7b72b112147e1b2fb457b84e74d1a30f04f737d4f62a668e9552d2b72f"
JETTON_WALLET_CODE_HASH = "a760d629d5343e76d045017d9dc216fc8a307a8377815feb2b0a5c490e733486"
JETTON_MASTER_CODE_HASH = "f95ba0330b38cdf3459b1e811e5fc6fa6cfee566d7b764455c0468140365a737"
TRANSFER = 0x0F8A7EA5
INTERNAL_TRANSFER = 0x178D4519
NOTIFICATION = 0x7362D09C
EXCESSES = 0xD53276DB
SEND_MODE = 3  # V5 external MUST use +2; terminal delivery proof remains mandatory.


@dataclass(frozen=True)
class TonAddress:
    raw: str
    workchain: int
    bounceable: bool | None
    test_only: bool | None


def normalize_address(value: str, *, require_test: bool = False) -> TonAddress:
    """Raw addresses carry no display bounce/network flags. Never infer them."""
    if not isinstance(value, str) or value != value.strip():
        raise ValueError("invalid TON address encoding")
    match = re.fullmatch(r"(-?\d+):([0-9a-fA-F]{64})", value)
    if match:
        wc = int(match[1])
        if not -128 <= wc <= 127:
            raise ValueError("unsupported TON workchain")
        return TonAddress(f"{wc}:{match[2].lower()}", wc, None, None)
    if not re.fullmatch(r"[A-Za-z0-9_+/\-]{48}", value):
        raise ValueError("invalid TON friendly address")
    raw = base64.b64decode(value.replace("-", "+").replace("_", "/"), validate=True)
    if len(raw) != 36 or raw[34:] != crc16(raw[:34]) or raw[0] not in (0x11, 0x51, 0x91, 0xD1):
        raise ValueError("invalid TON address checksum/tag")
    wc = int.from_bytes(raw[1:2], "big", signed=True)
    test = bool(raw[0] & 0x80)
    if require_test and not test:
        raise ValueError("mainnet friendly identity is forbidden")
    return TonAddress(f"{wc}:{raw[2:34].hex()}", wc, raw[0] & 0x7F == 0x11, test)


def uint(value, bits):
    if type(value) is not int or not 0 <= value < 2**bits:
        raise ValueError("noncanonical TON unsigned integer")
    return value


def coins(value):
    if not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]*", value):
        raise ValueError("TON coins must use canonical integer base units")
    result = int(value)
    if result >= 2**120:
        raise ValueError("TON Coins overflow")
    return result


def approved_code(name="wallet-v5r1"):
    expected = {
        "wallet-v5r1": WALLET_CODE_HASH,
        "jetton-wallet": JETTON_WALLET_CODE_HASH,
        "jetton-minter": JETTON_MASTER_CODE_HASH,
    }[name]
    code = Cell.one_from_boc(
        bytes.fromhex(
            (Path(__file__).parent / "ton_contracts" / (name + ".boc.hex")).read_text().strip()
        )
    )
    if code.hash.hex() != expected:
        raise ValueError("approved TON contract artifact mismatch")
    return code


def wallet_id(global_id):
    if type(global_id) is not int or not -(2**31) <= global_id < 0 or global_id in (-239, -3):
        raise ValueError("distinct isolated TON network global ID required")
    # client context: workchain=0, version=0, subwallet=0, high bit=1.
    return (global_id & 0xFFFFFFFF) ^ 0x80000000


def wallet_init(public_key, global_id):
    if len(public_key) != 32:
        raise ValueError("TON original FROST public key must be 32 bytes")
    data = (
        Builder()
        .store_bit(1)
        .store_uint(0, 32)
        .store_uint(wallet_id(global_id), 32)
        .store_bytes(public_key)
        .store_bit(0)
        .end_cell()
    )
    return Builder().store_bits("00110").store_ref(approved_code()).store_ref(data).end_cell()


def wallet_address(public_key, global_id):
    return "0:" + wallet_init(public_key, global_id).hash.hex()


def verify_wallet_state(address, public_key, global_id, *, status, code=None, data=None):
    expected = wallet_address(public_key, global_id)
    if normalize_address(address).raw != expected:
        raise ValueError("TON StateInit address does not bind original DKG owner")
    if status == "uninit":
        if code is not None or data is not None:
            raise ValueError("uninitialized wallet unexpectedly has contract state")
        return 0
    if status != "active" or code is None or data is None or code.hash.hex() != WALLET_CODE_HASH:
        raise ValueError("unknown/frozen TON wallet contract")
    s = data.begin_parse()
    enabled, seqno, identifier, owner = (
        s.load_uint(1),
        s.load_uint(32),
        s.load_uint(32),
        s.load_bytes(32),
    )
    if (
        enabled != 1
        or identifier != wallet_id(global_id)
        or owner != public_key
        or s.load_uint(1) != 0
        or s.remaining_bits
        or s.remaining_refs
    ):
        raise ValueError("TON owner/wallet ID/extensions state mismatch")
    return seqno


def jetton_wallet_address(owner, master):
    owner, master = normalize_address(owner).raw, normalize_address(master).raw
    if not owner.startswith("0:") or not master.startswith("0:"):
        raise ValueError("Jetton contracts support workchain zero only")
    code = approved_code("jetton-wallet")
    data = (
        Builder()
        .store_coins(0)
        .store_address(owner)
        .store_address(master)
        .store_ref(code)
        .end_cell()
    )
    init = Builder().store_bits("00110").store_ref(code).store_ref(data).end_cell()
    return "0:" + init.hash.hex()


def verify_jetton_wallet(address, owner, master, code, data, getter_address):
    expected = jetton_wallet_address(owner, master)
    if (
        normalize_address(address).raw != expected
        or normalize_address(getter_address).raw != expected
        or code.hash.hex() != JETTON_WALLET_CODE_HASH
    ):
        raise ValueError("Jetton get_wallet_address/code mismatch")
    s = data.begin_parse()
    balance, actual_owner, actual_master, wallet_code = (
        s.load_coins(),
        s.load_address(),
        s.load_address(),
        s.load_ref(),
    )
    if (
        actual_owner != Address(owner)
        or actual_master != Address(master)
        or wallet_code.hash.hex() != JETTON_WALLET_CODE_HASH
        or s.remaining_bits
        or s.remaining_refs
    ):
        raise ValueError("Jetton get_wallet_data owner/master mismatch")
    return balance


def comment_cell(comment_hex):
    raw = bytes.fromhex(comment_hex)
    if raw.hex() != comment_hex or len(raw) > 96:
        raise ValueError("unsupported TON comment")
    return Builder().store_uint(0, 32).store_bytes(raw).end_cell() if raw else Builder().end_cell()


def jetton_transfer(a, source):
    return (
        Builder()
        .store_uint(TRANSFER, 32)
        .store_uint(uint(a["query_id"], 64), 64)
        .store_coins(coins(a["amount"]))
        .store_address(a["destination"])
        .store_address(source)
        .store_bit(0)
        .store_coins(1)
        .store_bit(1)
        .store_ref(comment_cell(a["comment_hex"]))
        .end_cell()
    )


def internal_message(destination, value, bounce, body):
    builder = (
        Builder()
        .store_bit(0)
        .store_bit(1)
        .store_bool(bounce)
        .store_bit(0)
        .store_address(None)
        .store_address(destination)
        .store_coins(value)
        .store_bit(0)
        .store_coins(0)
        .store_coins(0)
        .store_uint(0, 64)
        .store_uint(0, 32)
        .store_bit(0)
    )
    if len(body.bits) <= builder.available_bits - 1 and len(body.refs) <= builder.available_refs:
        return builder.store_bit(0).store_cell(body).end_cell()
    return builder.store_bit(1).store_ref(body).end_cell()


def signing_cell(a, public_key):
    """Rebuild the only approved single-action authorization, without a signature."""
    if (
        a["wallet_version"] != WALLET_VERSION
        or a["code_hash"] != WALLET_CODE_HASH
        or a["workchain"] != 0
        or a["wallet_id"] != wallet_id(a["network_global_id"])
        or a["send_mode"] != SEND_MODE
        or type(a["bounce"]) is not bool
        or type(a["deploy"]) is not bool
    ):
        raise ValueError("unsupported TON wallet/action identity")
    source = wallet_address(public_key, a["network_global_id"])
    destination = normalize_address(a["destination"], require_test=True)
    if destination.raw != a["destination"] or destination.workchain != 0:
        raise ValueError("canonical workchain-zero destination required")
    seqno = uint(a["seqno"], 32)
    if a["deploy"] and seqno != 0:
        raise ValueError("deployment must use original seqno zero")
    valid_until = uint(a["valid_until"], 32)
    if valid_until == 0 or coins(a["amount"]) == 0:
        raise ValueError("positive amount and expiry required")
    if a["jetton_master"] is None:
        if (
            any(
                a[k] is not None
                for k in (
                    "query_id",
                    "jetton_source",
                    "jetton_destination",
                    "jetton_wallet_code_hash",
                )
            )
            or a["attached_nanoton"] != a["amount"]
        ):
            raise ValueError("invalid native TON authorization")
        body, to = comment_cell(a["comment_hex"]), a["destination"]
    else:
        if (
            a["jetton_wallet_code_hash"] != JETTON_WALLET_CODE_HASH
            or a["jetton_source"] != jetton_wallet_address(source, a["jetton_master"])
            or a["jetton_destination"]
            != jetton_wallet_address(a["destination"], a["jetton_master"])
            or a["attached_nanoton"] != "100000000"
            or not a["bounce"]
        ):
            raise ValueError("invalid Jetton master/wallet/funding authorization")
        body, to = jetton_transfer(a, source), a["jetton_source"]
    msg = internal_message(to, coins(a["attached_nanoton"]), a["bounce"], body)
    actions = (
        Builder()
        .store_ref(Builder().end_cell())
        .store_uint(0x0EC3C86D, 32)
        .store_uint(SEND_MODE, 8)
        .store_ref(msg)
        .end_cell()
    )
    return (
        Builder()
        .store_uint(0x7369676E, 32)
        .store_uint(a["wallet_id"], 32)
        .store_uint(valid_until, 32)
        .store_uint(seqno, 32)
        .store_bit(1)
        .store_ref(actions)
        .store_bit(0)
        .end_cell()
    )


def validate_authorization(a, public_key):
    cell = signing_cell(a, public_key)
    raw = bytes.fromhex(a["signed_cell_boc_hex"])
    decoded = Cell.one_from_boc(raw)
    if raw != cell.to_boc() or decoded.hash != cell.hash:
        raise ValueError("TON canonical signing cell/BOC mismatch")
    init = wallet_init(public_key, a["network_global_id"])
    if a["state_init_boc_hex"] != (init.to_boc().hex() if a["deploy"] else None):
        raise ValueError("TON deployment StateInit mismatch")
    return cell.hash


def assemble_signature(a, public_key_hex, signature_hex):
    public_key, signature = bytes.fromhex(public_key_hex), bytes.fromhex(signature_hex)
    if len(signature) != 64 or signature.hex() != signature_hex:
        raise ValueError("noncanonical TON Ed25519 signature")
    digest = validate_authorization(a, public_key)
    Ed25519PublicKey.from_public_bytes(public_key).verify(signature, digest)
    body = Builder().store_cell(signing_cell(a, public_key)).store_bytes(signature).end_cell()
    init = (
        StateInit.deserialize(wallet_init(public_key, a["network_global_id"]).begin_parse())
        if a["deploy"]
        else None
    )
    message = MessageAny(
        ExternalMsgInfo(None, Address(wallet_address(public_key, a["network_global_id"])), 0),
        init,
        body,
    ).serialize()
    return message.to_boc().hex(), message.hash.hex()
