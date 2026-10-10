"""Canonical single-FROST-signer legacy message authorization and assembly."""

import base64
import struct

from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.message import Message
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.system_program import TransferParams, transfer
from solders.transaction import Transaction

from .spl import ASSOCIATED_TOKEN_PROGRAM, derive_ata
from .token_metadata import CLASSIC_TOKEN_PROGRAM

SYSTEM_PROGRAM = "11111111111111111111111111111111"
U64_MAX = 2**64 - 1
MAX_TRANSACTION_BYTES = 1232


def uint(value, *, positive=False):
    if type(value) is int:
        result = value
    elif isinstance(value, str) and value.isascii() and value.isdecimal():
        result = int(value)
        if str(result) != value:
            raise ValueError("noncanonical Solana integer")
    else:
        raise ValueError("Solana integer required")
    if not (1 if positive else 0) <= result <= U64_MAX:
        raise ValueError("Solana amount is outside u64 range")
    return result


def instructions(source, destination, units, *, mint=None, decimals=None, create_ata=False):
    source_key, destination_key = Pubkey.from_string(source), Pubkey.from_string(destination)
    uint(units, positive=True)
    if source_key == destination_key:
        raise ValueError("Solana self-transfer is outside reviewed custody scope")
    if mint is None:
        if create_ata:
            raise ValueError("native transfer cannot create ATA")
        return [
            transfer(
                TransferParams(from_pubkey=source_key, to_pubkey=destination_key, lamports=units)
            )
        ]
    if type(decimals) is not int or not 0 <= decimals <= 18:
        raise ValueError("unsupported SPL ledger precision")
    mint_key = Pubkey.from_string(mint)
    source_ata = Pubkey.from_string(derive_ata(source, mint))
    destination_ata = Pubkey.from_string(derive_ata(destination, mint))
    token = Pubkey.from_string(CLASSIC_TOKEN_PROGRAM)
    result = []
    if create_ata:
        result.append(
            Instruction(
                Pubkey.from_string(ASSOCIATED_TOKEN_PROGRAM),
                b"\x01",
                [
                    AccountMeta(source_key, True, True),
                    AccountMeta(destination_ata, False, True),
                    AccountMeta(destination_key, False, False),
                    AccountMeta(mint_key, False, False),
                    AccountMeta(Pubkey.from_string(SYSTEM_PROGRAM), False, False),
                    AccountMeta(token, False, False),
                ],
            )
        )
    result.append(
        Instruction(
            token,
            b"\x0c" + struct.pack("<Q", units) + bytes([decimals]),
            [
                AccountMeta(source_ata, False, True),
                AccountMeta(mint_key, False, False),
                AccountMeta(destination_ata, False, True),
                AccountMeta(source_key, True, False),
            ],
        )
    )
    return result


def build_message(source, destination, units, blockhash, **token):
    return bytes(
        Message.new_with_blockhash(
            instructions(source, destination, units, **token),
            Pubkey.from_string(source),
            Hash.from_string(blockhash),
        )
    )


def decode_message(encoded):
    raw = base64.b64decode(encoded, validate=True)
    if base64.b64encode(raw).decode() != encoded or not raw or raw[0] & 0x80:
        raise ValueError("only canonical legacy Solana messages are reviewed")
    message = Message.from_bytes(raw)
    if bytes(message) != raw or len(raw) + 65 > MAX_TRANSACTION_BYTES:
        raise ValueError("noncanonical or oversized Solana transaction")
    keys = [str(key) for key in message.account_keys]
    header = message.header
    if (
        header.num_required_signatures != 1
        or header.num_readonly_signed_accounts != 0
        or len(keys) != len(set(keys))
        or header.num_readonly_unsigned_accounts > len(keys) - 1
    ):
        raise ValueError("unexpected signer or account set")
    # Independently decode compiled accounts and flags before expected-message comparison.
    writable_end = len(keys) - header.num_readonly_unsigned_accounts
    decoded = []
    for instruction in message.instructions:
        if instruction.program_id_index >= len(keys) or any(
            i >= len(keys) for i in instruction.accounts
        ):
            raise ValueError("Solana account index is outside message")
        decoded.append(
            {
                "program": keys[instruction.program_id_index],
                "accounts": [
                    {"address": keys[i], "signer": i == 0, "writable": i < writable_end}
                    for i in instruction.accounts
                ],
                "data_hex": bytes(instruction.data).hex(),
            }
        )
    return raw, message, decoded


def validate_message(encoded, source, destination, units, blockhash, **token):
    raw, message, decoded = decode_message(encoded)
    expected = build_message(source, destination, units, blockhash, **token)
    if raw != expected or str(message.account_keys[0]) != source:
        raise ValueError(
            "serialized message differs from authorized instructions/accounts/fee payer"
        )
    return raw, decoded


def verify_signature(public_hex, raw, signature_hex):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    public = bytes.fromhex(public_hex)
    signature = bytes.fromhex(signature_hex)
    if len(public) != 32 or len(signature) != 64 or signature.hex() != signature_hex:
        raise ValueError("noncanonical Ed25519 signature encoding")
    # Explicit canonical scalar and compressed-point encoding checks; independent verifiers follow.
    order = 2**252 + 27742317777372353535851937790883648493
    if (
        int.from_bytes(signature[32:], "little") >= order
        or int.from_bytes(signature[:32], "little") % (2**255) >= 2**255 - 19
    ):
        raise ValueError("noncanonical Ed25519 signature")
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, raw)
    except InvalidSignature:
        raise ValueError("Ed25519 signature does not verify original DKG key/message") from None
    sig = Signature.from_bytes(signature)
    if not sig.verify(Pubkey.from_bytes(public), raw):
        raise ValueError("Solana Ed25519 verifier rejected signature")
    return sig


def assemble_signature(encoded, public_hex, signature_hex):
    raw, message, _ = decode_message(encoded)
    if bytes(message.account_keys[0]).hex() != public_hex:
        raise ValueError("original DKG key is not transaction fee payer/signer")
    signature = verify_signature(public_hex, raw, signature_hex)
    signed = bytes(Transaction.populate(message, [signature]))
    parsed = Transaction.from_bytes(signed)
    parsed.sanitize()
    if (
        bytes(parsed.message) != raw
        or list(parsed.signatures) != [signature]
        or not all(parsed.verify_with_results())
    ):
        raise ValueError("assembled transaction differs from verified message/signature")
    return signed.hex(), str(signature)
