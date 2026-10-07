"""Exact, provider-neutral cryptographic inputs for MPC signing."""

from __future__ import annotations

import base64

from .chain_registry import ChainKind, get_chain_spec


def evm_signing_digest(unsigned_transaction: dict) -> tuple[str, bytes]:
    """Return the Ethereum signing hash without signing or double hashing."""
    if "maxFeePerGas" in unsigned_transaction or unsigned_transaction.get("type") in (2, "0x2"):
        from eth_account.typed_transactions import TypedTransaction

        transaction = dict(unsigned_transaction)
        transaction["type"] = 2
        return "EVM_EIP1559_DIGEST", TypedTransaction.from_dict(transaction).hash()
    from eth_account._utils.legacy_transactions import (
        serializable_unsigned_transaction_from_dict,
    )

    signable = serializable_unsigned_transaction_from_dict(unsigned_transaction)
    return "EVM_LEGACY_DIGEST", signable.hash()


def exact_signing_payload(
    chain_id: str, prepared_payload: dict, signing_payload: bytes
) -> tuple[str, bytes]:
    kind = get_chain_spec(chain_id).kind
    if kind is ChainKind.EVM:
        return evm_signing_digest(prepared_payload)
    if kind is ChainKind.TRON:
        tx_id = prepared_payload.get("txID")
        if not isinstance(tx_id, str) or len(tx_id) != 64:
            raise ValueError("TRON MPC signing requires an exact 32-byte txID")
        return "TRON_TXID", bytes.fromhex(tx_id)
    if kind is ChainKind.SOLANA:
        if not signing_payload and prepared_payload.get("message"):
            signing_payload = base64.b64decode(prepared_payload["message"], validate=True)
        if not signing_payload:
            raise ValueError("Solana MPC signing requires the serialized message")
        return "SOLANA_MESSAGE", signing_payload
    raise ValueError(f"MPC signing is unsupported for chain kind {kind}")


def assemble_evm_signature(unsigned_transaction: dict, signature: dict, expected_source: str):
    """Verify normalized MPC components and assemble the persisted EVM transaction locally."""
    from eth_account import Account
    from eth_account._utils.legacy_transactions import (
        encode_transaction,
        serializable_unsigned_transaction_from_dict,
    )
    from eth_account.typed_transactions import TypedTransaction
    from eth_utils import keccak

    r = int(signature["r"], 16)
    s = int(signature["s"], 16)
    parity = int(signature["recovery_id"])
    if parity not in (0, 1) or not (
        0 < r < 2**256
        and 0 < s <= int("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0", 16)
    ):
        raise ValueError("invalid or non-canonical ECDSA signature")
    if "maxFeePerGas" in unsigned_transaction or unsigned_transaction.get("type") in (2, "0x2"):
        transaction = dict(unsigned_transaction)
        transaction["type"] = 2
        signable = TypedTransaction.from_dict(transaction)
        raw = encode_transaction(signable, (parity, r, s))
    else:
        signable = serializable_unsigned_transaction_from_dict(unsigned_transaction)
        chain_id = int(unsigned_transaction["chainId"])
        raw = encode_transaction(signable, (chain_id * 2 + 35 + parity, r, s))
    recovered = Account.recover_transaction(raw)
    if recovered.lower() != expected_source.lower():
        raise ValueError("threshold signature does not control the expected EVM source")
    return raw.hex(), "0x" + keccak(raw).hex()
