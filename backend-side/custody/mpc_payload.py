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
