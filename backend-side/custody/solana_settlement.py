"""Finalized original-wire execution evidence, never balance-only settlement."""

import base64

from solders.signature import Signature
from solders.transaction import Transaction

from .chain_registry import rpc_urls
from .mpc_solana_network import guarded_solana_rpc
from .native_tx import ReconciliationResult, ReconciliationState
from .solana_wire import uint
from .token_metadata import CLASSIC_TOKEN_PROGRAM


def finalized_transaction(response, signature, status):
    """Authenticate a canonical legacy wire transaction and consistent finalized metadata."""
    if not response or not status or status.get("confirmationStatus") != "finalized":
        raise ValueError("complete finalized transaction/status required")
    expected = Signature.from_string(signature)
    if str(expected) != signature:
        raise ValueError("noncanonical Solana transaction signature")
    wire = response["transaction"]
    if (
        not isinstance(wire, list)
        or len(wire) != 2
        or wire[1] != "base64"
        or response.get("version", "legacy") != "legacy"
    ):
        raise ValueError("canonical legacy finalized transaction required")
    raw = base64.b64decode(wire[0], validate=True)
    tx = Transaction.from_bytes(raw)
    tx.sanitize()
    if (
        bytes(tx) != raw
        or not tx.signatures
        or tx.signatures[0] != expected
        or not all(tx.verify_with_results())
    ):
        raise ValueError("finalized transaction signature/wire mismatch")
    slot = uint(response["slot"], positive=True)
    meta = response.get("meta")
    if (
        not isinstance(meta, dict)
        or "err" not in meta
        or status.get("slot") != slot
        or status.get("err") != meta["err"]
    ):
        raise ValueError("finalized slot/execution result conflict")
    keys = list(tx.message.account_keys)
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate finalized account keys")
    for name in ("preBalances", "postBalances"):
        values = meta.get(name)
        if not isinstance(values, list) or len(values) != len(keys):
            raise ValueError("incomplete finalized account balances")
        for value in values:
            uint(value)
    uint(meta["fee"])
    return tx, meta, slot


def token_balances(meta, phase, keys, mint, decimals):
    values = meta.get(phase)
    if not isinstance(values, list):
        raise ValueError("finalized SPL balance evidence unavailable")
    result = {}
    for balance in values:
        index = balance["accountIndex"]
        if type(index) is not int or not 0 <= index < len(keys) or index in result:
            raise ValueError("invalid or repeated token balance account index")
        if balance.get("mint") != mint or balance.get("programId") != CLASSIC_TOKEN_PROGRAM:
            raise ValueError("finalized token mint/program mismatch")
        amount = balance["uiTokenAmount"]
        if amount.get("decimals") != decimals or not balance.get("owner"):
            raise ValueError("finalized token decimals/owner mismatch")
        result[index] = (uint(amount["amount"]), balance["owner"])
    return result


def validate_effect(prepared, tx, meta):
    raw = prepared.unsigned_payload
    message = base64.b64decode(raw["message"], validate=True)
    if (
        bytes(tx.message) != message
        or len(tx.signatures) != 1
        or str(tx.message.account_keys[0]) != prepared.from_address
    ):
        raise ValueError("finalized wire differs from original authorized message/signer")
    if str(tx.message.recent_blockhash) != raw["recentBlockhash"]:
        raise ValueError("finalized blockhash mismatch")
    fee = uint(meta["fee"])
    if fee != uint(prepared.fee_metadata["fee_lamports"]):
        raise ValueError("actual finalized fee differs from frozen fee")
    pre, post = meta["preBalances"], meta["postBalances"]
    keys = [str(k) for k in tx.message.account_keys]
    if meta["err"] is not None:
        if pre[0] - post[0] != fee or any(a != b for a, b in zip(pre[1:], post[1:], strict=True)):
            raise ValueError("failed finalized transfer has inconsistent fee/rollback effects")
        if "mint" in raw:
            from .models import Asset

            asset = Asset.objects.get(asset_key=prepared.asset_key)
            before = token_balances(meta, "preTokenBalances", keys, raw["mint"], asset.decimals)
            after = token_balances(meta, "postTokenBalances", keys, raw["mint"], asset.decimals)
            source = keys.index(raw["sourceAta"])
            destination = keys.index(raw["destinationAta"])
            if (
                before != after
                or set(before) - {source, destination}
                or before.get(source, (None, None))[1] != prepared.from_address
                or (destination in before and before[destination][1] != prepared.to_address)
            ):
                raise ValueError("failed finalized SPL transfer has inconsistent token rollback")
        return {"fee_lamports": str(fee), "rent_lamports": "0", "effect": "failed_rollback"}
    units = prepared.base_unit_amount
    if "mint" not in raw:
        destination = keys.index(prepared.to_address)
        if (
            pre[0] - post[0] != units + fee
            or post[destination] - pre[destination] != units
            or meta.get("innerInstructions") not in (None, [])
            or any(pre[i] != post[i] for i in range(len(keys)) if i not in {0, destination})
        ):
            raise ValueError("native System transfer effects are inconsistent")
        return {
            "fee_lamports": str(fee),
            "rent_lamports": "0",
            "effect": "system_transfer",
            "amount": str(units),
        }
    source = keys.index(raw["sourceAta"])
    destination = keys.index(raw["destinationAta"])
    from .models import Asset

    asset = Asset.objects.get(asset_key=prepared.asset_key)
    before = token_balances(meta, "preTokenBalances", keys, raw["mint"], asset.decimals)
    after = token_balances(meta, "postTokenBalances", keys, raw["mint"], asset.decimals)
    if (
        before.get(source, (None, None))[1] != prepared.from_address
        or after.get(source, (None, None))[1] != prepared.from_address
    ):
        raise ValueError("source token balance owner mismatch")
    if after.get(destination, (None, None))[1] != prepared.to_address:
        raise ValueError("destination token balance owner mismatch")
    destination_before = before.get(destination)
    if destination_before is None:
        if not raw["createDestinationAta"] or pre[destination] != 0:
            raise ValueError("missing existing destination token balance")
        destination_before = (0, prepared.to_address)
    if (
        destination_before[1] != prepared.to_address
        or before[source][0] - after[source][0] != units
        or after[destination][0] - destination_before[0] != units
    ):
        raise ValueError("SPL TransferChecked amount effects mismatch")
    if set(before) - {source, destination} or set(after) != {source, destination}:
        raise ValueError("unexpected token balance effects")
    rent = post[destination] - pre[destination]
    if not 0 <= rent <= uint(prepared.fee_metadata["ata_rent_lamports"]) or (
        rent and not raw["createDestinationAta"]
    ):
        raise ValueError("ATA rent effects exceed bound creation budget")
    if pre[0] - post[0] != fee + rent or any(
        pre[i] != post[i] for i in range(len(keys)) if i not in {0, destination}
    ):
        raise ValueError("SPL fee/rent/account effects mismatch")
    return {
        "fee_lamports": str(fee),
        "rent_lamports": str(rent),
        "effect": "classic_transfer_checked",
        "amount": str(units),
    }


def reconcile_solana_transfer(transport, prepared, signature):
    errors = []
    for url in rpc_urls(prepared.chain_id):
        try:

            def rpc(method, params):
                return guarded_solana_rpc(prepared.chain_id, url, transport, method, params)

            status = rpc("getSignatureStatuses", [[signature], {"searchTransactionHistory": True}])[
                "value"
            ][0]
            if not status or status.get("confirmationStatus") != "finalized":
                errors.append("FINALIZED_STATUS_UNAVAILABLE")
                continue
            response = rpc(
                "getTransaction", [signature, {"encoding": "base64", "commitment": "finalized"}]
            )
            tx, meta, slot = finalized_transaction(response, signature, status)
            if slot < prepared.unsigned_payload["blockhashContextSlot"]:
                raise ValueError("transaction predates frozen blockhash context")
            effect = validate_effect(prepared, tx, meta)
            return ReconciliationResult(
                ReconciliationState.FAILED
                if meta["err"] is not None
                else ReconciliationState.CONFIRMED,
                {
                    "signature": signature,
                    "slot": slot,
                    "finalized": True,
                    "err": meta["err"],
                    **effect,
                },
            )
        except (ValueError, KeyError, TypeError, IndexError) as exc:
            errors.append(type(exc).__name__)
            # Conflicting evidence is never overridden by another endpoint.
            return ReconciliationResult(
                ReconciliationState.RECONCILIATION_REQUIRED,
                {
                    "error": "SOLANA_FINALIZED_EVIDENCE_INVALID",
                    "manual_reconciliation_required": True,
                },
            )
        except Exception as exc:
            errors.append(type(exc).__name__)
    return ReconciliationResult(
        ReconciliationState.RECONCILIATION_REQUIRED,
        {
            "error": "SOLANA_FINALIZED_EVIDENCE_UNAVAILABLE",
            "observations": errors,
            "manual_reconciliation_required": True,
            "non_inclusion_proven": False,
        },
    )
