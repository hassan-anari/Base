"""Solidified inclusion and exact transfer evidence; absence never proves non-inclusion."""

import time

import requests
from eth_keys import keys

from .chain_registry import rpc_urls
from .native_tx import ReconciliationResult, ReconciliationState
from .tron_wire import address_bytes, block_identity, hex_bytes, serialize_raw, validate_wire

FAILURES = {
    "REVERT",
    "BAD_JUMP_DESTINATION",
    "OUT_OF_MEMORY",
    "PRECOMPILED_CONTRACT",
    "STACK_TOO_SMALL",
    "STACK_TOO_LARGE",
    "ILLEGAL_OPERATION",
    "STACK_OVERFLOW",
    "OUT_OF_ENERGY",
    "OUT_OF_TIME",
    "JVM_STACK_OVER_FLOW",
    "TRANSFER_FAILED",
    "INVALID_CODE",
}
TRANSFER_TOPIC = "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


def reconcile_tron_transfer(executor, prepared, tx_id, *, token=False):
    validate_wire(prepared.unsigned_payload)
    if prepared.unsigned_payload["txID"] != tx_id:
        raise ValueError("original TRON txID differs from reconciliation identity")
    last_error = None
    missing_evidence = None
    for url in rpc_urls(prepared.chain_id):
        try:

            def post(path, payload):
                return executor._post(prepared.chain_id, url, path, payload)

            info = post("/walletsolidity/gettransactioninfobyid", {"value": tx_id})
            tx = post("/walletsolidity/gettransactionbyid", {"value": tx_id})
            if not info or not tx:
                if (info and info.get("id") != tx_id) or (tx and tx.get("txID") != tx_id):
                    raise ValueError("TRON partial solidified evidence identity mismatch")
                expired = prepared.expires_at_ms <= int(time.time() * 1000)
                missing_evidence = ReconciliationResult(
                    ReconciliationState.RECONCILIATION_REQUIRED
                    if expired
                    else ReconciliationState.UNKNOWN,
                    {
                        "outcome": "UNKNOWN",
                        **({"error": "TRON_EXPIRED_OUTCOME_UNKNOWN"} if expired else {}),
                        "expiration_ms": prepared.expires_at_ms,
                        "manual_non_inclusion_reconciliation_required": True,
                    },
                )
                # A lagging authorized endpoint does not establish non-inclusion.
                # Never combine partial responses: another endpoint must provide
                # the complete, independently validated solidified evidence.
                continue
            evidence = _validate_inclusion(prepared, tx_id, info, tx, post)
            results = tx.get("ret")
            if not isinstance(results, list) or len(results) != 1:
                raise ValueError("TRON execution evidence missing")
            outcome = results[0].get("contractRet")
            if outcome not in {"SUCCESS", *FAILURES}:
                raise ValueError("TRON execution outcome unknown")
            receipt_result = info.get("receipt", {}).get("result")
            if token and receipt_result != outcome:
                raise ValueError("TRC20 execution outcome disagreement")
            if info.get("result") == "FAILED" and outcome == "SUCCESS":
                raise ValueError("TRON inconsistent success evidence")
            evidence["execution"] = outcome
            if outcome in FAILURES:
                return ReconciliationResult(ReconciliationState.FAILED, evidence)
            if token:
                effect = _token_effect(prepared, info.get("log", []))
                if effect is None:
                    return ReconciliationResult(
                        ReconciliationState.RECONCILIATION_REQUIRED,
                        {**evidence, "error": "TOKEN_EFFECT_MISMATCH"},
                    )
                evidence["token_effect"] = effect
            else:
                evidence["native_effect"] = {
                    "source": prepared.from_address,
                    "destination": prepared.to_address,
                    "sun": str(prepared.base_unit_amount),
                }
            return ReconciliationResult(ReconciliationState.CONFIRMED, evidence)
        except (requests.Timeout, requests.ConnectionError) as exc:
            last_error = exc
    if missing_evidence is not None:
        return missing_evidence
    raise ValueError("TRON solidified evidence unavailable") from last_error


def _validate_inclusion(prepared, tx_id, info, tx, post):
    if info.get("id") != tx_id or tx.get("txID") != tx_id:
        raise ValueError("TRON solidified transaction identity mismatch")
    unsigned = {k: tx[k] for k in ("raw_data", "raw_data_hex", "txID")}
    validate_wire(unsigned)
    if serialize_raw(tx["raw_data"]).hex() != prepared.unsigned_payload["raw_data_hex"]:
        raise ValueError("TRON included transaction differs from frozen bytes")
    signatures = tx.get("signature", [])
    if len(signatures) != 1:
        raise ValueError("TRON included signature shape unsupported")
    raw = hex_bytes(signatures[0], 65)
    r, s, v = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:64], "big"), raw[64]
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    if v not in (0, 1) or not 0 < r < order or not 0 < s <= order // 2:
        raise ValueError("TRON included signature is noncanonical")
    signature = keys.Signature(vrs=(v, r, s))
    public = signature.recover_public_key_from_msg_hash(bytes.fromhex(tx_id))
    if address_bytes(prepared.from_address)[1:] != public.to_canonical_address():
        raise ValueError("TRON included signature source mismatch")
    number = info["blockNumber"]
    block = post("/walletsolidity/getblockbynum", {"num": number})
    height, block_id, timestamp = block_identity(block)
    solid_head, _, _ = block_identity(post("/walletsolidity/getnowblock", {}))
    matches = [item for item in block.get("transactions", []) if item.get("txID") == tx_id]
    if (
        height != number
        or solid_head < height
        or len(matches) != 1
        or matches[0].get("raw_data_hex") != unsigned["raw_data_hex"]
        or matches[0].get("signature") != signatures
        or matches[0].get("ret") != tx.get("ret")
        or info.get("blockTimeStamp") != timestamp
    ):
        raise ValueError("TRON solidified block inclusion evidence mismatch")
    return {
        "solidified": True,
        "txid": tx_id,
        "block_number": height,
        "block_id": block_id,
        "solid_head": solid_head,
        "receipt": info.get("receipt", {}),
        "fee": str(info.get("fee", 0)),
    }


def _token_effect(prepared, logs):
    contract = address_bytes(prepared.fee_metadata["token_contract"])[1:].hex()
    source = address_bytes(prepared.from_address)[1:].hex().rjust(64, "0")
    destination = address_bytes(prepared.to_address)[1:].hex().rjust(64, "0")
    matches = []
    for index, log in enumerate(logs):
        if log.get("address") != contract or log.get("topics") != [
            TRANSFER_TOPIC,
            source,
            destination,
        ]:
            continue
        if int.from_bytes(hex_bytes(log.get("data"), 32), "big") == prepared.base_unit_amount:
            matches.append(index)
    # Reject duplicate matching effects as an unsupported contract execution shape.
    return (
        {"log_index": matches[0], "contract": contract, "amount": str(prepared.base_unit_amount)}
        if len(matches) == 1
        else None
    )
