"""Native transaction execution boundary.

Family executors prepare opaque signing payloads, assemble signatures, broadcast
the exact persisted bytes and interpret transaction-specific chain evidence.
Business services never choose fees, nonce, blockhash or TAPOS fields.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from typing import Any, Protocol

import requests
from django.db import IntegrityError, transaction

from .chain_registry import ChainKind, get_chain_spec, rpc_urls
from .models import SourceAccountSequence


class NativeTxError(RuntimeError):
    pass


class PreparationError(NativeTxError):
    pass


class FeePolicyError(PreparationError):
    pass


class InsufficientBalance(PreparationError):
    pass


class DeterministicBroadcastRejection(NativeTxError):
    pass


class SafePreBroadcastRejection(DeterministicBroadcastRejection):
    """The node proved non-acceptance; the same prepared attempt may retry."""


class AmbiguousBroadcast(NativeTxError):
    pass


class UnsupportedNativeTransaction(NativeTxError):
    pass


class ReconciliationState(StrEnum):
    UNKNOWN = "UNKNOWN"
    PENDING = "PENDING"
    INCLUDED = "INCLUDED"
    CONFIRMED = "CONFIRMED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"


@dataclass(frozen=True)
class PreparedNativeTransaction:
    chain_id: str
    asset_key: str
    from_address: str
    to_address: str
    amount: Decimal
    base_unit_amount: int
    signing_payload: bytes
    unsigned_payload: dict[str, Any]
    fee_metadata: dict[str, str]
    sequence: int | None = None
    expected_tx_id: str | None = None
    expires_at_ms: int | None = None
    last_valid_block: int | None = None


@dataclass(frozen=True)
class ReconciliationResult:
    state: ReconciliationState
    evidence: dict[str, Any] = field(default_factory=dict)


def to_base_units(amount: Decimal | str, decimals: int, *, maximum: int = 2**256 - 1) -> int:
    """Convert exactly, rejecting rounding, non-positive and out-of-range values."""
    try:
        value = Decimal(amount) if isinstance(amount, str) else amount
        scaled = value * (Decimal(10) ** decimals)
    except (InvalidOperation, TypeError) as exc:
        raise ValueError("invalid decimal amount") from exc
    if not value.is_finite() or value <= 0:
        raise ValueError("amount must be a positive finite Decimal")
    integral = scaled.to_integral_value()
    if scaled != integral:
        raise ValueError(f"amount exceeds asset precision ({decimals} decimals)")
    result = int(integral)
    if result > maximum:
        raise OverflowError("base-unit amount exceeds chain range")
    return result


class RpcTransport(Protocol):
    def rpc(self, url: str, method: str, params: list[Any]) -> Any: ...

    def post(self, url: str, path: str, payload: dict[str, Any]) -> Any: ...


class RequestsTransport:
    def rpc(self, url: str, method: str, params: list[Any]) -> Any:
        response = requests.post(
            url,
            json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
            timeout=15,
            allow_redirects=False,
        )
        if 300 <= response.status_code < 400:
            raise PreparationError("RPC redirects are not permitted")
        response.raise_for_status()
        body = response.json()
        if body.get("error"):
            raise DeterministicBroadcastRejection(str(body["error"]))
        return body.get("result")

    def post(self, url: str, path: str, payload: dict[str, Any]) -> Any:
        response = requests.post(url.rstrip("/") + path, json=payload, timeout=15)
        response.raise_for_status()
        return response.json()


def _int(value: Any) -> int:
    return int(value, 16) if isinstance(value, str) and value.startswith("0x") else int(value)


def _cap(settings: dict[str, Any], name: str) -> int:
    value = settings.get(name)
    if value is None or isinstance(value, (float, bool)):
        raise FeePolicyError(f"reviewed integer-string {name} is required")
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise FeePolicyError(f"invalid {name}") from exc
    if result <= 0:
        raise FeePolicyError(f"{name} must be positive")
    return result


def allocate_evm_nonce(chain_id: str, address: str, network_pending: int) -> int:
    """Allocate under a PostgreSQL row lock; uniqueness also protects the attempt."""
    normalized = address.lower()
    with transaction.atomic():
        try:
            state = SourceAccountSequence.objects.select_for_update().get(
                chain_id=chain_id, address=normalized
            )
        except SourceAccountSequence.DoesNotExist:
            try:
                # Savepoint keeps the outer locking transaction usable when a
                # concurrent allocator creates the row first.
                with transaction.atomic():
                    state = SourceAccountSequence.objects.create(
                        chain_id=chain_id, address=normalized, next_sequence=network_pending
                    )
            except IntegrityError:
                state = SourceAccountSequence.objects.select_for_update().get(
                    chain_id=chain_id, address=normalized
                )
        nonce = max(network_pending, state.next_sequence)
        state.next_sequence = nonce + 1
        state.save(update_fields=["next_sequence", "updated_at"])
        return nonce


class EvmNativeExecutor:
    def __init__(self, transport: RpcTransport | None = None):
        self.transport = transport or RequestsTransport()

    def _rpc(self, chain_id, url, method, params):
        from .mpc_evm_network import guarded_evm_rpc

        return guarded_evm_rpc(chain_id, url, self.transport, method, params)

    def prepare(
        self,
        chain_id: str,
        asset_key: str,
        source: str,
        destination: str,
        amount: Decimal,
        *,
        sweep: bool = False,
    ):
        spec = get_chain_spec(chain_id)
        if spec.kind is not ChainKind.EVM or not spec.evm_chain_id:
            raise UnsupportedNativeTransaction("valid EVM chain id is required")
        url = rpc_urls(chain_id)[0]
        value = to_base_units(amount, spec.native_decimals)
        pending = _int(self._rpc(chain_id, url, "eth_getTransactionCount", [source, "pending"]))
        candidate = {
            "chainId": spec.evm_chain_id,
            # A provisional nonce is sufficient for estimation. Durable nonce
            # ownership is allocated atomically with attempt persistence.
            "nonce": pending,
            "from": source,
            "to": destination,
            "value": value,
        }
        gas = _int(self._rpc(chain_id, url, "eth_estimateGas", [candidate]))
        gas_cap = _cap(spec.gas_settings, "max_gas_limit")
        if gas > gas_cap:
            raise FeePolicyError("estimated gas exceeds max_gas_limit")
        latest = self._rpc(chain_id, url, "eth_getBlockByNumber", ["latest", False]) or {}
        fees: dict[str, str]
        if latest.get("baseFeePerGas") is not None:
            priority = _int(self._rpc(chain_id, url, "eth_maxPriorityFeePerGas", []))
            suggested = _int(latest["baseFeePerGas"]) * 2 + priority
            max_fee_cap = _cap(spec.gas_settings, "max_fee_per_gas")
            if suggested > max_fee_cap:
                raise FeePolicyError("suggested max fee exceeds configured cap")
            max_fee = suggested
            if priority > _cap(spec.gas_settings, "max_priority_fee_per_gas"):
                raise FeePolicyError("priority fee exceeds configured cap")
            candidate.update(
                {"gas": gas, "maxFeePerGas": max_fee, "maxPriorityFeePerGas": priority}
            )
            fees = {
                "mode": "eip1559",
                "gas": str(gas),
                "max_fee_per_gas": str(max_fee),
                "max_priority_fee_per_gas": str(priority),
            }
            worst_fee = gas * max_fee
        else:
            gas_price = _int(self._rpc(chain_id, url, "eth_gasPrice", []))
            if gas_price > _cap(spec.gas_settings, "max_legacy_gas_price"):
                raise FeePolicyError("gas price exceeds configured cap")
            candidate.update({"gas": gas, "gasPrice": gas_price})
            fees = {"mode": "legacy", "gas": str(gas), "gas_price": str(gas_price)}
            worst_fee = gas * gas_price
        total_cap = spec.gas_settings.get("max_total_fee_base_units")
        if total_cap is not None and worst_fee > _cap(
            spec.gas_settings, "max_total_fee_base_units"
        ):
            raise FeePolicyError("worst-case fee exceeds total fee cap")
        balance = _int(self._rpc(chain_id, url, "eth_getBalance", [source, "pending"]))
        if sweep:
            value = balance - worst_fee
            if value <= 0:
                raise InsufficientBalance("source cannot fund EVM sweep fee")
            candidate["value"] = value
        elif balance < value + worst_fee:
            raise InsufficientBalance("source cannot fund value plus worst-case fee")
        fees["worst_case_base_units"] = str(worst_fee)
        return PreparedNativeTransaction(
            spec.chain_id,
            asset_key,
            source,
            destination,
            amount,
            value,
            b"",
            candidate,
            fees,
            sequence=pending,
        )

    def prepare_sweep(self, chain_id, asset_key, source, destination, amount):
        return self.prepare(chain_id, asset_key, source, destination, amount, sweep=True)

    @staticmethod
    def assemble(prepared: PreparedNativeTransaction, signed_ref: str) -> bytes:
        if not signed_ref.startswith("signed:"):
            raise NativeTxError("signer returned an invalid payload reference")
        return bytes.fromhex(signed_ref.removeprefix("signed:").removeprefix("0x"))

    @staticmethod
    def transaction_id(signed: bytes) -> str:
        from eth_utils import keccak

        return "0x" + keccak(signed).hex()

    def broadcast(self, chain_id: str, signed: bytes, expected: str) -> str:
        raw = "0x" + signed.hex()
        ambiguous = False
        for url in rpc_urls(chain_id):
            try:
                returned = self._rpc(chain_id, url, "eth_sendRawTransaction", [raw])
                if str(returned).lower() != expected.lower():
                    raise DeterministicBroadcastRejection("RPC returned an unexpected tx hash")
                return expected
            except DeterministicBroadcastRejection as exc:
                message = str(exc).lower()
                if any(
                    word in message for word in ("already known", "already imported", "duplicate")
                ):
                    return expected
                if any(
                    phrase in message
                    for phrase in (
                        "insufficient funds",
                        "intrinsic gas too low",
                        "invalid sender",
                        "exceeds block gas limit",
                    )
                ):
                    if ambiguous:
                        raise AmbiguousBroadcast(
                            "an earlier RPC may have accepted the exact signed transaction"
                        ) from exc
                    raise SafePreBroadcastRejection(message) from exc
                if "timeout" not in message and "connection" not in message:
                    raise
                ambiguous = True
            except (requests.Timeout, requests.ConnectionError):
                ambiguous = True
        if ambiguous:
            raise AmbiguousBroadcast("broadcast outcome is unknown; reconcile exact tx id")
        raise DeterministicBroadcastRejection("all RPC endpoints rejected transaction")

    def reconcile(self, prepared: PreparedNativeTransaction, tx_id: str) -> ReconciliationResult:
        urls = rpc_urls(prepared.chain_id)
        receipt, url = self._read(prepared.chain_id, urls, "eth_getTransactionReceipt", [tx_id])
        if receipt is None:
            tx, _ = self._read(prepared.chain_id, urls, "eth_getTransactionByHash", [tx_id])
            return ReconciliationResult(
                ReconciliationState.PENDING if tx else ReconciliationState.UNKNOWN
            )
        if str(receipt.get("transactionHash", "")).lower() != tx_id.lower():
            raise NativeTxError("receipt transaction hash mismatch")
        evidence = {"block_number": _int(receipt["blockNumber"]), "receipt": receipt}
        head, _ = self._read(
            prepared.chain_id, [url, *(item for item in urls if item != url)], "eth_blockNumber", []
        )
        head = _int(head)
        confirmations = head - evidence["block_number"] + 1
        evidence["confirmations"] = confirmations
        threshold = get_chain_spec(prepared.chain_id).confirmations
        final = confirmations >= threshold
        if not final:
            state = ReconciliationState.INCLUDED
        elif _int(receipt.get("status", 0)) == 1:
            state = ReconciliationState.CONFIRMED
        else:
            state = ReconciliationState.FAILED
        return ReconciliationResult(state, evidence)

    def _read(self, chain_id, urls, method, params):
        last_error = None
        for url in urls:
            try:
                return self._rpc(chain_id, url, method, params), url
            except (requests.Timeout, requests.ConnectionError) as exc:
                last_error = exc
        raise PreparationError(f"all EVM endpoints unavailable for {method}") from last_error


class TronNativeExecutor:
    def __init__(self, transport: RpcTransport | None = None):
        self.transport = transport or RequestsTransport()

    def prepare(
        self, chain_id: str, asset_key: str, source: str, destination: str, amount: Decimal
    ):
        spec = get_chain_spec(chain_id)
        if spec.kind is not ChainKind.TRON:
            raise UnsupportedNativeTransaction("TRON executor requires a TRON chain")
        value = to_base_units(amount, spec.native_decimals, maximum=2**63 - 1)
        body = self.transport.post(
            rpc_urls(chain_id)[0],
            "/wallet/createtransaction",
            {"owner_address": source, "to_address": destination, "amount": value, "visible": True},
        )
        tx_id = body.get("txID")
        raw = body.get("raw_data")
        if not tx_id or not raw:
            raise PreparationError("TRON node did not return txID/raw_data")
        expiration = raw.get("expiration")
        return PreparedNativeTransaction(
            spec.chain_id,
            asset_key,
            source,
            destination,
            amount,
            value,
            bytes.fromhex(tx_id),
            body,
            {},
            expected_tx_id=tx_id,
            expires_at_ms=expiration,
        )

    @staticmethod
    def assemble(prepared: PreparedNativeTransaction, signed_ref: str) -> dict[str, Any]:
        signature = signed_ref.removeprefix("signed:")
        body = dict(prepared.unsigned_payload)
        body["signature"] = [signature]
        return body

    def broadcast(self, chain_id: str, signed: dict[str, Any], expected: str) -> str:
        ambiguous = False
        for url in rpc_urls(chain_id):
            try:
                result = self.transport.post(url, "/wallet/broadcasttransaction", signed)
            except (requests.Timeout, requests.ConnectionError):
                ambiguous = True
                continue
            if result.get("result") is True:
                return expected
            message = base64.b64decode(result.get("message", "")).decode(errors="replace").lower()
            if "duplicate" in message:
                return expected
            raise DeterministicBroadcastRejection(message or result.get("code", "TRON rejected tx"))
        if ambiguous:
            raise AmbiguousBroadcast("TRON broadcast outcome is unknown")
        raise DeterministicBroadcastRejection("all TRON endpoints rejected transaction")

    def reconcile(self, prepared: PreparedNativeTransaction, tx_id: str) -> ReconciliationResult:
        urls = rpc_urls(prepared.chain_id)
        full_info = None
        last_error = None
        for candidate in urls:
            try:
                full_info = self.transport.post(
                    candidate, "/wallet/gettransactioninfobyid", {"value": tx_id}
                )
                break
            except (requests.Timeout, requests.ConnectionError) as exc:
                last_error = exc
        else:
            raise PreparationError("all TRON reconciliation endpoints unavailable") from last_error
        # FullNode evidence is deliberately early/non-terminal. Terminal state
        # comes only from the canonical SolidityNode receipt for this txID.
        solid_info = None
        for candidate in urls:
            try:
                solid_info = self.transport.post(
                    candidate, "/walletsolidity/gettransactioninfobyid", {"value": tx_id}
                )
                break
            except (requests.Timeout, requests.ConnectionError) as exc:
                last_error = exc
        if not solid_info or solid_info.get("blockNumber") is None:
            return ReconciliationResult(
                ReconciliationState.INCLUDED if full_info else ReconciliationState.UNKNOWN,
                {
                    "full_node_observation": full_info or {},
                    "expiration": prepared.expires_at_ms,
                    "manual_non_inclusion_reconciliation_required": True,
                },
            )
        info = solid_info
        evidence = {
            "block_number": _int(info["blockNumber"]),
            "fee": str(info.get("fee", 0)),
            "receipt": info.get("receipt", {}),
        }
        evidence["solidified"] = True
        result = str(info.get("receipt", {}).get("result", "SUCCESS")).upper()
        if result == "SUCCESS":
            state = ReconciliationState.CONFIRMED
        else:
            state = ReconciliationState.FAILED
        return ReconciliationResult(state, evidence)


class SolanaNativeExecutor:
    def __init__(self, transport: RpcTransport | None = None):
        self.transport = transport or RequestsTransport()

    def prepare(
        self,
        chain_id: str,
        asset_key: str,
        source: str,
        destination: str,
        amount: Decimal,
        *,
        sweep: bool = False,
    ):
        spec = get_chain_spec(chain_id)
        if spec.kind is not ChainKind.SOLANA:
            raise UnsupportedNativeTransaction("Solana executor requires a Solana chain")
        url = rpc_urls(chain_id)[0]
        value = to_base_units(amount, spec.native_decimals, maximum=2**64 - 1)
        block = self.transport.rpc(url, "getLatestBlockhash", [{"commitment": "confirmed"}])[
            "value"
        ]
        raw = {
            "from": source,
            "to": destination,
            "lamports": value,
            "recentBlockhash": block["blockhash"],
        }
        from solders.hash import Hash
        from solders.message import Message
        from solders.pubkey import Pubkey
        from solders.system_program import TransferParams, transfer

        instruction = transfer(
            TransferParams(
                from_pubkey=Pubkey.from_string(source),
                to_pubkey=Pubkey.from_string(destination),
                lamports=value,
            )
        )
        message = bytes(
            Message.new_with_blockhash(
                [instruction], Pubkey.from_string(source), Hash.from_string(block["blockhash"])
            )
        )
        raw["message"] = base64.b64encode(message).decode()
        fee = _int(
            self.transport.rpc(url, "getFeeForMessage", [base64.b64encode(message).decode()])[
                "value"
            ]
        )
        cap = _cap(spec.gas_settings, "max_fee_lamports")
        if fee > cap:
            raise FeePolicyError("Solana fee exceeds configured cap")
        balance = _int(
            self.transport.rpc(url, "getBalance", [source, {"commitment": "confirmed"}])["value"]
        )
        if sweep:
            # Converge the encoded value and its fee. Never mutate metadata
            # after constructing the final signing message.
            for _ in range(3):
                value = balance - fee
                if value <= 0:
                    raise InsufficientBalance("source cannot fund Solana sweep fee")
                instruction = transfer(
                    TransferParams(
                        from_pubkey=Pubkey.from_string(source),
                        to_pubkey=Pubkey.from_string(destination),
                        lamports=value,
                    )
                )
                message = bytes(
                    Message.new_with_blockhash(
                        [instruction],
                        Pubkey.from_string(source),
                        Hash.from_string(block["blockhash"]),
                    )
                )
                final_fee = _int(
                    self.transport.rpc(
                        url, "getFeeForMessage", [base64.b64encode(message).decode()]
                    )["value"]
                )
                if final_fee > cap:
                    raise FeePolicyError("Solana final sweep fee exceeds configured cap")
                if final_fee == fee:
                    raw.update({"lamports": value, "message": base64.b64encode(message).decode()})
                    break
                fee = final_fee
            else:
                raise FeePolicyError("Solana sweep fee did not converge")
        elif balance < value + fee:
            raise InsufficientBalance("source cannot fund lamports plus fee")
        return PreparedNativeTransaction(
            spec.chain_id,
            asset_key,
            source,
            destination,
            amount,
            value,
            message,
            raw,
            {"fee_lamports": str(fee)},
            last_valid_block=_int(block["lastValidBlockHeight"]),
        )

    def prepare_sweep(self, chain_id, asset_key, source, destination, amount):
        return self.prepare(chain_id, asset_key, source, destination, amount, sweep=True)

    @staticmethod
    def assemble(prepared: PreparedNativeTransaction, signed_ref: str) -> bytes:
        from solders.message import Message
        from solders.signature import Signature
        from solders.transaction import Transaction

        signature = Signature.from_bytes(base64.b64decode(signed_ref.removeprefix("signed:")))
        return bytes(
            Transaction.populate(Message.from_bytes(prepared.signing_payload), [signature])
        )

    @staticmethod
    def transaction_id(signed: bytes) -> str:
        from solders.transaction import Transaction

        return str(Transaction.from_bytes(signed).signatures[0])

    def broadcast(self, chain_id: str, signed: bytes, expected: str) -> str:
        encoded = base64.b64encode(signed).decode()
        ambiguous = False
        for url in rpc_urls(chain_id):
            try:
                result = self.transport.rpc(
                    url,
                    "sendTransaction",
                    [encoded, {"encoding": "base64", "skipPreflight": False}],
                )
                if str(result) != expected:
                    raise DeterministicBroadcastRejection("RPC returned an unexpected signature")
                return expected
            except (requests.Timeout, requests.ConnectionError):
                ambiguous = True
        if ambiguous:
            raise AmbiguousBroadcast("Solana send outcome is unknown")
        raise DeterministicBroadcastRejection("all Solana endpoints rejected transaction")

    def reconcile(self, prepared: PreparedNativeTransaction, tx_id: str) -> ReconciliationResult:
        urls = rpc_urls(prepared.chain_id)
        response, url = self._read(
            urls, "getSignatureStatuses", [[tx_id], {"searchTransactionHistory": True}]
        )
        value = response["value"][0]
        if value is None:
            if prepared.last_valid_block is not None:
                height, _ = self._read(
                    [url, *(item for item in urls if item != url)],
                    "getBlockHeight",
                    [{"commitment": "confirmed"}],
                )
                height = _int(height)
                if height > prepared.last_valid_block:
                    return ReconciliationResult(
                        ReconciliationState.EXPIRED, {"block_height": height}
                    )
            return ReconciliationResult(ReconciliationState.UNKNOWN)
        evidence = {
            "slot": value.get("slot"),
            "confirmation_status": value.get("confirmationStatus"),
        }
        status = value.get("confirmationStatus")
        if value.get("err") is not None and status == "finalized":
            evidence["err"] = value["err"]
            return ReconciliationResult(ReconciliationState.FAILED, evidence)
        if value.get("err") is not None:
            evidence["err"] = value["err"]
            return ReconciliationResult(ReconciliationState.INCLUDED, evidence)
        state = (
            ReconciliationState.CONFIRMED if status == "finalized" else ReconciliationState.PENDING
        )
        return ReconciliationResult(state, evidence)

    def _read(self, urls, method, params):
        last_error = None
        for url in urls:
            try:
                return self.transport.rpc(url, method, params), url
            except (requests.Timeout, requests.ConnectionError) as exc:
                last_error = exc
        raise PreparationError(f"all Solana endpoints unavailable for {method}") from last_error


def get_native_executor(chain_id: str, transport: RpcTransport | None = None):
    kind = get_chain_spec(chain_id).kind
    if kind is ChainKind.EVM:
        return EvmNativeExecutor(transport)
    if kind is ChainKind.TRON:
        return TronNativeExecutor(transport)
    if kind is ChainKind.SOLANA:
        return SolanaNativeExecutor(transport)
    raise UnsupportedNativeTransaction("TON outbound custody is not supported")
