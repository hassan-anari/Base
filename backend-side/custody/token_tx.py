"""Reviewed fungible-token transfer executors sharing Phase 4 orchestration."""

from __future__ import annotations

from .chain_registry import ChainKind, get_chain_spec, rpc_urls
from .models import Asset
from .native_tx import (
    EvmNativeExecutor,
    FeePolicyError,
    InsufficientBalance,
    PreparedNativeTransaction,
    ReconciliationResult,
    ReconciliationState,
    TronNativeExecutor,
    UnsupportedNativeTransaction,
    _cap,
    _int,
    to_base_units,
)
from .token_metadata import assert_verified_token

TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


class Erc20Executor(EvmNativeExecutor):
    def prepare(self, chain_id, asset_key, source, destination, amount, *, sweep=False):
        spec = get_chain_spec(chain_id)
        asset = assert_verified_token(asset_key)
        if spec.kind is not ChainKind.EVM or asset.chain_id != chain_id:
            raise UnsupportedNativeTransaction("ERC20 chain mismatch")
        units = to_base_units(amount, asset.decimals)
        url = rpc_urls(chain_id)[0]
        balance_data = "0x70a08231" + source.lower().removeprefix("0x").rjust(64, "0")
        token_balance = _int(
            self._rpc(
                chain_id,
                url,
                "eth_call",
                [{"to": asset.contract_address, "data": balance_data}, "latest"],
            )
        )
        if token_balance < units:
            raise InsufficientBalance("source token balance is insufficient")
        pending = _int(self._rpc(chain_id, url, "eth_getTransactionCount", [source, "pending"]))
        calldata = (
            "0xa9059cbb"
            + destination.lower().removeprefix("0x").rjust(64, "0")
            + units.to_bytes(32, "big").hex()
        )
        tx = {
            "chainId": spec.evm_chain_id,
            "nonce": pending,
            "from": source,
            "to": asset.contract_address,
            "value": 0,
            "data": calldata,
        }
        gas = _int(self._rpc(chain_id, url, "eth_estimateGas", [tx]))
        if gas > _cap(spec.gas_settings, "max_gas_limit"):
            raise FeePolicyError("estimated gas exceeds max_gas_limit")
        latest = self._rpc(chain_id, url, "eth_getBlockByNumber", ["latest", False]) or {}
        if latest.get("baseFeePerGas") is not None:
            priority = _int(self._rpc(chain_id, url, "eth_maxPriorityFeePerGas", []))
            if priority > _cap(spec.gas_settings, "max_priority_fee_per_gas"):
                raise FeePolicyError("priority fee exceeds configured cap")
            max_fee = _int(latest["baseFeePerGas"]) * 2 + priority
            if max_fee > _cap(spec.gas_settings, "max_fee_per_gas"):
                raise FeePolicyError("suggested max fee exceeds configured cap")
            tx.update(gas=gas, maxFeePerGas=max_fee, maxPriorityFeePerGas=priority)
            fees = {
                "mode": "eip1559",
                "gas": str(gas),
                "max_fee_per_gas": str(max_fee),
                "max_priority_fee_per_gas": str(priority),
            }
            worst = gas * max_fee
        else:
            price = _int(self._rpc(chain_id, url, "eth_gasPrice", []))
            if price > _cap(spec.gas_settings, "max_legacy_gas_price"):
                raise FeePolicyError("gas price exceeds configured cap")
            tx.update(gas=gas, gasPrice=price)
            fees = {"mode": "legacy", "gas": str(gas), "gas_price": str(price)}
            worst = gas * price
        if _int(self._rpc(chain_id, url, "eth_getBalance", [source, "pending"])) < worst:
            raise InsufficientBalance("source native balance cannot fund token gas")
        fees["worst_case_base_units"] = str(worst)
        fees["token_contract"] = asset.contract_address
        fees["token_amount"] = str(units)
        fees["token_recipient"] = destination
        return PreparedNativeTransaction(
            chain_id, asset_key, source, destination, amount, units, b"", tx, fees, sequence=pending
        )

    prepare_sweep = prepare

    def reconcile(self, prepared, tx_id):
        native = super().reconcile(prepared, tx_id)
        if native.state is not ReconciliationState.CONFIRMED:
            return native
        receipt = native.evidence["receipt"]
        expected_contract = prepared.fee_metadata["token_contract"].lower()
        source = prepared.from_address.lower().removeprefix("0x").rjust(64, "0")
        destination = prepared.to_address.lower().removeprefix("0x").rjust(64, "0")
        for log in receipt.get("logs") or []:
            topics = log.get("topics") or []
            if (
                log.get("address", "").lower() == expected_contract
                and len(topics) == 3
                and topics[0].lower() == TRANSFER_TOPIC
                and topics[1].lower().removeprefix("0x") == source
                and topics[2].lower().removeprefix("0x") == destination
                and int(log.get("data", "0x0"), 16) == prepared.base_unit_amount
            ):
                native.evidence["token_effect"] = {"log_index": log.get("logIndex")}
                return native
        return ReconciliationResult(
            ReconciliationState.RECONCILIATION_REQUIRED,
            {**native.evidence, "error": "TOKEN_EFFECT_MISMATCH"},
        )


def get_transfer_executor(chain_id: str, asset_key: str, transport=None):
    asset = Asset.objects.get(asset_key=asset_key, chain_id=chain_id, enabled=True)
    if asset.is_native:
        from .native_tx import get_native_executor

        return get_native_executor(chain_id, transport)
    assert_verified_token(asset_key)
    if asset.token_standard == "ERC20":
        return Erc20Executor(transport)
    if asset.token_standard == "TRC20":
        return Trc20Executor(transport)
    if asset.token_standard == "SPL":
        return SplTokenExecutor(transport)
    raise UnsupportedNativeTransaction(f"{asset.token_standard} executor is not yet available")


class Trc20Executor(TronNativeExecutor):
    """TRC20 executor over the exact node-generated TRON transaction."""

    def __init__(self, transport=None):
        from .native_tx import RequestsTransport

        self.transport = transport or RequestsTransport()

    def prepare(self, chain_id, asset_key, source, destination, amount, *, sweep=False):
        from .token_metadata import tron_address_hex

        spec = get_chain_spec(chain_id)
        asset = assert_verified_token(asset_key)
        if (
            spec.kind is not ChainKind.TRON
            or asset.token_standard != "TRC20"
            or asset.chain_id != chain_id
        ):
            raise UnsupportedNativeTransaction("TRC20 chain mismatch")
        units = to_base_units(amount, asset.decimals)
        fee_limit = _cap(spec.gas_settings, "max_trc20_fee_limit")
        source_hex = tron_address_hex(source)
        destination_hex = tron_address_hex(destination)
        balance_parameter = source_hex[2:].rjust(64, "0")
        url = rpc_urls(chain_id)[0]
        balance = self._post(
            chain_id,
            url,
            "/wallet/triggerconstantcontract",
            {
                "owner_address": source,
                "contract_address": asset.contract_address,
                "function_selector": "balanceOf(address)",
                "parameter": balance_parameter,
                "visible": True,
            },
        )
        try:
            from django.conf import settings

            if settings.MPC_SIGNER_BACKEND == "self_hosted_mpc" and (
                balance.get("result", {}).get("result") is not True
                or len(balance.get("constant_result", [])) != 1
                or len(bytes.fromhex(balance["constant_result"][0])) != 32
            ):
                raise ValueError("TRC20 balance ABI/result mismatch")
            available = int(balance["constant_result"][0], 16)
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise InsufficientBalance("TRC20 balance preflight failed") from exc
        if available < units:
            raise InsufficientBalance("source token balance is insufficient")
        account = self._post(
            chain_id, url, "/wallet/getaccount", {"address": source, "visible": True}
        )
        if int(account.get("balance", 0)) < fee_limit:
            raise InsufficientBalance("source TRX balance cannot fund reviewed fee_limit")
        parameter = destination_hex[2:].rjust(64, "0") + units.to_bytes(32, "big").hex()
        from django.conf import settings

        mpc = settings.MPC_SIGNER_BACKEND == "self_hosted_mpc"
        fees = {"fee_limit_sun": str(fee_limit)}
        if mpc:
            from .tron_policy import resource_budget

            def post(path, payload):
                return self._post(chain_id, url, path, payload)

            estimate = post(
                "/wallet/estimateenergy",
                {
                    "owner_address": source,
                    "contract_address": asset.contract_address,
                    "function_selector": "transfer(address,uint256)",
                    "parameter": parameter,
                    "call_value": 0,
                    "visible": True,
                },
            )
            _, _, resource_fees = resource_budget(
                chain_id, source, destination, post, token=True, estimate=estimate
            )
            fees.update(resource_fees)
        body = self._post(
            chain_id,
            url,
            "/wallet/triggersmartcontract",
            {
                "owner_address": source,
                "contract_address": asset.contract_address,
                "function_selector": "transfer(address,uint256)",
                "parameter": parameter,
                "call_value": 0,
                "fee_limit": fee_limit,
                "visible": True,
            },
        )
        tx = body.get("transaction") or body
        txid, raw = tx.get("txID"), tx.get("raw_data")
        if not txid or not raw or body.get("result", {}).get("result") is False:
            raise FeePolicyError("TRON node did not prepare TRC20 transaction")
        if mpc:
            from .mpc_tron_network import network_identity
            from .tron_policy import freeze_transaction, validate_transfer

            validate_transfer(
                tx, source, destination, units, contract=asset.contract_address, fee_limit=fee_limit
            )
            tx, evidence = freeze_transaction(chain_id, tx, post)
            fees.update(evidence)
            fees["network"] = network_identity(chain_id)
            fees["token_contract"] = asset.contract_address
            txid, raw = tx["txID"], tx["raw_data"]
        else:
            tx.update(
                {
                    "token_contract": asset.contract_address,
                    "token_amount": str(units),
                    "token_recipient": destination,
                    "fee_limit": fee_limit,
                }
            )
        return PreparedNativeTransaction(
            chain_id,
            asset_key,
            source,
            destination,
            amount,
            units,
            bytes.fromhex(txid),
            tx,
            fees,
            expected_tx_id=txid,
            expires_at_ms=raw.get("expiration"),
        )

    prepare_sweep = prepare

    @staticmethod
    def assemble(prepared, signed_ref):
        tx = {
            key: value
            for key, value in prepared.unsigned_payload.items()
            if key not in {"token_contract", "token_amount", "token_recipient", "fee_limit"}
        }
        tx["signature"] = [signed_ref.removeprefix("signed:")]
        return tx

    def broadcast(self, chain_id, signed, expected):
        from .native_tx import TronNativeExecutor

        return TronNativeExecutor(self.transport).broadcast(chain_id, signed, expected)

    def reconcile(self, prepared, tx_id):
        from django.conf import settings

        from .token_metadata import tron_address_hex

        if settings.MPC_SIGNER_BACKEND == "self_hosted_mpc":
            from .tron_settlement import reconcile_tron_transfer

            return reconcile_tron_transfer(self, prepared, tx_id, token=True)

        last_error = None
        info = None
        for url in rpc_urls(prepared.chain_id):
            try:
                info = self.transport.post(
                    url, "/walletsolidity/gettransactioninfobyid", {"value": tx_id}
                )
                break
            except Exception as exc:
                last_error = exc
        if not info or info.get("blockNumber") is None:
            return ReconciliationResult(
                ReconciliationState.UNKNOWN,
                {
                    "manual_non_inclusion_reconciliation_required": True,
                    "error": str(last_error or "not solidified"),
                },
            )
        if info.get("id") and str(info["id"]).lower() != tx_id.lower():
            return ReconciliationResult(
                ReconciliationState.RECONCILIATION_REQUIRED,
                {"error": "TXID_MISMATCH", "solidified": True},
            )
        evidence = {
            "solidified": True,
            "block_number": info.get("blockNumber"),
            "receipt": info.get("receipt", {}),
            "logs": info.get("log", []),
        }
        execution = info.get("receipt", {}).get("result")
        if str(info.get("result", "")).upper() == "FAILED":
            return ReconciliationResult(ReconciliationState.FAILED, evidence)
        if execution is None:
            return ReconciliationResult(
                ReconciliationState.RECONCILIATION_REQUIRED,
                {**evidence, "error": "TRON_EXECUTION_STATUS_UNAVAILABLE"},
            )
        if str(execution).upper() != "SUCCESS":
            return ReconciliationResult(ReconciliationState.FAILED, evidence)
        contract = tron_address_hex(prepared.unsigned_payload["token_contract"])[2:].lower()
        source = tron_address_hex(prepared.from_address)[2:].lower()
        destination = tron_address_hex(prepared.to_address)[2:].lower()
        for index, log in enumerate(info.get("log", [])):
            topics = log.get("topics") or []
            emitting = str(log.get("address", "")).lower().removeprefix("0x")
            if emitting.startswith("41"):
                emitting = emitting[2:]
            if (
                emitting == contract
                and len(topics) == 3
                and topics[0].lower().removeprefix("0x") == TRANSFER_TOPIC.removeprefix("0x")
                and topics[1].lower().removeprefix("0x")[-40:] == source
                and topics[2].lower().removeprefix("0x")[-40:] == destination
                and int(str(log.get("data", "0")), 16) == prepared.base_unit_amount
            ):
                evidence["token_effect"] = {"log_index": index}
                return ReconciliationResult(ReconciliationState.CONFIRMED, evidence)
        return ReconciliationResult(
            ReconciliationState.RECONCILIATION_REQUIRED,
            {**evidence, "error": "TOKEN_EFFECT_MISMATCH"},
        )


class SplTokenExecutor:
    """Classic SPL TransferChecked executor with deterministic ATA policy."""

    def __init__(self, transport=None):
        from .native_tx import RequestsTransport

        self.transport = transport or RequestsTransport()

    def prepare(self, chain_id, asset_key, source, destination, amount, *, sweep=False):
        from django.conf import settings

        if settings.MPC_SIGNER_BACKEND == "self_hosted_mpc":
            from .solana_policy import prepare_solana

            return prepare_solana(
                self.transport, chain_id, asset_key, source, destination, amount, sweep=sweep
            )
        import base64
        import struct

        from solders.hash import Hash
        from solders.instruction import AccountMeta, Instruction
        from solders.message import Message
        from solders.pubkey import Pubkey

        from .spl import ASSOCIATED_TOKEN_PROGRAM, derive_ata
        from .token_metadata import CLASSIC_TOKEN_PROGRAM

        spec = get_chain_spec(chain_id)
        asset = assert_verified_token(asset_key)
        if spec.kind is not ChainKind.SOLANA or asset.token_standard != "SPL":
            raise UnsupportedNativeTransaction("SPL chain mismatch")
        units = to_base_units(amount, asset.decimals, maximum=2**64 - 1)
        source_ata, destination_ata = (
            derive_ata(source, asset.contract_address),
            derive_ata(destination, asset.contract_address),
        )
        url = rpc_urls(chain_id)[0]
        source_info = self.transport.rpc(
            url,
            "getAccountInfo",
            [source_ata, {"encoding": "jsonParsed", "commitment": "confirmed"}],
        )["value"]
        if not source_info or source_info.get("owner") != CLASSIC_TOKEN_PROGRAM:
            raise InsufficientBalance("classic SPL source ATA does not exist")
        info = source_info["data"]["parsed"]["info"]
        if info.get("mint") != asset.contract_address or info.get("owner") != source:
            raise UnsupportedNativeTransaction("SPL source ATA mint/authority mismatch")
        if int(info["tokenAmount"]["amount"]) < units:
            raise InsufficientBalance("source token balance is insufficient")
        destination_info = self.transport.rpc(
            url,
            "getAccountInfo",
            [destination_ata, {"encoding": "jsonParsed", "commitment": "confirmed"}],
        )["value"]
        instructions = []
        rent = 0
        if destination_info is None:
            rent_cap = _cap(spec.gas_settings, "max_ata_rent_lamports")
            rent = _int(self.transport.rpc(url, "getMinimumBalanceForRentExemption", [165]))
            if rent > rent_cap:
                raise FeePolicyError("ATA rent exceeds configured cap")
            instructions.append(
                Instruction(
                    Pubkey.from_string(ASSOCIATED_TOKEN_PROGRAM),
                    bytes([1]),
                    [
                        AccountMeta(Pubkey.from_string(source), True, True),
                        AccountMeta(Pubkey.from_string(destination_ata), False, True),
                        AccountMeta(Pubkey.from_string(destination), False, False),
                        AccountMeta(Pubkey.from_string(asset.contract_address), False, False),
                        AccountMeta(
                            Pubkey.from_string("11111111111111111111111111111111"), False, False
                        ),
                        AccountMeta(Pubkey.from_string(CLASSIC_TOKEN_PROGRAM), False, False),
                    ],
                )
            )
        elif destination_info.get("owner") != CLASSIC_TOKEN_PROGRAM:
            raise UnsupportedNativeTransaction("destination ATA program mismatch")
        else:
            try:
                destination_token = destination_info["data"]["parsed"]["info"]
            except (KeyError, TypeError) as exc:
                raise UnsupportedNativeTransaction("destination ATA has invalid shape") from exc
            if (
                destination_token.get("mint") != asset.contract_address
                or destination_token.get("owner") != destination
            ):
                raise UnsupportedNativeTransaction("destination ATA mint/authority mismatch")
        instructions.append(
            Instruction(
                Pubkey.from_string(CLASSIC_TOKEN_PROGRAM),
                bytes([12]) + struct.pack("<Q", units) + bytes([asset.decimals]),
                [
                    AccountMeta(Pubkey.from_string(source_ata), False, True),
                    AccountMeta(Pubkey.from_string(asset.contract_address), False, False),
                    AccountMeta(Pubkey.from_string(destination_ata), False, True),
                    AccountMeta(Pubkey.from_string(source), True, False),
                ],
            )
        )
        block = self.transport.rpc(url, "getLatestBlockhash", [{"commitment": "confirmed"}])[
            "value"
        ]
        message = bytes(
            Message.new_with_blockhash(
                instructions, Pubkey.from_string(source), Hash.from_string(block["blockhash"])
            )
        )
        encoded = base64.b64encode(message).decode()
        fee = _int(self.transport.rpc(url, "getFeeForMessage", [encoded])["value"])
        if fee > _cap(spec.gas_settings, "max_fee_lamports"):
            raise FeePolicyError("Solana token fee exceeds configured cap")
        sol = _int(
            self.transport.rpc(url, "getBalance", [source, {"commitment": "confirmed"}])["value"]
        )
        if sol < fee + rent:
            raise InsufficientBalance("source SOL cannot fund token fee and ATA rent")
        raw = {
            "message": encoded,
            "mint": asset.contract_address,
            "sourceAta": source_ata,
            "destinationAta": destination_ata,
            "destinationOwner": destination,
            "recentBlockhash": block["blockhash"],
            "tokenAmount": str(units),
            "createDestinationAta": destination_info is None,
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
            {"fee_lamports": str(fee), "ata_rent_lamports": str(rent)},
            last_valid_block=_int(block["lastValidBlockHeight"]),
        )

    prepare_sweep = prepare

    def assemble(self, prepared, signed_ref):
        from .native_tx import SolanaNativeExecutor

        return SolanaNativeExecutor.assemble(prepared, signed_ref)

    def transaction_id(self, signed):
        from .native_tx import SolanaNativeExecutor

        return SolanaNativeExecutor.transaction_id(signed)

    def broadcast(self, chain_id, signed, expected):
        from .native_tx import SolanaNativeExecutor

        return SolanaNativeExecutor(self.transport).broadcast(chain_id, signed, expected)

    def reconcile(self, prepared, tx_id):
        from django.conf import settings

        if settings.MPC_SIGNER_BACKEND == "self_hosted_mpc":
            from .solana_settlement import reconcile_solana_transfer

            return reconcile_solana_transfer(self.transport, prepared, tx_id)
        from .token_metadata import CLASSIC_TOKEN_PROGRAM

        urls = rpc_urls(prepared.chain_id)
        status = None
        status_error = None
        for url in urls:
            try:
                status = self.transport.rpc(
                    url, "getSignatureStatuses", [[tx_id], {"searchTransactionHistory": True}]
                )["value"][0]
                break
            except Exception as exc:
                status_error = exc
        if status is None and status_error:
            return ReconciliationResult(
                ReconciliationState.UNKNOWN, {"rpc_error": str(status_error)}
            )
        if not status or status.get("confirmationStatus") != "finalized":
            return ReconciliationResult(
                ReconciliationState.PENDING if status else ReconciliationState.UNKNOWN
            )
        if status.get("err") is not None:
            return ReconciliationResult(
                ReconciliationState.FAILED, {"err": status["err"], "slot": status.get("slot")}
            )
        tx = None
        transaction_error = None
        for url in urls:
            try:
                tx = self.transport.rpc(
                    url,
                    "getTransaction",
                    [
                        tx_id,
                        {
                            "encoding": "jsonParsed",
                            "commitment": "finalized",
                            "maxSupportedTransactionVersion": 0,
                        },
                    ],
                )
                if tx is not None:
                    break
            except Exception as exc:
                transaction_error = exc
        evidence = {"slot": (tx or {}).get("slot"), "finalized": True}
        if not tx:
            return ReconciliationResult(
                ReconciliationState.RECONCILIATION_REQUIRED,
                {
                    **evidence,
                    "error": "FINALIZED_TRANSACTION_UNAVAILABLE",
                    "rpc_error": str(transaction_error or ""),
                },
            )
        if (tx.get("meta") or {}).get("err") is not None:
            return ReconciliationResult(
                ReconciliationState.RECONCILIATION_REQUIRED,
                {
                    **evidence,
                    "error": "INCONSISTENT_FINALIZED_EVIDENCE",
                    "transaction_err": tx["meta"]["err"],
                },
            )
        instructions = list(tx["transaction"]["message"].get("instructions", []))
        for group in tx.get("meta", {}).get("innerInstructions", []) or []:
            instructions.extend(group.get("instructions", []))
        for instruction in instructions:
            parsed = instruction.get("parsed") if isinstance(instruction, dict) else None
            details = (parsed or {}).get("info", {})
            amount = details.get("tokenAmount", {}).get("amount", details.get("amount", 0))
            mint = details.get("mint") or _solana_mint_for_account(tx, details.get("source"))
            if (
                instruction.get("programId") == CLASSIC_TOKEN_PROGRAM
                and parsed
                and parsed.get("type") in {"transfer", "transferChecked"}
                and details.get("source") == prepared.unsigned_payload["sourceAta"]
                and details.get("destination") == prepared.unsigned_payload["destinationAta"]
                and mint == prepared.unsigned_payload["mint"]
                and int(amount) == prepared.base_unit_amount
            ):
                evidence["token_effect"] = True
                return ReconciliationResult(ReconciliationState.CONFIRMED, evidence)
        return ReconciliationResult(
            ReconciliationState.RECONCILIATION_REQUIRED,
            {**evidence, "error": "TOKEN_EFFECT_MISMATCH"},
        )


def _solana_mint_for_account(tx, address):
    keys = tx.get("transaction", {}).get("message", {}).get("accountKeys", [])
    for index, key in enumerate(keys):
        pubkey = key.get("pubkey") if isinstance(key, dict) else key
        if pubkey != address:
            continue
        balances = (tx.get("meta", {}).get("preTokenBalances") or []) + (
            tx.get("meta", {}).get("postTokenBalances") or []
        )
        for balance in balances:
            if int(balance.get("accountIndex", -1)) == index:
                return balance.get("mint")
    return None
