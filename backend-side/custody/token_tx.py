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
            self.transport.rpc(
                url, "eth_call", [{"to": asset.contract_address, "data": balance_data}, "latest"]
            )
        )
        if token_balance < units:
            raise InsufficientBalance("source token balance is insufficient")
        pending = _int(self.transport.rpc(url, "eth_getTransactionCount", [source, "pending"]))
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
        gas = _int(self.transport.rpc(url, "eth_estimateGas", [tx]))
        if gas > _cap(spec.gas_settings, "max_gas_limit"):
            raise FeePolicyError("estimated gas exceeds max_gas_limit")
        latest = self.transport.rpc(url, "eth_getBlockByNumber", ["latest", False]) or {}
        if latest.get("baseFeePerGas") is not None:
            priority = _int(self.transport.rpc(url, "eth_maxPriorityFeePerGas", []))
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
            price = _int(self.transport.rpc(url, "eth_gasPrice", []))
            if price > _cap(spec.gas_settings, "max_legacy_gas_price"):
                raise FeePolicyError("gas price exceeds configured cap")
            tx.update(gas=gas, gasPrice=price)
            fees = {"mode": "legacy", "gas": str(gas), "gas_price": str(price)}
            worst = gas * price
        if _int(self.transport.rpc(url, "eth_getBalance", [source, "pending"])) < worst:
            raise InsufficientBalance("source native balance cannot fund token gas")
        fees["worst_case_base_units"] = str(worst)
        tx["token_contract"] = asset.contract_address
        tx["token_amount"] = str(units)
        tx["token_recipient"] = destination
        return PreparedNativeTransaction(
            chain_id, asset_key, source, destination, amount, units, b"", tx, fees, sequence=pending
        )

    prepare_sweep = prepare

    def reconcile(self, prepared, tx_id):
        native = super().reconcile(prepared, tx_id)
        if native.state is not ReconciliationState.CONFIRMED:
            return native
        receipt = native.evidence["receipt"]
        expected_contract = prepared.unsigned_payload["token_contract"].lower()
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
            ReconciliationState.INCLUDED, {**native.evidence, "token_effect_mismatch": True}
        )


def get_transfer_executor(chain_id: str, asset_key: str, transport=None):
    asset = Asset.objects.get(asset_key=asset_key, chain_id=chain_id, enabled=True)
    if asset.is_native:
        from .native_tx import get_native_executor

        return get_native_executor(chain_id, transport)
    assert_verified_token(asset_key)
    if asset.token_standard == "ERC20":
        return Erc20Executor(transport)
    raise UnsupportedNativeTransaction(f"{asset.token_standard} executor is not yet available")
