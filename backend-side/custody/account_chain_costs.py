"""Observed EVM/TRON native fees in the existing authoritative journal."""

from decimal import Decimal

from .chain_registry import ChainKind, get_chain_spec
from .ledger import financial_precision, post_transaction
from .models import LedgerAccount


def unsigned(value):
    if type(value) not in {str, int}:
        raise ValueError("invalid observed network fee")
    result = int(value, 16 if value.startswith("0x") else 10) if isinstance(value, str) else value
    if not 0 <= result < 2**256:
        raise ValueError("invalid observed network fee")
    return result


@financial_precision()
def post_execution_costs(attempt, evidence):
    """Caller holds the existing attempt lock and terminal settlement transaction.

    Only observed fees are expenses. A token operation always pays the runtime
    chain's frozen native asset; no token symbol participates in account selection.
    Failed terminal transactions also incur their actual execution costs.
    """
    spec = get_chain_spec(attempt.chain_id)
    if spec.kind is ChainKind.EVM:
        receipt = evidence["receipt"]
        if receipt["transactionHash"].lower() != attempt.network_tx_id.lower():
            raise ValueError("network fee transaction identity mismatch")
        if evidence["confirmations"] < spec.confirmations:
            raise ValueError("network fee lacks finality")
        gas, price = unsigned(receipt["gasUsed"]), unsigned(receipt["effectiveGasPrice"])
        raw = attempt.prepared_metadata
        if gas > raw["gas"] or price > raw.get("maxFeePerGas", raw.get("gasPrice", 0)):
            raise ValueError("observed network fee exceeds original authorization")
        units = gas * price
    elif spec.kind is ChainKind.TRON:
        if evidence.get("solidified") is not True or evidence["txid"] != attempt.network_tx_id:
            raise ValueError("network fee lacks original solidified identity")
        units = unsigned(evidence["fee"])
        if units > int(attempt.fee_metadata["worst_case_base_units"]):
            raise ValueError("observed network fee exceeds original authorization")
    else:
        raise ValueError("unsupported account-chain fee")
    if not units:
        return
    accounts = []
    for bucket in ("NETWORK_FEE_EXPENSE", "TREASURY_ASSET"):
        account, _ = LedgerAccount.objects.get_or_create(
            owner_type="SYSTEM", owner_id="custody", asset_key=spec.native_asset_key, bucket=bucket
        )
        accounts.append(account)
    amount = Decimal(units) / Decimal(10**spec.native_decimals)
    post_transaction(
        event_key=f"network:{attempt.chain_id}:{attempt.network_tx_id}:fee",
        event_type="NETWORK_FEE",
        asset_key=spec.native_asset_key,
        ref_type="OnchainTransactionAttempt",
        ref_id=str(attempt.pk),
        postings=[(accounts[0], amount), (accounts[1], -amount)],
        metadata={
            "chain": attempt.chain_id,
            "txid": attempt.network_tx_id,
            "base_units": str(units),
        },
    )
