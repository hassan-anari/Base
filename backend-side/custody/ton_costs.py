"""Exactly-once observed TON contract fees and separate external Jetton funding."""

import hashlib
from decimal import Decimal

from django.db import connection, transaction

from .ledger import post_transaction
from .models import LedgerAccount
from .ton_wire import normalize_address, uint


@transaction.atomic
def post_native_cost(event_key, units, bucket, ref_type, ref_id, metadata):
    units = uint(units, 64)
    if not units:
        return
    if connection.vendor != "postgresql":
        raise ValueError("TON financial posting requires PostgreSQL")
    # Scanner and outbound reconciliation can see the same contract transaction.
    # Serialize journal creation and system account creation across both callers.
    key = int.from_bytes(hashlib.sha256(b"TON:financial-costs").digest()[:8], "big", signed=True)
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_advisory_xact_lock(%s)", [key])
    treasury, _ = LedgerAccount.objects.get_or_create(
        owner_type="SYSTEM", owner_id="custody", asset_key="TON", bucket="TREASURY_ASSET"
    )
    debit, _ = LedgerAccount.objects.get_or_create(
        owner_type="SYSTEM", owner_id="custody", asset_key="TON", bucket=bucket
    )
    amount = Decimal(units) / Decimal(10**9)
    post_transaction(
        event_key=event_key,
        event_type="NETWORK_FEE" if bucket == "NETWORK_FEE_EXPENSE" else "TOKEN_GAS",
        asset_key="TON",
        ref_type=ref_type,
        ref_id=ref_id,
        postings=[(debit, amount), (treasury, -amount)],
        metadata=metadata,
    )


def post_verified_transaction_fee(account, tx_hash, units):
    account = normalize_address(account).raw
    if len(tx_hash) != 64 or bytes.fromhex(tx_hash).hex() != tx_hash:
        raise ValueError("TON fee transaction hash invalid")
    ref = account + ":" + tx_hash
    post_native_cost(
        "ton:tx:" + ref + ":fee",
        units,
        "NETWORK_FEE_EXPENSE",
        "TON_TRANSACTION",
        tx_hash,
        {"account": account, "transaction_hash": tx_hash, "nanoton": str(units)},
    )


def post_execution_costs(attempt, evidence):
    if not evidence.get("network_finality") or not evidence.get("ton_terminal_delivery"):
        raise ValueError("TON cost accounting lacks terminal finality")
    for item in evidence["fee_transactions"]:
        post_verified_transaction_fee(item["account"], item["hash"], item["fee_nanoton"])
    post_native_cost(
        f"ton:{attempt.network_tx_id}:external_jetton_funding",
        evidence["funding_expense_nanoton"],
        "TOKEN_GAS_EXPENSE",
        "OnchainTransactionAttempt",
        str(attempt.pk),
        {
            "message_hash": attempt.network_tx_id,
            "nanoton": str(evidence["funding_expense_nanoton"]),
            "returned_nanoton": str(evidence["returned_nanoton"]),
        },
    )
