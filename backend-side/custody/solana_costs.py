"""Exactly-once observed Solana fees and ATA rent using the shared journal."""

from decimal import Decimal

from .ledger import post_transaction
from .models import LedgerAccount
from .solana_wire import uint


def post_execution_costs(attempt, evidence):
    treasury, _ = LedgerAccount.objects.get_or_create(
        owner_type="SYSTEM", owner_id="custody", asset_key="SOL", bucket="TREASURY_ASSET"
    )
    for name, bucket, kind in (
        ("fee_lamports", "NETWORK_FEE_EXPENSE", "NETWORK_FEE"),
        ("rent_lamports", "ATA_RENT_ASSET", "ATA_RENT"),
    ):
        units = uint(evidence[name])
        if not units:
            continue
        debit, _ = LedgerAccount.objects.get_or_create(
            owner_type="SYSTEM", owner_id="custody", asset_key="SOL", bucket=bucket
        )
        amount = Decimal(units) / (10**9)
        post_transaction(
            event_key=f"solana:{attempt.pk}:{kind.lower()}",
            event_type=kind,
            asset_key="SOL",
            ref_type="OnchainTransactionAttempt",
            ref_id=str(attempt.pk),
            postings=[(debit, amount), (treasury, -amount)],
            metadata={
                "signature": attempt.network_tx_id,
                "slot": evidence["slot"],
                "lamports": str(units),
            },
        )
