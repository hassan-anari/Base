"""Authoritative deposit-event ingestion and reversal boundaries."""

from decimal import Decimal

from django.db import transaction

from .config import get_confirmation_threshold
from .ledger import credit_deposit, reverse_deposit_posting
from .models import Deposit


def ingest_event(user_wallet, event) -> tuple[Deposit, bool]:
    """Persist/update one concrete indexer event and credit at finality exactly once."""
    amount = Decimal(str(event.amount))
    threshold = get_confirmation_threshold(user_wallet.chain_id)
    with transaction.atomic():
        deposit, created = Deposit.objects.get_or_create(
            user_wallet=user_wallet,
            tx_hash=event.tx_hash,
            asset_key=user_wallet.asset_key,
            defaults={
                "amount": amount,
                "block": event.block,
                "confirmations": event.confirmations,
                "memo": event.memo,
                "status": "PENDING",
            },
        )
        deposit = (
            Deposit.objects.select_for_update().select_related("user_wallet").get(pk=deposit.pk)
        )
        if deposit.amount != amount:
            raise ValueError("deposit event amount changed")
        if deposit.status != "REVERTED":
            fields = []
            if event.confirmations > deposit.confirmations:
                deposit.confirmations = event.confirmations
                fields.append("confirmations")
            if event.block is not None and event.block != deposit.block:
                deposit.block = event.block
                fields.append("block")
            became_confirmed = deposit.status == "PENDING" and event.confirmations >= threshold
            if became_confirmed:
                deposit.status = "CONFIRMED"
                fields.append("status")
                credit_deposit(deposit)
            if fields:
                deposit.save(update_fields=fields)
        return deposit, created


def reverse_confirmed(deposit_id: int) -> Deposit:
    """Record CONFIRMED -> REVERTED with its exact compensating journal entry."""
    with transaction.atomic():
        deposit = (
            Deposit.objects.select_for_update().select_related("user_wallet").get(pk=deposit_id)
        )
        if deposit.status == "REVERTED":
            return deposit
        if deposit.status != "CONFIRMED":
            raise ValueError(f"cannot reverse deposit in state {deposit.status}")
        reverse_deposit_posting(deposit)
        deposit.status = "REVERTED"
        deposit.save(update_fields=["status"])
        return deposit
