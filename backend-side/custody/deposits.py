"""Authoritative deposit-event ingestion and reversal boundaries."""

from decimal import Decimal

from django.db import transaction

from .config import get_confirmation_threshold, validate_chain_asset
from .ledger import credit_deposit, reverse_deposit_posting
from .models import Asset, Deposit


@transaction.atomic
def ingest_event(user_wallet, event) -> tuple[Deposit, bool]:
    """Persist/update one concrete indexer event and credit at finality exactly once."""
    # Serialize validation and first credit with registry mutation. Account
    # insertion freezes this same row before the transaction can release it.
    Asset.objects.select_for_update().get(asset_key=user_wallet.asset_key)
    asset = validate_chain_asset(user_wallet.chain_id, user_wallet.asset_key, "deposit")
    if event.asset_key and event.asset_key != user_wallet.asset_key:
        raise ValueError("deposit event asset does not match wallet asset")
    if not event.asset_key and not asset.is_native:
        raise ValueError("token deposit event must identify its asset")
    amount = Decimal(str(event.amount))
    if not amount.is_finite() or amount <= 0:
        raise ValueError("deposit amount must be positive and finite")
    if amount != amount.quantize(Decimal(1).scaleb(-asset.decimals)):
        raise ValueError("deposit amount exceeds asset precision")
    if not asset.is_native:
        from .chain_registry import get_chain_spec
        from .token_metadata import canonical_contract

        if not event.contract_address:
            raise ValueError("token deposit is missing contract/mint evidence")
        kind = get_chain_spec(user_wallet.chain_id).kind
        if canonical_contract(kind, event.contract_address) != canonical_contract(
            kind, asset.contract_address
        ):
            raise ValueError("token deposit came from an unreviewed contract/mint")
    chain_evidence = {}
    if user_wallet.chain_id == "TON":
        from .ton_wire import jetton_wallet_address

        chain_evidence = getattr(event, "ton_finality_evidence", None)
        expected = (
            user_wallet.deposit_address
            if asset.is_native
            else jetton_wallet_address(user_wallet.deposit_address, asset.contract_address)
        )
        if (
            not chain_evidence
            or chain_evidence.get("account") != expected
            or chain_evidence.get("transaction_hash") != event.tx_hash
            or chain_evidence.get("inbound_message_hash") != event.event_index
            or chain_evidence.get("shard_block", {}).get("root_hash") != event.block_hash
        ):
            raise ValueError("TON deposit lacks verified account/message inclusion evidence")
    threshold = get_confirmation_threshold(user_wallet.chain_id)
    with transaction.atomic():
        deposit, created = Deposit.objects.get_or_create(
            user_wallet=user_wallet,
            tx_hash=event.tx_hash,
            asset_key=user_wallet.asset_key,
            event_index=event.event_index,
            defaults={
                "amount": amount,
                "block": event.block,
                "confirmations": event.confirmations,
                "memo": event.memo,
                "block_hash": event.block_hash,
                "status": "PENDING",
                "chain_evidence": chain_evidence,
            },
        )
        deposit = (
            Deposit.objects.select_for_update().select_related("user_wallet").get(pk=deposit.pk)
        )
        if deposit.amount != amount:
            raise ValueError("deposit event amount changed")
        if deposit.block_hash and event.block_hash and deposit.block_hash != event.block_hash:
            raise ValueError("deposit event block identity changed")
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
