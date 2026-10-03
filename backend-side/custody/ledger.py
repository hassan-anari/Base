"""Transactional, append-only, double-entry custody ledger."""

from __future__ import annotations

from decimal import Decimal

from django.db import IntegrityError, transaction
from django.db.models import Sum
from django.db.models.functions import Coalesce

from .models import LedgerAccount, LedgerPosting, LedgerTransaction

ZERO = Decimal("0")


class InsufficientFunds(ValueError):
    pass


class LedgerIdempotencyConflict(ValueError):
    pass


class ReservationReconciliationRequired(ValueError):
    pass


def ensure_accounts(user_id: str, asset_key: str) -> None:
    identities = [
        ("USER", user_id, "AVAILABLE"),
        ("USER", user_id, "RESERVED"),
        ("SYSTEM", "custody", "CUSTODY_CLEARING"),
    ]
    for owner_type, owner_id, bucket in identities:
        try:
            # Isolate a unique-constraint race in a savepoint so a caller's
            # outer accounting transaction remains usable.
            with transaction.atomic():
                LedgerAccount.objects.get_or_create(
                    owner_type=owner_type,
                    owner_id=owner_id,
                    asset_key=asset_key,
                    bucket=bucket,
                )
        except IntegrityError:
            # A concurrent creator won the unique-constraint race.
            LedgerAccount.objects.get(
                owner_type=owner_type,
                owner_id=owner_id,
                asset_key=asset_key,
                bucket=bucket,
            )


def lock_user_accounts(user_id: str, asset_key: str) -> dict[str, LedgerAccount]:
    ensure_accounts(user_id, asset_key)
    rows = (
        LedgerAccount.objects.select_for_update()
        .filter(owner_type="USER", owner_id=user_id, asset_key=asset_key)
        .order_by("id")
    )
    return {row.bucket: row for row in rows}


def clearing_account(asset_key: str) -> LedgerAccount:
    return LedgerAccount.objects.get(
        owner_type="SYSTEM", owner_id="custody", asset_key=asset_key, bucket="CUSTODY_CLEARING"
    )


def account_balance(account: LedgerAccount) -> Decimal:
    return account.postings.aggregate(total=Coalesce(Sum("amount"), ZERO))["total"]


def user_balances(user_id: str, asset_key: str) -> dict[str, Decimal]:
    ensure_accounts(user_id, asset_key)
    accounts = LedgerAccount.objects.filter(
        owner_type="USER", owner_id=user_id, asset_key=asset_key
    )
    balances = {row.bucket: account_balance(row) for row in accounts}
    available = balances.get("AVAILABLE", ZERO)
    reserved = balances.get("RESERVED", ZERO)
    return {"available": available, "reserved": reserved, "total": available + reserved}


@transaction.atomic
def post_transaction(
    *,
    event_key: str,
    event_type: str,
    asset_key: str,
    ref_type: str,
    ref_id: str,
    postings: list[tuple[LedgerAccount, Decimal]],
    metadata: dict | None = None,
) -> tuple[LedgerTransaction, bool]:
    normalized = [(account, Decimal(amount)) for account, amount in postings]
    if not normalized or any(amount == ZERO for _, amount in normalized):
        raise ValueError("ledger postings must be non-zero")
    if any(account.asset_key != asset_key for account, _ in normalized):
        raise ValueError("ledger transaction cannot mix assets")
    if sum((amount for _, amount in normalized), ZERO) != ZERO:
        raise ValueError("ledger transaction postings must balance to zero")
    existing = LedgerTransaction.objects.filter(event_key=event_key).first()
    if existing:
        _validate_existing_transaction(
            existing, event_type, asset_key, ref_type, str(ref_id), normalized
        )
        return existing, False
    journal = LedgerTransaction.objects.create(
        event_key=event_key,
        event_type=event_type,
        asset_key=asset_key,
        ref_type=ref_type,
        ref_id=str(ref_id),
        metadata=metadata or {},
    )
    LedgerPosting.objects.bulk_create(
        [
            LedgerPosting(transaction=journal, account=account, amount=amount)
            for account, amount in normalized
        ]
    )
    return journal, True


def _posting_signature(postings):
    return sorted(
        (
            account.owner_type,
            account.owner_id,
            account.asset_key,
            account.bucket,
            Decimal(amount),
        )
        for account, amount in postings
    )


def _validate_existing_transaction(
    existing, event_type, asset_key, ref_type, ref_id, expected_postings
):
    header = (existing.event_type, existing.asset_key, existing.ref_type, existing.ref_id)
    expected_header = (event_type, asset_key, ref_type, ref_id)
    actual_postings = [
        (posting.account, posting.amount)
        for posting in existing.postings.select_related("account").all()
    ]
    if header != expected_header or _posting_signature(actual_postings) != _posting_signature(
        expected_postings
    ):
        raise LedgerIdempotencyConflict(
            f"ledger event key {existing.event_key!r} already has different semantics"
        )


def _require_withdrawal_reservation(req, accounts):
    event_key = f"withdrawal:{req.pk}:reserve"
    reservation = LedgerTransaction.objects.filter(event_key=event_key).first()
    if reservation is None:
        raise ReservationReconciliationRequired(
            f"withdrawal {req.pk} has no valid reservation; explicit reconciliation required"
        )
    try:
        _validate_existing_transaction(
            reservation,
            "WITHDRAWAL_RESERVE",
            req.asset_key,
            "WithdrawalRequest",
            str(req.pk),
            [(accounts["AVAILABLE"], -req.amount), (accounts["RESERVED"], req.amount)],
        )
    except LedgerIdempotencyConflict as exc:
        raise ReservationReconciliationRequired(
            f"withdrawal {req.pk} reservation is invalid; explicit reconciliation required"
        ) from exc


def credit_deposit(deposit):
    accounts = lock_user_accounts(deposit.user_wallet.user_id, deposit.asset_key)
    return post_transaction(
        event_key=f"deposit:{deposit.pk}:credit",
        event_type="DEPOSIT_CREDIT",
        asset_key=deposit.asset_key,
        ref_type="Deposit",
        ref_id=deposit.pk,
        postings=[
            (accounts["AVAILABLE"], deposit.amount),
            (clearing_account(deposit.asset_key), -deposit.amount),
        ],
    )


def reverse_deposit_posting(deposit):
    accounts = lock_user_accounts(deposit.user_wallet.user_id, deposit.asset_key)
    return post_transaction(
        event_key=f"deposit:{deposit.pk}:reversal",
        event_type="DEPOSIT_REVERSAL",
        asset_key=deposit.asset_key,
        ref_type="Deposit",
        ref_id=deposit.pk,
        postings=[
            (accounts["AVAILABLE"], -deposit.amount),
            (clearing_account(deposit.asset_key), deposit.amount),
        ],
    )


def reserve_withdrawal(req):
    accounts = lock_user_accounts(req.user_id, req.asset_key)
    if account_balance(accounts["AVAILABLE"]) < req.amount:
        raise InsufficientFunds("insufficient available ledger balance")
    return post_transaction(
        event_key=f"withdrawal:{req.pk}:reserve",
        event_type="WITHDRAWAL_RESERVE",
        asset_key=req.asset_key,
        ref_type="WithdrawalRequest",
        ref_id=req.pk,
        postings=[(accounts["AVAILABLE"], -req.amount), (accounts["RESERVED"], req.amount)],
    )


def release_withdrawal(req):
    accounts = lock_user_accounts(req.user_id, req.asset_key)
    _require_withdrawal_reservation(req, accounts)
    return post_transaction(
        event_key=f"withdrawal:{req.pk}:release",
        event_type="WITHDRAWAL_RELEASE",
        asset_key=req.asset_key,
        ref_type="WithdrawalRequest",
        ref_id=req.pk,
        postings=[(accounts["RESERVED"], -req.amount), (accounts["AVAILABLE"], req.amount)],
    )


def settle_withdrawal(req):
    accounts = lock_user_accounts(req.user_id, req.asset_key)
    _require_withdrawal_reservation(req, accounts)
    return post_transaction(
        event_key=f"withdrawal:{req.pk}:settle",
        event_type="WITHDRAWAL_SETTLE",
        asset_key=req.asset_key,
        ref_type="WithdrawalRequest",
        ref_id=req.pk,
        postings=[
            (accounts["RESERVED"], -req.amount),
            (clearing_account(req.asset_key), req.amount),
        ],
    )
