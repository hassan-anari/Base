from decimal import Decimal

from django.test import TestCase

from custody.deposits import ingest_event, reverse_confirmed
from custody.indexer.base import DepositEvent
from custody.ledger import (
    InsufficientFunds,
    LedgerIdempotencyConflict,
    ReservationReconciliationRequired,
    ensure_accounts,
    post_transaction,
    user_balances,
)
from custody.models import (
    LedgerAccount,
    LedgerPosting,
    LedgerTransaction,
    UserWallet,
    WithdrawalRequest,
)
from custody.withdrawals import approve, create_request, deny, mark_confirmed


def make_wallet(user="alice", asset="ETH", suffix="1"):
    return UserWallet.objects.create(
        user_id=user,
        chain_id="ETH",
        asset_key=asset,
        derivation_path=f"m/{suffix}",
        deposit_address="0x" + suffix * 40,
    )


def event(tx="0xdeposit", amount="1", confirmations=12):
    return DepositEvent(tx, Decimal(amount), 100, confirmations)


class LedgerTests(TestCase):
    def test_pending_confirmed_idempotent_and_reversal(self):
        wallet = make_wallet()
        deposit, _ = ingest_event(wallet, event(confirmations=2))
        self.assertEqual(user_balances("alice", "ETH")["available"], Decimal("0"))
        deposit, _ = ingest_event(wallet, event(confirmations=12))
        ingest_event(wallet, event(confirmations=13))
        self.assertEqual(deposit.status, "CONFIRMED")
        self.assertEqual(user_balances("alice", "ETH")["available"], Decimal("1"))
        reverse_confirmed(deposit.pk)
        reverse_confirmed(deposit.pk)
        self.assertEqual(user_balances("alice", "ETH")["available"], Decimal("0"))
        self.assertEqual(LedgerTransaction.objects.count(), 2)

    def test_withdrawal_reserve_release_and_settle(self):
        wallet = make_wallet()
        ingest_event(wallet, event(amount="2"))
        req = create_request(
            "alice", "ETH", "0x" + "9" * 40, Decimal("0.75"), idempotency_key="ledger-withdrawal"
        )
        retry = create_request(
            "alice", "ETH", "0x" + "9" * 40, Decimal("0.75"), idempotency_key="ledger-withdrawal"
        )
        self.assertEqual(req.pk, retry.pk)
        self.assertEqual(
            user_balances("alice", "ETH"),
            {"available": Decimal("1.25"), "reserved": Decimal("0.75"), "total": Decimal("2.00")},
        )
        approve("admin", req.pk)
        self.assertEqual(user_balances("alice", "ETH")["reserved"], Decimal("0.75"))
        req.status = "BROADCASTED"
        req.save(update_fields=["status"])
        mark_confirmed(req.pk)
        mark_confirmed(req.pk)
        self.assertEqual(
            user_balances("alice", "ETH"),
            {"available": Decimal("1.25"), "reserved": Decimal("0"), "total": Decimal("1.25")},
        )

    def test_denial_releases_and_insufficient_creates_nothing(self):
        wallet = make_wallet()
        ingest_event(wallet, event())
        req = create_request(
            "alice", "ETH", "0x" + "9" * 40, Decimal("0.75"), idempotency_key="release-key"
        )
        deny("admin", req.pk)
        deny("admin", req.pk)
        self.assertEqual(user_balances("alice", "ETH")["available"], Decimal("1"))
        before = LedgerTransaction.objects.count()
        with self.assertRaises(InsufficientFunds):
            create_request(
                "alice", "ETH", "0x" + "8" * 40, Decimal("1.1"), idempotency_key="too-much"
            )
        self.assertFalse(WithdrawalRequest.objects.filter(idempotency_key="too-much").exists())
        self.assertEqual(LedgerTransaction.objects.count(), before)

    def test_posting_validation_and_asset_isolation(self):
        ensure_accounts("alice", "ETH")
        ensure_accounts("bob", "BNB")
        eth = LedgerAccount.objects.get(
            owner_type="USER", owner_id="alice", asset_key="ETH", bucket="AVAILABLE"
        )
        bnb = LedgerAccount.objects.get(
            owner_type="USER", owner_id="bob", asset_key="BNB", bucket="AVAILABLE"
        )
        with self.assertRaisesMessage(ValueError, "non-zero"):
            post_transaction(
                event_key="zero",
                event_type="DEPOSIT_CREDIT",
                asset_key="ETH",
                ref_type="test",
                ref_id="1",
                postings=[(eth, Decimal("0"))],
            )
        with self.assertRaisesMessage(ValueError, "mix assets"):
            post_transaction(
                event_key="mixed",
                event_type="DEPOSIT_CREDIT",
                asset_key="ETH",
                ref_type="test",
                ref_id="2",
                postings=[(eth, Decimal("1")), (bnb, Decimal("-1"))],
            )
        with self.assertRaisesMessage(ValueError, "balance"):
            post_transaction(
                event_key="unbalanced",
                event_type="DEPOSIT_CREDIT",
                asset_key="ETH",
                ref_type="test",
                ref_id="3",
                postings=[(eth, Decimal("1"))],
            )

    def test_event_key_requires_identical_semantics(self):
        wallet = make_wallet()
        deposit, _ = ingest_event(wallet, event())
        transaction_row = LedgerTransaction.objects.get(event_key=f"deposit:{deposit.pk}:credit")
        available = LedgerAccount.objects.get(
            owner_type="USER", owner_id="alice", asset_key="ETH", bucket="AVAILABLE"
        )
        clearing = LedgerAccount.objects.get(
            owner_type="SYSTEM", owner_id="custody", asset_key="ETH", bucket="CUSTODY_CLEARING"
        )
        same, created = post_transaction(
            event_key=transaction_row.event_key,
            event_type="DEPOSIT_CREDIT",
            asset_key="ETH",
            ref_type="Deposit",
            ref_id=str(deposit.pk),
            postings=[(available, Decimal("1")), (clearing, Decimal("-1"))],
        )
        self.assertEqual(same.pk, transaction_row.pk)
        self.assertFalse(created)
        with self.assertRaises(LedgerIdempotencyConflict):
            post_transaction(
                event_key=transaction_row.event_key,
                event_type="DEPOSIT_REVERSAL",
                asset_key="ETH",
                ref_type="Deposit",
                ref_id=str(deposit.pk),
                postings=[(available, Decimal("-1")), (clearing, Decimal("1"))],
            )

    def test_journal_is_append_only_through_model_and_queryset_apis(self):
        wallet = make_wallet()
        ingest_event(wallet, event())
        journal = LedgerTransaction.objects.get()
        posting = LedgerPosting.objects.first()
        journal.event_type = "DEPOSIT_REVERSAL"
        posting.amount = Decimal("99")
        for operation in (
            journal.save,
            journal.delete,
            posting.save,
            posting.delete,
            lambda: LedgerTransaction.objects.filter(pk=journal.pk).update(ref_id="changed"),
            lambda: LedgerTransaction.objects.filter(pk=journal.pk).delete(),
            lambda: LedgerPosting.objects.filter(pk=posting.pk).update(amount=Decimal("99")),
            lambda: LedgerPosting.objects.filter(pk=posting.pk).delete(),
        ):
            with self.assertRaisesMessage(ValueError, "append-only"):
                operation()
        journal.refresh_from_db()
        posting.refresh_from_db()
        self.assertEqual(journal.event_type, "DEPOSIT_CREDIT")
        self.assertNotEqual(posting.amount, Decimal("99"))

    def test_legacy_withdrawals_cannot_release_or_settle_other_reservations(self):
        wallet = make_wallet()
        ingest_event(wallet, event(amount="2"))
        reserved = create_request(
            "alice", "ETH", "0x" + "9" * 40, Decimal("0.75"), idempotency_key="reserved"
        )
        expected_balances = user_balances("alice", "ETH")
        expected_journals = LedgerTransaction.objects.count()
        legacy_pending = WithdrawalRequest.objects.create(
            user_id="alice",
            chain_id="ETH",
            asset_key="ETH",
            to_address="0x" + "8" * 40,
            amount=Decimal("0.5"),
            status="PENDING_APPROVAL",
            idempotency_key="legacy-pending",
        )
        with self.assertRaises(ReservationReconciliationRequired):
            deny("admin", legacy_pending.pk)
        legacy_pending.refresh_from_db()
        self.assertEqual(legacy_pending.status, "PENDING_APPROVAL")
        legacy_broadcast = WithdrawalRequest.objects.create(
            user_id="alice",
            chain_id="ETH",
            asset_key="ETH",
            to_address="0x" + "7" * 40,
            amount=Decimal("0.5"),
            status="BROADCASTED",
            idempotency_key="legacy-broadcast",
        )
        with self.assertRaises(ReservationReconciliationRequired):
            mark_confirmed(legacy_broadcast.pk)
        legacy_broadcast.refresh_from_db()
        self.assertEqual(legacy_broadcast.status, "BROADCASTED")
        self.assertEqual(user_balances("alice", "ETH"), expected_balances)
        self.assertEqual(LedgerTransaction.objects.count(), expected_journals)
        self.assertTrue(
            LedgerTransaction.objects.filter(event_key=f"withdrawal:{reserved.pk}:reserve").exists()
        )
