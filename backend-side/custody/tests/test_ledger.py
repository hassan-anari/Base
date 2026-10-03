from decimal import Decimal

from django.test import TestCase

from custody.deposits import ingest_event, reverse_confirmed
from custody.indexer.base import DepositEvent
from custody.ledger import InsufficientFunds, ensure_accounts, post_transaction, user_balances
from custody.models import LedgerAccount, LedgerTransaction, UserWallet, WithdrawalRequest
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
