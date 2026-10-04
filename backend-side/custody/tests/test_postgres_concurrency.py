import threading
import time
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from types import SimpleNamespace
from unittest import skipUnless
from unittest.mock import patch

from django.db import close_old_connections, connection
from django.test import TransactionTestCase

from custody.ledger import InsufficientFunds, ensure_accounts, post_transaction, user_balances
from custody.models import HotWallet, LedgerAccount, LedgerTransaction, WithdrawalRequest
from custody.withdrawals import create_request, process_withdrawal


@skipUnless(connection.vendor == "postgresql", "PostgreSQL row-lock integration test")
class WithdrawalConcurrencyTests(TransactionTestCase):
    def fund(self, user="concurrent", amount="1"):
        ensure_accounts(user, "ETH")
        available = LedgerAccount.objects.get(
            owner_type="USER", owner_id=user, asset_key="ETH", bucket="AVAILABLE"
        )
        clearing = LedgerAccount.objects.get(
            owner_type="SYSTEM", owner_id="custody", asset_key="ETH", bucket="CUSTODY_CLEARING"
        )
        post_transaction(
            event_key=f"concurrency:{user}:fund",
            event_type="DEPOSIT_CREDIT",
            asset_key="ETH",
            ref_type="TestFixture",
            ref_id="fund",
            postings=[(available, Decimal(amount)), (clearing, -Decimal(amount))],
        )

    def test_two_workers_cannot_double_reserve(self):
        self.fund()

        def reserve(key):
            close_old_connections()
            try:
                return create_request(
                    "concurrent", "ETH", "0x" + key[-1] * 40, Decimal("0.75"), idempotency_key=key
                ).pk
            except InsufficientFunds:
                return "insufficient"
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(reserve, ["reserve-worker-a", "reserve-worker-b"]))
        self.assertEqual(results.count("insufficient"), 1)
        self.assertEqual(
            user_balances("concurrent", "ETH"),
            {"available": Decimal("0.25"), "reserved": Decimal("0.75"), "total": Decimal("1.00")},
        )
        self.assertEqual(
            LedgerTransaction.objects.filter(event_type="WITHDRAWAL_RESERVE").count(), 1
        )

    def test_concurrent_same_idempotency_key_returns_same_request(self):
        self.fund("same-key", "2")

        def worker():
            close_old_connections()
            try:
                return create_request(
                    "same-key",
                    "ETH",
                    "0x" + "a" * 40,
                    Decimal("0.75"),
                    idempotency_key="concurrent-same-key",
                ).pk
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: worker(), range(2)))
        self.assertEqual(results[0], results[1])
        self.assertEqual(
            WithdrawalRequest.objects.filter(idempotency_key="concurrent-same-key").count(), 1
        )
        self.assertEqual(
            LedgerTransaction.objects.filter(
                event_type="WITHDRAWAL_RESERVE", ref_id=str(results[0])
            ).count(),
            1,
        )

    def test_concurrent_same_key_conflicting_payload_is_conflict(self):
        self.fund("conflict-key", "2")

        def worker(destination):
            close_old_connections()
            try:
                return create_request(
                    "conflict-key",
                    "ETH",
                    destination,
                    Decimal("0.75"),
                    idempotency_key="concurrent-conflict-key",
                ).pk
            except ValueError as exc:
                return str(exc)
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(worker, ["0x" + "b" * 40, "0x" + "c" * 40]))
        self.assertEqual(sum(isinstance(result, int) for result in results), 1)
        self.assertEqual(sum("different parameters" in str(result) for result in results), 1)
        request = WithdrawalRequest.objects.get(idempotency_key="concurrent-conflict-key")
        self.assertEqual(
            LedgerTransaction.objects.filter(
                event_type="WITHDRAWAL_RESERVE", ref_id=str(request.pk)
            ).count(),
            1,
        )

    def test_two_workers_broadcast_exactly_once(self):
        HotWallet.objects.update_or_create(
            chain_id="ETH", defaults={"address": "0x" + "2" * 40, "signing_key_ref": "m/hot"}
        )
        req = WithdrawalRequest.objects.create(
            user_id="customer",
            chain_id="ETH",
            asset_key="ETH",
            to_address="0x" + "4" * 40,
            amount=1,
            status="APPROVED",
            idempotency_key="postgres-concurrency-key",
        )
        calls = 0
        calls_lock = threading.Lock()

        class BlockingSigner:
            def sign_and_broadcast(self, **kwargs):
                nonlocal calls
                kwargs["before_sign"]()
                with calls_lock:
                    calls += 1
                time.sleep(0.25)
                return SimpleNamespace(tx_hash="0xpostgres")

        def worker():
            close_old_connections()
            try:
                return process_withdrawal("admin", req.pk).status
            except ValueError as exc:
                return str(exc)
            finally:
                close_old_connections()

        with (
            patch("custody.withdrawals.get_signer", return_value=BlockingSigner()),
            ThreadPoolExecutor(max_workers=2) as pool,
        ):
            results = list(pool.map(lambda _: worker(), range(2)))

        req.refresh_from_db()
        self.assertEqual(calls, 1)
        self.assertEqual(req.status, "BROADCASTED")
        self.assertEqual(results.count("BROADCASTED"), 1)
        self.assertEqual(sum("must be APPROVED" in result for result in results), 1)
