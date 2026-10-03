import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest import skipUnless
from unittest.mock import patch

from django.db import close_old_connections, connection
from django.test import TransactionTestCase

from custody.models import HotWallet, WithdrawalRequest
from custody.withdrawals import process_withdrawal


@skipUnless(connection.vendor == "postgresql", "PostgreSQL row-lock integration test")
class WithdrawalConcurrencyTests(TransactionTestCase):
    reset_sequences = True

    def test_two_workers_broadcast_exactly_once(self):
        HotWallet.objects.create(chain_id="ETH", address="0x" + "2" * 40)
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
