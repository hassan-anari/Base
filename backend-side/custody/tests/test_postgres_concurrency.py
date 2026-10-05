import threading
import time
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from types import SimpleNamespace
from unittest import skipUnless
from unittest.mock import patch

from django.db import close_old_connections, connection
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from custody.ledger import InsufficientFunds, ensure_accounts, post_transaction, user_balances
from custody.models import (
    Asset,
    HotWallet,
    LedgerAccount,
    LedgerTransaction,
    OnchainTransactionAttempt,
    SweepJob,
    UserWallet,
    WithdrawalRequest,
)
from custody.native_tx import PreparedNativeTransaction, allocate_evm_nonce
from custody.token_metadata import metadata_fingerprint
from custody.withdrawals import approve, create_request, process_withdrawal


@skipUnless(connection.vendor == "postgresql", "PostgreSQL row-lock integration test")
class WithdrawalConcurrencyTests(TransactionTestCase):
    def test_concurrent_processing_sweep_recovery_broadcasts_once(self):
        wallet = UserWallet.objects.create(
            user_id="recover-sweep",
            chain_id="ETH",
            asset_key="USDT-ETH",
            derivation_path="m/recover",
            deposit_address="0x" + "3" * 40,
        )
        job = SweepJob.objects.create(
            user_wallet=wallet,
            asset_key="USDT-ETH",
            balance_snapshot=Decimal("1"),
            status="SWEEP_PROCESSING",
            idempotency_key="postgres-recover-sweep",
        )
        attempt = OnchainTransactionAttempt.objects.create(
            operation_type="SWEEP",
            operation_id=job.pk,
            chain_id="ETH",
            asset_key="USDT-ETH",
            from_address=wallet.deposit_address,
            to_address="0x" + "4" * 40,
            amount=Decimal("1"),
            base_unit_amount=10**6,
            status="PREPARED",
            sequence=81,
        )
        calls = 0
        lock = threading.Lock()

        def execute(pk, actor):
            nonlocal calls
            with lock:
                calls += 1
            time.sleep(0.2)
            OnchainTransactionAttempt.objects.filter(pk=pk).update(
                status="BROADCASTED", network_tx_id="0xrecovered"
            )
            return OnchainTransactionAttempt.objects.get(pk=pk)

        def worker():
            from custody.sweeper import advance_sweep

            close_old_connections()
            try:
                return advance_sweep(job.pk).status
            finally:
                close_old_connections()

        with (
            patch("custody.outbound.execute_attempt", side_effect=execute),
            ThreadPoolExecutor(max_workers=2) as pool,
        ):
            statuses = list(pool.map(lambda _: worker(), range(2)))
        job.refresh_from_db()
        attempt.refresh_from_db()
        self.assertEqual(calls, 1)
        self.assertEqual(job.status, "SWEEP_BROADCASTED")
        self.assertEqual(attempt.sequence, 81)
        self.assertEqual(
            OnchainTransactionAttempt.objects.filter(
                operation_type="SWEEP", operation_id=job.pk
            ).count(),
            1,
        )
        self.assertIn("SWEEP_PROCESSING", statuses)
        self.assertIn("SWEEP_BROADCASTED", statuses)

    def test_evm_nonce_allocator_assigns_consecutive_unique_nonces(self):
        def allocate():
            close_old_connections()
            try:
                return allocate_evm_nonce("ETH", "0x" + "2" * 40, 41)
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as pool:
            nonces = sorted(pool.map(lambda _: allocate(), range(2)))
        self.assertEqual(nonces, [41, 42])

    @override_settings(CUSTODY_TX_MODE="live")
    def test_two_live_withdrawals_own_consecutive_nonces_without_settlement(self):
        self.fund("live-nonce", "3")
        HotWallet.objects.update_or_create(
            chain_id="ETH", defaults={"address": "0x" + "2" * 40, "signing_key_ref": "m/hot"}
        )
        requests = [
            create_request(
                "live-nonce",
                "ETH",
                "0x" + suffix * 40,
                Decimal("1"),
                idempotency_key=f"live-nonce-{suffix}",
            )
            for suffix in ("a", "b")
        ]
        for request in requests:
            approve("admin", request.pk)
        broadcasts = []
        lock = threading.Lock()

        class Executor:
            def prepare(self, chain, asset, source, destination, amount):
                return PreparedNativeTransaction(
                    chain,
                    asset,
                    source,
                    destination,
                    amount,
                    10**18,
                    b"",
                    {"chainId": 1, "nonce": 50, "value": 10**18},
                    {},
                    sequence=50,
                )

            def assemble(self, prepared, signed):
                return bytes([prepared.unsigned_payload["nonce"]])

            def transaction_id(self, signed):
                return "0x" + signed.hex()

            def broadcast(self, chain, signed, expected):
                with lock:
                    broadcasts.append((signed, expected))

        class Signer:
            def sign(self, *args, **kwargs):
                return "signed:00"

        def worker(request):
            close_old_connections()
            try:
                return process_withdrawal("admin", request.pk).status
            finally:
                close_old_connections()

        with (
            patch("custody.outbound.get_native_executor", return_value=Executor()),
            patch("custody.outbound.get_signer", return_value=Signer()),
            ThreadPoolExecutor(max_workers=2) as pool,
        ):
            statuses = list(pool.map(worker, requests))
        attempts = OnchainTransactionAttempt.objects.filter(operation_type="WITHDRAWAL")
        self.assertEqual(statuses, ["BROADCASTED", "BROADCASTED"])
        self.assertEqual(attempts.count(), 2)
        self.assertEqual(sorted(attempts.values_list("sequence", flat=True)), [50, 51])
        self.assertEqual(len(broadcasts), 2)
        self.assertEqual(len({raw for raw, _ in broadcasts}), 2)
        self.assertEqual(user_balances("live-nonce", "ETH")["reserved"], Decimal("2"))

    @override_settings(CUSTODY_TX_MODE="live")
    def test_native_and_erc20_share_full_withdrawal_nonce_domain(self):
        self.fund("cross-asset", "2")
        token = Asset.objects.get(asset_key="USDT-ETH")
        token.contract_address = "0x" + "1" * 40
        token.token_standard = "ERC20"
        token.decimals = 6
        token.withdrawal_supported = True
        token.metadata_verified_at = timezone.now()
        token.metadata_fingerprint = metadata_fingerprint(token)
        Asset.objects.filter(pk=token.pk).update(
            contract_address=token.contract_address,
            token_standard="ERC20",
            decimals=6,
            withdrawal_supported=True,
            metadata_verified_at=token.metadata_verified_at,
            metadata_fingerprint=token.metadata_fingerprint,
        )
        ensure_accounts("cross-asset", token.asset_key)
        available = LedgerAccount.objects.get(
            owner_type="USER", owner_id="cross-asset", asset_key=token.asset_key, bucket="AVAILABLE"
        )
        clearing = LedgerAccount.objects.get(
            owner_type="SYSTEM",
            owner_id="custody",
            asset_key=token.asset_key,
            bucket="CUSTODY_CLEARING",
        )
        post_transaction(
            event_key="cross-asset:token-fund",
            event_type="DEPOSIT_CREDIT",
            asset_key=token.asset_key,
            ref_type="TestFixture",
            ref_id="token-fund",
            postings=[(available, Decimal("2")), (clearing, Decimal("-2"))],
        )
        HotWallet.objects.update_or_create(
            chain_id="ETH", defaults={"address": "0x" + "2" * 40, "signing_key_ref": "m/hot"}
        )
        native = create_request(
            "cross-asset", "ETH", "0x" + "a" * 40, Decimal("1"), idempotency_key="cross-native"
        )
        erc20 = create_request(
            "cross-asset",
            "ETH",
            "0x" + "b" * 40,
            Decimal("1"),
            asset_key=token.asset_key,
            idempotency_key="cross-token",
        )
        for request in (native, erc20):
            approve("admin", request.pk)
        broadcasts = []
        lock = threading.Lock()

        class Executor:
            def prepare(self, chain, asset, source, destination, amount):
                decimals = 18 if asset == "ETH" else 6
                return PreparedNativeTransaction(
                    chain,
                    asset,
                    source,
                    destination,
                    amount,
                    int(amount * Decimal(10) ** decimals),
                    b"",
                    {"chainId": 1, "nonce": 70, "value": 0},
                    {},
                    sequence=70,
                )

            def assemble(self, prepared, signed):
                return bytes([prepared.unsigned_payload["nonce"]])

            def transaction_id(self, signed):
                return "0x" + signed.hex()

            def broadcast(self, chain, signed, expected):
                with lock:
                    broadcasts.append(expected)

        class Signer:
            def sign(self, *args, **kwargs):
                return "signed:00"

        def worker(request):
            close_old_connections()
            try:
                return process_withdrawal("admin", request.pk).status
            finally:
                close_old_connections()

        executor = Executor()
        with (
            patch("custody.outbound.get_native_executor", return_value=executor),
            patch("custody.outbound.get_transfer_executor", return_value=executor),
            patch("custody.outbound.get_signer", return_value=Signer()),
            ThreadPoolExecutor(max_workers=2) as pool,
        ):
            statuses = list(pool.map(worker, [native, erc20]))
        attempts = OnchainTransactionAttempt.objects.filter(operation_type="WITHDRAWAL")
        self.assertEqual(statuses, ["BROADCASTED", "BROADCASTED"])
        self.assertEqual(sorted(attempts.values_list("sequence", flat=True)), [70, 71])
        self.assertEqual(attempts.values("from_address").distinct().count(), 1)
        self.assertEqual(len(broadcasts), 2)
        self.assertEqual(user_balances("cross-asset", "ETH")["reserved"], Decimal("1"))
        self.assertEqual(user_balances("cross-asset", token.asset_key)["reserved"], Decimal("1"))

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
