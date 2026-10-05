from decimal import Decimal

from django.test import TestCase, override_settings
from django.utils import timezone

from custody.deposits import ingest_event
from custody.indexer.base import DepositEvent
from custody.ledger import account_balance
from custody.models import Asset, Deposit, LedgerAccount, UserWallet
from custody.token_metadata import metadata_fingerprint


class TokenDepositIdentityTests(TestCase):
    def setUp(self):
        from ops.models import Chain

        chain = Chain.objects.get(chain_id="ETH")
        chain.gas_settings = {
            **chain.gas_settings,
            "max_gas_limit": "100000",
            "max_fee_per_gas": "10000000000",
        }
        chain.save(update_fields=["gas_settings"])
        self.asset = Asset.objects.get(asset_key="USDT-ETH")
        self.asset.enabled = True
        self.asset.token_standard = "ERC20"
        self.asset.contract_address = "0x" + "a" * 40
        self.asset.decimals = 6
        self.asset.deposit_supported = True
        self.asset.metadata_verified_at = timezone.now()
        # Verification service is the normal writer; bind equivalent reviewed state for isolation.
        self.asset.metadata_fingerprint = metadata_fingerprint(self.asset)
        Asset.objects.filter(pk=self.asset.pk).update(
            enabled=True,
            token_standard=self.asset.token_standard,
            contract_address=self.asset.contract_address,
            decimals=6,
            deposit_supported=True,
            metadata_verified_at=self.asset.metadata_verified_at,
            metadata_fingerprint=self.asset.metadata_fingerprint,
        )
        self.wallet = UserWallet.objects.create(
            user_id="token-user",
            chain_id="ETH",
            asset_key=self.asset.asset_key,
            derivation_path="m/token/0",
            deposit_address="0x" + "1" * 40,
        )

    def event(self, index, amount="1.25"):
        return DepositEvent(
            tx_hash="0xsame",
            amount=Decimal(amount),
            block=100,
            confirmations=12,
            asset_key=self.asset.asset_key,
            event_index=f"log:{index}",
            block_hash="0xblock",
            contract_address=self.asset.contract_address,
        )

    def test_two_logs_same_transaction_credit_exactly_once(self):
        ingest_event(self.wallet, self.event(7))
        ingest_event(self.wallet, self.event(8))
        ingest_event(self.wallet, self.event(7))
        self.assertEqual(Deposit.objects.count(), 2)
        available = LedgerAccount.objects.get(
            owner_type="USER",
            owner_id="token-user",
            asset_key=self.asset.asset_key,
            bucket="AVAILABLE",
        )
        self.assertEqual(
            account_balance(available),
            Decimal("2.5"),
        )

    def test_same_event_cannot_mutate_amount(self):
        ingest_event(self.wallet, self.event(7))
        with self.assertRaisesMessage(ValueError, "amount changed"):
            ingest_event(self.wallet, self.event(7, "2"))

    def test_wrong_contract_and_asset_are_rejected(self):
        wrong = self.event(1)
        wrong.contract_address = "0x" + "b" * 40
        with self.assertRaisesMessage(ValueError, "unreviewed"):
            ingest_event(self.wallet, wrong)
        wrong = self.event(2)
        wrong.asset_key = "ETH"
        with self.assertRaisesMessage(ValueError, "does not match"):
            ingest_event(self.wallet, wrong)

    def test_identity_edit_invalidates_verification(self):
        asset = Asset.objects.get(pk=self.asset.pk)
        asset.decimals = 5
        asset.save(update_fields=["decimals"])
        asset.refresh_from_db()
        self.assertIsNone(asset.metadata_verified_at)
        self.assertEqual(asset.metadata_fingerprint, "")


class TokenGasSweepTests(TestCase):
    def setUp(self):
        from ops.models import Chain

        chain = Chain.objects.get(chain_id="ETH")
        chain.gas_settings = {
            **chain.gas_settings,
            "max_gas_limit": "100000",
            "max_fee_per_gas": "10000000000",
        }
        chain.save(update_fields=["gas_settings"])
        self.asset = Asset.objects.get(asset_key="USDT-ETH")
        self.asset.contract_address = "0x" + "a" * 40
        self.asset.token_standard = "ERC20"
        self.asset.decimals = 6
        self.asset.metadata_verified_at = timezone.now()
        self.asset.metadata_fingerprint = metadata_fingerprint(self.asset)
        Asset.objects.filter(pk=self.asset.pk).update(
            enabled=True,
            contract_address=self.asset.contract_address,
            token_standard="ERC20",
            decimals=6,
            sweep_supported=True,
            metadata_verified_at=self.asset.metadata_verified_at,
            metadata_fingerprint=self.asset.metadata_fingerprint,
        )
        self.wallet = UserWallet.objects.create(
            user_id="gas-user",
            chain_id="ETH",
            asset_key="USDT-ETH",
            derivation_path="m/gas",
            deposit_address="0x" + "3" * 40,
        )

    def test_repeated_advancement_reuses_broadcast_gas_intent(self):
        from types import SimpleNamespace
        from unittest.mock import patch

        from custody.models import GasTopupIntent, SweepJob
        from custody.sweeper import advance_sweep

        job = SweepJob.objects.create(
            user_wallet=self.wallet,
            asset_key="USDT-ETH",
            balance_snapshot=Decimal("2"),
            idempotency_key="sweep:gas:1",
        )

        def create_intent(wallet, *, idempotency_key):
            intent, _ = GasTopupIntent.objects.get_or_create(
                idempotency_key=idempotency_key,
                defaults={
                    "actor_id": "system:gas_station",
                    "chain_id": "ETH",
                    "to_address": wallet.deposit_address,
                    "amount": Decimal("0.005"),
                    "status": "BROADCASTED",
                },
            )
            return intent

        def execute(intent_id):
            linked = SweepJob.objects.get(pk=job.pk)
            self.assertEqual(linked.gas_topup_intent_id, intent_id)
            GasTopupIntent.objects.filter(pk=intent_id).update(status="BROADCASTED")
            return False

        indexer = SimpleNamespace(
            get_balance=lambda *args, **kwargs: SimpleNamespace(confirmed_balance=Decimal("0"))
        )
        with (
            patch("custody.sweeper.get_indexer", return_value=indexer),
            patch("custody.sweeper.get_or_create_gas_intent", side_effect=create_intent) as create,
            patch("custody.sweeper.execute_gas_intent", side_effect=execute) as execute_mock,
        ):
            advance_sweep(job.pk)
            advance_sweep(job.pk)
        job.refresh_from_db()
        self.assertEqual(job.status, "GAS_TOPUP_BROADCASTED")
        self.assertIsNotNone(job.gas_topup_intent_id)
        self.assertEqual(GasTopupIntent.objects.count(), 1)
        self.assertEqual(create.call_count, 1)
        self.assertEqual(execute_mock.call_count, 1)


class TokenVerificationPrecisionTests(TestCase):
    def test_more_than_18_decimals_is_rejected(self):
        from custody.token_metadata import TokenVerificationError, verify_token_asset

        asset = Asset.objects.get(asset_key="USDT-ETH")
        Asset.objects.filter(pk=asset.pk).update(
            contract_address="0x" + "a" * 40,
            token_standard="ERC20",
            decimals=19,
        )

        class Transport:
            def rpc(self, url, method, params):
                if method == "eth_getCode":
                    return "0x6000"
                if method == "eth_call":
                    value = 19 if params[0]["data"] == "0x313ce567" else 0
                    return "0x" + value.to_bytes(32, "big").hex()
                raise AssertionError(method)

        with self.assertRaisesMessage(TokenVerificationError, "ledger precision"):
            verify_token_asset(asset.asset_key, transport=Transport())


class TokenStubIsolationTests(TestCase):
    def test_token_stubs_do_not_call_live_clients(self):
        from unittest.mock import patch

        from custody.indexer.evm import EvmIndexer
        from custody.indexer.sol import SolIndexer
        from custody.indexer.trx import TrxIndexer

        cases = [
            (EvmIndexer("ETH"), "USDT-ETH"),
            (TrxIndexer("TRX"), "USDT-TRX"),
            (SolIndexer("SOL"), "USDT-SOL"),
        ]
        with patch.dict("os.environ", {"CUSTODY_INDEXER_MODE": "stub"}):
            for indexer, asset_key in cases:
                with patch.object(indexer, "_token_balance") as live:
                    result = indexer.get_balance("stub-owner", asset_key=asset_key)
                    live.assert_not_called()
                    self.assertEqual(result.deposit_events[0].asset_key, asset_key)
                    self.assertTrue(result.deposit_events[0].contract_address)


class TokenSignerPolicyTests(TestCase):
    def test_small_token_amount_is_not_compared_to_native_threshold(self):
        from custody.mpc_signer import MpcSigner, SignPolicy, UnsignedTx

        Asset.objects.filter(asset_key="USDT-ETH").update(enabled=True)
        tx = UnsignedTx(
            chain_id="ETH",
            asset_key="USDT-ETH",
            from_address="0x" + "1" * 40,
            to_address="0x" + "2" * 40,
            amount=Decimal("0.000001"),
            derivation_path="m/token",
        )
        MpcSigner().validate_transaction(tx, SignPolicy.WITHDRAWAL)


class CrashRecoveryTests(TokenGasSweepTests):
    def setUp(self):
        super().setUp()
        from custody.models import HotWallet

        HotWallet.objects.update_or_create(
            chain_id="ETH",
            defaults={"address": "0x" + "2" * 40, "signing_key_ref": "m/hot"},
        )

    @override_settings(CUSTODY_TX_MODE="live")
    def test_processing_gas_intent_without_attempt_is_recovered(self):
        from unittest.mock import patch

        from custody.gas_station import execute_gas_intent
        from custody.models import GasTopupIntent

        intent = GasTopupIntent.objects.create(
            idempotency_key="recover-gas",
            actor_id="system:gas_station",
            chain_id="ETH",
            to_address=self.wallet.deposit_address,
            amount=Decimal("0.001"),
            status="PROCESSING",
        )
        with patch("custody.gas_station._execute_live") as execute:
            execute_gas_intent(intent.pk)
        execute.assert_called_once()

    @override_settings(CUSTODY_TX_MODE="live")
    def test_processing_gas_intent_resumes_existing_prepared_attempt(self):
        from unittest.mock import patch

        from custody.gas_station import execute_gas_intent
        from custody.models import GasTopupIntent, OnchainTransactionAttempt

        intent = GasTopupIntent.objects.create(
            idempotency_key="recover-attempt",
            actor_id="system:gas_station",
            chain_id="ETH",
            to_address=self.wallet.deposit_address,
            amount=Decimal("0.001"),
            status="PROCESSING",
        )
        attempt = OnchainTransactionAttempt.objects.create(
            operation_type="GAS_TOPUP",
            operation_id=intent.pk,
            chain_id="ETH",
            asset_key="ETH",
            from_address="0x" + "2" * 40,
            to_address=self.wallet.deposit_address,
            amount=Decimal("0.001"),
            base_unit_amount=10**15,
            status="PREPARED",
            sequence=44,
        )
        with patch("custody.gas_station._execute_live") as execute:
            execute_gas_intent(intent.pk)
        self.assertEqual(execute.call_args.args[0].pk, intent.pk)
        self.assertEqual(OnchainTransactionAttempt.objects.get(pk=attempt.pk).sequence, 44)
        self.assertEqual(
            OnchainTransactionAttempt.objects.filter(
                operation_type="GAS_TOPUP", operation_id=intent.pk
            ).count(),
            1,
        )

    def test_processing_sweep_recovers_same_attempt(self):
        from unittest.mock import patch

        from custody.models import OnchainTransactionAttempt, SweepJob
        from custody.sweeper import advance_sweep

        job = SweepJob.objects.create(
            user_wallet=self.wallet,
            asset_key="USDT-ETH",
            balance_snapshot=Decimal("1"),
            status="SWEEP_PROCESSING",
            idempotency_key="recover-sweep",
        )
        attempt = OnchainTransactionAttempt.objects.create(
            operation_type="SWEEP",
            operation_id=job.pk,
            chain_id="ETH",
            asset_key="USDT-ETH",
            from_address=self.wallet.deposit_address,
            to_address="0x" + "4" * 40,
            amount=Decimal("1"),
            base_unit_amount=10**6,
            status="PREPARED",
            sequence=51,
        )

        def execute(pk, actor):
            self.assertEqual(pk, attempt.pk)
            OnchainTransactionAttempt.objects.filter(pk=pk).update(
                status="BROADCASTED", network_tx_id="0xrecover"
            )
            return OnchainTransactionAttempt.objects.get(pk=pk)

        with patch("custody.outbound.execute_attempt", side_effect=execute) as call:
            recovered = advance_sweep(job.pk)
        self.assertEqual(call.call_count, 1)
        self.assertEqual(recovered.status, "SWEEP_BROADCASTED")
        self.assertEqual(
            OnchainTransactionAttempt.objects.filter(
                operation_type="SWEEP", operation_id=job.pk
            ).count(),
            1,
        )
        self.assertEqual(OnchainTransactionAttempt.objects.get(pk=attempt.pk).sequence, 51)

    def test_safe_rejection_keeps_sweep_retryable_with_same_attempt(self):
        from unittest.mock import patch

        from custody.models import OnchainTransactionAttempt, SweepJob
        from custody.native_tx import SafePreBroadcastRejection
        from custody.sweeper import advance_sweep

        job = SweepJob.objects.create(
            user_wallet=self.wallet,
            asset_key="USDT-ETH",
            balance_snapshot=Decimal("1"),
            status="SWEEP_PROCESSING",
            idempotency_key="safe-retry",
        )
        attempt = OnchainTransactionAttempt.objects.create(
            operation_type="SWEEP",
            operation_id=job.pk,
            chain_id="ETH",
            asset_key="USDT-ETH",
            from_address=self.wallet.deposit_address,
            to_address="0x" + "4" * 40,
            amount=Decimal("1"),
            base_unit_amount=10**6,
            status="PREPARED",
            sequence=61,
        )
        with patch(
            "custody.outbound.execute_attempt", side_effect=SafePreBroadcastRejection("safe")
        ):
            with self.assertRaises(SafePreBroadcastRejection):
                advance_sweep(job.pk)
        job.refresh_from_db()
        attempt.refresh_from_db()
        self.assertEqual(job.status, "CREATED")
        self.assertEqual(attempt.status, "PREPARED")
        self.assertEqual(attempt.sequence, 61)
        self.assertEqual(
            OnchainTransactionAttempt.objects.filter(
                operation_type="SWEEP", operation_id=job.pk
            ).count(),
            1,
        )

    def test_legacy_evm_gas_requirement(self):
        from ops.models import Chain

        from custody.models import SweepJob
        from custody.sweeper import _token_native_requirement

        chain = Chain.objects.get(chain_id="ETH")
        chain.gas_settings = {"max_gas_limit": "100000", "max_legacy_gas_price": "2000000000"}
        chain.save(update_fields=["gas_settings"])
        job = SweepJob(user_wallet=self.wallet, asset_key="USDT-ETH")
        self.assertEqual(_token_native_requirement(job), Decimal("0.0002"))
