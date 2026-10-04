from decimal import Decimal

from django.test import TestCase
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
            "max_fee_per_gas": "100000000000",
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
            "max_fee_per_gas": "100000000000",
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

        def topup(wallet, *, idempotency_key):
            GasTopupIntent.objects.get_or_create(
                idempotency_key=idempotency_key,
                defaults={
                    "actor_id": "system:gas_station",
                    "chain_id": "ETH",
                    "to_address": wallet.deposit_address,
                    "amount": Decimal("0.005"),
                    "status": "BROADCASTED",
                },
            )
            return False

        indexer = SimpleNamespace(
            get_balance=lambda *args, **kwargs: SimpleNamespace(confirmed_balance=Decimal("0"))
        )
        with (
            patch("custody.sweeper.get_indexer", return_value=indexer),
            patch("custody.sweeper.ensure_gas", side_effect=topup) as ensure,
        ):
            advance_sweep(job.pk)
            advance_sweep(job.pk)
        job.refresh_from_db()
        self.assertEqual(job.status, "GAS_TOPUP_BROADCASTED")
        self.assertIsNotNone(job.gas_topup_intent_id)
        self.assertEqual(GasTopupIntent.objects.count(), 1)
        self.assertEqual(ensure.call_count, 1)
