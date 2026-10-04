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
