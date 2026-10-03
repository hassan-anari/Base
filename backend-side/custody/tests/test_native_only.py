from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase

from custody.api import _ensure_deposit_address
from custody.deposits import ingest_event
from custody.indexer.base import BalanceResult, DepositEvent
from custody.models import (
    Asset,
    Deposit,
    LedgerTransaction,
    SweepJob,
    UserWallet,
    WithdrawalRequest,
)
from custody.sweeper import trigger_sweep
from custody.withdrawals import create_request


class NativeOnlyCustodyTests(TestCase):
    def setUp(self):
        # Simulate a dangerous operator edit. Runtime code must reject this
        # regardless of all capability flags being manually enabled.
        Asset.objects.filter(asset_key="USDT-ETH").update(
            enabled=True,
            deposit_supported=True,
            withdrawal_supported=True,
            sweep_supported=True,
        )

    def test_non_native_asset_cannot_provision_or_ingest(self):
        with self.assertRaisesMessage(ValueError, "non-native asset"):
            _ensure_deposit_address("token-user", "ETH", "USDT-ETH")
        self.assertFalse(UserWallet.objects.filter(user_id="token-user").exists())

        wallet = UserWallet.objects.create(
            user_id="token-user",
            chain_id="ETH",
            asset_key="USDT-ETH",
            derivation_path="m/token",
            deposit_address="0x" + "1" * 40,
        )
        event = DepositEvent("0xnative-event", Decimal("5"), 100, 100)
        with self.assertRaisesMessage(ValueError, "non-native asset"):
            ingest_event(wallet, event)
        self.assertFalse(Deposit.objects.exists())
        self.assertFalse(LedgerTransaction.objects.exists())

    def test_non_native_asset_cannot_withdraw_or_sweep(self):
        with self.assertRaisesMessage(ValueError, "non-native asset"):
            create_request(
                "token-user",
                "ETH",
                "0x" + "2" * 40,
                Decimal("1"),
                asset_key="USDT-ETH",
                idempotency_key="token-native-path",
            )
        self.assertFalse(WithdrawalRequest.objects.exists())
        self.assertFalse(LedgerTransaction.objects.exists())

        wallet = UserWallet.objects.create(
            user_id="token-user",
            chain_id="ETH",
            asset_key="USDT-ETH",
            derivation_path="m/token",
            deposit_address="0x" + "3" * 40,
        )
        balance = BalanceResult(confirmed_balance=Decimal("5"))
        with (
            patch("custody.sweeper.get_indexer") as get_indexer,
            patch("custody.sweeper.get_signer") as get_signer,
            self.assertRaisesMessage(ValueError, "non-native asset"),
        ):
            trigger_sweep(wallet, "system:test", balance_result=balance)
        get_indexer.assert_not_called()
        get_signer.assert_not_called()
        self.assertFalse(SweepJob.objects.exists())
        self.assertFalse(LedgerTransaction.objects.exists())
