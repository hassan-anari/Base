from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import patch

from django.test import Client, TestCase

from custody.auth import create_token
from custody.indexer.base import BalanceResult, IndexerUnavailable
from custody.indexer_service import scan_all_wallets, scan_wallet
from custody.models import Asset, Deposit, LedgerTransaction, SweepJob, UserWallet


class DefaultWalletCapabilityTests(TestCase):
    def setUp(self):
        self.client = Client()

    def bearer(self):
        return {"HTTP_AUTHORIZATION": f"Bearer {create_token('ops', 'operator')}"}

    @patch("custody.api.derive_deposit_address")
    def test_default_provisions_only_deposit_capable_native_assets(self, derive):
        def derived(chain_id, user_index, address_index, *, asset_key):
            address = "0x" + "1" * 40
            if chain_id == "TRX":
                address = "T" + "1" * 33
            elif chain_id == "SOL":
                address = "1" * 32
            return SimpleNamespace(
                deposit_address=address,
                derivation_path=f"m/{chain_id}/{user_index}/{address_index}/{asset_key}",
            )

        derive.side_effect = derived
        response = self.client.post(
            "/api/wallet/create",
            data={"subject_user_id": "default-user"},
            content_type="application/json",
            **self.bearer(),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            set(UserWallet.objects.values_list("chain_id", flat=True)),
            {"ETH", "BSC", "TRX", "SOL"},
        )
        self.assertNotIn("TON", {row["network"] for row in response.json()["addresses"]})

    @patch("custody.api.derive_deposit_address")
    def test_invalid_explicit_plan_has_no_partial_side_effects(self, derive):
        response = self.client.post(
            "/api/wallet/create",
            data={"subject_user_id": "atomic-user", "networks": ["ETH", "TON"]},
            content_type="application/json",
            **self.bearer(),
        )
        self.assertEqual(response.status_code, 422)
        derive.assert_not_called()
        self.assertFalse(UserWallet.objects.filter(user_id="atomic-user").exists())


class LegacyScannerIsolationTests(TestCase):
    def setUp(self):
        self.ton = UserWallet.objects.create(
            user_id="legacy-ton",
            chain_id="TON",
            asset_key="TON",
            derivation_path="m/ton",
            deposit_address="0:" + "1" * 64,
            memo="legacy",
        )
        Asset.objects.filter(asset_key="USDT-ETH").update(
            enabled=True,
            deposit_supported=True,
        )
        self.token = UserWallet.objects.create(
            user_id="legacy-token",
            chain_id="ETH",
            asset_key="USDT-ETH",
            derivation_path="m/token",
            deposit_address="0x" + "2" * 40,
        )

    @patch("custody.indexer_service.get_indexer")
    @patch("custody.indexer_service.trigger_sweep")
    def test_unsupported_legacy_wallets_skip_without_side_effects(self, sweep, get_indexer):
        for wallet in (self.ton, self.token):
            result = scan_wallet(wallet)
            self.assertEqual(result["outcome"], "unsupported")
            self.assertIn("deposit scanning unsupported", result["reason"])
        get_indexer.assert_not_called()
        sweep.assert_not_called()
        self.assertFalse(Deposit.objects.exists())
        self.assertFalse(LedgerTransaction.objects.exists())
        self.assertFalse(SweepJob.objects.exists())

    @patch("custody.indexer_service.trigger_sweep")
    @patch("custody.indexer_service.get_indexer")
    def test_batch_continues_to_valid_wallet_and_distinguishes_outage(self, get_indexer, sweep):
        eth = UserWallet.objects.create(
            user_id="valid-eth",
            chain_id="ETH",
            asset_key="ETH",
            derivation_path="m/eth",
            deposit_address="0x" + "3" * 40,
        )
        client = SimpleNamespace(
            get_balance=lambda address, memo=None: BalanceResult(confirmed_balance=Decimal("0"))
        )
        get_indexer.return_value = client
        results = {result["wallet_id"]: result for result in scan_all_wallets()}
        self.assertEqual(results[self.ton.id]["outcome"], "unsupported")
        self.assertEqual(results[self.token.id]["outcome"], "unsupported")
        self.assertEqual(results[eth.id]["outcome"], "scanned")
        get_indexer.assert_called_once_with("ETH")
        sweep.assert_not_called()

        get_indexer.reset_mock()
        get_indexer.side_effect = IndexerUnavailable("rpc down")
        outage = scan_wallet(eth)
        self.assertEqual(outage["outcome"], "indexer_unavailable")
        self.assertNotEqual(outage["outcome"], results[self.ton.id]["outcome"])
