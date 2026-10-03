import os
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import patch

from django.test import Client, TestCase, override_settings

from custody.auth import create_token
from custody.checks import custody_signer_configuration
from custody.config import ensure_hot_wallet
from custody.gas_station import admin_topup
from custody.indexer.base import BalanceResult, IndexerUnavailable
from custody.models import HotWallet, SweepJob, UserWallet, WithdrawalRequest
from custody.signer_adapter import LocalVault
from custody.sweeper import trigger_sweep
from custody.withdrawals import approve, create_request, process_withdrawal


class FakeSigner:
    def __init__(self):
        self.calls = 0

    def sign_and_broadcast(self, **kwargs):
        self.calls += 1
        return SimpleNamespace(tx_hash="0xdemo")


def wallet(chain="ETH", asset="ETH"):
    return UserWallet.objects.create(
        user_id="customer",
        chain_id=chain,
        asset_key=asset,
        derivation_path="m/demo",
        deposit_address="0x" + "1" * 40,
    )


class CustodyWorkflowTests(TestCase):
    def setUp(self):
        HotWallet.objects.update_or_create(chain_id="ETH", defaults={"address": "0x" + "2" * 40})

    @patch("custody.sweeper.ensure_gas", return_value=True)
    @patch("custody.sweeper.get_signer")
    @patch("custody.sweeper.get_indexer")
    def test_sweep_persists_asset_and_prevents_duplicate(self, indexer, signer, _gas):
        indexer.return_value.get_balance.return_value = BalanceResult(Decimal("1"))
        signer.return_value = FakeSigner()
        w = wallet()

        first = trigger_sweep(w, "operator")
        second = trigger_sweep(w, "operator")

        self.assertTrue(first[0])
        self.assertEqual(first[1], second[1])
        job = SweepJob.objects.get(pk=first[1])
        self.assertEqual(job.asset_key, "ETH")
        self.assertEqual(job.status, "SWEEP_BROADCASTED")
        self.assertEqual(SweepJob.objects.count(), 1)

    @patch("custody.sweeper.ensure_gas", return_value=False)
    @patch("custody.sweeper.get_indexer")
    def test_failed_gas_topup_aborts_and_persists_failure(self, indexer, _gas):
        indexer.return_value.get_balance.return_value = BalanceResult(Decimal("1"))
        with self.assertRaisesMessage(RuntimeError, "gas top-up failed"):
            trigger_sweep(wallet(), "operator")
        job = SweepJob.objects.get()
        self.assertEqual(job.status, "FAILED")
        self.assertIsNotNone(job.completed_at)

    @patch("custody.gas_station.get_signer")
    def test_admin_topup_uses_canonical_native_asset(self, get_signer):
        signer = FakeSigner()
        get_signer.return_value = signer
        destination = wallet(chain="BSC", asset="USDT-BSC")
        HotWallet.objects.update_or_create(chain_id="BSC", defaults={"address": "0x" + "3" * 40})
        with patch.object(signer, "sign_and_broadcast", wraps=signer.sign_and_broadcast) as call:
            admin_topup("operator", "BSC", destination.deposit_address, 0.01)
        self.assertEqual(call.call_args.kwargs["tx"].asset_key, "BNB")

    def test_chain_asset_mismatch_is_rejected(self):
        with self.assertRaisesMessage(ValueError, "belongs to BSC"):
            create_request(
                "customer",
                "ETH",
                "0x" + "4" * 40,
                1,
                asset_key="USDT-BSC",
                idempotency_key="mismatch-key",
            )

    def test_withdrawal_idempotency_and_conflict(self):
        args = ("customer", "ETH", "0x" + "4" * 40, Decimal("1"))
        one = create_request(*args, idempotency_key="request-key")
        two = create_request(*args, idempotency_key="request-key")
        self.assertEqual(one.pk, two.pk)
        with self.assertRaisesMessage(ValueError, "different parameters"):
            create_request(
                "customer",
                "ETH",
                "0x" + "5" * 40,
                1,
                idempotency_key="request-key",
            )

    @patch("custody.withdrawals.get_signer")
    def test_withdrawal_state_guard_prevents_second_broadcast(self, get_signer):
        signer = FakeSigner()
        get_signer.return_value = signer
        req = create_request(
            "customer",
            "ETH",
            "0x" + "4" * 40,
            1,
            idempotency_key="broadcast-key",
        )
        approve("admin", req.pk)
        process_withdrawal("admin", req.pk)
        with self.assertRaisesMessage(ValueError, "must be APPROVED"):
            process_withdrawal("admin", req.pk)
        self.assertEqual(signer.calls, 1)

    def test_missing_hot_wallet_fails_closed(self):
        HotWallet.objects.filter(chain_id="ETH").delete()
        with self.assertRaisesMessage(RuntimeError, "no custody hot wallet"):
            ensure_hot_wallet("ETH")

    @patch("custody.withdrawals.get_signer")
    def test_signing_failure_is_persisted(self, get_signer):
        get_signer.return_value.sign_and_broadcast.side_effect = RuntimeError("vendor down")
        req = create_request(
            "customer",
            "ETH",
            "0x" + "4" * 40,
            1,
            idempotency_key="failed-broadcast-key",
        )
        approve("admin", req.pk)
        with self.assertRaisesMessage(RuntimeError, "vendor down"):
            process_withdrawal("admin", req.pk)
        req.refresh_from_db()
        self.assertEqual(req.status, "FAILED")


class ConfigurationTests(TestCase):
    @override_settings(
        MPC_SIGNER_BACKEND="local_key",
        CUSTODY_DEMO_MODE=False,
        LOCAL_KEY_ENCRYPTION_PASSPHRASE="secret",
    )
    def test_local_signer_rejected_outside_demo(self):
        self.assertIn("custody.E003", {e.id for e in custody_signer_configuration(None)})
        with self.assertRaisesMessage(RuntimeError, "restricted to demo mode"):
            LocalVault().broadcast("ETH", "signed:demo")

    @override_settings(
        MPC_SIGNER_BACKEND="local_key",
        CUSTODY_DEMO_MODE=True,
        LOCAL_KEY_ENCRYPTION_PASSPHRASE="",
    )
    def test_empty_local_passphrase_rejected(self):
        self.assertIn("custody.E004", {e.id for e in custody_signer_configuration(None)})
        with self.assertRaisesMessage(RuntimeError, "must be non-empty"):
            LocalVault().get_derived_address("ETH", "m/demo")

    @override_settings(MPC_SIGNER_BACKEND="mpc_vendor", CUSTODY_DEMO_MODE=False)
    def test_unimplemented_vendor_rejected(self):
        self.assertIn("custody.E002", {e.id for e in custody_signer_configuration(None)})


class IndexerAndApiTests(TestCase):
    def setUp(self):
        self.client = Client()

    def bearer(self, user, role):
        return {"HTTP_AUTHORIZATION": f"Bearer {create_token(user, role)}"}

    def test_indexer_outage_is_not_zero_balance(self):
        from custody.indexer.eth import EthIndexer

        with (
            patch.dict(os.environ, {"CUSTODY_INDEXER_MODE": "live"}),
            patch("custody.indexer.eth.evm_get_balance", side_effect=OSError("down")),
        ):
            with self.assertRaises(IndexerUnavailable):
                EthIndexer().get_balance("0x" + "1" * 40)

    def test_sensitive_endpoint_rejects_unauthenticated_request(self):
        response = self.client.post(
            "/api/withdrawals/request",
            data={
                "subject_user_id": "c",
                "network": "ETH",
                "to_address": "0x" + "4" * 40,
                "amount": 1,
                "idempotency_key": "api-request",
            },
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 401)

    def test_operator_cannot_approve_withdrawal(self):
        req = WithdrawalRequest.objects.create(
            user_id="c",
            chain_id="ETH",
            asset_key="ETH",
            to_address="0x" + "4" * 40,
            amount=1,
            idempotency_key="approval-key",
        )
        response = self.client.post(
            f"/api/withdrawals/{req.pk}/approve",
            data={"admin_notes": "no"},
            content_type="application/json",
            **self.bearer("ops", "operator"),
        )
        self.assertEqual(response.status_code, 403)

    @patch("custody.api.derive_deposit_address")
    def test_wallet_creation_is_idempotent(self, derive):
        derive.return_value = SimpleNamespace(
            derivation_path="m/test", deposit_address="0x" + "7" * 40
        )
        payload = {"subject_user_id": "c", "networks": ["ETH"]}
        first = self.client.post(
            "/api/wallet/create",
            data=payload,
            content_type="application/json",
            **self.bearer("ops", "operator"),
        )
        second = self.client.post(
            "/api/wallet/create",
            data=payload,
            content_type="application/json",
            **self.bearer("ops", "operator"),
        )
        self.assertEqual((first.status_code, second.status_code), (200, 200))
        self.assertEqual(UserWallet.objects.count(), 1)
