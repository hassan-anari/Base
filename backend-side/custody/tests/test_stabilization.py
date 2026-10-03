import os
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import patch

from django.test import Client, TestCase, override_settings

from custody.auth import create_token
from custody.checks import custody_signer_configuration
from custody.config import ensure_hot_wallet
from custody.gas_station import AmbiguousBroadcastError, admin_topup, ensure_gas
from custody.indexer.base import BalanceResult, IndexerUnavailable
from custody.models import HotWallet, SweepJob, UserWallet, WithdrawalRequest
from custody.rate_limit import RateLimitExceeded
from custody.signer_adapter import LocalVault
from custody.sweeper import trigger_sweep
from custody.withdrawals import approve, create_request, process_withdrawal


class FakeSigner:
    def __init__(self):
        self.calls = 0

    def sign_and_broadcast(self, **kwargs):
        if kwargs.get("before_sign"):
            kwargs["before_sign"]()
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

    @patch("custody.sweeper.ensure_gas", side_effect=RuntimeError("configuration invalid"))
    @patch("custody.sweeper.get_indexer")
    def test_failed_gas_topup_aborts_and_persists_failure(self, indexer, _gas):
        indexer.return_value.get_balance.return_value = BalanceResult(Decimal("1"))
        with self.assertRaisesMessage(RuntimeError, "configuration invalid"):
            trigger_sweep(wallet(), "operator")
        job = SweepJob.objects.get()
        self.assertEqual(job.status, "FAILED")
        self.assertIsNotNone(job.completed_at)

    @patch("custody.sweeper.ensure_gas", return_value=True)
    @patch("custody.sweeper.get_signer")
    @patch("custody.sweeper.get_indexer")
    def test_ambiguous_sweep_broadcast_requires_reconciliation(self, indexer, signer, _gas):
        indexer.return_value.get_balance.return_value = BalanceResult(Decimal("1"))
        signer.return_value.sign_and_broadcast.side_effect = RuntimeError("lost response")
        with self.assertRaises(AmbiguousBroadcastError):
            trigger_sweep(wallet(), "operator")
        self.assertEqual(SweepJob.objects.get().status, "RECONCILIATION_REQUIRED")

    @patch("custody.gas_station.get_signer")
    def test_admin_topup_uses_canonical_native_asset(self, get_signer):
        signer = FakeSigner()
        get_signer.return_value = signer
        destination = wallet(chain="BSC", asset="USDT-BSC")
        HotWallet.objects.update_or_create(chain_id="BSC", defaults={"address": "0x" + "3" * 40})
        with patch.object(signer, "sign_and_broadcast", wraps=signer.sign_and_broadcast) as call:
            admin_topup(
                "operator",
                "BSC",
                destination.deposit_address,
                0.01,
                "admin-topup-key",
            )
        self.assertEqual(call.call_args.kwargs["tx"].asset_key, "BNB")

    @patch("custody.gas_station.get_signer")
    def test_manual_gas_topup_idempotency_and_conflict(self, get_signer):
        signer = FakeSigner()
        get_signer.return_value = signer
        destination = wallet()
        args = ("operator", "ETH", destination.deposit_address, 0.001, "manual-gas-key")
        first = admin_topup(*args)
        second = admin_topup(*args)
        self.assertEqual(first, second)
        self.assertEqual(signer.calls, 1)
        with self.assertRaisesMessage(ValueError, "different parameters"):
            admin_topup(
                "operator",
                "ETH",
                destination.deposit_address,
                0.002,
                "manual-gas-key",
            )

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
        class FailingSigner:
            def sign_and_broadcast(self, **kwargs):
                kwargs["before_sign"]()
                raise RuntimeError("vendor down")

        get_signer.return_value = FailingSigner()
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
        self.assertEqual(req.status, "RECONCILIATION_REQUIRED")
        with self.assertRaisesMessage(ValueError, "must be APPROVED"):
            process_withdrawal("admin", req.pk)

    @patch("custody.gas_station.get_signer")
    def test_ambiguous_gas_topup_is_persisted_and_not_retried(self, get_signer):
        get_signer.return_value.sign_and_broadcast.side_effect = RuntimeError("lost response")
        w = wallet()
        with self.assertRaises(AmbiguousBroadcastError):
            ensure_gas(w, idempotency_key="gas-sweep-1")
        with self.assertRaises(AmbiguousBroadcastError):
            ensure_gas(w, idempotency_key="gas-sweep-1")
        self.assertEqual(get_signer.return_value.sign_and_broadcast.call_count, 1)

    def test_empty_and_placeholder_hot_wallets_fail_closed_in_gas_path(self):
        w = wallet()
        HotWallet.objects.filter(chain_id="ETH").delete()
        with self.assertRaises(RuntimeError):
            ensure_gas(w, idempotency_key="gas-missing")
        for address in ("", "ETH_HOT_STUB"):
            HotWallet.objects.update_or_create(chain_id="ETH", defaults={"address": address})
            with self.assertRaises(RuntimeError):
                ensure_gas(w, idempotency_key=f"gas-{address or 'empty'}")

    def test_unsupported_token_custody_operations_fail_closed(self):
        with self.assertRaisesMessage(ValueError, "withdrawal is not supported"):
            create_request(
                "customer",
                "ETH",
                "0x" + "4" * 40,
                1,
                asset_key="USDT-ETH",
                idempotency_key="unsupported-token",
            )


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

    def test_withdrawal_api_idempotency_conflict_and_missing_key(self):
        payload = {
            "subject_user_id": "c",
            "network": "ETH",
            "to_address": "0x" + "4" * 40,
            "amount": 1,
            "idempotency_key": "api-idempotency-key",
        }
        first = self.client.post(
            "/api/withdrawals/request",
            data=payload,
            content_type="application/json",
            **self.bearer("ops", "operator"),
        )
        second = self.client.post(
            "/api/withdrawals/request",
            data=payload,
            content_type="application/json",
            **self.bearer("ops", "operator"),
        )
        self.assertEqual((first.status_code, second.status_code), (200, 200))
        self.assertEqual(first.json()["id"], second.json()["id"])
        conflict = self.client.post(
            "/api/withdrawals/request",
            data={**payload, "to_address": "0x" + "5" * 40},
            content_type="application/json",
            **self.bearer("ops", "operator"),
        )
        self.assertEqual(conflict.status_code, 409)
        missing = self.client.post(
            "/api/withdrawals/request",
            data={key: value for key, value in payload.items() if key != "idempotency_key"},
            content_type="application/json",
            **self.bearer("ops", "operator"),
        )
        self.assertEqual(missing.status_code, 422)

    def test_invalid_chain_asset_inputs_are_client_errors(self):
        base = {
            "subject_user_id": "c",
            "network": "ETH",
            "to_address": "0x" + "4" * 40,
            "amount": 1,
            "idempotency_key": "validation-key",
        }
        cases = [
            {**base, "network": "NOPE"},
            {**base, "asset_key": "NOPE"},
            {**base, "asset_key": "USDT-BSC"},
        ]
        for payload in cases:
            response = self.client.post(
                "/api/withdrawals/request",
                data=payload,
                content_type="application/json",
                **self.bearer("ops", "operator"),
            )
            self.assertEqual(response.status_code, 422)

    @patch("custody.api.get_indexer")
    def test_gas_station_reports_unavailable_balance_as_null(self, get_indexer):
        get_indexer.return_value.get_balance.side_effect = IndexerUnavailable("private detail")
        response = self.client.get("/api/gas-station", **self.bearer("ops", "operator"))
        self.assertEqual(response.status_code, 200)
        eth = next(item for item in response.json()["entries"] if item["chain_id"] == "ETH")
        self.assertIsNone(eth["native_balance"])
        self.assertEqual(eth["balance_status"], "UNAVAILABLE")
        self.assertNotIn("private detail", response.content.decode())

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

    @patch("custody.withdrawals.get_signer")
    def test_approval_retry_resumes_approved_after_rate_limit(self, get_signer):
        get_signer.return_value = FakeSigner()
        HotWallet.objects.update_or_create(chain_id="ETH", defaults={"address": "0x" + "2" * 40})
        req = WithdrawalRequest.objects.create(
            user_id="c",
            chain_id="ETH",
            asset_key="ETH",
            to_address="0x" + "4" * 40,
            amount=1,
            idempotency_key="approval-retry-key",
        )
        url = f"/api/withdrawals/{req.pk}/approve"
        with patch("custody.api.process_withdrawal", side_effect=RateLimitExceeded("busy")):
            first = self.client.post(
                url, data={}, content_type="application/json", **self.bearer("admin", "admin")
            )
        self.assertEqual(first.status_code, 429)
        req.refresh_from_db()
        self.assertEqual(req.status, "APPROVED")
        second = self.client.post(
            url, data={}, content_type="application/json", **self.bearer("admin", "admin")
        )
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second.json()["status"], "BROADCASTED")
        third = self.client.post(
            url, data={}, content_type="application/json", **self.bearer("admin", "admin")
        )
        self.assertEqual(third.status_code, 200)
        self.assertEqual(get_signer.return_value.calls, 1)

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
