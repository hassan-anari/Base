from decimal import Decimal
from unittest.mock import patch

from django.test import SimpleTestCase, TestCase, override_settings

from custody.chain_registry import ChainKind
from custody.ledger import ensure_accounts, post_transaction, user_balances
from custody.models import HotWallet, LedgerAccount, OnchainTransactionAttempt
from custody.mpc_signer import MpcSigner, SignerError, SignPolicy, UnsignedTx, _addresses_equal
from custody.native_tx import (
    EvmNativeExecutor,
    PreparedNativeTransaction,
    ReconciliationResult,
    ReconciliationState,
    SolanaNativeExecutor,
    to_base_units,
)
from custody.outbound import _signing_ref, execute_attempt
from custody.reconciliation import reconcile_attempt
from custody.withdrawals import create_request


class ExactBaseUnitTests(SimpleTestCase):
    def test_exact_wei(self):
        self.assertEqual(
            to_base_units(Decimal("1.000000000000000001"), 18),
            1_000_000_000_000_000_001,
        )

    def test_excess_precision_is_rejected(self):
        with self.assertRaisesMessage(ValueError, "exceeds asset precision"):
            to_base_units(Decimal("0.0000001"), 6)

    def test_non_positive_and_overflow_are_rejected(self):
        with self.assertRaises(ValueError):
            to_base_units(Decimal("0"), 18)
        with self.assertRaises(OverflowError):
            to_base_units(Decimal("256"), 0, maximum=255)


class HotWalletIdentityTests(TestCase):
    def test_missing_legacy_reference_fails_closed(self):
        HotWallet.objects.update_or_create(
            chain_id="ETH", defaults={"address": "0x" + "1" * 40, "signing_key_ref": None}
        )
        with self.assertRaisesMessage(ValueError, "signing_key_ref"):
            _signing_ref("WITHDRAWAL", 1, "ETH")


class _Rpc:
    def __init__(self, values):
        self.values = values

    def rpc(self, url, method, params):
        value = self.values[method]
        return value.pop(0) if isinstance(value, list) else value


class FinalityTests(SimpleTestCase):
    def prepared(self):
        return PreparedNativeTransaction(
            "ETH",
            "ETH",
            "0x" + "1" * 40,
            "0x" + "2" * 40,
            Decimal("1"),
            10**18,
            b"",
            {},
            {},
        )

    @patch("custody.native_tx.rpc_urls", return_value=["rpc"])
    @patch("custody.native_tx.get_chain_spec")
    def test_failed_evm_receipt_is_not_terminal_before_finality(self, spec, _urls):
        spec.return_value.confirmations = 12
        receipt = {"transactionHash": "0xabc", "blockNumber": "0x64", "status": "0x0"}
        executor = EvmNativeExecutor(
            _Rpc({"eth_getTransactionReceipt": receipt, "eth_blockNumber": "0x69"})
        )
        self.assertEqual(
            executor.reconcile(self.prepared(), "0xabc").state, ReconciliationState.INCLUDED
        )

    @patch("custody.native_tx.rpc_urls", return_value=["rpc"])
    @patch("custody.native_tx.get_chain_spec")
    def test_failed_evm_receipt_is_terminal_at_finality(self, spec, _urls):
        spec.return_value.confirmations = 6
        receipt = {"transactionHash": "0xabc", "blockNumber": "0x64", "status": "0x0"}
        executor = EvmNativeExecutor(
            _Rpc({"eth_getTransactionReceipt": receipt, "eth_blockNumber": "0x69"})
        )
        self.assertEqual(
            executor.reconcile(self.prepared(), "0xabc").state, ReconciliationState.FAILED
        )

    @patch("custody.native_tx.rpc_urls", return_value=["rpc"])
    def test_solana_error_requires_finalized_status(self, _urls):
        prepared = self.prepared().__class__(**{**self.prepared().__dict__, "chain_id": "SOL"})
        pending = SolanaNativeExecutor(
            _Rpc(
                {
                    "getSignatureStatuses": {
                        "value": [
                            {
                                "slot": 1,
                                "confirmationStatus": "confirmed",
                                "err": {"InstructionError": [0, "x"]},
                            }
                        ]
                    }
                }
            )
        )
        final = SolanaNativeExecutor(
            _Rpc(
                {
                    "getSignatureStatuses": {
                        "value": [
                            {
                                "slot": 1,
                                "confirmationStatus": "finalized",
                                "err": {"InstructionError": [0, "x"]},
                            }
                        ]
                    }
                }
            )
        )
        self.assertEqual(pending.reconcile(prepared, "sig").state, ReconciliationState.INCLUDED)
        self.assertEqual(final.reconcile(prepared, "sig").state, ReconciliationState.FAILED)


class LegacyTransportTests(SimpleTestCase):
    @patch("custody.chain_registry.get_chain_spec")
    def test_address_comparison_is_family_correct(self, spec):
        spec.return_value.kind = ChainKind.EVM
        self.assertTrue(_addresses_equal("ETH", "0x" + "a" * 40, "0x" + "A" * 40))
        spec.return_value.kind = ChainKind.SOLANA
        self.assertFalse(_addresses_equal("SOL", "AbC", "abc"))
        spec.return_value.kind = ChainKind.TRON
        self.assertFalse(_addresses_equal("TRX", "TAbC", "TabC"))

    @override_settings(CUSTODY_TX_MODE="live")
    def test_combined_sign_and_broadcast_is_forbidden_in_live_mode(self):
        with self.assertRaises(SignerError):
            MpcSigner().sign_and_broadcast(
                "actor",
                UnsignedTx("ETH", "ETH", "0x" + "1" * 40, "0x" + "2" * 40, Decimal("1"), "m/1"),
                SignPolicy.WITHDRAWAL,
                idempotency_key="key",
            )


class AttemptRecoveryTests(TestCase):
    def attempt(self, status, **extra):
        values = {
            "operation_type": "WITHDRAWAL",
            "operation_id": 999,
            "attempt_number": 1,
            "chain_id": "ETH",
            "asset_key": "ETH",
            "from_address": "0x" + "1" * 40,
            "to_address": "0x" + "2" * 40,
            "amount": Decimal("1"),
            "base_unit_amount": 10**18,
            "status": status,
            "prepared_metadata": {"chainId": 1},
            "fee_metadata": {},
        }
        values.update(extra)
        return OnchainTransactionAttempt.objects.create(**values)

    @patch("custody.outbound.get_native_executor")
    def test_signed_attempt_rebroadcasts_persisted_exact_bytes(self, factory):
        attempt = self.attempt("SIGNED", signed_payload="0102", network_tx_id="0xhash")
        executor = factory.return_value
        execute_attempt(attempt.pk, "actor")
        executor.broadcast.assert_called_once_with("ETH", b"\x01\x02", "0xhash")
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, "BROADCASTED")

    @patch("custody.outbound.get_native_executor")
    def test_broadcasting_crash_becomes_reconciliation_required(self, factory):
        attempt = self.attempt("BROADCASTING", network_tx_id="0xhash")
        execute_attempt(attempt.pk, "actor")
        factory.return_value.broadcast.assert_not_called()
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, "RECONCILIATION_REQUIRED")


class FailedWithdrawalFinalityTests(TestCase):
    def setUp(self):
        ensure_accounts("finality-user", "ETH")
        available = LedgerAccount.objects.get(
            owner_type="USER", owner_id="finality-user", asset_key="ETH", bucket="AVAILABLE"
        )
        clearing = LedgerAccount.objects.get(
            owner_type="SYSTEM",
            owner_id="custody",
            asset_key="ETH",
            bucket="CUSTODY_CLEARING",
        )
        post_transaction(
            event_key="finality:fund",
            event_type="DEPOSIT_CREDIT",
            asset_key="ETH",
            ref_type="test",
            ref_id="fund",
            postings=[(available, Decimal("2")), (clearing, Decimal("-2"))],
        )
        self.request = create_request(
            "finality-user",
            "ETH",
            "0x" + "9" * 40,
            Decimal("1"),
            idempotency_key="finality-withdrawal",
        )
        self.request.status = "BROADCASTED"
        self.request.save(update_fields=["status"])
        self.attempt = OnchainTransactionAttempt.objects.create(
            operation_type="WITHDRAWAL",
            operation_id=self.request.pk,
            attempt_number=1,
            chain_id="ETH",
            asset_key="ETH",
            from_address="0x" + "1" * 40,
            to_address=self.request.to_address,
            amount=Decimal("1"),
            base_unit_amount=10**18,
            status="BROADCASTED",
            network_tx_id="0xabc",
        )

    @patch("custody.reconciliation.get_native_executor")
    def test_failed_observation_releases_only_after_finality_once(self, factory):
        factory.return_value.reconcile.return_value = ReconciliationResult(
            ReconciliationState.INCLUDED, {"confirmations": 2}
        )
        reconcile_attempt(self.attempt.pk)
        self.assertEqual(user_balances("finality-user", "ETH")["reserved"], Decimal("1"))
        factory.return_value.reconcile.return_value = ReconciliationResult(
            ReconciliationState.FAILED, {"confirmations": 12}
        )
        reconcile_attempt(self.attempt.pk)
        reconcile_attempt(self.attempt.pk)
        self.assertEqual(user_balances("finality-user", "ETH")["reserved"], Decimal("0"))
        self.assertEqual(user_balances("finality-user", "ETH")["available"], Decimal("2"))
