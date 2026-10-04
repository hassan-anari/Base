from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import patch

import requests
from django.test import SimpleTestCase, TestCase, override_settings

from custody.chain_registry import ChainKind
from custody.gas_station import _execute_live
from custody.ledger import ensure_accounts, post_transaction, user_balances
from custody.models import (
    GasTopupIntent,
    HotWallet,
    LedgerAccount,
    OnchainTransactionAttempt,
    SourceAccountSequence,
    SweepJob,
    UserWallet,
)
from custody.mpc_signer import MpcSigner, SignerError, SignPolicy, UnsignedTx, _addresses_equal
from custody.native_tx import (
    AmbiguousBroadcast,
    DeterministicBroadcastRejection,
    EvmNativeExecutor,
    PreparedNativeTransaction,
    ReconciliationResult,
    ReconciliationState,
    SafePreBroadcastRejection,
    SolanaNativeExecutor,
    TronNativeExecutor,
    to_base_units,
)
from custody.outbound import _signing_ref, execute_attempt
from custody.reconciliation import reconcile_attempt
from custody.sweeper import _run_sweep
from custody.withdrawals import approve, create_request, process_withdrawal


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


class _TronRpc:
    def __init__(self, values):
        self.values = values

    def post(self, url, path, payload):
        value = self.values[path]
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

    @patch("custody.native_tx.rpc_urls", return_value=["primary", "fallback"])
    def test_evm_timeout_cannot_be_downgraded_by_later_safe_rejection(self, _urls):
        class Transport:
            def rpc(self, url, method, params):
                if url == "primary":
                    raise requests.Timeout("outcome unknown")
                raise DeterministicBroadcastRejection("insufficient funds")

        with self.assertRaises(AmbiguousBroadcast):
            EvmNativeExecutor(Transport()).broadcast("ETH", b"signed", "0xexpected")

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

    @patch("custody.native_tx.rpc_urls", return_value=["rpc"])
    def test_tron_full_node_receipt_alone_is_non_terminal(self, _urls):
        prepared = self.prepared().__class__(
            **{**self.prepared().__dict__, "chain_id": "TRX", "expires_at_ms": 9999999999999}
        )
        for result in ("SUCCESS", "FAILED"):
            transport = _TronRpc(
                {
                    "/wallet/gettransactioninfobyid": {
                        "blockNumber": 10,
                        "receipt": {"result": result},
                    },
                    "/walletsolidity/gettransactioninfobyid": {},
                    "/walletsolidity/getnowblock": {"block_header": {"raw_data": {"timestamp": 1}}},
                }
            )
            self.assertEqual(
                TronNativeExecutor(transport).reconcile(prepared, "txid").state,
                ReconciliationState.INCLUDED,
            )

    @patch("custody.native_tx.rpc_urls", return_value=["rpc"])
    def test_tron_terminal_result_comes_from_solidity_receipt(self, _urls):
        prepared = self.prepared().__class__(**{**self.prepared().__dict__, "chain_id": "TRX"})
        for result, expected in (
            ("SUCCESS", ReconciliationState.CONFIRMED),
            ("FAILED", ReconciliationState.FAILED),
        ):
            transport = _TronRpc(
                {
                    "/wallet/gettransactioninfobyid": {},
                    "/walletsolidity/gettransactioninfobyid": {
                        "blockNumber": 10,
                        "receipt": {"result": result},
                    },
                }
            )
            self.assertEqual(
                TronNativeExecutor(transport).reconcile(prepared, "txid").state, expected
            )

    @patch("custody.native_tx.rpc_urls", return_value=["rpc"])
    def test_tron_absence_after_expiration_remains_unknown(self, _urls):
        prepared = self.prepared().__class__(
            **{**self.prepared().__dict__, "chain_id": "TRX", "expires_at_ms": 1}
        )
        transport = _TronRpc(
            {
                "/wallet/gettransactioninfobyid": {},
                "/walletsolidity/gettransactioninfobyid": {},
            }
        )
        result = TronNativeExecutor(transport).reconcile(prepared, "txid")
        self.assertEqual(result.state, ReconciliationState.UNKNOWN)
        self.assertTrue(result.evidence["manual_non_inclusion_reconciliation_required"])

    @patch("custody.native_tx.rpc_urls", return_value=["rpc"])
    @patch("custody.native_tx.get_chain_spec")
    def test_evm_full_balance_sweep_reserves_worst_case_fee(self, spec, _urls):
        spec.return_value = SimpleNamespace(
            kind=ChainKind.EVM,
            evm_chain_id=1,
            chain_id="ETH",
            native_decimals=18,
            gas_settings={
                "max_gas_limit": "21000",
                "max_legacy_gas_price": "10",
            },
        )
        rpc = _Rpc(
            {
                "eth_getTransactionCount": "0x5",
                "eth_estimateGas": "0x5208",
                "eth_getBlockByNumber": {},
                "eth_gasPrice": "0xa",
                "eth_getBalance": hex(10**18),
            }
        )
        prepared = EvmNativeExecutor(rpc).prepare_sweep(
            "ETH", "ETH", "0x" + "1" * 40, "0x" + "2" * 40, Decimal("1")
        )
        self.assertEqual(prepared.base_unit_amount, 10**18 - 21000 * 10)
        self.assertEqual(prepared.unsigned_payload["value"], prepared.base_unit_amount)

    @patch("custody.native_tx.rpc_urls", return_value=["rpc"])
    @patch("custody.native_tx.get_chain_spec")
    def test_solana_sweep_message_matches_persisted_lamports(self, spec, _urls):
        from solders.hash import Hash
        from solders.message import Message
        from solders.pubkey import Pubkey

        source, destination = str(Pubkey.new_unique()), str(Pubkey.new_unique())
        spec.return_value = SimpleNamespace(
            kind=ChainKind.SOLANA,
            chain_id="SOL",
            native_decimals=9,
            gas_settings={"max_fee_lamports": "10000"},
        )
        rpc = _Rpc(
            {
                "getLatestBlockhash": {
                    "value": {"blockhash": str(Hash.new_unique()), "lastValidBlockHeight": 99}
                },
                "getFeeForMessage": [
                    {"value": 5000},
                    {"value": 5000},
                ],
                "getBalance": {"value": 1_000_000},
            }
        )
        prepared = SolanaNativeExecutor(rpc).prepare_sweep(
            "SOL", "SOL", source, destination, Decimal("0.001")
        )
        message = Message.from_bytes(prepared.signing_payload)
        encoded_lamports = int.from_bytes(bytes(message.instructions[0].data)[4:12], "little")
        self.assertEqual(encoded_lamports, prepared.base_unit_amount)
        self.assertEqual(prepared.unsigned_payload["lamports"], prepared.base_unit_amount)


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
            ReconciliationState.UNKNOWN,
            {"manual_non_inclusion_reconciliation_required": True},
        )
        reconcile_attempt(self.attempt.pk)
        self.assertEqual(user_balances("finality-user", "ETH")["reserved"], Decimal("1"))
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


class DeterministicRejectionRetryTests(TestCase):
    def _funded_request(self, user, key):
        ensure_accounts(user, "ETH")
        available = LedgerAccount.objects.get(
            owner_type="USER", owner_id=user, asset_key="ETH", bucket="AVAILABLE"
        )
        clearing = LedgerAccount.objects.get(
            owner_type="SYSTEM",
            owner_id="custody",
            asset_key="ETH",
            bucket="CUSTODY_CLEARING",
        )
        post_transaction(
            event_key=f"{key}:fund",
            event_type="DEPOSIT_CREDIT",
            asset_key="ETH",
            ref_type="test",
            ref_id="fund",
            postings=[(available, Decimal("2")), (clearing, Decimal("-2"))],
        )
        HotWallet.objects.update_or_create(
            chain_id="ETH", defaults={"address": "0x" + "2" * 40, "signing_key_ref": "m/hot"}
        )
        request = create_request(user, "ETH", "0x" + "9" * 40, Decimal("1"), idempotency_key=key)
        approve("admin", request.pk)
        return request

    @override_settings(CUSTODY_TX_MODE="live")
    def test_ambiguous_broadcast_keeps_withdrawal_and_attempt_non_retryable(self):
        request = self._funded_request("ambiguous-user", "ambiguous-precedence")

        class Executor:
            prepare_calls = 0
            broadcast_calls = 0

            def prepare(self, chain, asset, source, destination, amount):
                self.prepare_calls += 1
                return PreparedNativeTransaction(
                    chain,
                    asset,
                    source,
                    destination,
                    amount,
                    10**18,
                    b"",
                    {"chainId": 1, "nonce": 20, "value": 10**18},
                    {},
                    sequence=20,
                )

            def assemble(self, prepared, signed):
                return b"exact-signed-payload"

            def transaction_id(self, signed):
                return "0xexpected"

            def broadcast(self, chain, signed, expected):
                self.broadcast_calls += 1
                raise AmbiguousBroadcast("primary timed out before fallback rejection")

        class Signer:
            calls = 0

            def sign(self, *args, **kwargs):
                self.calls += 1
                return "signed:00"

        executor, signer = Executor(), Signer()
        with (
            patch("custody.outbound.get_native_executor", return_value=executor),
            patch("custody.outbound.get_signer", return_value=signer),
        ):
            with self.assertRaises(AmbiguousBroadcast):
                process_withdrawal("admin", request.pk)
            with self.assertRaises(ValueError):
                process_withdrawal("admin", request.pk)

        request.refresh_from_db()
        attempt = OnchainTransactionAttempt.objects.get(operation_id=request.pk)
        self.assertEqual(request.status, "RECONCILIATION_REQUIRED")
        self.assertEqual(attempt.status, "RECONCILIATION_REQUIRED")
        self.assertEqual(attempt.network_tx_id, "0xexpected")
        self.assertTrue(attempt.signed_payload)
        self.assertEqual(OnchainTransactionAttempt.objects.count(), 1)
        self.assertEqual(
            (executor.prepare_calls, executor.broadcast_calls, signer.calls), (1, 1, 1)
        )
        self.assertEqual(user_balances("ambiguous-user", "ETH")["reserved"], Decimal("1"))

    @override_settings(CUSTODY_TX_MODE="live")
    def test_withdrawal_retries_same_attempt_and_nonce_then_settles_once(self):
        ensure_accounts("retry-user", "ETH")
        available = LedgerAccount.objects.get(
            owner_type="USER", owner_id="retry-user", asset_key="ETH", bucket="AVAILABLE"
        )
        clearing = LedgerAccount.objects.get(
            owner_type="SYSTEM",
            owner_id="custody",
            asset_key="ETH",
            bucket="CUSTODY_CLEARING",
        )
        post_transaction(
            event_key="retry:fund",
            event_type="DEPOSIT_CREDIT",
            asset_key="ETH",
            ref_type="test",
            ref_id="fund",
            postings=[(available, Decimal("2")), (clearing, Decimal("-2"))],
        )
        HotWallet.objects.update_or_create(
            chain_id="ETH", defaults={"address": "0x" + "2" * 40, "signing_key_ref": "m/hot"}
        )
        request = create_request(
            "retry-user",
            "ETH",
            "0x" + "9" * 40,
            Decimal("1"),
            idempotency_key="same-attempt-retry",
        )
        approve("admin", request.pk)

        class Executor:
            calls = 0
            nonces = []

            def prepare(self, chain, asset, source, destination, amount):
                return PreparedNativeTransaction(
                    chain,
                    asset,
                    source,
                    destination,
                    amount,
                    10**18,
                    b"",
                    {"chainId": 1, "nonce": 7, "value": 10**18},
                    {},
                    sequence=7,
                )

            def assemble(self, prepared, signed):
                self.nonces.append(prepared.unsigned_payload["nonce"])
                return bytes([prepared.unsigned_payload["nonce"]])

            def transaction_id(self, signed):
                return "0x" + signed.hex()

            def broadcast(self, chain, signed, expected):
                self.calls += 1
                if self.calls == 1:
                    raise SafePreBroadcastRejection("proven pre-acceptance rejection")

        class Signer:
            def sign(self, *args, **kwargs):
                return "signed:00"

        executor = Executor()
        with (
            patch("custody.outbound.get_native_executor", return_value=executor),
            patch("custody.outbound.get_signer", return_value=Signer()),
        ):
            with self.assertRaises(SafePreBroadcastRejection):
                process_withdrawal("admin", request.pk)
            request.refresh_from_db()
            attempt = OnchainTransactionAttempt.objects.get(operation_id=request.pk)
            self.assertEqual(request.status, "APPROVED")
            self.assertEqual(attempt.status, "PREPARED")
            self.assertEqual(user_balances("retry-user", "ETH")["reserved"], Decimal("1"))
            next_sequence = SourceAccountSequence.objects.get(chain_id="ETH").next_sequence
            attempt_id = attempt.pk
            process_withdrawal("admin", request.pk)

        request.refresh_from_db()
        attempt.refresh_from_db()
        self.assertEqual(request.status, "BROADCASTED")
        self.assertEqual(attempt.pk, attempt_id)
        self.assertEqual(OnchainTransactionAttempt.objects.count(), 1)
        self.assertEqual(executor.nonces, [7, 7])
        self.assertEqual(
            SourceAccountSequence.objects.get(chain_id="ETH").next_sequence, next_sequence
        )
        self.assertEqual(user_balances("retry-user", "ETH")["reserved"], Decimal("1"))

        with patch("custody.reconciliation.get_native_executor") as factory:
            factory.return_value.reconcile.return_value = ReconciliationResult(
                ReconciliationState.CONFIRMED, {"confirmations": 12}
            )
            reconcile_attempt(attempt.pk)
            reconcile_attempt(attempt.pk)
        self.assertEqual(user_balances("retry-user", "ETH")["reserved"], Decimal("0"))

    @override_settings(CUSTODY_TX_MODE="live")
    @patch("custody.outbound.execute_attempt", side_effect=SafePreBroadcastRejection("rejected"))
    @patch("custody.outbound.create_attempt")
    def test_gas_topup_rejection_returns_same_intent_to_created(self, create, _execute):
        create.return_value = SimpleNamespace(pk=11)
        intent = GasTopupIntent.objects.create(
            idempotency_key="gas-retry",
            actor_id="system",
            chain_id="ETH",
            to_address="0x" + "3" * 40,
            amount=Decimal("0.01"),
            status="PROCESSING",
        )
        with self.assertRaises(SafePreBroadcastRejection):
            _execute_live(intent, "system", "0x" + "2" * 40, "ETH")
        intent.refresh_from_db()
        self.assertEqual(intent.status, "CREATED")
        self.assertEqual(create.call_args.kwargs["operation_id"], intent.pk)

    @override_settings(CUSTODY_TX_MODE="live")
    @patch("custody.outbound.execute_attempt", side_effect=SafePreBroadcastRejection("rejected"))
    @patch("custody.outbound.create_attempt")
    @patch("custody.sweeper.ensure_hot_wallet", return_value="0x" + "2" * 40)
    @patch("custody.sweeper.get_chain")
    def test_sweep_rejection_remains_retryable_created(self, chain, _hot, create, _execute):
        chain.return_value.kind.value = "evm"
        wallet = UserWallet.objects.create(
            user_id="sweep-retry",
            chain_id="ETH",
            asset_key="ETH",
            derivation_path="m/1",
            deposit_address="0x" + "1" * 40,
        )
        job = SweepJob.objects.create(
            user_wallet=wallet,
            asset_key="ETH",
            sweep_round=1,
            balance_snapshot=Decimal("1"),
            idempotency_key="sweep-retry",
        )
        create.return_value = SimpleNamespace(pk=12)
        with self.assertRaises(SafePreBroadcastRejection):
            _run_sweep(job, "system")
        job.refresh_from_db()
        self.assertEqual(job.status, "CREATED")
        self.assertEqual(create.call_args.kwargs["operation_id"], job.pk)
