from decimal import Decimal
from unittest.mock import patch

import base58
from django.test import SimpleTestCase

from custody.native_tx import PreparedNativeTransaction, ReconciliationState
from custody.token_metadata import CLASSIC_TOKEN_PROGRAM
from custody.token_tx import SplTokenExecutor, Trc20Executor


def tron(byte):
    return base58.b58encode_check(bytes([0x41]) + bytes([byte]) * 20).decode()


class FakeTronTransport:
    def __init__(self, info=None):
        self.info = info
        self.posts = []

    def post(self, url, path, payload):
        self.posts.append((url, path, payload))
        if path.endswith("gettransactioninfobyid"):
            return self.info or {}
        raise AssertionError(path)


class Trc20ReconciliationTests(SimpleTestCase):
    source, destination, contract = tron(1), tron(2), tron(3)

    def prepared(self):
        return PreparedNativeTransaction(
            "TRX",
            "TOKEN",
            self.source,
            self.destination,
            Decimal("1"),
            1_000_000,
            b"",
            {"token_contract": self.contract},
            {},
            expected_tx_id="ab" * 32,
        )

    def log(self, amount=1_000_000, contract=None, destination=None):
        from custody.token_metadata import tron_address_hex

        topic = "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        return {
            "address": tron_address_hex(contract or self.contract)[2:],
            "topics": [
                topic,
                tron_address_hex(self.source)[2:].rjust(64, "0"),
                tron_address_hex(destination or self.destination)[2:].rjust(64, "0"),
            ],
            "data": hex(amount)[2:].rjust(64, "0"),
        }

    @patch("custody.token_tx.rpc_urls", return_value=["node"])
    def test_solidified_exact_effect_confirms(self, _):
        txid = "ab" * 32
        transport = FakeTronTransport(
            {"id": txid, "blockNumber": 10, "receipt": {"result": "SUCCESS"}, "log": [self.log()]}
        )
        result = Trc20Executor(transport).reconcile(self.prepared(), txid)
        self.assertEqual(result.state, ReconciliationState.CONFIRMED)

    @patch("custody.token_tx.rpc_urls", return_value=["node"])
    def test_success_without_effect_is_manual(self, _):
        result = Trc20Executor(
            FakeTronTransport({"blockNumber": 10, "receipt": {"result": "SUCCESS"}, "log": []})
        ).reconcile(self.prepared(), "ab" * 32)
        self.assertEqual(result.state, ReconciliationState.RECONCILIATION_REQUIRED)
        self.assertEqual(result.evidence["error"], "TOKEN_EFFECT_MISMATCH")

    @patch("custody.token_tx.rpc_urls", return_value=["node"])
    def test_solidified_failure_fails(self, _):
        result = Trc20Executor(
            FakeTronTransport({"blockNumber": 10, "receipt": {"result": "OUT_OF_ENERGY"}})
        ).reconcile(self.prepared(), "ab" * 32)
        self.assertEqual(result.state, ReconciliationState.FAILED)

    @patch("custody.token_tx.rpc_urls", return_value=["node"])
    def test_wrong_destination_is_manual(self, _):
        result = Trc20Executor(
            FakeTronTransport(
                {
                    "blockNumber": 10,
                    "receipt": {"result": "SUCCESS"},
                    "log": [self.log(destination=tron(9))],
                }
            )
        ).reconcile(self.prepared(), "ab" * 32)
        self.assertEqual(result.state, ReconciliationState.RECONCILIATION_REQUIRED)


class FakeSolTransport:
    def __init__(self, status, tx):
        self.status, self.tx = status, tx

    def rpc(self, url, method, params):
        if method == "getSignatureStatuses":
            return {"value": [self.status]}
        if method == "getTransaction":
            return self.tx
        raise AssertionError(method)


class SplReconciliationTests(SimpleTestCase):
    def prepared(self):
        return PreparedNativeTransaction(
            "SOL",
            "TOKEN",
            "owner",
            "destination",
            Decimal("1"),
            25,
            b"",
            {"mint": "mint", "sourceAta": "source-ata", "destinationAta": "destination-ata"},
            {},
        )

    def transaction(self, *, amount="25", destination="destination-ata", err=None):
        return {
            "slot": 9,
            "meta": {"err": err, "preTokenBalances": [{"accountIndex": 0, "mint": "mint"}]},
            "transaction": {
                "message": {
                    "accountKeys": ["source-ata"],
                    "instructions": [
                        {
                            "programId": CLASSIC_TOKEN_PROGRAM,
                            "parsed": {
                                "type": "transferChecked",
                                "info": {
                                    "source": "source-ata",
                                    "destination": destination,
                                    "mint": "mint",
                                    "tokenAmount": {"amount": amount},
                                },
                            },
                        }
                    ],
                }
            },
        }

    @patch("custody.token_tx.rpc_urls", return_value=["node"])
    def test_finalized_exact_effect_confirms(self, _):
        result = SplTokenExecutor(
            FakeSolTransport({"confirmationStatus": "finalized", "err": None}, self.transaction())
        ).reconcile(self.prepared(), "sig")
        self.assertEqual(result.state, ReconciliationState.CONFIRMED)

    @patch("custody.token_tx.rpc_urls", return_value=["node"])
    def test_finalized_mismatch_is_manual(self, _):
        result = SplTokenExecutor(
            FakeSolTransport(
                {"confirmationStatus": "finalized", "err": None},
                self.transaction(destination="wrong"),
            )
        ).reconcile(self.prepared(), "sig")
        self.assertEqual(result.state, ReconciliationState.RECONCILIATION_REQUIRED)

    @patch("custody.token_tx.rpc_urls", return_value=["node"])
    def test_finalized_error_fails(self, _):
        result = SplTokenExecutor(
            FakeSolTransport(
                {"confirmationStatus": "finalized", "err": {"InstructionError": [0, "Custom"]}},
                None,
            )
        ).reconcile(self.prepared(), "sig")
        self.assertEqual(result.state, ReconciliationState.FAILED)

    @patch("custody.token_tx.rpc_urls", return_value=["node"])
    def test_finalized_success_missing_transaction_is_manual(self, _):
        result = SplTokenExecutor(
            FakeSolTransport({"confirmationStatus": "finalized", "err": None}, None)
        ).reconcile(self.prepared(), "sig")
        self.assertEqual(result.state, ReconciliationState.RECONCILIATION_REQUIRED)
        self.assertEqual(result.evidence["error"], "FINALIZED_TRANSACTION_UNAVAILABLE")

    @patch("custody.token_tx.rpc_urls", return_value=["node"])
    def test_nonfinal_is_pending(self, _):
        result = SplTokenExecutor(
            FakeSolTransport({"confirmationStatus": "confirmed", "err": None}, None)
        ).reconcile(self.prepared(), "sig")
        self.assertEqual(result.state, ReconciliationState.PENDING)

    @patch("custody.token_tx.rpc_urls", return_value=["primary", "fallback"])
    def test_reconciliation_fails_over_for_status_and_transaction(self, _):
        tx = self.transaction()

        class FailoverTransport:
            def rpc(self, url, method, params):
                if url == "primary":
                    raise ConnectionError("primary unavailable")
                if method == "getSignatureStatuses":
                    return {"value": [{"confirmationStatus": "finalized", "err": None}]}
                if method == "getTransaction":
                    return tx
                raise AssertionError(method)

        result = SplTokenExecutor(FailoverTransport()).reconcile(self.prepared(), "sig")
        self.assertEqual(result.state, ReconciliationState.CONFIRMED)
