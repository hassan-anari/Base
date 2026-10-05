from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase

from custody.indexer.base import IndexerUnavailable
from custody.indexer.sol import SolIndexer
from custody.indexer.trx import TrxIndexer
from custody.token_metadata import CLASSIC_TOKEN_PROGRAM


class SolanaPaginationTests(SimpleTestCase):
    @patch("custody.indexer.sol.rpc_urls", return_value=["node"])
    @patch("custody.token_metadata.assert_verified_token")
    def test_second_signature_page_is_processed(self, _verified, _urls):
        asset = SimpleNamespace(asset_key="USDC-SOL", contract_address="mint", decimals=6)
        first = [
            {"signature": f"failed-{i}", "slot": 2, "err": {"failed": True}} for i in range(100)
        ]
        second = [{"signature": "deposit", "slot": 2, "err": None}]

        def rpc(url, method, params):
            if method == "getAccountInfo":
                return {"value": None}
            if method == "getSlot":
                return 3
            if method == "getSignaturesForAddress":
                return second if params[1].get("before") else first
            if method == "getTransaction":
                return {
                    "slot": 2,
                    "meta": {"err": None, "innerInstructions": []},
                    "transaction": {
                        "message": {
                            "accountKeys": [],
                            "instructions": [
                                {
                                    "programId": CLASSIC_TOKEN_PROGRAM,
                                    "parsed": {
                                        "type": "transferChecked",
                                        "info": {
                                            "destination": "ata",
                                            "mint": "mint",
                                            "tokenAmount": {"amount": "7"},
                                        },
                                    },
                                }
                            ],
                        }
                    },
                }
            raise AssertionError(method)

        with (
            patch("custody.spl.derive_ata", return_value="ata"),
            patch("custody.indexer.sol._rpc", side_effect=rpc),
        ):
            # get_chain_spec is imported locally; patch its defining module instead.
            with patch(
                "custody.chain_registry.get_chain_spec",
                return_value=SimpleNamespace(gas_settings={"token_signature_max_pages": 3}),
            ):
                result = SolIndexer()._token_balance(asset, "owner", 1)
        self.assertEqual(len(result.deposit_events), 1)
        self.assertEqual(result.deposit_events[0].amount, Decimal("0.000007"))

    @patch("custody.indexer.sol.rpc_urls", return_value=["node"])
    @patch("custody.token_metadata.assert_verified_token")
    def test_required_missing_transaction_fails_scan(self, _verified, _urls):
        asset = SimpleNamespace(asset_key="USDC-SOL", contract_address="mint", decimals=6)

        def rpc(url, method, params):
            if method == "getAccountInfo":
                return {"value": None}
            if method == "getSlot":
                return 3
            if method == "getSignaturesForAddress":
                return [{"signature": "missing", "slot": 2, "err": None}]
            if method == "getTransaction":
                return None
            raise AssertionError(method)

        with (
            patch("custody.spl.derive_ata", return_value="ata"),
            patch("custody.indexer.sol._rpc", side_effect=rpc),
            patch(
                "custody.chain_registry.get_chain_spec",
                return_value=SimpleNamespace(gas_settings={"token_signature_max_pages": 3}),
            ),
        ):
            with self.assertRaises(IndexerUnavailable):
                SolIndexer()._token_balance(asset, "owner", 1)


class Response:
    def __init__(self, body):
        self.body = body

    def raise_for_status(self):
        return None

    def json(self):
        return self.body


class TronCursorSafetyTests(SimpleTestCase):
    @patch("custody.indexer.trx.rpc_urls", return_value=["node"])
    @patch("custody.token_metadata.assert_verified_token")
    def test_missing_solidified_receipt_fails_scan(self, _verified, _urls):
        asset = SimpleNamespace(
            asset_key="USDT-TRX", contract_address="TG3XXyExBkPp9nzdajDZsozEu4BkaSJozs", decimals=6
        )
        owner = "TG3XXyExBkPp9nzdajDZsozEu4BkaSJozs"
        bodies = iter(
            [
                {"constant_result": ["0"]},
                {"block_header": {"raw_data": {"number": 1}}},
                {
                    "blockID": "block",
                    "transactions": [
                        {"txID": "tx", "raw_data": {"contract": [{"type": "TriggerSmartContract"}]}}
                    ],
                },
                {},
            ]
        )
        with (
            patch(
                "custody.indexer.trx.requests.post",
                side_effect=lambda *a, **k: Response(next(bodies)),
            ),
            patch(
                "custody.chain_registry.get_chain_spec",
                return_value=SimpleNamespace(
                    gas_settings={
                        "token_initial_lookback_blocks": 1,
                        "token_log_chunk_blocks": 1,
                        "token_reorg_overlap_blocks": 0,
                    }
                ),
            ),
        ):
            with self.assertRaises(IndexerUnavailable):
                TrxIndexer()._token_balance(asset, owner, 1)
