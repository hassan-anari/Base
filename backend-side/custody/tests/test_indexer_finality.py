from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase

from custody.deposits import ingest_event
from custody.indexer.ton import TonIndexer
from custody.indexer.trx import TrxIndexer
from custody.ledger import user_balances
from custody.models import Deposit, UserWallet


class Response:
    def __init__(self, payload, *, ok=True):
        self._payload = payload
        self.ok = ok

    def json(self):
        return self._payload

    def raise_for_status(self):
        if not self.ok:
            raise RuntimeError("transport failed")


@patch.dict("os.environ", {"CUSTODY_INDEXER_MODE": "live"})
class LiveFinalityTests(TestCase):
    def setUp(self):
        self.trx_wallet = UserWallet.objects.create(
            user_id="tron-user",
            chain_id="TRX",
            asset_key="TRX",
            derivation_path="m/trx",
            deposit_address="T" + "1" * 33,
        )
        self.ton_wallet = UserWallet.objects.create(
            user_id="ton-user",
            chain_id="TON",
            asset_key="TON",
            derivation_path="m/ton",
            deposit_address="0:" + "1" * 64,
            memo="memo-1",
        )

    def _trx_post(self, url, **kwargs):
        if url.endswith("getaccount"):
            return Response({"balance": 1_000_000})
        return Response({"block_header": {"raw_data": {"number": 100}}})

    @patch("custody.indexer.trx.requests.post")
    @patch("custody.indexer.trx.requests.get")
    def test_tron_uses_mined_block_depth_and_unknown_is_pending(self, get, post):
        post.side_effect = self._trx_post

        def response(block_number_marker):
            tx = {
                "txID": "trx-unknown" if block_number_marker is None else "trx-deposit",
                "raw_data": {
                    "ref_block_bytes": "ffff",
                    "contract": [
                        {
                            "type": "TransferContract",
                            "parameter": {"value": {"amount": 1_000_000}},
                        }
                    ],
                },
            }
            if block_number_marker is not None:
                tx["blockNumber"] = block_number_marker
            return Response({"data": [tx]})

        get.return_value = response(83)  # 18 confirmations, below runtime policy 19
        event = TrxIndexer().get_balance(self.trx_wallet.deposit_address).deposit_events[0]
        deposit, _ = ingest_event(self.trx_wallet, event)
        self.assertEqual((event.block, event.confirmations, deposit.status), (83, 18, "PENDING"))

        get.return_value = response(82)  # exactly 19 confirmations
        event = TrxIndexer().get_balance(self.trx_wallet.deposit_address).deposit_events[0]
        deposit, _ = ingest_event(self.trx_wallet, event)
        self.assertEqual(deposit.status, "CONFIRMED")
        ingest_event(self.trx_wallet, event)
        self.assertEqual(user_balances("tron-user", "TRX")["available"], Decimal("1"))

        get.return_value = response(None)
        event = TrxIndexer().get_balance(self.trx_wallet.deposit_address).deposit_events[0]
        self.assertEqual((event.block, event.confirmations), (0, 0))
        unknown, _ = ingest_event(self.trx_wallet, event)
        self.assertEqual(unknown.status, "PENDING")
        self.assertEqual(user_balances("tron-user", "TRX")["available"], Decimal("1"))

    def _ton_get(self, confirmations):
        def get(url, **kwargs):
            if url.endswith("getAddressBalance"):
                return Response({"ok": True, "result": "1000000000"})
            if url.endswith("getMasterchainInfo"):
                return Response({"ok": True, "result": {"last": {"seqno": 100}}})
            tx = {
                "transaction_id": {
                    "hash": "ton-unknown" if confirmations is None else "ton-deposit",
                    "lt": "999",
                },
                "utime": 999999999,
                "in_msg": {"value": "1000000000", "message": "memo-1"},
                "block_id": {"seqno": 90},
            }
            if confirmations is not None:
                tx["confirmations"] = confirmations
            return Response({"ok": True, "result": [tx]})

        return get

    @patch("custody.indexer.ton.requests.get")
    def test_ton_requires_explicit_provider_finality(self, get):
        get.side_effect = self._ton_get(4)
        result = TonIndexer().get_balance(self.ton_wallet.deposit_address, memo="memo-1")
        deposit, _ = ingest_event(self.ton_wallet, result.deposit_events[0])
        self.assertEqual(deposit.status, "PENDING")
        self.assertEqual(result.confirmed_balance, Decimal("0"))
        self.assertEqual(result.pending_balance, Decimal("1"))

        get.side_effect = self._ton_get(5)
        event = (
            TonIndexer()
            .get_balance(self.ton_wallet.deposit_address, memo="memo-1")
            .deposit_events[0]
        )
        deposit, _ = ingest_event(self.ton_wallet, event)
        self.assertEqual(deposit.status, "CONFIRMED")
        ingest_event(self.ton_wallet, event)
        self.assertEqual(user_balances("ton-user", "TON")["available"], Decimal("1"))

        get.side_effect = self._ton_get(None)
        event = (
            TonIndexer()
            .get_balance(self.ton_wallet.deposit_address, memo="memo-1")
            .deposit_events[0]
        )
        self.assertEqual(event.confirmations, 0)
        unknown, _ = ingest_event(self.ton_wallet, event)
        self.assertEqual(unknown.status, "PENDING")
        self.assertEqual(Deposit.objects.filter(status="CONFIRMED").count(), 1)
        self.assertEqual(user_balances("ton-user", "TON")["available"], Decimal("1"))
