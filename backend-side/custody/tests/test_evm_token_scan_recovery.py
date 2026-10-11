"""PostgreSQL ERC-20 history regressions; fixtures are not cryptographic evidence."""

import importlib
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import rlp
from django.apps import apps
from django.db import DatabaseError, close_old_connections, connection
from eth_utils import keccak
from ops.models import Chain
from trie import HexaryTrie

from custody.indexer.evm import TRANSFER_TOPIC
from custody.indexer_service import scan_wallet
from custody.ledger import user_balances
from custody.models import Asset, Deposit, LedgerPosting, LedgerTransaction, UserWallet
from custody.tests.test_evm_native_scan_recovery import (
    ADDRESS,
    RpcHistory,
    block_hash,
)
from custody.tests.test_evm_native_scan_recovery import (
    history as native_history,
)
from custody.token_metadata import metadata_fingerprint

history = native_history
CONTRACT = "0x" + "ef" * 20
SENDER = "0x" + "12" * 20
ZERO_BLOOM = "0x" + "00" * 256


def bloom(logs):
    result = 0
    for log in logs:
        for value in [log["address"], *log["topics"]]:
            digest = keccak(bytes.fromhex(value[2:]))
            for offset in (0, 2, 4):
                result |= 1 << (int.from_bytes(digest[offset : offset + 2], "big") % 2048)
    return "0x" + int(result).to_bytes(256, "big").hex()


class TokenHistory(RpcHistory):
    def __init__(self):
        super().__init__()
        self.transfers = {2: [1_000_000]}

    def logs(self, height):
        txid = "0x" + height.to_bytes(32, "big").hex()
        return [
            {
                "blockNumber": hex(height),
                "blockHash": block_hash(height),
                "transactionHash": txid,
                "transactionIndex": "0x0",
                "logIndex": hex(index),
                "address": CONTRACT,
                "topics": [
                    TRANSFER_TOPIC,
                    "0x" + SENDER[2:].rjust(64, "0"),
                    "0x" + ADDRESS[2:].rjust(64, "0"),
                ],
                "data": "0x" + units.to_bytes(32, "big").hex(),
                "removed": False,
            }
            for index, units in enumerate(self.transfers.get(height, []))
        ]

    def original(self, method, params):
        if method == "eth_call":
            return "0x" + sum(sum(v) for v in self.transfers.values()).to_bytes(32, "big").hex()
        if method == "eth_getBlockTransactionCountByHash":
            n = next(n for n in range(self.head + 1) if block_hash(n) == params[0])
            return hex(int(n in self.transfers))
        if method == "eth_getBlockByNumber":
            n = int(params[0], 16)
            if params[1]:
                self.blocks_read.append(n)
            return {
                "number": hex(n),
                "hash": block_hash(n),
                "parentHash": block_hash(max(0, n - 1)),
                "logsBloom": bloom(self.logs(n)),
                "receiptsRoot": self.receipt_root(n),
                "transactions": [{"hash": self.logs(n)[0]["transactionHash"]}]
                if n in self.transfers
                else [],
            }
        if method == "eth_getTransactionReceipt":
            n = int(params[0], 16)
            return {
                "status": "0x1",
                "type": "0x2",
                "cumulativeGasUsed": "0x5208",
                "transactionHash": params[0],
                "blockHash": block_hash(n),
                "blockNumber": hex(n),
                "transactionIndex": "0x0",
                "logs": self.logs(n),
                "logsBloom": bloom(self.logs(n)),
            }
        if method == "eth_getLogs":
            return [
                log
                for n in range(int(params[0]["fromBlock"], 16), int(params[0]["toBlock"], 16) + 1)
                for log in self.logs(n)
            ]
        return super().rpc("node", method, params)

    def receipt_root(self, height):
        trie = HexaryTrie({})
        logs = self.logs(height)
        if height in self.transfers:
            encoded = rlp.encode(
                [
                    1,
                    21000,
                    bytes.fromhex(bloom(logs)[2:]),
                    [
                        [
                            bytes.fromhex(log["address"][2:]),
                            [bytes.fromhex(topic[2:]) for topic in log["topics"]],
                            bytes.fromhex(log["data"][2:]),
                        ]
                        for log in logs
                    ],
                ]
            )
            trie[rlp.encode(0)] = b"\x02" + encoded
        return "0x" + trie.root_hash.hex()

    def rpc(self, url, method, params):
        if self.failure:
            value = self.failure(method, params)
            if value is not NotImplemented:
                return value
        return self.original(method, params)


@pytest.fixture
def token_history(history, monkeypatch):
    asset = Asset.objects.get(asset_key="USDT-ETH")
    asset.enabled = True
    asset.deposit_supported = True
    asset.contract_address = CONTRACT
    asset.token_standard = "ERC20"
    asset.decimals = 6
    asset.deposit_threshold = Decimal("100")
    from django.utils import timezone

    asset.save()
    asset.refresh_from_db()
    asset.metadata_verified_at = timezone.now()
    asset.metadata_fingerprint = metadata_fingerprint(asset)
    asset.save(update_fields=["metadata_verified_at", "metadata_fingerprint"])
    wallet = UserWallet.objects.create(
        user_id=history.wallet.user_id,
        chain_id="ETH",
        asset_key=asset.asset_key,
        derivation_path="m/token-scanner",
        deposit_address=ADDRESS,
    )
    rpc = TokenHistory()
    monkeypatch.setattr("custody.native_tx.RequestsTransport.rpc", lambda _, *args: rpc.rpc(*args))
    return SimpleNamespace(rpc=rpc, wallet=wallet, native=history.wallet, asset=asset)


def assert_untouched(h):
    h.wallet.refresh_from_db()
    assert h.wallet.last_scanned_block is None and h.wallet.evm_scan_block_hash is None
    assert not Deposit.objects.filter(user_wallet=h.wallet).exists()
    assert not LedgerTransaction.objects.filter(asset_key=h.wallet.asset_key).exists()


def test_genesis_backfill_recovers_deposits_outside_old_initial_lookback(token_history):
    h = token_history
    h.rpc.head = 1500
    result = scan_wallet(h.wallet)
    assert result["outcome"] == "backfill", result["reason"]
    h.wallet.refresh_from_db()
    assert h.wallet.last_scanned_block == 63 and h.wallet.evm_scan_block_hash == block_hash(63)
    assert user_balances(h.wallet.user_id, h.wallet.asset_key)["available"] == Decimal(1)
    original_journals = list(LedgerPosting.objects.values_list("pk", "amount"))
    # Prolonged outage: the second real event is far beyond the old overlap.
    h.rpc.transfers[80] = [2_000_000]
    close_old_connections()
    restarted = UserWallet.objects.get(pk=h.wallet.pk)
    assert scan_wallet(restarted)["outcome"] == "backfill"
    restarted.refresh_from_db()
    assert restarted.last_scanned_block == 127 and restarted.evm_scan_block_hash == block_hash(127)
    assert user_balances(h.wallet.user_id, h.wallet.asset_key)["available"] == Decimal(3)
    assert scan_wallet(h.wallet)["outcome"] == "pending"  # stale reader cannot commit
    # Replay the original verified range; existing journals remain immutable.
    UserWallet.objects.filter(pk=h.wallet.pk).update(
        last_scanned_block=63, evm_scan_block_hash=block_hash(63)
    )
    restarted.refresh_from_db()
    assert scan_wallet(restarted)["outcome"] == "backfill"
    assert Deposit.objects.filter(user_wallet=h.wallet).count() == 2
    assert LedgerTransaction.objects.filter(event_type="DEPOSIT_CREDIT").count() == 2
    assert (
        list(
            LedgerPosting.objects.filter(pk__in=[p[0] for p in original_journals]).values_list(
                "pk", "amount"
            )
        )
        == original_journals
    )
    assert sum(LedgerPosting.objects.values_list("amount", flat=True)) == 0


@pytest.mark.parametrize(
    "fault",
    [
        "null_logs",
        "empty_logs",
        "truncated_logs",
        "duplicate_logs",
        "missing_block",
        "missing_transactions",
        "truncated_transactions",
        "missing_receipt",
        "missing_receipt_logs",
        "empty_receipt_logs",
        "wrong_receipt_hash",
        "wrong_receipt_index",
        "removed_log",
        "wrong_contract",
        "wrong_log_height",
        "wrong_block_bloom",
        "same_bloom_tail_omission",
        "missing_receipt_type",
        "wrong_cumulative_gas",
    ],
)
def test_incomplete_history_never_commits_credit_or_checkpoint(token_history, fault):
    h = token_history
    h.rpc.transfers[2] = [1_000_000, 2_000_000]

    def fail(method, params):
        if method == "eth_getLogs":
            logs = h.rpc.original(method, params)
            if fault == "null_logs":
                return None
            if fault == "empty_logs":
                return []
            if fault in {"truncated_logs", "same_bloom_tail_omission"}:
                return logs[:1]
            if fault == "duplicate_logs":
                return logs + logs[:1]
            if fault in {"removed_log", "wrong_contract", "wrong_log_height"}:
                logs[0].update(
                    {
                        "removed_log": {"removed": True},
                        "wrong_contract": {"address": SENDER},
                        "wrong_log_height": {"blockNumber": "0x4"},
                    }[fault]
                )
                return logs
        if method == "eth_getBlockByNumber" and params == ["0x2", True]:
            block = h.rpc.original(method, params)
            if fault == "missing_block":
                return None
            if fault == "missing_transactions":
                block.pop("transactions")
            if fault == "truncated_transactions":
                block["transactions"] = []
            if fault == "wrong_block_bloom":
                block["logsBloom"] = ZERO_BLOOM
            return block
        if method == "eth_getTransactionReceipt":
            receipt = h.rpc.original(method, params)
            if fault == "missing_receipt":
                return None
            if fault == "missing_receipt_logs":
                receipt.pop("logs")
            if fault == "empty_receipt_logs":
                receipt["logs"] = []
            if fault == "same_bloom_tail_omission":
                receipt["logs"] = receipt["logs"][:1]
            if fault == "missing_receipt_type":
                receipt.pop("type")
            if fault == "wrong_cumulative_gas":
                receipt["cumulativeGasUsed"] = "0x1"
            if fault == "wrong_receipt_hash":
                receipt["blockHash"] = block_hash(3)
            if fault == "wrong_receipt_index":
                receipt["transactionIndex"] = "0x1"
            return receipt
        return NotImplemented

    h.rpc.failure = fail
    assert scan_wallet(h.wallet)["outcome"] == "indexer_unavailable"
    assert_untouched(h)
    h.rpc.failure = None
    assert scan_wallet(h.wallet)["outcome"] == "scanned"
    assert user_balances(h.wallet.user_id, h.wallet.asset_key)["available"] == Decimal(3)
    assert Deposit.objects.filter(user_wallet=h.wallet).count() == 2


@pytest.mark.parametrize(
    "fault", ["missing_hash", "changed_hash", "missing_checkpoint", "low_head"]
)
def test_original_token_checkpoint_is_required(token_history, fault):
    h = token_history
    assert scan_wallet(h.wallet)["outcome"] == "scanned"
    h.wallet.refresh_from_db()
    original = (h.wallet.last_scanned_block, h.wallet.evm_scan_block_hash)
    if fault == "missing_hash":
        UserWallet.objects.filter(pk=h.wallet.pk).update(evm_scan_block_hash=None)
        h.wallet.refresh_from_db()
        original = (original[0], None)
    if fault == "low_head":
        h.rpc.head = 3
    if fault in {"changed_hash", "missing_checkpoint"}:

        def fail(method, params):
            if method == "eth_getBlockByNumber" and params == [hex(original[0]), False]:
                if fault == "missing_checkpoint":
                    return None
                block = h.rpc.original(method, params)
                block["hash"] = block_hash(999)
                return block
            return NotImplemented

        h.rpc.failure = fail
    assert scan_wallet(h.wallet)["outcome"] == "indexer_unavailable"
    h.wallet.refresh_from_db()
    assert (h.wallet.last_scanned_block, h.wallet.evm_scan_block_hash) == original
    assert LedgerTransaction.objects.filter(event_type="DEPOSIT_CREDIT").count() == 1


@pytest.mark.parametrize("failure_at", ["credit", "checkpoint"])
def test_credit_and_checkpoint_rollback_together(token_history, failure_at):
    h = token_history
    original_save = UserWallet.save

    def save(wallet, *args, **kwargs):
        if wallet.pk == h.wallet.pk and "last_scanned_block" in kwargs.get("update_fields", []):
            raise DatabaseError("controlled checkpoint interruption")
        return original_save(wallet, *args, **kwargs)

    target = "custody.deposits.credit_deposit" if failure_at == "credit" else None
    context = (
        patch(target, side_effect=DatabaseError("controlled journal interruption"))
        if target
        else patch.object(UserWallet, "save", save)
    )
    with context, pytest.raises(DatabaseError):
        scan_wallet(h.wallet)
    assert_untouched(h)
    assert scan_wallet(h.wallet)["outcome"] == "scanned"
    h.wallet.refresh_from_db()
    assert scan_wallet(h.wallet)["outcome"] == "scanned"
    assert LedgerTransaction.objects.filter(event_type="DEPOSIT_CREDIT").count() == 1


def test_confirmations_larger_than_overlap_never_skip_pending_transfers(token_history):
    h = token_history
    Chain.objects.filter(chain_id="ETH").update(min_confirmations=20)
    h.rpc.head = 21
    assert scan_wallet(h.wallet)["outcome"] == "scanned"
    h.wallet.refresh_from_db()
    assert (
        h.wallet.last_scanned_block == 1
        and not Deposit.objects.filter(user_wallet=h.wallet).exists()
    )
    h.rpc.head = 22
    assert scan_wallet(h.wallet)["outcome"] == "scanned"
    h.wallet.refresh_from_db()
    deposit = Deposit.objects.get(user_wallet=h.wallet)
    assert deposit.confirmations == 20 and h.wallet.last_scanned_block == 2


def test_backfill_does_not_start_sweep(token_history):
    h = token_history
    h.rpc.head = 150
    Asset.objects.filter(pk=h.asset.pk).update(deposit_threshold=Decimal("0.0001"))
    with patch("custody.indexer_service.trigger_sweep") as sweep:
        assert scan_wallet(h.wallet)["outcome"] == "backfill"
    sweep.assert_not_called()


def test_confirmation_policy_race_rejects_commit(token_history):
    h = token_history

    def change(method, params):
        if method == "eth_getLogs":
            Chain.objects.filter(chain_id="ETH").update(min_confirmations=20)
        return NotImplemented

    h.rpc.failure = change
    assert scan_wallet(h.wallet)["outcome"] == "indexer_unavailable"
    assert_untouched(h)


def test_migration_reconciles_only_old_evm_token_cursors_without_changing_journals(token_history):
    h = token_history
    assert scan_wallet(h.wallet)["outcome"] == "scanned"
    original = list(LedgerPosting.objects.values())
    UserWallet.objects.filter(pk=h.native.pk).update(
        last_scanned_block=4, evm_scan_block_hash=block_hash(4)
    )
    other = UserWallet.objects.create(
        user_id="other",
        chain_id="TRX",
        asset_key="USDT-TRX",
        derivation_path="m/other",
        deposit_address="other",
        last_scanned_block=999,
    )
    module = importlib.import_module("custody.migrations.0026_evm_token_verified_scan_checkpoint")
    module.reset_unverified_token_cursors(apps, SimpleNamespace(connection=connection))
    h.wallet.refresh_from_db()
    h.native.refresh_from_db()
    other.refresh_from_db()
    assert h.wallet.last_scanned_block is None and h.wallet.evm_scan_block_hash is None
    assert h.native.last_scanned_block == 4 and h.native.evm_scan_block_hash == block_hash(4)
    assert other.last_scanned_block == 999
    assert scan_wallet(h.wallet)["outcome"] == "scanned"
    assert list(LedgerPosting.objects.values()) == original
    assert LedgerTransaction.objects.filter(event_type="DEPOSIT_CREDIT").count() == 1


def test_verified_empty_history_can_advance_without_credit(token_history):
    h = token_history
    h.rpc.transfers = {}
    assert scan_wallet(h.wallet)["outcome"] == "scanned"
    h.wallet.refresh_from_db()
    assert h.wallet.last_scanned_block == 4 and h.wallet.evm_scan_block_hash == block_hash(4)
    assert not Deposit.objects.filter(user_wallet=h.wallet).exists()
