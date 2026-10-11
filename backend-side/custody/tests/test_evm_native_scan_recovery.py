"""PostgreSQL scanner durability regressions; RPC fixtures are not MPC evidence."""

import hashlib
import importlib
from decimal import Decimal
from types import SimpleNamespace

import pytest
import requests
from django.apps import apps
from django.db import DatabaseError, close_old_connections, connection
from ops.models import Chain, NodeEndpoint

from custody.indexer.evm_live import EvmLiveError, evm_get_balance
from custody.indexer_service import scan_wallet
from custody.ledger import user_balances
from custody.models import Asset, Deposit, LedgerTransaction, UserWallet
from custody.mpc_evm_network import MpcNetworkError

ADDRESS = "0x" + "ab" * 20
TXID = "0x" + "cd" * 32


def block_hash(n):
    return "0x" + ("11" * 32 if n == 0 else hashlib.sha256(str(n).encode()).hexdigest())


class RpcHistory:
    def __init__(self):
        self.head = 6
        self.deposit_block = 2
        self.failure = None
        self.blocks_read = []
        self.receipt = {
            "status": "0x1",
            "transactionHash": TXID,
            "blockHash": block_hash(2),
            "blockNumber": "0x2",
        }

    def rpc(self, url, method, params):
        if self.failure:
            value = self.failure(method, params)
            if value is not NotImplemented:
                return value
        if method == "eth_chainId":
            return "0x7a69"
        if method == "eth_blockNumber":
            return hex(self.head)
        if method == "eth_getBalance":
            return hex(2 * 10**18)
        if method == "eth_getBlockByNumber":
            n = int(params[0], 16)
            if params[1]:
                self.blocks_read.append(n)
            return {
                "number": hex(n),
                "hash": block_hash(n),
                "parentHash": block_hash(max(0, n - 1)),
                "transactions": [{"to": ADDRESS, "value": hex(2 * 10**18), "hash": TXID}]
                if n == self.deposit_block
                else [],
            }
        assert method == "eth_getTransactionReceipt"
        return self.receipt


@pytest.fixture
def history(transactional_db, settings, monkeypatch):
    assert connection.vendor == "postgresql"
    settings.MPC_SIGNER_BACKEND = "self_hosted_mpc"
    settings.MPC_INTEGRATION_ENVIRONMENT = "development"
    settings.MPC_EVM_INTEGRATION_ENABLED = True
    settings.MPC_EVM_DEVELOPMENT_CHAINS = {"ETH": 31337}
    settings.MPC_EVM_GENESIS_HASHES = {"ETH": block_hash(0)}
    monkeypatch.setenv("CUSTODY_INDEXER_MODE", "live")
    Asset.objects.filter(asset_key="ETH").update(deposit_threshold=Decimal("100"))
    Chain.objects.filter(chain_id="ETH").update(
        kind="evm",
        enabled=True,
        is_testnet=True,
        evm_chain_id=31337,
        min_confirmations=2,
        sweep_threshold=Decimal("100"),
    )
    NodeEndpoint.objects.filter(chain_id="ETH").update(enabled=False)
    NodeEndpoint.objects.create(
        chain_id="ETH",
        name="recovery-fixture",
        kind="rpc",
        enabled=True,
        url="http://127.0.0.1:8545",
        is_primary=True,
    )
    rpc = RpcHistory()
    monkeypatch.setattr("custody.native_tx.RequestsTransport.rpc", lambda _, *args: rpc.rpc(*args))
    wallet = UserWallet.objects.create(
        user_id="scanner-customer",
        chain_id="ETH",
        asset_key="ETH",
        derivation_path="m/scanner-fixture",
        deposit_address=ADDRESS,
    )
    return SimpleNamespace(rpc=rpc, wallet=wallet)


def assert_uncommitted(h):
    h.wallet.refresh_from_db()
    assert h.wallet.last_scanned_block is None and h.wallet.evm_scan_block_hash is None
    assert not Deposit.objects.filter(user_wallet=h.wallet).exists()
    assert not LedgerTransaction.objects.filter(event_type="DEPOSIT_CREDIT").exists()


@pytest.mark.parametrize("failed_block", [1, 3])
def test_intermittent_rpc_failure_aborts_entire_chunk_then_recovers(history, failed_block):
    def failure(method, params):
        if method == "eth_getBlockByNumber" and params == [hex(failed_block), True]:
            raise requests.ConnectionError("intermittent outage")
        return NotImplemented

    history.rpc.failure = failure
    assert scan_wallet(history.wallet)["outcome"] == "indexer_unavailable"
    assert_uncommitted(history)
    history.rpc.failure = None
    assert scan_wallet(history.wallet)["outcome"] == "scanned"
    assert user_balances("scanner-customer", "ETH")["available"] == 2
    assert LedgerTransaction.objects.filter(event_type="DEPOSIT_CREDIT").count() == 1


@pytest.mark.parametrize("missing", ["block", "transactions", "receipt", "receipt_block"])
def test_missing_or_inconsistent_history_never_advances_cursor(history, missing):
    def failure(method, params):
        if method == "eth_getBlockByNumber" and params == ["0x3", True]:
            if missing == "block":
                return None
            if missing == "transactions":
                return {"number": "0x3", "hash": block_hash(3), "parentHash": block_hash(2)}
        return NotImplemented

    history.rpc.failure = failure
    if missing == "receipt":
        history.rpc.receipt = None
    if missing == "receipt_block":
        history.rpc.receipt["blockHash"] = block_hash(9)
    assert scan_wallet(history.wallet)["outcome"] == "indexer_unavailable"
    assert_uncommitted(history)


def test_receipt_rpc_outage_is_not_a_successful_empty_scan(history):
    def failure(method, params):
        if method == "eth_getTransactionReceipt":
            raise requests.Timeout("receipt outage")
        return NotImplemented

    history.rpc.failure = failure
    assert scan_wallet(history.wallet)["outcome"] == "indexer_unavailable"
    assert_uncommitted(history)


def test_network_identity_failure_inside_history_scan_propagates(history):
    calls = 0

    def failure(method, params):
        nonlocal calls
        if method == "eth_chainId":
            calls += 1
            if calls > 6:
                return "0x1"
        return NotImplemented

    history.rpc.failure = failure
    with pytest.raises(MpcNetworkError, match="chain ID"):
        evm_get_balance("ETH", ADDRESS)
    assert_uncommitted(history)
    calls = 0
    assert scan_wallet(history.wallet)["outcome"] == "indexer_unavailable"
    assert_uncommitted(history)


def test_restart_backfills_more_than_64_blocks_without_duplicate_credit(history):
    history.rpc.head = 150
    stale = UserWallet.objects.get(pk=history.wallet.pk)
    assert scan_wallet(history.wallet)["outcome"] == "backfill"
    history.wallet.refresh_from_db()
    assert history.wallet.last_scanned_block == 63
    assert history.wallet.evm_scan_block_hash == block_hash(63)
    assert history.rpc.blocks_read == list(range(64))
    assert scan_wallet(stale)["outcome"] == "pending"  # stale competing worker
    close_old_connections()
    history.rpc.blocks_read.clear()
    restarted = UserWallet.objects.get(pk=history.wallet.pk)
    assert scan_wallet(restarted)["outcome"] == "backfill"
    restarted.refresh_from_db()
    assert restarted.last_scanned_block == 127
    assert history.rpc.blocks_read == list(range(64, 128))
    history.rpc.head = 240  # another interruption exceeds the former lookback
    restarted = UserWallet.objects.get(pk=restarted.pk)
    assert scan_wallet(restarted)["outcome"] == "backfill"
    restarted.refresh_from_db()
    assert scan_wallet(restarted)["outcome"] == "scanned"
    restarted.refresh_from_db()
    assert restarted.last_scanned_block == 238
    # A deliberate genesis replay uses the original unique event/journal identity.
    UserWallet.objects.filter(pk=restarted.pk).update(
        last_scanned_block=None, evm_scan_block_hash=None
    )
    replay = UserWallet.objects.get(pk=restarted.pk)
    assert scan_wallet(replay)["outcome"] == "backfill"
    assert Deposit.objects.filter(user_wallet=restarted).count() == 1
    assert LedgerTransaction.objects.filter(event_type="DEPOSIT_CREDIT").count() == 1
    assert user_balances("scanner-customer", "ETH") == {
        "available": Decimal(2),
        "reserved": 0,
        "total": Decimal(2),
    }


def test_outage_retains_previously_verified_progress_across_restart(history):
    history.rpc.head = 150
    assert scan_wallet(history.wallet)["outcome"] == "backfill"
    original = (63, block_hash(63))

    def failure(method, params):
        if method == "eth_getBlockByNumber" and params == ["0x46", True]:
            return None  # pruned or missing archival history
        return NotImplemented

    history.rpc.failure = failure
    close_old_connections()
    restarted = UserWallet.objects.get(pk=history.wallet.pk)
    assert scan_wallet(restarted)["outcome"] == "indexer_unavailable"
    restarted.refresh_from_db()
    assert (restarted.last_scanned_block, restarted.evm_scan_block_hash) == original
    history.rpc.failure = None
    assert scan_wallet(restarted)["outcome"] == "backfill"
    restarted.refresh_from_db()
    assert restarted.last_scanned_block == 127
    assert LedgerTransaction.objects.filter(event_type="DEPOSIT_CREDIT").count() == 1


@pytest.mark.parametrize(
    "fault", ["checkpoint_hash", "checkpoint_missing", "short_history", "ancestry"]
)
def test_changed_or_insufficient_checkpoint_history_fails_closed(history, fault):
    assert scan_wallet(history.wallet)["outcome"] == "scanned"
    history.wallet.refresh_from_db()
    original = (4, block_hash(4))
    history.rpc.head = 9
    if fault == "short_history":
        history.rpc.head = 4

    def failure(method, params):
        if method == "eth_getBlockByNumber" and params == ["0x4", False]:
            if fault == "checkpoint_missing":
                return None
            if fault == "checkpoint_hash":
                return {"number": "0x4", "hash": block_hash(88)}
        if fault == "ancestry" and method == "eth_getBlockByNumber" and params == ["0x5", True]:
            return {
                "number": "0x5",
                "hash": block_hash(5),
                "parentHash": block_hash(88),
                "transactions": [],
            }
        return NotImplemented

    history.rpc.failure = failure
    assert scan_wallet(history.wallet)["outcome"] == "indexer_unavailable"
    history.wallet.refresh_from_db()
    assert (history.wallet.last_scanned_block, history.wallet.evm_scan_block_hash) == original
    assert LedgerTransaction.objects.filter(event_type="DEPOSIT_CREDIT").count() == 1


def test_journal_and_cursor_commit_roll_back_together(history, monkeypatch):
    def failed_credit(*args):
        raise DatabaseError("controlled interruption before journal commit")

    monkeypatch.setattr("custody.deposits.credit_deposit", failed_credit)
    with pytest.raises(DatabaseError, match="interruption"):
        scan_wallet(history.wallet)
    assert_uncommitted(history)


def test_cursor_persistence_failure_rolls_back_deposit_credit(history, monkeypatch):
    original_save = UserWallet.save

    def failed_save(wallet, *args, **kwargs):
        if "last_scanned_block" in (kwargs.get("update_fields") or []):
            raise DatabaseError("controlled interruption during checkpoint persistence")
        return original_save(wallet, *args, **kwargs)

    with monkeypatch.context() as patcher:
        patcher.setattr(UserWallet, "save", failed_save)
        with pytest.raises(DatabaseError, match="checkpoint persistence"):
            scan_wallet(history.wallet)
    assert_uncommitted(history)
    close_old_connections()
    restarted = UserWallet.objects.get(pk=history.wallet.pk)
    assert scan_wallet(restarted)["outcome"] == "scanned"
    assert LedgerTransaction.objects.filter(event_type="DEPOSIT_CREDIT").count() == 1


def test_bounded_backfill_never_triggers_sweep(history, monkeypatch):
    Asset.objects.filter(asset_key="ETH").update(deposit_threshold=Decimal("0.001"))
    history.rpc.head = 150

    def premature_sweep(*args, **kwargs):
        pytest.fail("sweep started before complete deposit history")

    monkeypatch.setattr("custody.indexer_service.trigger_sweep", premature_sweep)
    assert scan_wallet(history.wallet)["outcome"] == "backfill"


def test_confirmation_policy_change_cannot_consume_pending_history(history, monkeypatch):
    def changed_policy(*args, **kwargs):
        result = evm_get_balance("ETH", ADDRESS)
        Chain.objects.filter(chain_id="ETH").update(min_confirmations=20)
        return result

    with monkeypatch.context() as patcher:
        patcher.setattr(
            "custody.indexer_service.get_indexer",
            lambda _: SimpleNamespace(get_balance=changed_policy),
        )
        assert scan_wallet(history.wallet)["outcome"] == "indexer_unavailable"
    assert_uncommitted(history)
    history.rpc.head = 30
    assert scan_wallet(history.wallet)["outcome"] == "scanned"
    assert Deposit.objects.get(user_wallet=history.wallet).confirmations == 28
    assert LedgerTransaction.objects.filter(event_type="DEPOSIT_CREDIT").count() == 1


def test_unconfirmed_native_history_is_not_consumed(history):
    history.rpc.head = 3
    assert scan_wallet(history.wallet)["outcome"] == "scanned"
    history.wallet.refresh_from_db()
    assert history.wallet.last_scanned_block == 1
    assert not Deposit.objects.filter(user_wallet=history.wallet).exists()
    history.rpc.head = 4
    assert scan_wallet(history.wallet)["outcome"] == "scanned"
    assert Deposit.objects.get(user_wallet=history.wallet).confirmations == 2
    assert user_balances("scanner-customer", "ETH")["available"] == 2


def test_genesis_checkpoint_zero_is_durable_and_failed_execution_is_not_credited(history):
    history.rpc.head = 2
    assert scan_wallet(history.wallet)["outcome"] == "scanned"
    history.wallet.refresh_from_db()
    assert history.wallet.last_scanned_block == 0
    assert history.wallet.evm_scan_block_hash == block_hash(0)
    history.rpc.head = 6
    history.rpc.receipt["status"] = "0x0"
    assert scan_wallet(history.wallet)["outcome"] == "scanned"
    assert not Deposit.objects.filter(user_wallet=history.wallet).exists()


def test_migration_resets_only_unverified_native_evm_progress(history):
    assert scan_wallet(history.wallet)["outcome"] == "scanned"
    other = UserWallet.objects.create(
        user_id="other",
        chain_id="SOL",
        asset_key="SOL",
        derivation_path="m/other",
        deposit_address="other",
        last_scanned_block=999,
        solana_scan_cursor={"original": True},
    )
    token = UserWallet.objects.create(
        user_id="token",
        chain_id="BSC",
        asset_key="USDT-BSC",
        derivation_path="m/token",
        deposit_address=ADDRESS,
        last_scanned_block=888,
    )
    module = importlib.import_module("custody.migrations.0025_evm_native_verified_scan_checkpoint")
    module.reset_unverified_native_cursors(apps, SimpleNamespace(connection=connection))
    history.wallet.refresh_from_db()
    other.refresh_from_db()
    token.refresh_from_db()
    assert history.wallet.last_scanned_block is None and history.wallet.evm_scan_block_hash is None
    assert other.last_scanned_block == 999 and other.solana_scan_cursor == {"original": True}
    assert token.last_scanned_block == 888
    assert scan_wallet(history.wallet)["outcome"] == "scanned"
    assert LedgerTransaction.objects.filter(event_type="DEPOSIT_CREDIT").count() == 1


def test_invalid_checkpoint_input_fails_closed(history):
    with pytest.raises(EvmLiveError, match="checkpoint"):
        evm_get_balance("ETH", ADDRESS, after_block=-1)
