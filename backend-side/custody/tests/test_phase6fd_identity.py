"""Shared-ledger identity boundaries; PostgreSQL is the execution authority."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from types import SimpleNamespace
from uuid import uuid4

import pytest
from django.db import DatabaseError, IntegrityError, close_old_connections, connection, transaction
from ops.models import Chain

from custody.account_chain_costs import post_execution_costs
from custody.ledger import ensure_accounts, post_transaction, user_balances
from custody.models import Asset, LedgerAccount, LedgerTransaction, MpcKeyset, TonWalletBinding


@pytest.mark.django_db(transaction=True)
def test_account_creation_serializes_with_registry_reassignment():
    assert connection.vendor == "postgresql"
    asset = Asset.objects.get(asset_key="ETH")
    account_created, release = threading.Event(), threading.Event()
    pids = []

    def credit():
        close_old_connections()
        try:
            with transaction.atomic():
                ensure_accounts("race-customer", asset.asset_key)
                account_created.set()
                assert release.wait(10)
        finally:
            close_old_connections()

    def mutate():
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                pids.append(cursor.fetchone()[0])
            with pytest.raises(DatabaseError, match="financial identity"):
                Asset.objects.filter(pk=asset.pk).update(chain_id="TRX", decimals=6)
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as workers:
        first = workers.submit(credit)
        assert account_created.wait(10)
        second = workers.submit(mutate)
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if pids:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "SELECT wait_event_type FROM pg_stat_activity WHERE pid=%s", pids
                        )
                        if cursor.fetchone() == ("Lock",):
                            break
                time.sleep(0.01)
            else:
                pytest.fail("registry writer did not wait on account creation")
        finally:
            release.set()
        first.result(timeout=10)
        second.result(timeout=10)
    asset.refresh_from_db()
    assert asset.chain_id == "ETH" and asset.financial_identity_locked


def keyset(scope="TON"):
    return MpcKeyset.objects.create(
        keyset_id=uuid4(),
        algorithm="FROST_ED25519",
        curve="ed25519",
        scope=scope,
        derivation_version="frost_keyset_v1",
    )


@pytest.mark.django_db(transaction=True)
def test_root_network_and_scope_cannot_be_replaced_by_bulk_update():
    assert connection.vendor == "postgresql"
    k = keyset("SOLANA")
    MpcKeyset.objects.filter(pk=k.pk).update(network_bindings={"SOL": {"genesis_hash": "original"}})
    for change in (
        {"scope": "TON"},
        {"network_bindings": {}},
        {"network_bindings": {"SOL": {"genesis_hash": "replacement"}}},
    ):
        with pytest.raises(DatabaseError, match="original root"), transaction.atomic():
            MpcKeyset.objects.filter(pk=k.pk).update(**change)


@pytest.mark.django_db(transaction=True)
def test_ton_root_cannot_adopt_another_genesis_with_same_global_id():
    assert connection.vendor == "postgresql"
    k = keyset()
    values = dict(
        chain_id="TON",
        address="0:" + "11" * 32,
        keyset=k,
        network_identity={"global_id": -777, "zerostate_root_hash": "11" * 32},
        code_hash="22" * 32,
        wallet_id=2147482871,
        state_init="original",
    )
    binding = TonWalletBinding.objects.create(**values)
    replacement = {"global_id": -777, "zerostate_root_hash": "33" * 32}
    with pytest.raises(DatabaseError, match="immutable"), transaction.atomic():
        TonWalletBinding.objects.filter(pk=binding.pk).update(network_identity=replacement)
    with pytest.raises(DatabaseError), transaction.atomic():
        TonWalletBinding.objects.create(
            **{**values, "address": "0:" + "44" * 32, "network_identity": replacement}
        )
    with pytest.raises(DatabaseError, match="immutable"), transaction.atomic():
        TonWalletBinding.objects.filter(pk=binding.pk).delete()


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("chain,native,units", [("ETH", "ETH", 210000), ("TRX", "TRX", 700000)])
def test_token_network_cost_posts_once_to_its_native_asset(chain, native, units):
    token = credited_asset(chain)
    txid = "ab" * 32
    spec = Chain.objects.get(chain_id=chain)
    attempt = SimpleNamespace(
        pk=71,
        chain_id=chain,
        asset_key=token.asset_key,
        network_tx_id=txid,
        prepared_metadata={"gas": 21000, "gasPrice": 10},
        fee_metadata={"worst_case_base_units": "1000000"},
    )
    evidence = (
        {
            "confirmations": spec.min_confirmations,
            "receipt": {"transactionHash": txid, "gasUsed": "0x5208", "effectiveGasPrice": "0xa"},
        }
        if chain == "ETH"
        else {"txid": txid, "solidified": True, "fee": str(units)}
    )
    for _ in range(2):
        with transaction.atomic():
            post_execution_costs(attempt, evidence)
    journal = LedgerTransaction.objects.get(event_type="NETWORK_FEE")
    assert journal.asset_key == native
    assert set(journal.postings.values_list("account__asset_key", flat=True)) == {native}
    assert sum(journal.postings.values_list("amount", flat=True), Decimal(0)) == 0
    assert user_balances("integrated-customer", token.asset_key)["available"] == Decimal(2)


@pytest.mark.django_db(transaction=True)
def test_equal_symbols_do_not_share_available_or_reserved_amounts():
    from django.utils import timezone

    from custody.ledger import InsufficientFunds
    from custody.token_metadata import metadata_fingerprint
    from custody.withdrawals import create_request

    evm = credited_asset()
    other = Asset.objects.create(
        asset_key="SAME-SYMBOL-TRON",
        chain_id="TRX",
        symbol=evm.symbol,
        decimals=6,
        token_standard="TRC20",
        contract_address=__import__("base58").b58encode_check(b"\x41" + b"\x12" * 20).decode(),
    )
    other.metadata_verified_at = timezone.now()
    other.metadata_fingerprint = metadata_fingerprint(other)
    other.save()
    with pytest.raises(InsufficientFunds):
        create_request(
            "integrated-customer",
            "TRX",
            other.contract_address,
            Decimal(1),
            asset_key=other.asset_key,
            idempotency_key="same-symbol-spend",
        )
    assert user_balances("integrated-customer", evm.asset_key)["available"] == Decimal(2)
    assert user_balances("integrated-customer", other.asset_key)["reserved"] == 0


def credited_asset(chain="ETH"):
    asset = Asset.objects.create(
        asset_key=f"SAME-SYMBOL-{chain}",
        chain_id=chain,
        symbol="SAME",
        decimals=6,
        token_standard="ERC20" if chain == "ETH" else "TRC20",
        contract_address=(
            "0x" + "12" * 20
            if chain == "ETH"
            else __import__("base58").b58encode_check(b"\x41" + b"\x12" * 20).decode()
        ),
    )
    ensure_accounts("integrated-customer", asset.asset_key)
    available = LedgerAccount.objects.get(
        owner_id="integrated-customer", asset_key=asset.asset_key, bucket="AVAILABLE"
    )
    clearing = LedgerAccount.objects.get(asset_key=asset.asset_key, bucket="CUSTODY_CLEARING")
    post_transaction(
        event_key="identity:credit",
        event_type="DEPOSIT_CREDIT",
        asset_key=asset.asset_key,
        ref_type="Acceptance",
        ref_id="identity",
        postings=[(available, Decimal("2")), (clearing, Decimal("-2"))],
    )
    return asset


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize(
    "change",
    [
        {"chain_id": "TRX"},
        {"decimals": 18},
        {"contract_address": "0x" + "34" * 20},
        {"token_standard": "TRC20"},
        {"asset_key": "RENAMED"},
        {"is_native": True, "token_standard": None, "contract_address": None},
    ],
)
def test_spendable_asset_identity_cannot_be_reassigned(change):
    assert connection.vendor == "postgresql"
    asset = credited_asset()
    with pytest.raises(DatabaseError, match="financial identity"), transaction.atomic():
        Asset.objects.filter(pk=asset.pk).update(**change)
    assert user_balances("integrated-customer", asset.asset_key)["available"] == Decimal("2")


@pytest.mark.django_db(transaction=True)
def test_spendable_asset_cannot_be_deleted_and_recreated():
    assert connection.vendor == "postgresql"
    asset = credited_asset()
    with pytest.raises(DatabaseError, match="financial identity"), transaction.atomic():
        Asset.objects.filter(pk=asset.pk).delete()
    Asset.objects.filter(pk=asset.pk).update(symbol="DISPLAY-ONLY", enabled=False)
    assert user_balances("integrated-customer", asset.asset_key)["available"] == Decimal("2")


@pytest.mark.django_db(transaction=True)
def test_unregistered_asset_cannot_acquire_ledger_accounts():
    assert connection.vendor == "postgresql"
    with (
        pytest.raises(IntegrityError, match="registered asset financial identity"),
        transaction.atomic(),
    ):
        ensure_accounts("integrated-customer", "UNREGISTERED")
    assert not LedgerAccount.objects.filter(asset_key="UNREGISTERED").exists()


@pytest.mark.django_db(transaction=True)
def test_native_alias_cannot_duplicate_one_deposit_into_two_ledger_assets():
    from custody.deposits import ingest_event
    from custody.indexer.base import DepositEvent
    from custody.models import UserWallet

    with pytest.raises(IntegrityError, match="uq_native_asset_per_chain"), transaction.atomic():
        Asset.objects.create(
            asset_key="DUPLICATE-ETH", chain_id="ETH", symbol="ETH", decimals=18, is_native=True
        )
        # Before the fix this real ingestion path credited both keys for the
        # same financial event. This is a financial regression, not MPC proof.
        for key in ("ETH", "DUPLICATE-ETH"):
            wallet = UserWallet.objects.create(
                user_id="native-alias-customer",
                chain_id="ETH",
                asset_key=key,
                deposit_address="0x" + "89" * 20,
                derivation_path="m/native-alias",
            )
            ingest_event(wallet, DepositEvent("0xone-financial-event", Decimal(1), 100, 12))
            assert user_balances(wallet.user_id, key)["available"] == 1
