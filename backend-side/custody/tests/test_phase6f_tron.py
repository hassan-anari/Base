"""Deterministic 6F-A contracts. Local test keys and RPC emulator are NOT MPC acceptance."""

import copy
import hashlib
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import requests
from django.core.management import call_command
from django.db import IntegrityError, close_old_connections, connection
from django.db import transaction as atomic_transaction
from eth_keys import keys
from ops.models import Chain, NodeEndpoint

from custody.ledger import ensure_accounts, post_transaction, user_balances
from custody.models import (
    Asset,
    GasTopupIntent,
    HotWallet,
    LedgerAccount,
    LedgerTransaction,
    MpcKeyset,
    MpcSigningSession,
    OnchainTransactionAttempt,
    SweepJob,
    UserWallet,
)
from custody.mpc_binding import local_root_keyset, validate_custody_intent
from custody.mpc_identity import address_from_public_key
from custody.mpc_signing import advance_mpc_signing
from custody.mpc_tron_network import verify_tron_rpc_endpoints
from custody.native_tx import (
    AmbiguousBroadcast,
    InsufficientBalance,
    RequestsTransport,
    TronNativeExecutor,
    to_base_units,
)
from custody.outbound import create_attempt, execute_attempt
from custody.reconciliation import reconcile_attempt
from custody.token_metadata import verify_token_asset
from custody.token_tx import Trc20Executor
from custody.tron_policy import assemble_tron_signature, validate_transfer
from custody.tron_wire import serialize_raw, validate_wire
from custody.withdrawals import approve, create_request

from .test_phase6_signing import CoordinatorClient, metadata_for
from .test_phase6_signing import integration_settings as integration_settings
from .tron_fixture import CAPS, RpcEmulator, transaction

SOURCE = "41" + "11" * 20
DESTINATION = "41" + "22" * 20
TOKEN = "41" + "33" * 20


@pytest.mark.parametrize("token", [False, True])
def test_exact_protobuf_digest_matches_independent_generated_sdk(token):
    pytest.importorskip("google.protobuf")
    from tronpy.proto.transaction import _raw_data_to_protobuf

    tx = transaction(SOURCE, DESTINATION, 1250000, token=TOKEN if token else None)
    independent = _raw_data_to_protobuf(tx["raw_data"]).SerializeToString()
    assert independent == serialize_raw(tx["raw_data"])
    assert hashlib.sha256(independent).digest() == validate_wire(tx)


@pytest.mark.parametrize(
    "field",
    [
        "amount",
        "source",
        "destination",
        "type",
        "any",
        "raw_hex",
        "txid",
        "expiration",
        "permission",
        "extra",
        "multi",
    ],
)
def test_tampered_node_identity_rejected(field):
    tx = transaction(SOURCE, DESTINATION, 1250000)
    value = tx["raw_data"]["contract"][0]["parameter"]["value"]
    contract = tx["raw_data"]["contract"][0]
    if field == "amount":
        value["amount"] += 1
    elif field == "source":
        value["owner_address"] = TOKEN
    elif field == "destination":
        value["to_address"] = TOKEN
    elif field == "type":
        contract["type"] = "TriggerSmartContract"
    elif field == "any":
        contract["parameter"]["type_url"] = "evil"
    elif field == "raw_hex":
        tx["raw_data_hex"] += "00"
    elif field == "txid":
        tx["txID"] = "00" * 32
    elif field == "expiration":
        tx["raw_data"]["expiration"] += 1
    elif field == "permission":
        contract["Permission_id"] = 2
    elif field == "extra":
        tx["raw_data"]["data"] = "00"
    else:
        tx["raw_data"]["contract"].append(copy.deepcopy(contract))
    with pytest.raises((ValueError, KeyError)):
        validate_transfer(tx, SOURCE, DESTINATION, 1250000)


@pytest.mark.parametrize("change", ["destination", "amount", "contract", "call_value", "fee_limit"])
def test_trc20_abi_and_contract_intent(change):
    tx = transaction(SOURCE, DESTINATION, 1250000, token=TOKEN)
    value = tx["raw_data"]["contract"][0]["parameter"]["value"]
    if change == "contract":
        value["contract_address"] = DESTINATION
    elif change == "call_value":
        value["call_value"] = 1
    elif change == "fee_limit":
        tx["raw_data"]["fee_limit"] += 1
    elif change == "destination":
        value["data"] = value["data"][:8] + "00" * 32 + value["data"][72:]
    else:
        value["data"] = value["data"][:-64] + f"{1250001:064x}"
    if change != "call_value":
        encoded = serialize_raw(tx["raw_data"])
        tx["raw_data_hex"], tx["txID"] = encoded.hex(), hashlib.sha256(encoded).hexdigest()
    with pytest.raises(ValueError):
        validate_transfer(tx, SOURCE, DESTINATION, 1250000, contract=TOKEN, fee_limit=50000000)


@pytest.fixture
def tron_context(db, integration_settings, settings):
    from custody.rate_limit import rate_limiter

    # Test isolation: each scenario starts with a fresh in-memory admission bucket.
    rate_limiter._buckets.clear()
    private = keys.PrivateKey(bytes.fromhex("04".rjust(64, "0")))
    public = private.public_key.to_compressed_bytes().hex()
    Chain.objects.filter(chain_id="TRX").update(
        kind="tron",
        is_testnet=True,
        enabled=True,
        evm_chain_id=None,
        gas_settings=CAPS,
        native_asset_key="TRX",
    )
    Asset.objects.filter(asset_key="TRX").update(
        decimals=6, enabled=True, withdrawal_supported=True, sweep_supported=True
    )
    source = address_from_public_key("TRX", public)
    destination = address_from_public_key(
        "TRX",
        keys.PrivateKey(bytes.fromhex("05".rjust(64, "0"))).public_key.to_compressed_bytes().hex(),
    )
    token = address_from_public_key(
        "TRX",
        keys.PrivateKey(bytes.fromhex("06".rjust(64, "0"))).public_key.to_compressed_bytes().hex(),
    )
    rpc = RpcEmulator(source, destination, token)
    settings.MPC_EVM_INTEGRATION_ENABLED = False
    settings.MPC_TRON_INTEGRATION_ENABLED = True
    settings.MPC_TRON_NETWORK = rpc.policy()
    NodeEndpoint.objects.filter(chain_id="TRX", kind="rpc").update(enabled=False)
    NodeEndpoint.objects.create(
        chain_id="TRX",
        name="phase6f-loopback",
        kind="rpc",
        url=rpc.policy()["trusted_endpoints"][0],
        enabled=True,
    )
    keyset = MpcKeyset.objects.create(
        keyset_id=uuid.uuid4(),
        algorithm="CGGMP24_ECDSA",
        curve="secp256k1",
        scope="TRON",
        derivation_version="cggmp_hd_v1",
        participant_identities=["signer-a", "signer-b", "signer-c"],
        status="ACTIVE",
        public_key=public,
        dkg_execution_id=uuid.uuid4(),
        dkg_result_fingerprint="ab" * 32,
    )
    HotWallet.objects.update_or_create(
        chain_id="TRX",
        defaults={
            "address": source,
            "mpc_keyset": keyset,
            "signing_key_ref": f"keyset:{keyset.keyset_id}",
        },
    )
    context = SimpleNamespace(
        private=private,
        source=source,
        destination=destination,
        token=token,
        keyset=keyset,
        metadata=metadata_for(keyset),
        rpc=rpc,
    )
    with patch.object(RequestsTransport, "post", side_effect=rpc.post):
        yield context


def approved(context, *, token=False):
    asset = "F6-TRC20" if token else "TRX"
    if token:
        Asset.objects.create(
            asset_key=asset,
            chain_id="TRX",
            symbol="REVIEWED",
            decimals=6,
            is_native=False,
            token_standard="TRC20",
            contract_address=context.token,
            enabled=True,
            withdrawal_supported=True,
            sweep_supported=True,
        )
        verify_token_asset(asset)
    ensure_accounts("phase6f", asset)
    available = LedgerAccount.objects.get(owner_id="phase6f", asset_key=asset, bucket="AVAILABLE")
    clearing = LedgerAccount.objects.get(
        owner_type="SYSTEM", asset_key=asset, bucket="CUSTODY_CLEARING"
    )
    post_transaction(
        event_key=f"phase6f-fund:{asset}",
        event_type="TEST_FUNDING",
        asset_key=asset,
        ref_type="Test",
        ref_id="1",
        postings=[(available, Decimal(100)), (clearing, Decimal(-100))],
    )
    withdrawal = create_request(
        "phase6f",
        "TRX",
        context.destination,
        Decimal("1.25"),
        asset_key=asset,
        idempotency_key=f"phase6f:{asset}",
    )
    approve("reviewer", withdrawal.pk)
    context.withdrawal = withdrawal
    context.attempt = create_attempt(
        operation_type="WITHDRAWAL",
        operation_id=withdrawal.pk,
        chain_id="TRX",
        asset_key=asset,
        source=context.source,
        destination=context.destination,
        amount=withdrawal.amount,
    )
    context.client = CoordinatorClient(context)
    with patch("custody.signer_adapter.get_adapter", return_value=context.client):
        execute_attempt(context.attempt.pk, "reviewer")
    context.session = MpcSigningSession.objects.get(attempt=context.attempt)
    context.attempt.refresh_from_db()
    return context


def signed(context):
    context.client.complete()
    assert advance_mpc_signing(context.attempt.pk, context.client).status == "SIGNED"
    context.attempt.refresh_from_db()
    return context


@pytest.mark.parametrize("token", [False, True])
def test_approved_tron_sign_broadcast_solidify_and_settle(tron_context, token):
    c = signed(approved(tron_context, token=token))
    assert c.client.request["chain"] == "TRON"
    assert c.client.request["expected_source"] == c.source
    assert c.client.request["payload_hex"] == c.attempt.network_tx_id
    assert c.attempt.expires_at is not None
    frozen = copy.deepcopy(c.attempt.prepared_metadata)
    assert execute_attempt(c.attempt.pk, "worker").status == "BROADCASTED"
    assert len(c.rpc.submissions) == 1
    assert len(bytes.fromhex(c.rpc.submissions[0]["signature"][0])) == 65
    assert reconcile_attempt(c.attempt.pk).status == "CONFIRMED"
    assert reconcile_attempt(c.attempt.pk).status == "CONFIRMED"
    assert user_balances("phase6f", c.attempt.asset_key)["reserved"] == 0
    assert (
        LedgerTransaction.objects.filter(event_key=f"withdrawal:{c.withdrawal.pk}:settle").count()
        == 1
    )
    c.attempt.refresh_from_db()
    assert c.attempt.prepared_metadata == frozen


@pytest.mark.parametrize("token", [False, True])
def test_broadcast_timeout_never_resigns_or_rebroadcasts(tron_context, token):
    c = signed(approved(tron_context, token=token))
    c.rpc.failure = requests.Timeout("response lost after inclusion")
    with pytest.raises(AmbiguousBroadcast):
        execute_attempt(c.attempt.pk, "worker")
    assert execute_attempt(c.attempt.pk, "worker").status == "RECONCILIATION_REQUIRED"
    assert len(c.rpc.submissions) == 1 and len(c.client.executes) == 1
    assert user_balances("phase6f", c.attempt.asset_key)["reserved"] == Decimal("1.25")
    assert reconcile_attempt(c.attempt.pk).status == "CONFIRMED"


@pytest.mark.parametrize("field", ["txID", "raw_data_hex", "expiration", "network", "address"])
def test_frozen_identity_mutation_cannot_broadcast(tron_context, field):
    c = signed(approved(tron_context))
    if field == "expiration":
        c.attempt.prepared_metadata["raw_data"]["expiration"] += 1
    elif field == "network":
        c.attempt.fee_metadata["network"]["genesis_block_id"] = "00" * 32
    elif field == "address":
        c.attempt.from_address = c.source.swapcase()
    else:
        c.attempt.prepared_metadata[field] = "00" * 32
    c.attempt.save()
    assert execute_attempt(c.attempt.pk, "worker").status == "RECONCILIATION_REQUIRED"
    assert not c.rpc.submissions
    assert user_balances("phase6f", "TRX")["reserved"] == Decimal("1.25")


@pytest.mark.parametrize(
    "fault", ["id", "missing_id", "block", "raw", "outcome", "token", "topic", "duplicates"]
)
def test_bad_solidified_evidence_preserves_reservation(tron_context, fault):
    c = signed(approved(tron_context, token=True))
    execute_attempt(c.attempt.pk, "worker")
    info = c.rpc.receipts[c.attempt.network_tx_id]
    tx = c.rpc.transactions[c.attempt.network_tx_id]
    if fault == "id":
        info["id"] = "00" * 32
    elif fault == "missing_id":
        info.pop("id")
    elif fault == "block":
        info["blockNumber"] += 1
    elif fault == "raw":
        tx["raw_data_hex"] += "00"
    elif fault == "outcome":
        info["receipt"].pop("result")
    elif fault == "token":
        info["log"][0]["address"] = "00" * 20
    elif fault == "topic":
        info["log"][0]["topics"][2] = "ff" * 12 + info["log"][0]["topics"][2][24:]
    else:
        info["log"].append(copy.deepcopy(info["log"][0]))
    if fault in {"token", "topic", "duplicates"}:
        assert reconcile_attempt(c.attempt.pk).status == "RECONCILIATION_REQUIRED"
    else:
        with pytest.raises(ValueError):
            reconcile_attempt(c.attempt.pk)
    c.attempt.refresh_from_db()
    c.withdrawal.refresh_from_db()
    assert c.attempt.status == c.withdrawal.status == "RECONCILIATION_REQUIRED"
    assert user_balances("phase6f", c.attempt.asset_key)["reserved"] == Decimal("1.25")


def test_absent_expired_transaction_is_unknown(tron_context):
    c = signed(approved(tron_context))
    # Time passing changes no frozen bytes and supplies no proof of non-inclusion.
    with patch("time.time", return_value=time.time() + 3600):
        with pytest.raises(ValueError, match="stale"):
            execute_attempt(c.attempt.pk, "worker")
        assert reconcile_attempt(c.attempt.pk).status == "RECONCILIATION_REQUIRED"
    assert len(c.client.executes) == 1 and not c.rpc.submissions
    assert user_balances("phase6f", "TRX")["reserved"] == Decimal("1.25")


@pytest.mark.parametrize("token", [False, True])
def test_expired_broadcast_with_unknown_inclusion_requires_reconciliation(tron_context, token):
    c = signed(approved(tron_context, token=token))
    execute_attempt(c.attempt.pk, "worker")
    c.rpc.receipts.clear()
    c.rpc.transactions.clear()
    with patch("time.time", return_value=time.time() + 3600):
        result = reconcile_attempt(c.attempt.pk)
        assert result.status == "RECONCILIATION_REQUIRED"
        assert result.confirmation_metadata["outcome"] == "UNKNOWN"
        assert result.error_code == "TRON_EXPIRED_OUTCOME_UNKNOWN"
        assert execute_attempt(c.attempt.pk, "worker").status == "RECONCILIATION_REQUIRED"
    c.withdrawal.refresh_from_db()
    assert c.withdrawal.status == "RECONCILIATION_REQUIRED"
    assert len(c.client.executes) == len(c.rpc.submissions) == 1
    assert user_balances("phase6f", c.attempt.asset_key)["reserved"] == Decimal("1.25")
    assert not LedgerTransaction.objects.filter(
        event_key=f"withdrawal:{c.withdrawal.pk}:release"
    ).exists()


def test_signing_timeout_and_restart_reuses_original_result(tron_context):
    c = approved(tron_context)
    execution = c.session.crypto_execution_id
    with patch.object(c.client, "get_signing_session", side_effect=requests.Timeout):
        assert advance_mpc_signing(c.attempt.pk, c.client).status == "RECONCILIATION_REQUIRED"
    c.client.complete()
    assert advance_mpc_signing(c.attempt.pk, c.client).status == "SIGNED"
    c.session.refresh_from_db()
    assert c.session.crypto_execution_id == execution
    assert len(c.client.creates) == len(c.client.executes) == 1


@pytest.mark.parametrize("change", ["enabled", "mainnet", "numeric", "pin", "endpoint", "parent"])
def test_wrong_or_untrusted_network_fails_before_preparation(tron_context, settings, change):
    c = tron_context
    if change == "enabled":
        settings.MPC_TRON_INTEGRATION_ENABLED = False
    elif change == "mainnet":
        Chain.objects.filter(chain_id="TRX").update(is_testnet=False)
    elif change == "numeric":
        Chain.objects.filter(chain_id="TRX").update(evm_chain_id=1)
    elif change == "pin":
        settings.MPC_TRON_NETWORK["checkpoint_block_id"] = "00" * 32
    elif change == "parent":
        c.rpc.anchor["block_header"]["raw_data"]["parentHash"] = "ff" * 32
    else:
        NodeEndpoint.objects.create(
            chain_id="TRX", name="untrusted-failover", kind="rpc", url="https://mainnet.example"
        )
    with pytest.raises(ValueError):
        verify_tron_rpc_endpoints("TRX", RequestsTransport())
    assert not c.rpc.submissions


def test_unbound_case_changed_and_child_sources_fail_closed(tron_context):
    c = approved(tron_context)
    hot = HotWallet.objects.get(chain_id="TRX")
    for changes in (
        {"mpc_keyset": None},
        {"address": c.source.swapcase()},
        {"signing_key_ref": "m/44'/195'/0'/0/1"},
    ):
        with atomic_transaction.atomic():
            HotWallet.objects.filter(pk=hot.pk).update(**changes)
            with pytest.raises(ValueError):
                local_root_keyset(c.attempt)
            atomic_transaction.set_rollback(True)


@pytest.mark.parametrize("token", [False, True])
def test_fee_or_energy_budget_rejected(tron_context, token):
    c = tron_context
    c.rpc.balance = 1
    executor = Trc20Executor() if token else TronNativeExecutor()
    if token:
        Asset.objects.create(
            asset_key="F6-TRC20",
            chain_id="TRX",
            symbol="REVIEWED",
            decimals=6,
            is_native=False,
            token_standard="TRC20",
            contract_address=c.token,
        )
        verify_token_asset("F6-TRC20")
    with pytest.raises(InsufficientBalance):
        executor.prepare("TRX", "F6-TRC20" if token else "TRX", c.source, c.destination, Decimal(1))


@pytest.mark.parametrize("token", [False, True])
def test_root_deposit_sweeps_and_binding_command(tron_context, token):
    c = tron_context
    asset = "F6-TRC20" if token else "TRX"
    if token:
        Asset.objects.create(
            asset_key=asset,
            chain_id="TRX",
            symbol="REVIEWED",
            decimals=6,
            is_native=False,
            token_standard="TRC20",
            contract_address=c.token,
        )
        verify_token_asset(asset)
    HotWallet.objects.filter(chain_id="TRX").update(address=c.destination)
    wallet = UserWallet.objects.create(
        user_id="root-deposit",
        chain_id="TRX",
        asset_key=asset,
        deposit_address=c.source,
        derivation_path="unbound",
        derivation_version="mpc_root_v1",
        address_index=0,
    )
    call_command(
        "bind_mpc_hot_wallet",
        chain="TRX",
        keyset_id=str(c.keyset.keyset_id),
        user_wallet_id=wallet.pk,
        derivation_reference="",
    )
    job = SweepJob.objects.create(
        user_wallet=wallet, asset_key=asset, balance_snapshot=Decimal("100"), sweep_round=1
    )
    c.attempt = create_attempt(
        operation_type="SWEEP",
        operation_id=job.pk,
        chain_id="TRX",
        asset_key=asset,
        source=c.source,
        destination=c.destination,
        amount=Decimal("100"),
    )
    c.client = CoordinatorClient(c)
    with patch("custody.signer_adapter.get_adapter", return_value=c.client):
        execute_attempt(c.attempt.pk, "system:sweeper")
    c.session = MpcSigningSession.objects.get(attempt=c.attempt)
    signed(c)
    execute_attempt(c.attempt.pk, "worker")
    assert reconcile_attempt(c.attempt.pk).status == "CONFIRMED"


def test_tron_duplicate_wire_identity_cannot_settle_two_intents(tron_context):
    c = approved(tron_context)
    with pytest.raises(IntegrityError), atomic_transaction.atomic():
        OnchainTransactionAttempt.objects.create(
            operation_type="WITHDRAWAL",
            operation_id=c.withdrawal.pk + 100,
            chain_id="TRX",
            asset_key="TRX",
            from_address=c.source,
            to_address=c.destination,
            amount=1,
            base_unit_amount=1000000,
            network_tx_id=c.attempt.network_tx_id,
        )


@pytest.mark.django_db(transaction=True)
def test_duplicate_workers_own_one_broadcast(tron_context):
    assert connection.vendor == "postgresql", "6F-A concurrency acceptance requires PostgreSQL"
    c = signed(approved(tron_context))
    entered, release = threading.Event(), threading.Event()
    original = c.rpc.post

    def post(url, path, body):
        if path.endswith("broadcasttransaction"):
            entered.set()
            assert release.wait(10)
        return original(url, path, body)

    def worker():
        close_old_connections()
        try:
            return execute_attempt(c.attempt.pk, "worker").status
        finally:
            close_old_connections()

    with (
        patch.object(RequestsTransport, "post", side_effect=post),
        ThreadPoolExecutor(max_workers=2) as pool,
    ):
        first = pool.submit(worker)
        assert entered.wait(10)
        second = pool.submit(worker)
        assert second.result(timeout=10) == "BROADCASTING"
        release.set()
        assert first.result(timeout=10) == "BROADCASTED"
    assert len(c.rpc.submissions) == 1 and len(c.client.executes) == 1


@pytest.mark.parametrize("v,s", [(2, 1), (27, 1), (True, 1), (0, 2**256 - 1), (0, 0)])
def test_noncanonical_signature_components_rejected(v, s):
    with pytest.raises(ValueError):
        assemble_tron_signature(
            transaction(SOURCE, DESTINATION, 1), {"r": "01", "s": f"{s:064x}", "recovery_id": v}
        )


def test_post_redirects_cannot_cross_trust_boundary():
    with patch(
        "custody.native_tx.requests.post", return_value=SimpleNamespace(status_code=302)
    ) as post:
        with pytest.raises(RuntimeError, match="redirects"):
            RequestsTransport().post("http://127.0.0.1:8090", "/wallet/getnowblock", {})
        assert post.call_args.kwargs["allow_redirects"] is False


def test_large_token_amount_keeps_every_integer_digit():
    assert (
        to_base_units(Decimal("123456789012345678901234567890.123456"), 6)
        == 123456789012345678901234567890123456
    )
    with pytest.raises(ValueError):
        to_base_units(Decimal("1.0000001"), 6)


def test_unsigned_txid_cannot_release_or_settle_reservation(tron_context):
    c = approved(tron_context)
    assert reconcile_attempt(c.attempt.pk).status == "SIGNING"
    assert user_balances("phase6f", "TRX")["reserved"] == Decimal("1.25")


def test_solidified_contract_failure_releases_once(tron_context):
    c = signed(approved(tron_context, token=True))
    execute_attempt(c.attempt.pk, "worker")
    tx = c.rpc.transactions[c.attempt.network_tx_id]
    tx["ret"] = [{"contractRet": "REVERT"}]
    c.rpc.head["transactions"][0]["ret"] = tx["ret"]
    c.rpc.receipts[c.attempt.network_tx_id]["receipt"]["result"] = "REVERT"
    assert reconcile_attempt(c.attempt.pk).status == "FAILED"
    assert reconcile_attempt(c.attempt.pk).status == "FAILED"
    assert (
        LedgerTransaction.objects.filter(event_key=f"withdrawal:{c.withdrawal.pk}:release").count()
        == 1
    )
    assert not LedgerTransaction.objects.filter(
        event_key=f"withdrawal:{c.withdrawal.pk}:settle"
    ).exists()


def test_completed_expired_signature_is_reused_without_new_execution(tron_context):
    c = approved(tron_context)
    c.client.complete()
    with patch("time.time", return_value=time.time() + 3600):
        assert advance_mpc_signing(c.attempt.pk, c.client).status == "SIGNED"
        with pytest.raises(ValueError, match="stale"):
            execute_attempt(c.attempt.pk, "worker")
    assert MpcSigningSession.objects.filter(attempt=c.attempt).count() == 1
    assert len(c.client.creates) == len(c.client.executes) == 1
    assert not c.rpc.submissions


def test_mpc_indexer_rejects_environment_stub(tron_context, monkeypatch):
    from custody.indexer.base import IndexerUnavailable
    from custody.indexer.trx import TrxIndexer

    monkeypatch.setenv("CUSTODY_INDEXER_MODE", "stub")
    with pytest.raises(IndexerUnavailable, match="simulated"):
        TrxIndexer().get_balance(tron_context.source, asset_key="TRX")


@pytest.mark.parametrize("problem", ["unbound", "wrong_key", "oversized", None])
def test_resource_grant_requires_owned_destination_and_bounded_amount(tron_context, problem):
    c = resource_grant(tron_context, problem)
    if problem:
        with pytest.raises(ValueError):
            validate_custody_intent(c.attempt)
    else:
        validate_custody_intent(c.attempt)


def resource_grant(c, problem=None):
    target = MpcKeyset.objects.get(pk=c.keyset.pk)
    target.pk = None
    target.keyset_id = uuid.uuid4()
    target.dkg_execution_id = uuid.uuid4()
    target.public_key = (
        keys.PrivateKey(bytes.fromhex("05".rjust(64, "0"))).public_key.to_compressed_bytes().hex()
    )
    target.save()
    UserWallet.objects.create(
        user_id="resource-recipient",
        chain_id="TRX",
        asset_key="TRX",
        deposit_address=c.destination,
        mpc_keyset=None if problem == "unbound" else c.keyset if problem == "wrong_key" else target,
        derivation_version="mpc_root_v1",
        derivation_path=f"keyset:{target.keyset_id}",
    )
    intent = GasTopupIntent.objects.create(
        idempotency_key="resource-budget",
        actor_id="system:gas_station",
        chain_id="TRX",
        to_address=c.destination,
        amount=Decimal(61 if problem == "oversized" else 60),
        status="PROCESSING",
    )
    c.attempt = create_attempt(
        operation_type="GAS_TOPUP",
        operation_id=intent.pk,
        chain_id="TRX",
        asset_key="TRX",
        source=c.source,
        destination=c.destination,
        amount=intent.amount,
    )
    return c


def test_internal_mpc_gas_grant_cannot_credit_customer_deposit(tron_context, monkeypatch):
    from custody.indexer.base import IndexerUnavailable
    from custody.indexer.trx import TrxIndexer

    c = resource_grant(tron_context)
    c.client = CoordinatorClient(c)
    with patch("custody.signer_adapter.get_adapter", return_value=c.client):
        execute_attempt(c.attempt.pk, "system:gas_station")
    c.session = MpcSigningSession.objects.get(attempt=c.attempt)
    signed(c)
    execute_attempt(c.attempt.pk, "worker")
    monkeypatch.setenv("CUSTODY_INDEXER_MODE", "live")
    observation = TrxIndexer().get_balance(c.destination, asset_key="TRX")
    assert observation.deposit_events == []
    assert reconcile_attempt(c.attempt.pk).status == "CONFIRMED"
    assert TrxIndexer().get_balance(c.destination, asset_key="TRX").deposit_events == []
    MpcSigningSession.objects.filter(pk=c.session.pk).update(signature_consumed_at=None)
    with pytest.raises(IndexerUnavailable):
        TrxIndexer().get_balance(c.destination, asset_key="TRX")


@pytest.mark.parametrize("token", [False, True])
def test_solidified_indexer_matches_actual_effect_and_excludes_genesis(
    tron_context, monkeypatch, token
):
    from custody.indexer.trx import TrxIndexer

    c = signed(approved(tron_context, token=token))
    execute_attempt(c.attempt.pk, "worker")
    monkeypatch.setenv("CUSTODY_INDEXER_MODE", "live")
    result = TrxIndexer().get_balance(c.destination, asset_key=c.attempt.asset_key)
    assert result.last_scanned_block == 3
    assert len(result.deposit_events) == 1
    event = result.deposit_events[0]
    assert (event.tx_hash, event.amount, event.block, event.confirmations) == (
        c.attempt.network_tx_id,
        Decimal("1.25"),
        3,
        1,
    )
    if token:
        c.rpc.receipts[c.attempt.network_tx_id]["log"][0]["address"] = "aa" * 20
        assert (
            not TrxIndexer()
            .get_balance(c.destination, asset_key=c.attempt.asset_key)
            .deposit_events
        )


@pytest.mark.django_db(transaction=True)
def test_reconcilers_share_execution_ownership_and_settle_once(tron_context):
    c = signed(approved(tron_context))
    execute_attempt(c.attempt.pk, "worker")
    entered, release = threading.Event(), threading.Event()
    original = c.rpc.post

    def post(url, path, body):
        if path.endswith("gettransactioninfobyid"):
            entered.set()
            assert release.wait(10)
        return original(url, path, body)

    def worker():
        close_old_connections()
        try:
            return reconcile_attempt(c.attempt.pk).status
        finally:
            close_old_connections()

    with (
        patch.object(RequestsTransport, "post", side_effect=post),
        ThreadPoolExecutor(max_workers=2) as pool,
    ):
        first = pool.submit(worker)
        assert entered.wait(10)
        assert pool.submit(worker).result(timeout=10) == "BROADCASTED"
        release.set()
        assert first.result(timeout=10) == "CONFIRMED"
    assert (
        LedgerTransaction.objects.filter(event_key=f"withdrawal:{c.withdrawal.pk}:settle").count()
        == 1
    )
