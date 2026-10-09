"""PostgreSQL sweep recovery; deterministic signing/RPC fixtures, not MPC acceptance."""

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import requests
from django.db import close_old_connections, connection
from eth_keys import keys

from custody.indexer.base import BalanceResult
from custody.models import (
    Asset,
    GasTopupIntent,
    HotWallet,
    LedgerTransaction,
    MpcKeyset,
    MpcSigningSession,
    OnchainTransactionAttempt,
    SweepJob,
    UserWallet,
)
from custody.outbound import execute_attempt
from custody.reconciliation import reconcile_attempt
from custody.sweeper import _record_sweep_error, trigger_sweep
from custody.token_metadata import verify_token_asset

from .test_phase6_signing import CoordinatorClient
from .test_phase6_signing import integration_settings as integration_settings
from .test_phase6f_tron import approved, signed
from .test_phase6f_tron import tron_context as tron_context


def root_wallet(c, *, token=False, needs_gas=False):
    asset_key = "TRX"
    if token:
        asset_key = "F6-SWEEP-TOKEN"
        Asset.objects.create(
            asset_key=asset_key,
            chain_id="TRX",
            symbol="REVIEWED",
            decimals=6,
            is_native=False,
            token_standard="TRC20",
            contract_address=c.token,
            enabled=True,
            sweep_supported=True,
        )
        verify_token_asset(asset_key)
    keyset = c.keyset
    address = c.source
    if needs_gas:
        keyset = MpcKeyset.objects.get(pk=c.keyset.pk)
        keyset.pk = None
        keyset.keyset_id, keyset.dkg_execution_id = uuid.uuid4(), uuid.uuid4()
        keyset.public_key = (
            keys.PrivateKey(bytes.fromhex("05".rjust(64, "0")))
            .public_key.to_compressed_bytes()
            .hex()
        )
        keyset.save()
        address = c.destination
    else:
        HotWallet.objects.filter(chain_id="TRX").update(address=c.destination)
    return UserWallet.objects.create(
        user_id="sweep-recovery",
        chain_id="TRX",
        asset_key=asset_key,
        deposit_address=address,
        mpc_keyset=keyset,
        derivation_version="mpc_root_v1",
        derivation_path=f"keyset:{keyset.keyset_id}",
    )


def drive_completion(c, monkeypatch):
    """Drive the existing deterministic coordinator completion in one worker call.

    Both preparation and broadcast still use the real durable outbound lifecycle.
    Only the test coordinator transport/signature is simulated.
    """

    def execute(pk, actor):
        c.client = CoordinatorClient(c)
        with patch("custody.signer_adapter.get_adapter", return_value=c.client):
            c.attempt = execute_attempt(pk, actor)
            c.session = MpcSigningSession.objects.get(attempt=c.attempt)
            signed(c)
            return execute_attempt(pk, actor)

    monkeypatch.setattr("custody.outbound.execute_attempt", execute)


@pytest.mark.parametrize("token", [False, True])
def test_trigger_retains_accepted_sweep_after_http_error(tron_context, monkeypatch, token):
    c = tron_context
    wallet = root_wallet(c, token=token)
    monkeypatch.setattr(
        "custody.sweeper.get_indexer",
        lambda chain: SimpleNamespace(get_balance=lambda *a, **kw: BalanceResult(Decimal(2000))),
    )
    drive_completion(c, monkeypatch)
    c.rpc.failure = requests.HTTPError("node accepted before HTTP failure")
    with pytest.raises(requests.HTTPError):
        trigger_sweep(wallet, "system:sweep", BalanceResult(Decimal(100)))
    job = SweepJob.objects.get(user_wallet=wallet)
    c.attempt.refresh_from_db()
    c.session.refresh_from_db()
    assert c.attempt.status == job.status == "RECONCILIATION_REQUIRED"
    assert c.attempt.network_tx_id in c.rpc.transactions
    assert job.completed_at is None
    assert c.session.signature_consumed_at
    identity = (c.attempt.network_tx_id, c.session.session_id, c.session.crypto_execution_id)
    journals = list(LedgerTransaction.objects.values_list("pk", flat=True))
    for _ in range(3):
        assert trigger_sweep(wallet, "system:sweep", BalanceResult(Decimal(100))) == (
            True,
            job.pk,
            "already running",
        )
    assert SweepJob.objects.count() == OnchainTransactionAttempt.objects.count() == 1
    assert MpcSigningSession.objects.count() == len(c.rpc.submissions) == 1
    assert len(c.client.creates) == len(c.client.executes) == 1
    c.attempt.refresh_from_db()
    c.session.refresh_from_db()
    assert identity == (
        c.attempt.network_tx_id,
        c.session.session_id,
        c.session.crypto_execution_id,
    )
    assert journals == list(LedgerTransaction.objects.values_list("pk", flat=True))
    assert reconcile_attempt(c.attempt.pk).status == "CONFIRMED"
    assert reconcile_attempt(c.attempt.pk).status == "CONFIRMED"
    job.refresh_from_db()
    assert job.status == "CONFIRMED"
    assert journals == list(LedgerTransaction.objects.values_list("pk", flat=True))


def test_trigger_retains_ambiguous_resource_grant(tron_context, monkeypatch):
    c = tron_context
    wallet = root_wallet(c, token=True, needs_gas=True)
    monkeypatch.setattr(
        "custody.sweeper.get_indexer",
        lambda chain: SimpleNamespace(get_balance=lambda *a, **kw: BalanceResult(Decimal(0))),
    )
    drive_completion(c, monkeypatch)
    c.rpc.failure = requests.HTTPError("grant accepted before HTTP failure")
    with pytest.raises(requests.HTTPError):
        trigger_sweep(wallet, "system:sweep", BalanceResult(Decimal(100)))
    job = SweepJob.objects.get(user_wallet=wallet)
    intent = GasTopupIntent.objects.get(pk=job.gas_topup_intent_id)
    assert job.status == intent.status == "RECONCILIATION_REQUIRED"
    assert intent.idempotency_key == f"gas_topup:sweep:{job.pk}"
    assert c.attempt.operation_type == "GAS_TOPUP"
    c.attempt.refresh_from_db()
    assert c.attempt.status == "RECONCILIATION_REQUIRED"
    for _ in range(3):
        assert trigger_sweep(wallet, "system:sweep", BalanceResult(Decimal(100)))[1] == job.pk
    assert SweepJob.objects.count() == GasTopupIntent.objects.count() == 1
    assert OnchainTransactionAttempt.objects.count() == MpcSigningSession.objects.count() == 1
    assert len(c.rpc.submissions) == len(c.client.executes) == 1
    assert not LedgerTransaction.objects.exists()


@pytest.mark.parametrize("token", [False, True])
def test_proven_solidified_failure_allows_next_sweep_round(tron_context, monkeypatch, token):
    c = tron_context
    wallet = root_wallet(c, token=token)
    monkeypatch.setattr(
        "custody.sweeper.get_indexer",
        lambda chain: SimpleNamespace(get_balance=lambda *a, **kw: BalanceResult(Decimal(2000))),
    )
    drive_completion(c, monkeypatch)
    _, job_id, _ = trigger_sweep(wallet, "system:sweep", BalanceResult(Decimal(100)))
    tx = c.rpc.transactions[c.attempt.network_tx_id]
    tx["ret"] = [{"contractRet": "REVERT"}]
    c.rpc.head["transactions"][0]["ret"] = tx["ret"]
    c.rpc.receipts[c.attempt.network_tx_id]["receipt"]["result"] = "REVERT"
    assert reconcile_attempt(c.attempt.pk).status == "FAILED"
    assert SweepJob.objects.get(pk=job_id).status == "FAILED"
    _, retry_id, _ = trigger_sweep(wallet, "system:sweep", BalanceResult(Decimal(100)))
    assert retry_id != job_id
    assert SweepJob.objects.get(pk=retry_id).sweep_round == 2
    assert SweepJob.objects.count() == OnchainTransactionAttempt.objects.count() == 2
    assert MpcSigningSession.objects.count() == len(c.rpc.submissions) == 2


@pytest.mark.parametrize("token", [False, True])
def test_preparation_failure_is_definitive_and_retryable(tron_context, monkeypatch, token):
    from custody.native_tx import InsufficientBalance

    c = tron_context
    wallet = root_wallet(c, token=token)
    monkeypatch.setattr(
        "custody.sweeper.get_indexer",
        lambda chain: SimpleNamespace(get_balance=lambda *a, **kw: BalanceResult(Decimal(2000))),
    )
    c.rpc.balance = 1
    with pytest.raises(InsufficientBalance):
        trigger_sweep(wallet, "system:sweep", BalanceResult(Decimal(100)))
    job = SweepJob.objects.get(user_wallet=wallet)
    attempt = OnchainTransactionAttempt.objects.get(operation_id=job.pk, operation_type="SWEEP")
    assert job.status == attempt.status == "FAILED"
    assert job.completed_at and not attempt.broadcast_started_at
    assert not MpcSigningSession.objects.exists() and not c.rpc.submissions
    c.rpc.balance = 2000000000
    drive_completion(c, monkeypatch)
    assert trigger_sweep(wallet, "system:sweep", BalanceResult(Decimal(100)))[1] != job.pk
    assert SweepJob.objects.count() == OnchainTransactionAttempt.objects.count() == 2
    assert MpcSigningSession.objects.count() == len(c.rpc.submissions) == 1


@pytest.mark.parametrize("token", [False, True])
def test_success_publisher_preserves_reconciled_parent(tron_context, monkeypatch, token):
    c = tron_context
    wallet = root_wallet(c, token=token)
    monkeypatch.setattr(
        "custody.sweeper.get_indexer",
        lambda chain: SimpleNamespace(get_balance=lambda *a, **kw: BalanceResult(Decimal(2000))),
    )
    drive_completion(c, monkeypatch)
    from custody import outbound

    drive = outbound.execute_attempt

    def reconcile_before_publish(pk, actor):
        stale = drive(pk, actor)
        assert stale.status == "BROADCASTED"
        assert reconcile_attempt(pk).status == "CONFIRMED"
        return stale

    monkeypatch.setattr(outbound, "execute_attempt", reconcile_before_publish)
    _, job_id, _ = trigger_sweep(wallet, "system:sweep", BalanceResult(Decimal(100)))
    assert SweepJob.objects.get(pk=job_id).status == "CONFIRMED"
    assert len(c.rpc.submissions) == 1


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("token", [False, True])
def test_retry_and_reconciliation_before_stale_exception(tron_context, monkeypatch, token):
    assert connection.vendor == "postgresql"
    c = tron_context
    wallet = root_wallet(c, token=token)
    monkeypatch.setattr(
        "custody.sweeper.get_indexer",
        lambda chain: SimpleNamespace(get_balance=lambda *a, **kw: BalanceResult(Decimal(2000))),
    )
    drive_completion(c, monkeypatch)
    c.rpc.failure = requests.HTTPError("accepted")
    entered, release = threading.Event(), threading.Event()

    def delayed_error(pk):
        entered.set()
        assert release.wait(10)
        return _record_sweep_error(pk)

    monkeypatch.setattr("custody.sweeper._record_sweep_error", delayed_error)

    def worker():
        close_old_connections()
        try:
            with pytest.raises(requests.HTTPError):
                trigger_sweep(wallet, "system:sweep", BalanceResult(Decimal(100)))
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(worker)
        try:
            assert entered.wait(10)
            job = SweepJob.objects.get(user_wallet=wallet)
            assert trigger_sweep(wallet, "system:sweep", BalanceResult(Decimal(100)))[1] == job.pk
            assert reconcile_attempt(c.attempt.pk).status == "CONFIRMED"
            assert SweepJob.objects.get(pk=job.pk).status == "CONFIRMED"
        finally:
            release.set()
        future.result(timeout=10)
    job.refresh_from_db()
    assert job.status == "CONFIRMED" and job.completed_at is not None
    assert SweepJob.objects.count() == OnchainTransactionAttempt.objects.count() == 1
    assert MpcSigningSession.objects.count() == len(c.rpc.submissions) == 1
    assert not LedgerTransaction.objects.exists()


@pytest.mark.parametrize(
    "state",
    [
        "PREPARING",
        "PREPARED",
        "SIGNING",
        "SIGNED",
        "BROADCASTING",
        "BROADCASTED",
        "RECONCILIATION_REQUIRED",
    ],
)
def test_failed_gas_parent_cannot_hide_unresolved_attempt(tron_context, state):
    c = tron_context
    wallet = root_wallet(c, token=True, needs_gas=True)
    intent = GasTopupIntent.objects.create(
        idempotency_key="unresolved-gas",
        actor_id="system:gas_station",
        chain_id="TRX",
        to_address=wallet.deposit_address,
        amount=60,
        status="FAILED",
    )
    job = SweepJob.objects.create(
        user_wallet=wallet,
        asset_key=wallet.asset_key,
        balance_snapshot=100,
        idempotency_key="unresolved-sweep",
        gas_topup_intent=intent,
    )
    OnchainTransactionAttempt.objects.create(
        operation_type="GAS_TOPUP",
        operation_id=intent.pk,
        chain_id="TRX",
        asset_key="TRX",
        from_address=c.source,
        to_address=wallet.deposit_address,
        amount=60,
        base_unit_amount=60000000,
        status=state,
    )
    assert _record_sweep_error(job.pk).status == "RECONCILIATION_REQUIRED"
    assert trigger_sweep(wallet, "system:sweep", BalanceResult(Decimal(100)))[1] == job.pk
    assert SweepJob.objects.count() == GasTopupIntent.objects.count() == 1


@pytest.mark.parametrize("token", [False, True])
@pytest.mark.parametrize(
    "evidence",
    [
        "lagging",
        "missing_receipt",
        "missing_transaction",
        "absent",
        "conflicting",
        "partial_conflict",
        "wrong_network",
    ],
)
def test_tron_reconciliation_endpoint_failover(tron_context, settings, token, evidence):
    from ops.models import NodeEndpoint

    from custody.native_tx import RequestsTransport

    c = signed(approved(tron_context, token=token))
    execute_attempt(c.attempt.pk, "worker")
    first = settings.MPC_TRON_NETWORK["trusted_endpoints"][0]
    second = "http://127.0.0.1:18810"
    settings.MPC_TRON_NETWORK = {
        **settings.MPC_TRON_NETWORK,
        "trusted_endpoints": [first, second],
    }
    NodeEndpoint.objects.create(
        chain_id="TRX",
        name="reconciliation-failover",
        kind="rpc",
        url=second,
        enabled=True,
        priority=999,
    )
    queried = []

    def post(url, path, body):
        response = c.rpc.post(url, path, body)
        if "gettransaction" in path:
            queried.append(url)
            if evidence == "absent" or (evidence == "lagging" and url == first):
                return {}
            if url == first and (
                (evidence == "missing_receipt" and "infobyid" in path)
                or (evidence == "missing_transaction" and "infobyid" not in path)
            ):
                return {}
            if evidence == "partial_conflict" and url == first and "infobyid" not in path:
                return {}
            if (
                evidence in {"conflicting", "partial_conflict"}
                and url == first
                and "infobyid" in path
            ):
                response["id"] = "ff" * 32
        if evidence == "wrong_network" and url == first and body.get("num") == 0:
            response["blockID"] = "ff" * 32
        return response

    with patch.object(RequestsTransport, "post", side_effect=post):
        if evidence in {"conflicting", "partial_conflict", "wrong_network"}:
            with pytest.raises(ValueError):
                reconcile_attempt(c.attempt.pk)
            c.attempt.refresh_from_db()
            result = c.attempt
        else:
            result = reconcile_attempt(c.attempt.pk)
    settled = evidence in {"lagging", "missing_receipt", "missing_transaction"}
    if settled:
        assert result.status == "CONFIRMED" and second in queried
    elif evidence == "absent":
        assert result.status == "BROADCASTED" and second in queried
        assert result.confirmation_metadata["outcome"] == "UNKNOWN"
    else:
        assert result.status == "RECONCILIATION_REQUIRED"
        assert second not in queried
    assert len(c.rpc.submissions) == MpcSigningSession.objects.count() == 1
    assert not LedgerTransaction.objects.filter(
        event_key=f"withdrawal:{c.withdrawal.pk}:release"
    ).exists()
    assert LedgerTransaction.objects.filter(
        event_key=f"withdrawal:{c.withdrawal.pk}:settle"
    ).count() == int(settled)


@pytest.mark.django_db
@pytest.mark.parametrize("token", [False, True])
def test_evm_trigger_preserves_unresolved_sweep(db, monkeypatch, settings, token):
    from django.utils import timezone
    from ops.models import Chain

    from custody.token_metadata import metadata_fingerprint

    settings.CUSTODY_TX_MODE = "live"
    Chain.objects.filter(chain_id="ETH").update(
        gas_settings={"max_gas_limit": 100000, "max_fee_per_gas": 10000000000}
    )
    asset_key = "USDT-ETH" if token else "ETH"
    asset = Asset.objects.get(asset_key=asset_key)
    asset.enabled = asset.sweep_supported = True
    if token:
        asset.token_standard = "ERC20"
        asset.contract_address = "0x" + "a" * 40
        asset.decimals = 6
        asset.metadata_verified_at = timezone.now()
        asset.metadata_fingerprint = metadata_fingerprint(asset)
    Asset.objects.filter(pk=asset.pk).update(
        enabled=True,
        sweep_supported=True,
        token_standard=asset.token_standard,
        contract_address=asset.contract_address,
        decimals=asset.decimals,
        metadata_verified_at=asset.metadata_verified_at,
        metadata_fingerprint=asset.metadata_fingerprint,
    )
    wallet = UserWallet.objects.create(
        user_id="evm-sweep-recovery",
        chain_id="ETH",
        asset_key=asset_key,
        deposit_address="0x" + "3" * 40,
        derivation_path="m/test",
    )
    HotWallet.objects.update_or_create(chain_id="ETH", defaults={"address": "0x" + "4" * 40})
    monkeypatch.setattr(
        "custody.sweeper.get_indexer",
        lambda chain: SimpleNamespace(get_balance=lambda *a, **kw: BalanceResult(Decimal(2))),
    )

    def accepted_then_error(pk, actor):
        OnchainTransactionAttempt.objects.filter(pk=pk).update(status="RECONCILIATION_REQUIRED")
        raise requests.HTTPError("accepted EVM sweep, response lost")

    with patch("custody.outbound.execute_attempt", side_effect=accepted_then_error) as execute:
        with pytest.raises(requests.HTTPError):
            trigger_sweep(wallet, "system:sweep", BalanceResult(Decimal(2)))
        job = SweepJob.objects.get(user_wallet=wallet)
        assert job.status == "RECONCILIATION_REQUIRED" and job.completed_at is None
        assert trigger_sweep(wallet, "system:sweep", BalanceResult(Decimal(2)))[1] == job.pk
        assert execute.call_count == 1
    assert SweepJob.objects.count() == OnchainTransactionAttempt.objects.count() == 1
