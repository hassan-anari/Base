"""Real CGGMP services + pinned java-tron, PostgreSQL and genuine TVM execution.

No mocked signing, RPC evidence, chain inclusion or balance. Fault injection only
loses responses or stops processes after actual durable/chain effects.
"""

import hashlib
import json
import os
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

import pytest
import requests
from custody.deposits import ingest_event
from custody.gas_station import execute_gas_intent
from custody.indexer.trx import TrxIndexer
from custody.ledger import ensure_accounts, post_transaction, user_balances
from custody.models import (
    Asset,
    Deposit,
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
from custody.mpc_identity import address_from_public_key
from custody.native_tx import AmbiguousBroadcast, RequestsTransport
from custody.outbound import execute_attempt
from custody.reconciliation import reconcile_attempt
from custody.sweeper import advance_sweep, trigger_sweep
from custody.token_metadata import verify_token_asset
from custody.withdrawals import approve, create_request, process_withdrawal
from django.db import close_old_connections, connection
from django.test import override_settings
from test_cggmp import binding, execute
from test_cggmp_aux import advance_aux, get_keyset
from test_network import settings_for
from tron.validator import Validator
from tronpy import Tron
from tronpy.contract import Contract
from tronpy.providers import HTTPProvider

CAPS = {
    "mpc_validity_seconds": 600,
    "max_bandwidth_bytes": 1000,
    "max_bandwidth_price_sun": 1000,
    "max_energy_price_sun": 500,
    "max_energy_units": 100000,
    "max_trc20_fee_limit": 50000000,
    "max_total_fee_sun": 51000000,
    "topup_amount": "60",
    "token_initial_lookback_blocks": 20,
    "token_reorg_overlap_blocks": 1,
    "token_log_chunk_blocks": 100,
}
ROOT = Path(__file__).parent


def imported_keyset(context, state):
    return MpcKeyset.objects.create(
        keyset_id=context["keyset_id"],
        algorithm="CGGMP24_ECDSA",
        curve="secp256k1",
        scope="TRON",
        threshold=2,
        party_count=3,
        derivation_version="cggmp_hd_v1",
        status="ACTIVE",
        participant_identities=context["participants"],
        public_key=state["group_public_key"],
        dkg_execution_id=context["execution_id"],
        dkg_result_fingerprint=state["result_fingerprint"],
    )


def wait_signed(attempt):
    deadline = time.monotonic() + 210
    while time.monotonic() < deadline:
        attempt.refresh_from_db()
        if attempt.status == "SIGNED":
            return attempt
        assert attempt.status in {"SIGNING", "RECONCILIATION_REQUIRED"}, (
            attempt.status,
            attempt.error_code,
        )
        execute_attempt(attempt.pk, "system:mpc_advancement")
        time.sleep(0.1)
    pytest.fail("real TRON signing did not complete within prepared validity")


def fund_ledger(user, asset):
    ensure_accounts(user, asset)
    available = LedgerAccount.objects.get(owner_id=user, asset_key=asset, bucket="AVAILABLE")
    clearing = LedgerAccount.objects.get(
        owner_type="SYSTEM", asset_key=asset, bucket="CUSTODY_CLEARING"
    )
    post_transaction(
        event_key=f"tron-acceptance:{user}:{asset}",
        event_type="TEST_FUNDING",
        asset_key=asset,
        ref_type="Acceptance",
        ref_id=user,
        postings=[(available, Decimal(100)), (clearing, Decimal(-100))],
    )


def withdrawal(asset, destination, amount, suffix):
    user = "tron-acceptance-" + suffix
    fund_ledger(user, asset)
    operation = create_request(
        user, "TRX", destination, amount, asset_key=asset, idempotency_key=user
    )
    approve("acceptance-reviewer", operation.pk)
    process_withdrawal("acceptance-reviewer", operation.pk)
    return operation, OnchainTransactionAttempt.objects.get(
        operation_type="WITHDRAWAL", operation_id=operation.pk
    )


def settle(validator, attempt):
    validator.wait_info(attempt.network_tx_id)
    result = reconcile_attempt(attempt.pk)
    assert result.status == "CONFIRMED", result.confirmation_metadata
    assert reconcile_attempt(attempt.pk).status == "CONFIRMED"
    assert result.confirmation_metadata["solidified"] is True
    return result


def signing_evidence(attempt):
    assert MpcSigningSession.objects.filter(attempt=attempt).count() == 1
    completed = MpcSigningSession.objects.select_related("keyset").get(attempt=attempt)
    assert completed.status == "COMPLETED" and completed.signature_consumed_at
    return {
        "txid": attempt.network_tx_id,
        "session_id": str(completed.session_id),
        "execution_id": str(completed.crypto_execution_id),
        "selected_signers": completed.selected_signers,
        "public_key": completed.keyset.public_key,
        "signed_payload_sha256": hashlib.sha256(attempt.signed_payload.encode()).hexdigest(),
    }


def run_tron_acceptance(net, tmp_path, *, deposit_metadata=None):
    assert connection.vendor == "postgresql"
    hot_keyset = imported_keyset(net.aux_context, net.aux_state)
    hot = address_from_public_key("TRX", hot_keyset.public_key)
    # A second independently generated root proves deposit ownership; no child derivation.
    if deposit_metadata is None:
        context = binding("TRON")
        execute(net, context)
        assert advance_aux(net, context)[0] == 200
        started = time.monotonic()
        while time.monotonic() - started < 1815:
            state = get_keyset(net, context)
            if state["auxiliary"]["status"] != "IN_PROGRESS":
                break
            time.sleep(1)
    else:
        # Local fixture recovery only: restart persisted independent signer services.
        # Reuses DKG/auxiliary artifacts, never a replacement signing execution.
        context, state = deposit_metadata
    assert state["auxiliary"]["status"] == "AUXILIARY_COMPLETED", state["auxiliary"]["status"]
    deposit_keyset = imported_keyset(context, state)
    deposit = address_from_public_key("TRX", deposit_keyset.public_key)
    validator = Validator(tmp_path / "validator", [(hot, 10000000000), (deposit, 0)])
    evidence = {
        "validator_release": "GreatVoyage-v4.8.2.3",
        "network": validator.policy,
        "keysets": [str(hot_keyset.keyset_id), str(deposit_keyset.keyset_id)],
        "transactions": [],
    }
    try:
        with (
            settings_for(net),
            patch.dict(os.environ, {"CUSTODY_INDEXER_MODE": "live"}),
            override_settings(
                MPC_SIGNER_BACKEND="self_hosted_mpc",
                MPC_EVM_INTEGRATION_ENABLED=False,
                MPC_TRON_INTEGRATION_ENABLED=True,
                MPC_TRON_NETWORK=validator.policy,
                MPC_INTEGRATION_ENVIRONMENT="development",
                CUSTODY_DEMO_MODE=False,
                CUSTODY_TX_MODE="live",
                CUSTODY_INDEXER_MODE="live",
            ),
        ):
            setup_chain(hot_keyset, hot, validator.url)
            provider = HTTPProvider(validator.url)
            provider.sess.trust_env = False
            client = Tron(provider=provider)
            token_output = tmp_path / "token.json"
            subprocess.run(["node", str(ROOT / "tron/compile.cjs"), str(token_output)], check=True)
            token_info = json.loads(token_output.read_text())
            contract = Contract(
                name="AcceptanceToken", bytecode=token_info["bytecode"], abi=token_info["abi"]
            )
            # Append the ABI constructor holder before creating any deployment digest.
            from custody.tron_wire import address_bytes

            contract.bytecode = bytes.fromhex(
                token_info["bytecode"] + address_bytes(hot)[1:].hex().rjust(64, "0")
            )
            deployment = (
                client.trx.deploy_contract(validator.faucet_address, contract)
                .fee_limit(100000000)
                .build()
            )
            signed_deployment = deployment.sign(validator.faucet)
            assert signed_deployment.broadcast()["result"] is True
            deployed = validator.wait_info(signed_deployment.txid)
            import base58

            token_address = base58.b58encode_check(
                bytes.fromhex(deployed["contract_address"])
            ).decode()
            asset = Asset.objects.create(
                asset_key="ACCEPT-TRON",
                chain_id="TRX",
                symbol="REVIEWED",
                decimals=6,
                is_native=False,
                token_standard="TRC20",
                contract_address=token_address,
                enabled=True,
                withdrawal_supported=True,
                sweep_supported=True,
            )
            verify_token_asset(asset.asset_key)

            net.stop("signer-a")
            try:
                # Native withdrawal; real B+C signatures, persisted before RPC submission.
                operation, native = withdrawal("TRX", deposit, Decimal("20"), "native")
                native = wait_signed(native)
                assert MpcSigningSession.objects.get(attempt=native).selected_signers == [
                    "signer-b",
                    "signer-c",
                ]
                execute_attempt(native.pk, "worker")
                native = settle(validator, native)
                evidence["transactions"].append(
                    {
                        "operation": "native_withdrawal",
                        "txid": native.network_tx_id,
                        "confirmation": native.confirmation_metadata,
                    }
                )
                assert user_balances(operation.user_id, "TRX")["reserved"] == 0

                # Genuine owned deposit sweep back into treasury, with a separate DKG root.
                native_wallet = UserWallet.objects.create(
                    user_id="tron-deposit",
                    chain_id="TRX",
                    asset_key="TRX",
                    deposit_address=deposit,
                    derivation_path=f"keyset:{deposit_keyset.keyset_id}",
                    derivation_version="mpc_root_v1",
                    mpc_keyset=deposit_keyset,
                )
                balance = TrxIndexer().get_balance(deposit, asset_key="TRX")
                assert balance.confirmed_balance == Decimal("20")
                assert any(
                    event.tx_hash == native.network_tx_id for event in balance.deposit_events
                )
                triggered, job_id, reason = trigger_sweep(native_wallet, "acceptance", balance)
                assert triggered, reason
                job = SweepJob.objects.get(pk=job_id)
                native_deposit = Deposit.objects.get(
                    user_wallet=native_wallet, tx_hash=native.network_tx_id
                )
                for event in balance.deposit_events:
                    ingest_event(native_wallet, event)
                assert native_deposit.status == "CONFIRMED"
                assert (
                    LedgerTransaction.objects.filter(
                        event_key=f"deposit:{native_deposit.pk}:credit"
                    ).count()
                    == 1
                )
                assert user_balances(native_wallet.user_id, "TRX")["available"] == Decimal("20")
                sweep = wait_signed(
                    OnchainTransactionAttempt.objects.get(
                        operation_type="SWEEP", operation_id=job.pk
                    )
                )
                execute_attempt(sweep.pk, "worker")
                sweep = settle(validator, sweep)
                evidence["transactions"].append(
                    {
                        "operation": "native_sweep",
                        "txid": sweep.network_tx_id,
                        "confirmation": sweep.confirmation_metadata,
                    }
                )

                # TRC20 withdrawal completion survives coordinator and signer restarts.
                operation, token = withdrawal(asset.asset_key, deposit, Decimal("1.25"), "token")
                session = MpcSigningSession.objects.get(attempt=token)
                execution = session.crypto_execution_id
                deadline = time.monotonic() + 210
                with patch(
                    "custody.mpc_signing._consume_completed",
                    side_effect=RuntimeError("injected worker death after durable completion"),
                ):
                    while time.monotonic() < deadline:
                        try:
                            execute_attempt(token.pk, "worker")
                        except RuntimeError:
                            break
                        time.sleep(0.1)
                    else:
                        pytest.fail("TRC20 MPC completion unavailable")
                session.refresh_from_db()
                assert session.status == "COMPLETED" and session.signature_consumed_at is None
                for role in ("coordinator", "signer-b", "signer-c"):
                    net.stop(role)
                    net.start(role)
                token = wait_signed(token)
                original = RequestsTransport.post
                calls = []

                def lost_response(transport, url, path, body):
                    result = original(transport, url, path, body)
                    if path == "/wallet/broadcasttransaction":
                        calls.append(body)
                        raise requests.Timeout(
                            "response lost after real java-tron accepted transaction"
                        )
                    return result

                with patch.object(RequestsTransport, "post", lost_response):
                    with pytest.raises(AmbiguousBroadcast):
                        execute_attempt(token.pk, "worker")
                    assert execute_attempt(token.pk, "worker").status == "RECONCILIATION_REQUIRED"
                assert len(calls) == 1
                assert user_balances(operation.user_id, asset.asset_key)["reserved"] == Decimal(
                    "1.25"
                )
                token = settle(validator, token)
                session.refresh_from_db()
                assert session.crypto_execution_id == execution
                assert MpcSigningSession.objects.filter(attempt=token).count() == 1
                assert (
                    LedgerTransaction.objects.filter(
                        event_key=f"withdrawal:{operation.pk}:settle"
                    ).count()
                    == 1
                )
                evidence["transactions"].append(
                    {
                        "operation": "token_withdrawal_lost_response",
                        "txid": token.network_tx_id,
                        "crypto_execution_id": str(execution),
                        "confirmation": token.confirmation_metadata,
                    }
                )

                # Real TRX resource funding is confirmed before the deposit token sweep.
                wallet = UserWallet.objects.create(
                    user_id="tron-deposit",
                    chain_id="TRX",
                    asset_key=asset.asset_key,
                    deposit_address=deposit,
                    derivation_path=f"keyset:{deposit_keyset.keyset_id}",
                    derivation_version="mpc_root_v1",
                    mpc_keyset=deposit_keyset,
                )
                balance = TrxIndexer().get_balance(deposit, asset_key=asset.asset_key)
                assert balance.confirmed_balance == Decimal("1.25")
                assert any(event.tx_hash == token.network_tx_id for event in balance.deposit_events)
                triggered, job_id, reason = trigger_sweep(wallet, "acceptance", balance)
                assert triggered, reason
                job = SweepJob.objects.get(pk=job_id)
                token_deposit = Deposit.objects.get(user_wallet=wallet, tx_hash=token.network_tx_id)
                for event in balance.deposit_events:
                    ingest_event(wallet, event)
                assert token_deposit.status == "CONFIRMED"
                assert (
                    LedgerTransaction.objects.filter(
                        event_key=f"deposit:{token_deposit.pk}:credit"
                    ).count()
                    == 1
                )
                assert user_balances(wallet.user_id, asset.asset_key)["available"] == Decimal(
                    "1.25"
                )
                assert job.gas_topup_intent_id
                gas = wait_signed(
                    OnchainTransactionAttempt.objects.get(
                        operation_type="GAS_TOPUP", operation_id=job.gas_topup_intent_id
                    )
                )
                execute_attempt(gas.pk, "worker")
                gas = settle(validator, gas)
                assert GasTopupIntent.objects.get(pk=job.gas_topup_intent_id).status == "CONFIRMED"
                execute_gas_intent(job.gas_topup_intent_id)
                evidence["transactions"].append(
                    {
                        "operation": "gas_topup",
                        "txid": gas.network_tx_id,
                        "confirmation": gas.confirmation_metadata,
                    }
                )
                advance_sweep(job.pk)
                token_sweep = wait_signed(
                    OnchainTransactionAttempt.objects.get(
                        operation_type="SWEEP", operation_id=job.pk
                    )
                )

                # Two workers, one physical broadcast; PostgreSQL session ownership.
                calls, entered, release = [], threading.Event(), threading.Event()

                def counted(transport, url, path, body):
                    if path == "/wallet/broadcasttransaction":
                        calls.append(body)
                        entered.set()
                        assert release.wait(10)
                    return original(transport, url, path, body)

                def worker():
                    close_old_connections()
                    try:
                        return execute_attempt(token_sweep.pk, "worker").status
                    finally:
                        close_old_connections()

                with (
                    patch.object(RequestsTransport, "post", counted),
                    ThreadPoolExecutor(max_workers=2) as pool,
                ):
                    first = pool.submit(worker)
                    assert entered.wait(10)
                    assert pool.submit(worker).result(timeout=10) == "BROADCASTING"
                    release.set()
                    assert first.result(timeout=10) == "BROADCASTED"
                assert calls == [json.loads(token_sweep.signed_payload)]
                token_sweep = settle(validator, token_sweep)
                assert (
                    TrxIndexer().get_balance(deposit, asset_key=asset.asset_key).confirmed_balance
                    == 0
                )
                evidence["transactions"].append(
                    {
                        "operation": "token_sweep",
                        "txid": token_sweep.network_tx_id,
                        "confirmation": token_sweep.confirmation_metadata,
                    }
                )
                net.stop("signer-c")
                try:
                    _, unavailable = withdrawal("TRX", deposit, Decimal("0.1"), "unavailable")
                    deadline = time.monotonic() + 30
                    while time.monotonic() < deadline:
                        unavailable = execute_attempt(unavailable.pk, "worker")
                        if unavailable.status == "RECONCILIATION_REQUIRED":
                            break
                        time.sleep(0.1)
                    assert (
                        unavailable.status == "RECONCILIATION_REQUIRED"
                        and not unavailable.signed_payload
                    )
                    assert MpcSigningSession.objects.filter(attempt=unavailable).count() == 1
                finally:
                    net.start("signer-c")
                evidence["deposits"] = [
                    {
                        "txid": native_deposit.tx_hash,
                        "status": native_deposit.status,
                        "asset": "TRX",
                        "ledger_credit_count": 1,
                    },
                    {
                        "txid": token_deposit.tx_hash,
                        "status": token_deposit.status,
                        "asset": asset.asset_key,
                        "ledger_credit_count": 1,
                    },
                ]
                evidence["signing"] = [
                    signing_evidence(item) for item in (native, sweep, token, gas, token_sweep)
                ]
            finally:
                net.start("signer-a")
    finally:
        validator.close()
        (tmp_path / "tron-evidence.json").write_text(json.dumps(evidence, indent=2))
    print("REAL_TRON_ACCEPTANCE", json.dumps(evidence, sort_keys=True))


def setup_chain(keyset, hot, url):
    from ops.models import Chain, NodeEndpoint

    Chain.objects.filter(chain_id="TRX").update(
        kind="tron",
        is_testnet=True,
        enabled=True,
        evm_chain_id=None,
        native_asset_key="TRX",
        min_confirmations=1,
        sweep_threshold=Decimal("0.001"),
        gas_settings=CAPS,
    )
    Asset.objects.filter(asset_key="TRX").update(
        decimals=6, enabled=True, withdrawal_supported=True, sweep_supported=True
    )
    NodeEndpoint.objects.filter(chain_id="TRX", kind="rpc").update(enabled=False)
    NodeEndpoint.objects.create(
        chain_id="TRX", name="phase6f-real-validator", kind="rpc", url=url, enabled=True
    )
    HotWallet.objects.update_or_create(
        chain_id="TRX",
        defaults={
            "address": hot,
            "mpc_keyset": keyset,
            "signing_key_ref": f"keyset:{keyset.keyset_id}",
        },
    )
