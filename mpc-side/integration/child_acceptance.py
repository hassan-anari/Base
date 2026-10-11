"""Genuine child-source EVM execution, PostgreSQL recovery and actual issuance costs."""

import copy
import json
import os
import platform
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from unittest.mock import patch

import pytest
import requests
from custody import mpc_issuance
from custody.deposits import ingest_event
from custody.indexer.evm import EvmIndexer
from custody.ledger import user_balances
from custody.models import (
    Asset,
    Deposit,
    GasTopupIntent,
    HotWallet,
    LedgerPosting,
    LedgerTransaction,
    MpcCustodyAccount,
    MpcKeyset,
    MpcSigningSession,
    OnchainTransactionAttempt,
    SweepJob,
)
from custody.mpc_hd import child_reference
from custody.mpc_identity import address_from_public_key
from custody.mpc_issuance import attach_account_asset, attest_original_hd, issue_customer_account
from custody.mpc_provisioning import register_provisioning_root, reserve_derivation_path
from custody.native_tx import AmbiguousBroadcast, RequestsTransport
from custody.outbound import execute_attempt
from custody.reconciliation import reconcile_attempt
from custody.signer_adapter import SelfHostedMpcAdapter
from custody.sweeper import advance_sweep, trigger_sweep
from custody.token_metadata import verify_token_asset
from django.db import close_old_connections, connection
from django.test import override_settings
from evm_acceptance import CAPS, EVM, LocalChain, wait_signed
from ops.models import Chain, NodeEndpoint
from test_cggmp import binding, execute
from test_cggmp_aux import (
    advance_aux,
    advance_sign,
    get_keyset,
    sign_state,
    signing_request,
    wait_sign,
)
from test_dkg import request as authenticated_request
from test_network import settings_for


def hostile_child_cases(net, root, accounts):
    """Actual authenticated services reject replay and recover partial approvals."""
    child = accounts[0].evidence["child"]
    scope = child["request"]["root"]["request"]["scope"]
    url = f"/v1/keysets/{root.keyset.keyset_id}"
    assert (
        authenticated_request(net, "coordinator", "signer-a", url + "/hd-attestation", scope)[0]
        == 403
    )
    assert (
        authenticated_request(
            net, "signer-a", "custody", "/internal/v1/cggmp/hd/child", child["request"]
        )[0]
        == 403
    )
    for change in ("chain", "owner", "chain_code", "hardened", "public", "root"):
        altered = copy.deepcopy(child)
        if change == "chain":
            altered["request"]["root"]["request"]["scope"]["chain_id"] = "BSC"
        elif change == "owner":
            altered["request"]["customer_ref"] = "intruder"
        elif change == "chain_code":
            altered["request"]["root"]["chain_code"] = "12" * 32
        elif change == "hardened":
            altered["request"]["derivation_path"] += "'"
        elif change == "public":
            altered["public_key"] = root.keyset.public_key
        else:
            altered = copy.deepcopy(accounts[1].evidence["child"])
            altered["request"]["reservation_id"] = child["request"]["reservation_id"]
        signing = signing_request(net)
        signing.update(
            child_authorization=altered,
            expected_source=accounts[0].address,
            derivation_reference=child_reference(child),
        )
        assert (
            authenticated_request(net, "coordinator", "custody", "/v1/sign-sessions", signing)[0]
            == 400
        )
    # All three stores must approve issuance. First two partial writes survive
    # a missing third store; the exact original DB reservation recovers on retry.
    net.stop("signer-c")
    try:
        with pytest.raises(requests.HTTPError):
            issue_customer_account(
                keyset_id=root.keyset.keyset_id,
                ownership_scope=root.ownership_scope,
                customer_ref="quorum-recovery",
                idempotency_key="quorum-recovery",
            )
        pending = MpcCustodyAccount.objects.get(customer_ref="quorum-recovery")
        assert pending.status == "PROVISIONING"
    finally:
        net.start("signer-c")
    recovered = issue_customer_account(
        keyset_id=root.keyset.keyset_id,
        ownership_scope=root.ownership_scope,
        customer_ref="quorum-recovery",
        idempotency_key="quorum-recovery",
    )
    assert recovered.pk == pending.pk and recovered.status == "ISSUED"
    signing = signing_request(net)
    signing.update(
        child_authorization=child,
        expected_source=accounts[0].address,
        derivation_reference=child_reference(child),
    )
    assert (
        authenticated_request(net, "coordinator", "custody", "/v1/sign-sessions", signing)[0] == 200
    )
    initial = sign_state(net, signing)
    net.stop("signer-b")
    net.stop("signer-c")
    try:
        assert advance_sign(net, signing)[0] == 200
        current = wait_sign(net, signing)
        assert current["status"] == "RECONCILIATION_REQUIRED"
        assert current["crypto_execution_id"] == initial["crypto_execution_id"]
        assert advance_sign(net, signing)[0] == 409
        assert not (
            net.root / "signer-a" / "storage" / "cggmp-signing" / f"{signing['session_id']}.json"
        ).exists()
    finally:
        net.start("signer-b")
        net.start("signer-c")


def keyset(context, state, scope="EVM"):
    return MpcKeyset.objects.create(
        keyset_id=context["keyset_id"],
        algorithm="CGGMP24_ECDSA",
        curve="secp256k1",
        scope=scope,
        derivation_version="cggmp_hd_v1",
        status="ACTIVE",
        participant_identities=context["participants"],
        public_key=state["group_public_key"],
        dkg_execution_id=context["execution_id"],
        dkg_result_fingerprint=state["result_fingerprint"],
    )


def new_root(net):
    context = binding()
    execute(net, context)
    assert advance_aux(net, context)[0] == 200
    deadline = time.monotonic() + 1815
    while time.monotonic() < deadline:
        state = get_keyset(net, context)
        if state["auxiliary"]["status"] != "IN_PROGRESS":
            assert state["auxiliary"]["status"] == "AUXILIARY_COMPLETED"
            return keyset(context, state)
        time.sleep(1)
    pytest.fail("independent hot root setup exceeded auxiliary deadline")


def mine(chain):
    for _ in range(3):
        chain.rpc("evm_mine", [])


def settle(chain, attempt):
    mine(chain)
    result = reconcile_attempt(attempt.pk)
    assert result.status == "CONFIRMED", result.confirmation_metadata
    assert reconcile_attempt(attempt.pk).status == "CONFIRMED"
    return result


def sweep_attempt(wallet, balance):
    triggered, job_id, reason = trigger_sweep(wallet, "phase6gb-acceptance", balance)
    assert triggered, reason
    return SweepJob.objects.get(pk=job_id)


def record(attempt, child=None):
    session = MpcSigningSession.objects.get(attempt=attempt)
    assert session.status == "COMPLETED" and session.signature_consumed_at
    if child:
        assert attempt.from_address.lower() == child.address
        assert session.transaction_identity["public_key"] == child.public_key
        assert session.transaction_identity["root_public_key"] != child.public_key
        assert session.transaction_identity["child_authorization"] == child.evidence["child"]
    return {
        "txid": attempt.network_tx_id,
        "source": attempt.from_address,
        "signing_public_key": session.transaction_identity["public_key"],
        "session_id": str(session.session_id),
        "execution_id": str(session.crypto_execution_id),
        "selected_signers": session.selected_signers,
        "confirmation": attempt.confirmation_metadata,
    }


def benchmark(root, tmp_path):
    count = int(os.environ.get("PHASE6GB_BENCHMARK_COUNT", "1000"))
    assert 100 <= count <= 100000
    workers = 8
    timings = []
    phases = {
        "reservation": [],
        "independent_public_verification": [],
        "persistent_issue_save": [],
        "postgres_queries": [],
        "postgres_select_for_update": [],
        "asset_view": [],
    }

    def measured(name, fn):
        def wrapped(*args, **kwargs):
            start = time.perf_counter()
            try:
                return fn(*args, **kwargs)
            finally:
                phases[name].append(time.perf_counter() - start)

        return wrapped

    def sql_measure(execute, sql, params, many, context):
        start = time.perf_counter()
        try:
            return execute(sql, params, many, context)
        finally:
            elapsed = time.perf_counter() - start
            phases["postgres_queries"].append(elapsed)
            if "FOR UPDATE" in sql:
                phases["postgres_select_for_update"].append(elapsed)

    class Measured(SelfHostedMpcAdapter):
        def approve_child(self, keyset_id, request):
            start = time.perf_counter()
            result = super().approve_child(keyset_id, request)
            timings.append(time.perf_counter() - start)
            return result

    def worker(i):
        close_old_connections()
        try:
            with connection.execute_wrapper(sql_measure):
                account = issue_customer_account(
                    keyset_id=root.keyset.keyset_id,
                    ownership_scope=root.ownership_scope,
                    customer_ref=f"benchmark-{i}",
                    idempotency_key=f"benchmark-{i}",
                    client=Measured(),
                )
                started = time.perf_counter()
                attach_account_asset(
                    account_id=account.pk,
                    customer_ref=account.customer_ref,
                    ownership_scope=account.ownership_scope,
                    asset_key="ETH",
                )
                phases["asset_view"].append(time.perf_counter() - started)
                return account.pk
        finally:
            close_old_connections()

    start = time.perf_counter()
    with (
        patch.object(
            mpc_issuance,
            "reserve_derivation_path",
            measured("reservation", reserve_derivation_path),
        ),
        patch.object(
            mpc_issuance,
            "verify_child_evidence",
            measured("independent_public_verification", mpc_issuance.verify_child_evidence),
        ),
        patch.object(
            MpcCustodyAccount, "save", measured("persistent_issue_save", MpcCustodyAccount.save)
        ),
        ThreadPoolExecutor(max_workers=workers) as pool,
    ):
        accounts = list(pool.map(worker, range(count)))
    seconds = time.perf_counter() - start
    assert len(set(accounts)) == count
    assert MpcCustodyAccount.objects.filter(pk__in=accounts, status="ISSUED").count() == count
    retry = time.perf_counter()
    close_old_connections()
    assert worker(0) == accounts[0]
    recovery = time.perf_counter() - retry
    with connection.cursor() as cursor:
        cursor.execute("SHOW server_version")
        postgres = cursor.fetchone()[0]
        cursor.execute("SELECT pg_total_relation_size('custody_mpccustodyaccount')")
        size = cursor.fetchone()[0]
    evidence = {
        "kind": "real-three-store-verified-persistent-child-issuance",
        "customers": count,
        "workers": workers,
        "seconds": seconds,
        "issued_accounts_per_second": count / seconds,
        "authenticated_child_requests": len(timings),
        "coordinator_request_seconds_sum": sum(timings),
        "coordinator_request_seconds_mean": sum(timings) / len(timings),
        "reconnected_idempotent_issuance_seconds": recovery,
        "account_table_and_index_bytes": size,
        "postgres_version": postgres,
        "cpu": platform.processor(),
        "logical_cpus": os.cpu_count(),
        "machine": platform.machine(),
        "platform": platform.platform(),
        "root": str(root.keyset.keyset_id),
        "issued_asset_views_during_benchmark": count,
        "signatures_during_issuance": 0,
        "signing_latency": "measured separately on chain sweeps",
        "phase_latency_seconds": {
            name: {
                "samples": len(values),
                "sum": sum(values),
                "mean": sum(values) / len(values),
                "max": max(values),
            }
            for name, values in phases.items()
        },
        "reservation_operations_per_second_during_full_issuance": count / seconds,
        "postgres_contention_measure": (
            "FOR UPDATE query latency includes lock waiting; not isolated wait-time attribution"
        ),
    }
    (tmp_path / "child-issuance-benchmark.json").write_text(json.dumps(evidence, indent=2))
    print("PHASE6GB_BENCHMARK " + json.dumps(evidence, sort_keys=True))
    return evidence


def run_evm_child_acceptance(net, tmp_path):
    assert connection.vendor == "postgresql"
    root_keyset = keyset(net.aux_context, net.aux_state)
    hot_keyset = new_root(net)
    hot = address_from_public_key("ETH", hot_keyset.public_key)
    chain = LocalChain("shanghai", 31337)
    evidence = {"root_public_key": root_keyset.public_key, "transactions": []}
    try:
        genesis = chain.rpc("eth_getBlockByNumber", ["0x0", False])["hash"]
        Chain.objects.filter(chain_id="ETH").update(
            kind="evm",
            is_testnet=True,
            enabled=True,
            evm_chain_id=31337,
            min_confirmations=2,
            gas_settings={**CAPS, "topup_amount": "0.03"},
        )
        Asset.objects.filter(asset_key="ETH").update(
            enabled=True, sweep_supported=True, withdrawal_supported=True
        )
        NodeEndpoint.objects.filter(chain_id="ETH", kind="rpc").update(enabled=False)
        NodeEndpoint.objects.create(
            chain_id="ETH",
            name="phase6gb",
            kind="rpc",
            url=chain.url,
            enabled=True,
            is_primary=True,
        )
        HotWallet.objects.update_or_create(
            chain_id="ETH",
            defaults={
                "address": hot,
                "mpc_keyset": hot_keyset,
                "signing_key_ref": f"keyset:{hot_keyset.keyset_id}",
            },
        )
        with (
            settings_for(net),
            patch.dict(os.environ, {"CUSTODY_INDEXER_MODE": "live"}),
            override_settings(
                MPC_SIGNER_BACKEND="self_hosted_mpc",
                MPC_EVM_INTEGRATION_ENABLED=True,
                MPC_INTEGRATION_ENVIRONMENT="development",
                MPC_EVM_DEVELOPMENT_CHAINS={"ETH": 31337},
                MPC_EVM_GENESIS_HASHES={"ETH": genesis},
                CUSTODY_DEMO_MODE=False,
                CUSTODY_TX_MODE="live",
                CUSTODY_INDEXER_MODE="live",
            ),
        ):
            root = register_provisioning_root(
                keyset_id=root_keyset.keyset_id, chain_id="ETH", ownership_scope="phase6gb-evm"
            )
            attest_original_hd(
                keyset_id=root_keyset.keyset_id, ownership_scope=root.ownership_scope
            )

            def issue(i):
                return issue_customer_account(
                    keyset_id=root_keyset.keyset_id,
                    ownership_scope=root.ownership_scope,
                    customer_ref=f"evm-child-{i}",
                    idempotency_key=f"child-{i}",
                )

            accounts = [issue(i) for i in range(3)]
            assert len({a.address for a in accounts}) == 3
            assert all(a.public_key != root_keyset.public_key for a in accounts)
            hostile_child_cases(net, root, accounts)
            for role in ("coordinator", "signer-a", "signer-b", "signer-c"):
                net.stop(role)
                net.start(role)
            connection.close()
            assert issue(0).pk == accounts[0].pk
            account = accounts[0]
            wallet = attach_account_asset(
                account_id=account.pk,
                customer_ref=account.customer_ref,
                ownership_scope=account.ownership_scope,
                asset_key="ETH",
            )
            # Faucet signs only inbound fixture funding and token deployment.
            faucet = chain.rpc("eth_accounts", [])[0]
            chain.rpc("eth_sendTransaction", [{"from": faucet, "to": hot, "value": hex(10**19)}])
            deposit_hash = chain.rpc(
                "eth_sendTransaction",
                [{"from": faucet, "to": account.address, "value": hex(10**17)}],
            )
            mine(chain)
            balance = EvmIndexer("ETH").get_balance(account.address, asset_key="ETH")
            assert balance.scan_complete
            assert any(event.tx_hash == deposit_hash for event in balance.deposit_events)
            net.stop("signer-a")
            started = time.perf_counter()
            job = sweep_attempt(wallet, balance)
            deposit = Deposit.objects.get(user_wallet=wallet, tx_hash=deposit_hash)
            for event in balance.deposit_events:
                ingest_event(wallet, event)
            assert user_balances(wallet.user_id, "ETH")["available"] == Decimal("0.1")
            assert (
                LedgerTransaction.objects.filter(event_key=f"deposit:{deposit.pk}:credit").count()
                == 1
            )
            native = wait_signed(
                OnchainTransactionAttempt.objects.get(operation_type="SWEEP", operation_id=job.pk)
            )
            evidence["native_signing_seconds_including_prepare_and_dispatch"] = (
                time.perf_counter() - started
            )
            assert MpcSigningSession.objects.get(attempt=native).selected_signers == [
                "signer-b",
                "signer-c",
            ]
            signed = native.signed_payload
            net.stop("coordinator")
            net.start("coordinator")
            assert execute_attempt(native.pk, "worker").signed_payload == signed
            native = settle(chain, native)
            observed = chain.rpc("eth_getTransactionByHash", [native.network_tx_id])
            assert observed["from"].lower() == account.address
            evidence["transactions"].append(record(native, account))
            # Native sweep leaves insufficient conservative token gas; the MPC hot
            # root funds the SAME customer's canonical account, then the CHILD signs.
            bytecode = tmp_path / "token-bytecode"
            subprocess.run(["node", str(EVM / "compile.cjs"), str(bytecode)], check=True)
            deployment = chain.rpc(
                "eth_sendTransaction",
                [
                    {
                        "from": faucet,
                        "data": "0x" + bytecode.read_text() + faucet[2:].lower().rjust(64, "0"),
                        "gas": hex(1000000),
                    }
                ],
            )
            contract = chain.rpc("eth_getTransactionReceipt", [deployment])["contractAddress"]
            asset = Asset.objects.create(
                asset_key="CHILD-ERC20",
                chain_id="ETH",
                symbol="REVIEWED",
                decimals=6,
                is_native=False,
                token_standard="ERC20",
                contract_address=contract,
                enabled=True,
                withdrawal_supported=True,
                sweep_supported=True,
            )
            verify_token_asset(asset.asset_key)
            token_wallet = attach_account_asset(
                account_id=account.pk,
                customer_ref=account.customer_ref,
                ownership_scope=account.ownership_scope,
                asset_key=asset.asset_key,
            )
            assert token_wallet.custody_account_id == wallet.custody_account_id
            token_hash = chain.rpc(
                "eth_sendTransaction",
                [
                    {
                        "from": faucet,
                        "to": contract,
                        "data": "0xa9059cbb"
                        + account.address[2:].rjust(64, "0")
                        + (1250000).to_bytes(32, "big").hex(),
                        "gas": hex(100000),
                    }
                ],
            )
            mine(chain)
            balance = EvmIndexer("ETH").get_balance(account.address, asset_key=asset.asset_key)
            assert balance.scan_complete and balance.confirmed_balance == Decimal("1.25")
            token_job = sweep_attempt(token_wallet, balance)
            for event in balance.deposit_events:
                ingest_event(token_wallet, event)
            assert (
                Deposit.objects.get(user_wallet=token_wallet, tx_hash=token_hash).status
                == "CONFIRMED"
            )
            assert user_balances(wallet.user_id, asset.asset_key)["available"] == Decimal("1.25")
            assert token_job.gas_topup_intent_id
            gas = wait_signed(
                OnchainTransactionAttempt.objects.get(
                    operation_type="GAS_TOPUP", operation_id=token_job.gas_topup_intent_id
                )
            )
            execute_attempt(gas.pk, "worker")
            gas = settle(chain, gas)
            assert (
                GasTopupIntent.objects.get(pk=token_job.gas_topup_intent_id).status == "CONFIRMED"
            )
            evidence["transactions"].append(record(gas))
            native_history = EvmIndexer("ETH").get_balance(account.address, asset_key="ETH")
            assert native_history.scan_complete
            for event in native_history.deposit_events:
                ingest_event(wallet, event)
            assert user_balances(wallet.user_id, "ETH")["available"] == Decimal("0.1")
            advance_sweep(token_job.pk)
            started = time.perf_counter()
            token = wait_signed(
                OnchainTransactionAttempt.objects.get(
                    operation_type="SWEEP", operation_id=token_job.pk
                )
            )
            evidence["token_signing_seconds_after_dispatch"] = time.perf_counter() - started
            before = token.signed_payload
            original_rpc = RequestsTransport.rpc

            def lose_response(transport, url, method, params):
                result = original_rpc(transport, url, method, params)
                if method == "eth_sendRawTransaction":
                    raise requests.Timeout("lost response AFTER real child transaction acceptance")
                return result

            with (
                patch.object(RequestsTransport, "rpc", lose_response),
                pytest.raises(AmbiguousBroadcast),
            ):
                execute_attempt(token.pk, "worker")
            token.refresh_from_db()
            assert token.status == "RECONCILIATION_REQUIRED" and token.signed_payload == before
            assert execute_attempt(token.pk, "worker").status == "RECONCILIATION_REQUIRED"
            token = settle(chain, token)
            observed = chain.rpc("eth_getTransactionByHash", [token.network_tx_id])
            assert observed["from"].lower() == account.address
            evidence["transactions"].append(record(token, account))
            assert (
                EvmIndexer("ETH")
                .get_balance(account.address, asset_key=asset.asset_key)
                .confirmed_balance
                == 0
            )
            assert child_reference(account.evidence["child"]) == child_reference(
                issue(0).evidence["child"]
            )
            net.start("signer-a")
            evidence["benchmark"] = benchmark(root, tmp_path)
            for journal in LedgerTransaction.objects.all():
                assert (
                    sum(
                        LedgerPosting.objects.filter(transaction=journal).values_list(
                            "amount", flat=True
                        ),
                        Decimal(0),
                    )
                    == 0
                )
            evidence["child_accounts"] = [
                {
                    "account_id": str(a.pk),
                    "public_key": a.public_key,
                    "address": a.address,
                    "path": a.reservation.derivation_path,
                }
                for a in accounts
            ]
            (tmp_path / "evm-child-evidence.json").write_text(json.dumps(evidence, indent=2))
    finally:
        for role in ("coordinator", "signer-a", "signer-b", "signer-c"):
            if role not in net.running:
                net.start(role)
        chain.close()
