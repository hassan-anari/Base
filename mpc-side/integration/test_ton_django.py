"""Genuine Rust MPC, isolated validator proofs and PostgreSQL custody settlement."""

import json
import os
import subprocess
import time
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

import pytest
from custody.gas_station import execute_gas_intent, get_or_create_gas_intent
from custody.indexer_service import scan_wallet
from custody.ledger import user_balances
from custody.models import (
    Asset,
    HotWallet,
    LedgerPosting,
    LedgerTransaction,
    MpcKeyset,
    MpcSigningSession,
    OnchainTransactionAttempt,
    SweepJob,
    UserWallet,
)
from custody.native_tx import AmbiguousBroadcast
from custody.outbound import create_attempt, execute_attempt
from custody.reconciliation import reconcile_attempt
from custody.token_metadata import verify_token_asset
from custody.ton_tx import TonNativeExecutor
from custody.ton_wire import (
    JETTON_MASTER_CODE_HASH,
    JETTON_WALLET_CODE_HASH,
    jetton_wallet_address,
    wallet_address,
)
from custody.withdrawals import approve, create_request, process_withdrawal
from django.core.management import call_command
from django.db import connection
from django.test import override_settings
from environment import REPO, ROLES, Processes
from ops.models import Chain, NodeEndpoint
from test_dkg import dkg_request, execute
from test_network import settings_for
from ton.localnet import capture, fund


@pytest.mark.django_db(transaction=True)
def test_ton_postgresql_real_mpc_deposits_withdrawals_sweeps_gas_and_ambiguity(tmp_path):
    assert connection.vendor == "postgresql"
    container = os.environ.get("PHASE6FC_LOCALTON_CONTAINER", "phase6fc-localton")
    client = capture(container, tmp_path / "public-genesis")
    net = Processes(tmp_path / "private-mpc")
    admin = subprocess.Popen(
        ["node", str(Path(__file__).parent / "ton/admin.cjs")],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )

    def admin_call(action, **kwargs):
        admin.stdin.write(json.dumps(dict(action=action, **kwargs)) + "\n")
        admin.stdin.flush()
        r = json.loads(admin.stdout.readline())
        assert "error" not in r, r
        return r["result"]

    def wait_account(address, predicate):
        for _ in range(40):
            cp, block = client.checkpoint()
            state = client.account(address, cp)
            if predicate(state):
                return cp, block, state
            time.sleep(1)
        raise AssertionError("TON account proof effect unavailable")

    def submit_fixture(raw):
        p = tmp_path / "fixture-message.boc"
        p.write_bytes(bytes.fromhex(raw))
        client.command("sendfile " + str(p))

    def settle(attempt):
        for _ in range(40):
            result = reconcile_attempt(attempt.pk)
            if result.status == "CONFIRMED":
                assert reconcile_attempt(attempt.pk).status == "CONFIRMED"
                return result
            time.sleep(1)
        raise AssertionError((result.error_code, result.confirmation_metadata))

    def signed(attempt):
        for _ in range(20):
            attempt.refresh_from_db()
            if attempt.status == "SIGNED":
                return attempt
            assert attempt.status in {"SIGNING", "RECONCILIATION_REQUIRED"}, (
                attempt.status,
                attempt.error_code,
            )
            execute_attempt(attempt.pk, "ton-acceptance")
        raise AssertionError("TON genuine signature unavailable")

    def scan_complete(wallet):
        for _ in range(100):
            wallet.refresh_from_db()
            r = scan_wallet(wallet)
            assert r["outcome"] in {"backfill", "confirmed"}, r
            if r["outcome"] == "confirmed":
                return
        raise AssertionError("TON complete history backfill unavailable")

    evidence = {"category": "POSTGRES_MPC_ISOLATED_VALIDATOR", "transactions": []}
    try:
        for role in ROLES[:4]:
            net.start(role)
        bindings = []
        for _ in range(2):
            b = dkg_request()
            b["scope"] = "TON"
            status, dkg = execute(net, b)
            assert status == 200 and dkg["status"] == "COMPLETED"
            bindings.append(b)
        paths = tmp_path / "public-genesis"
        policy = {
            **client.identity,
            "trusted_endpoints": ["http://127.0.0.1:18002/api/v2/jsonRPC"],
            "artifacts": {
                "lite_client": str(paths / "lite-client"),
                "global_config": str(paths / "global.config.json"),
                "zerostate": str(paths / "zerostate.boc"),
                "basestate": str(paths / "basestate0.boc"),
                "settings": str(paths / "localton-settings.json"),
            },
        }
        with (
            settings_for(net),
            override_settings(
                MPC_SIGNER_BACKEND="self_hosted_mpc",
                MPC_TON_INTEGRATION_ENABLED=True,
                MPC_TON_NETWORK=policy,
                MPC_EVM_INTEGRATION_ENABLED=False,
                MPC_TRON_INTEGRATION_ENABLED=False,
                MPC_SOLANA_INTEGRATION_ENABLED=False,
                MPC_INTEGRATION_ENVIRONMENT="development",
                CUSTODY_DEMO_MODE=False,
                CUSTODY_TX_MODE="live",
                CUSTODY_INDEXER_MODE="live",
            ),
        ):
            Chain.objects.filter(chain_id="TON").update(
                kind="ton",
                enabled=True,
                is_testnet=True,
                evm_chain_id=None,
                native_asset_key="TON",
                min_confirmations=1,
                sweep_threshold=Decimal("0.001"),
                memo_required=True,
                gas_settings={"topup_amount": "0.13"},
            )
            NodeEndpoint.objects.filter(chain_id="TON", kind="rpc").update(enabled=False)
            NodeEndpoint.objects.create(
                chain_id="TON",
                name="isolated-ton",
                kind="rpc",
                url=policy["trusted_endpoints"][0],
                enabled=True,
            )
            Asset.objects.filter(asset_key="TON").update(
                enabled=True,
                deposit_supported=True,
                withdrawal_supported=True,
                sweep_supported=True,
            )
            roots = []
            for b in bindings:
                k = MpcKeyset.objects.create(
                    keyset_id=b["keyset_id"],
                    algorithm="FROST_ED25519",
                    curve="ed25519",
                    scope="TON",
                    derivation_version="frost_keyset_v1",
                    threshold=2,
                    party_count=3,
                )
                call_command("mpc_keyset", "import-dkg", keyset_id=str(k.keyset_id))
                call_command("mpc_keyset", "activate", keyset_id=str(k.keyset_id))
                k.refresh_from_db()
                address = wallet_address(bytes.fromhex(k.public_key), -777)
                call_command("ton_wallet_binding", str(k.keyset_id))
                roots.append((k, address))
            hot_key, hot = roots[0]
            user_key, user = roots[1]
            HotWallet.objects.filter(chain_id="TON").update(
                address=hot, mpc_keyset=None, signing_key_ref=None
            )
            call_command("bind_mpc_hot_wallet", chain="TON", keyset_id=str(hot_key.keyset_id))
            wallet = UserWallet.objects.create(
                user_id="ton-customer",
                chain_id="TON",
                asset_key="TON",
                deposit_address=user,
                memo="invoice-ton-unique-root",
                derivation_path=f"keyset:{user_key.keyset_id}",
                derivation_version="mpc_root_v1",
                mpc_keyset=user_key,
            )
            fund(container, hot, 5)
            wait_account(hot, lambda s: s["balance"] >= 5_000_000_000)
            fixture = admin_call("identity")
            fund(container, fixture["admin"], 5)
            _, block, _ = wait_account(fixture["admin"], lambda s: s["balance"] >= 5_000_000_000)
            submit_fixture(
                admin_call("deploy", seqno=0, valid_until=block.info.gen_utime + 120)["boc"]
            )
            wait_account(fixture["master"], lambda s: s["status"] == "active")
            intent = get_or_create_gas_intent(wallet, idempotency_key="ton-internal-gas-1")
            execute_gas_intent(intent.pk)
            gas = signed(
                OnchainTransactionAttempt.objects.get(
                    operation_type="GAS_TOPUP", operation_id=intent.pk
                )
            )
            execute_attempt(gas.pk, "worker")
            gas = settle(gas)
            evidence["transactions"].append(gas.confirmation_metadata)
            assert user_balances(wallet.user_id, "TON")["available"] == 0
            cp, block, _ = wait_account(fixture["admin"], lambda s: s["status"] == "active")
            submit_fixture(
                admin_call(
                    "native",
                    seqno=1,
                    valid_until=block.info.gen_utime + 120,
                    owner=user,
                    amount="200000000",
                    memo=wallet.memo,
                )["boc"]
            )
            wait_account(user, lambda s: s["balance"] >= 329_000_000)
            scan_complete(wallet)
            assert user_balances(wallet.user_id, "TON")["available"] == Decimal("0.2")
            count = LedgerTransaction.objects.count()
            scan_complete(wallet)
            assert LedgerTransaction.objects.count() == count
            job = SweepJob.objects.create(
                user_wallet=wallet,
                asset_key="TON",
                idempotency_key="ton-native-sweep",
                balance_snapshot=Decimal("0.33"),
                sweep_round=1,
                status="CREATED",
            )
            sweep = create_attempt(
                operation_type="SWEEP",
                operation_id=job.pk,
                chain_id="TON",
                asset_key="TON",
                source=user,
                destination=hot,
                amount=Decimal("0.33"),
            )
            sweep = signed(execute_attempt(sweep.pk, "worker"))
            execute_attempt(sweep.pk, "worker")
            sweep = settle(sweep)
            evidence["transactions"].append(sweep.confirmation_metadata)
            req = create_request(
                wallet.user_id,
                "TON",
                fixture["admin"],
                Decimal("0.1"),
                asset_key="TON",
                idempotency_key="ton-native-withdrawal",
            )
            approve("ton-reviewer", req.pk)
            process_withdrawal("ton-reviewer", req.pk)
            withdrawal = signed(
                OnchainTransactionAttempt.objects.get(
                    operation_type="WITHDRAWAL", operation_id=req.pk
                )
            )
            original = TonNativeExecutor.broadcast

            def lost_response(executor, *args):
                original(executor, *args)
                raise AmbiguousBroadcast("accepted response lost")

            with (
                patch.object(TonNativeExecutor, "broadcast", lost_response),
                pytest.raises(AmbiguousBroadcast),
            ):
                execute_attempt(withdrawal.pk, "worker")
            assert execute_attempt(withdrawal.pk, "worker").status == "RECONCILIATION_REQUIRED"
            assert user_balances(wallet.user_id, "TON")["reserved"] == Decimal("0.1")
            for role in ROLES[:4]:
                net.stop(role)
            for role in ROLES[:4]:
                net.start(role)
            withdrawal = settle(withdrawal)
            assert user_balances(wallet.user_id, "TON")["reserved"] == 0
            evidence["transactions"].append(withdrawal.confirmation_metadata)
            # Mint fixture tokens to the external administrator, then genuinely
            # deposit through the standard sender/recipient Jetton wallet chain.
            cp, block = client.checkpoint()
            submit_fixture(
                admin_call(
                    "mint",
                    seqno=2,
                    valid_until=block.info.gen_utime + 120,
                    owner=fixture["admin"],
                    amount="1000000",
                )["boc"]
            )
            wait_account(
                jetton_wallet_address(fixture["admin"], fixture["master"]),
                lambda s: s["status"] == "active",
            )
            policy["jetton_masters"] = {
                fixture["master"]: {
                    "decimals": 6,
                    "master_code_hash": JETTON_MASTER_CODE_HASH,
                    "wallet_code_hash": JETTON_WALLET_CODE_HASH,
                    "content_hash": fixture["content_hash"],
                    "provenance": "pinned TEP-74 disposable fixture; operator-approved decimals",
                }
            }
            asset = Asset.objects.create(
                asset_key="FIXTURE-TON",
                chain_id="TON",
                symbol="FIXTURE",
                decimals=6,
                is_native=False,
                token_standard="TEP74",
                contract_address=fixture["master"],
                enabled=True,
                deposit_supported=True,
                withdrawal_supported=True,
                sweep_supported=True,
            )
            verify_token_asset(asset.asset_key)
            tw = UserWallet.objects.create(
                user_id=wallet.user_id,
                chain_id="TON",
                asset_key=asset.asset_key,
                deposit_address=user,
                memo=wallet.memo,
                derivation_path=wallet.derivation_path,
                derivation_version="mpc_root_v1",
                mpc_keyset=user_key,
            )
            cp, block = client.checkpoint()
            submit_fixture(
                admin_call(
                    "jetton",
                    seqno=3,
                    valid_until=block.info.gen_utime + 120,
                    owner=user,
                    amount="500000",
                    memo=tw.memo,
                )["boc"]
            )
            wait_account(
                jetton_wallet_address(user, fixture["master"]), lambda s: s["status"] == "active"
            )
            scan_complete(tw)
            assert user_balances(wallet.user_id, asset.asset_key)["available"] == Decimal("0.5")
            intent2 = get_or_create_gas_intent(tw, idempotency_key="ton-jetton-gas")
            execute_gas_intent(intent2.pk)
            gas2 = signed(
                OnchainTransactionAttempt.objects.get(
                    operation_type="GAS_TOPUP", operation_id=intent2.pk
                )
            )
            execute_attempt(gas2.pk, "worker")
            settle(gas2)
            job2 = SweepJob.objects.create(
                user_wallet=tw,
                asset_key=asset.asset_key,
                idempotency_key="ton-jetton-sweep",
                balance_snapshot=Decimal("0.5"),
                sweep_round=1,
                status="CREATED",
                gas_topup_intent=intent2,
            )
            ts = create_attempt(
                operation_type="SWEEP",
                operation_id=job2.pk,
                chain_id="TON",
                asset_key=asset.asset_key,
                source=user,
                destination=hot,
                amount=Decimal("0.5"),
            )
            ts = signed(execute_attempt(ts.pk, "worker"))
            execute_attempt(ts.pk, "worker")
            ts = settle(ts)
            evidence["transactions"].append(ts.confirmation_metadata)
            req2 = create_request(
                wallet.user_id,
                "TON",
                fixture["admin"],
                Decimal("0.25"),
                asset_key=asset.asset_key,
                idempotency_key="ton-jetton-withdrawal",
            )
            approve("ton-reviewer", req2.pk)
            process_withdrawal("ton-reviewer", req2.pk)
            jt = signed(
                OnchainTransactionAttempt.objects.get(
                    operation_type="WITHDRAWAL", operation_id=req2.pk
                )
            )
            execute_attempt(jt.pk, "worker")
            jt = settle(jt)
            evidence["transactions"].append(jt.confirmation_metadata)
            assert user_balances(wallet.user_id, asset.asset_key)["reserved"] == 0
            final_count = LedgerTransaction.objects.count()
            reconcile_attempt(jt.pk)
            scan_complete(tw)
            assert LedgerTransaction.objects.count() == final_count
            evidence.update(
                ledger_transactions=LedgerTransaction.objects.count(),
                ledger_postings=LedgerPosting.objects.count(),
                signing_sessions=MpcSigningSession.objects.count(),
                reserved_native=str(user_balances(wallet.user_id, "TON")["reserved"]),
                reserved_jetton=str(user_balances(wallet.user_id, asset.asset_key)["reserved"]),
            )
            destination = REPO / "work/ton-review/django-validator-evidence.json"
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(json.dumps(evidence, indent=2))
    finally:
        net.close()
        admin.terminate()
        admin.wait(timeout=10)
