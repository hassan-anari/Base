"""One durable custody/MPC environment; staged validators, actual overlapping work.

This adds integration scenarios, not a second invocation of per-chain suites.
Only fixture faucets use complete disposable keys. Every custody operation uses
original authenticated Rust DKG, auxiliary protocols and distributed signing.
"""

import hashlib
import json
import multiprocessing
import os
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest
from custody.deposits import ingest_event
from custody.gas_station import execute_gas_intent, get_or_create_gas_intent
from custody.indexer.factory import get_indexer
from custody.indexer_service import scan_wallet
from custody.ledger import user_balances
from custody.models import (
    Asset,
    Deposit,
    HotWallet,
    LedgerPosting,
    LedgerTransaction,
    MpcKeyset,
    MpcSigningSession,
    OnchainTransactionAttempt,
    SweepJob,
    UserWallet,
)
from custody.mpc_identity import address_from_public_key
from custody.native_tx import AmbiguousBroadcast, RequestsTransport
from custody.outbound import create_attempt, execute_attempt
from custody.reconciliation import reconcile_attempt
from custody.spl import derive_ata
from custody.sweeper import advance_sweep, trigger_sweep
from custody.token_metadata import verify_token_asset
from custody.ton_wire import (
    JETTON_MASTER_CODE_HASH,
    JETTON_WALLET_CODE_HASH,
    jetton_wallet_address,
    wallet_address,
)
from custody.withdrawals import approve, create_request, process_withdrawal
from django.conf import settings
from django.core.management import call_command
from django.db import DatabaseError, close_old_connections, connection, transaction
from django.db.models import Q
from django.test import override_settings
from environment import REPO, ROLES, Processes
from evm_acceptance import CAPS as EVM_CAPS
from evm_acceptance import LocalChain
from ops.models import Chain, NodeEndpoint
from solana_local.validator import Validator as SolanaValidator
from test_cggmp import binding
from test_cggmp import execute as execute_cggmp
from test_cggmp_aux import advance_aux, get_keyset
from test_dkg import dkg_request
from test_dkg import execute as execute_frost
from test_network import settings_for
from ton.localnet import capture, fund
from tron.validator import Validator as TronValidator
from tron_acceptance import CAPS as TRON_CAPS
from tronpy import Tron
from tronpy.contract import Contract
from tronpy.providers import HTTPProvider

ROOT = Path(__file__).parent
CUSTOMER = "four-chain-customer"


class Integrated:
    def __init__(self, root, net, ton):
        self.root, self.net, self.ton = root, net, ton
        self.validators = {}
        self.roots = {}
        self.wallets = {}
        self.evidence = {
            "category": "SHARED_POSTGRES_AUTHENTICATED_MPC_VALIDATORS",
            "head_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
            "working_tree_dirty": bool(subprocess.check_output(["git", "diff", "HEAD"], text=True)),
            "operations": [],
            "deposits": [],
            "overlap": [],
            "faults": [],
            "keysets": [],
        }
        self.started = time.monotonic()

    def roots_for(self, chain, scope):
        roots = []
        public_requests = self.root / f"{scope}-public-dkg-requests.json"
        if public_requests.exists():
            requests = json.loads(public_requests.read_text())
        else:
            requests = [
                binding(scope) if scope in {"EVM", "TRON"} else dkg_request() for _ in range(2)
            ]
            for request in requests:
                request["scope"] = scope
            public_requests.write_text(json.dumps(requests))
        for request in requests:
            start = time.monotonic()
            state = get_keyset(self.net, request)
            if scope in {"EVM", "TRON"}:
                if state.get("status") != "KEYGEN_COMPLETED":
                    execute_cggmp(self.net, request)
                if (state.get("auxiliary") or {}).get("status") != "AUXILIARY_COMPLETED":
                    assert advance_aux(self.net, request)[0] == 200
                deadline = time.monotonic() + 1815
                while time.monotonic() < deadline:
                    state = get_keyset(self.net, request)
                    if state["auxiliary"]["status"] != "IN_PROGRESS":
                        break
                    time.sleep(1)
                assert state["auxiliary"]["status"] == "AUXILIARY_COMPLETED"
                algorithm, curve, version = "CGGMP24_ECDSA", "secp256k1", "cggmp_hd_v1"
            else:
                if state.get("status") != "COMPLETED":
                    status, state = execute_frost(self.net, request)
                    assert status == 200 and state["status"] == "COMPLETED"
                algorithm, curve, version = "FROST_ED25519", "ed25519", "frost_keyset_v1"
            k = MpcKeyset.objects.create(
                keyset_id=request["keyset_id"],
                algorithm=algorithm,
                curve=curve,
                scope=scope,
                derivation_version=version,
            )
            call_command("mpc_keyset", "import-dkg", keyset_id=str(k.keyset_id))
            call_command("mpc_keyset", "activate", keyset_id=str(k.keyset_id))
            k.refresh_from_db()
            address = (
                wallet_address(bytes.fromhex(k.public_key), -777)
                if chain == "TON"
                else address_from_public_key(chain, k.public_key)
            )
            roots.append((k, address))
            self.evidence["keysets"].append(
                {
                    "chain": chain,
                    "keyset": str(k.keyset_id),
                    "scope": scope,
                    "algorithm": algorithm,
                    "dkg_execution": str(k.dkg_execution_id),
                    "dkg_fingerprint": k.dkg_result_fingerprint,
                    "public_key": k.public_key,
                    "setup_seconds": time.monotonic() - start,
                }
            )
            print(f"Integrated {scope} root {len(roots)} authenticated and activated", flush=True)
        self.roots[chain] = roots
        return roots

    def configure(self, chain, kind, native, url, caps, policy):
        Chain.objects.filter(chain_id=chain).update(
            kind=kind,
            enabled=True,
            is_testnet=True,
            native_asset_key=native,
            evm_chain_id=31337 if chain == "ETH" else None,
            min_confirmations=2 if chain == "ETH" else 1,
            sweep_threshold=Decimal("0.0001"),
            gas_settings=caps,
            memo_required=chain == "TON",
        )
        Asset.objects.filter(asset_key=native).update(
            enabled=True, deposit_supported=True, withdrawal_supported=True, sweep_supported=True
        )
        NodeEndpoint.objects.filter(chain_id=chain, kind="rpc").update(enabled=False)
        NodeEndpoint.objects.create(
            chain_id=chain,
            name="integrated-isolated",
            kind="rpc",
            url=url,
            enabled=True,
            is_primary=True,
        )
        if chain == "TON":
            for k, _ in self.roots[chain]:
                call_command("ton_wallet_binding", str(k.keyset_id))
        k, hot = self.roots[chain][0]
        HotWallet.objects.filter(chain_id=chain).update(
            address=hot, mpc_keyset=None, signing_key_ref=None
        )
        call_command("bind_mpc_hot_wallet", chain=chain, keyset_id=str(k.keyset_id))
        self.evidence.setdefault("networks", {})[chain] = policy
        return self.wallet(chain, native)

    def wallet(self, chain, asset):
        k, address = self.roots[chain][1]
        wallet = UserWallet.objects.create(
            user_id=CUSTOMER,
            chain_id=chain,
            asset_key=asset,
            deposit_address=address,
            derivation_path=f"keyset:{k.keyset_id}",
            derivation_version="mpc_root_v1",
            mpc_keyset=k,
            memo="integrated-invoice" if chain == "TON" else None,
            asset_account_address=derive_ata(
                address, Asset.objects.get(asset_key=asset).contract_address
            )
            if Asset.objects.get(asset_key=asset).token_standard == "SPL"
            else None,
        )
        call_command(
            "bind_mpc_hot_wallet", chain=chain, keyset_id=str(k.keyset_id), user_wallet_id=wallet.pk
        )
        self.wallets[asset] = wallet
        return wallet

    def token(self, chain, standard, contract):
        asset = Asset.objects.create(
            asset_key=f"INTEGRATED-{chain}",
            chain_id=chain,
            symbol="SAME",
            decimals=6,
            token_standard=standard,
            contract_address=contract,
            enabled=True,
            deposit_supported=True,
            withdrawal_supported=True,
            sweep_supported=True,
        )
        verify_token_asset(asset.asset_key)
        return self.wallet(chain, asset.asset_key)

    def credit(self, wallet, minimum):
        if wallet.chain_id in {"TON", "SOL"}:
            for _ in range(100):
                wallet.refresh_from_db()
                result = scan_wallet(wallet)
                terminal = {"confirmed"} if wallet.chain_id == "TON" else {"sweep", "scanned"}
                assert result["outcome"] in {"backfill", *terminal}, result
                if result["outcome"] in terminal:
                    break
            else:
                pytest.fail("complete finalized deposit history unavailable")
            if wallet.chain_id == "SOL":
                assert wallet.last_scanned_block
                for event in (
                    get_indexer("SOL")
                    .get_balance(wallet.deposit_address, asset_key=wallet.asset_key, after_block=0)
                    .deposit_events
                ):
                    ingest_event(wallet, event)
        else:
            if wallet.chain_id == "ETH":
                for _ in range(3):
                    self.validators["ETH"].rpc("evm_mine", [])
            result = get_indexer(wallet.chain_id).get_balance(
                wallet.deposit_address, asset_key=wallet.asset_key
            )
            assert result.deposit_events, (wallet.chain_id, wallet.asset_key)
            for event in result.deposit_events:
                deposit, _ = ingest_event(wallet, event)
                assert deposit.status == "CONFIRMED", (wallet.asset_key, deposit.confirmations)
                ingest_event(wallet, event)
        assert user_balances(CUSTOMER, wallet.asset_key)["available"] >= minimum
        for d in Deposit.objects.filter(user_wallet=wallet):
            assert LedgerTransaction.objects.filter(event_key=f"deposit:{d.pk}:credit").count() == 1
            self.evidence["deposits"].append(
                {
                    "chain": wallet.chain_id,
                    "asset": d.asset_key,
                    "deposit": d.pk,
                    "txid": d.tx_hash,
                    "event": d.event_index,
                    "amount": str(d.amount),
                    "block": d.block,
                    "block_hash": d.block_hash,
                    "confirmations": d.confirmations,
                    "finality": d.chain_evidence,
                    "credit": f"deposit:{d.pk}:credit",
                }
            )

    def signed(self, attempt):
        deadline = time.monotonic() + 210
        while time.monotonic() < deadline:
            attempt.refresh_from_db()
            if attempt.status == "SIGNED":
                assert attempt.signed_payload and attempt.network_tx_id
                return attempt
            assert attempt.status in {"SIGNING", "RECONCILIATION_REQUIRED"}, (
                attempt.status,
                attempt.error_code,
            )
            execute_attempt(attempt.pk, "integrated-worker")
            time.sleep(0.05)
        pytest.fail("original genuine MPC execution did not complete")

    def settle(self, attempt):
        if attempt.chain_id == "ETH":
            for _ in range(3):
                self.validators["ETH"].rpc("evm_mine", [])
        elif attempt.chain_id == "TRX":
            self.validators["TRX"].wait_info(attempt.network_tx_id)
        elif attempt.chain_id == "SOL":
            self.validators["SOL"].wait(attempt.network_tx_id)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            result = reconcile_attempt(attempt.pk)
            if result.status == "CONFIRMED":
                assert reconcile_attempt(attempt.pk).status == "CONFIRMED"
                self.record(result)
                return result
            time.sleep(0.2)
        pytest.fail(str((result.status, result.error_code, result.confirmation_metadata)))

    def record(self, attempt):
        session = MpcSigningSession.objects.select_related("keyset").get(attempt=attempt)
        if attempt.status == "CONFIRMED":
            assert session.status == "COMPLETED" and session.signature_consumed_at
        financial_reference = {
            "WITHDRAWAL": "WithdrawalRequest",
            "SWEEP": "SweepJob",
            "GAS_TOPUP": "GasTopupIntent",
        }[attempt.operation_type]
        self.evidence["operations"].append(
            {
                "attempt": attempt.pk,
                "operation": attempt.operation_type,
                "operation_id": attempt.operation_id,
                "chain": attempt.chain_id,
                "asset": attempt.asset_key,
                "status": attempt.status,
                "error_code": attempt.error_code,
                "session": str(session.session_id),
                "session_status": session.status,
                "signature_consumed": bool(session.signature_consumed_at),
                "execution": str(session.crypto_execution_id),
                "keyset": str(session.keyset.keyset_id),
                "signers": session.selected_signers,
                "transaction_identity": session.transaction_identity,
                "txid": attempt.network_tx_id,
                "signed_bytes_sha256": hashlib.sha256(
                    attempt.signed_payload.encode()
                    if attempt.chain_id == "TRX"
                    else bytes.fromhex(attempt.signed_payload)
                ).hexdigest()
                if attempt.signed_payload
                else None,
                "signed_payload_encoding": "canonical-json" if attempt.chain_id == "TRX" else "hex",
                "finality": attempt.confirmation_metadata,
                "journals": list(
                    LedgerTransaction.objects.filter(
                        Q(ref_type="OnchainTransactionAttempt", ref_id=str(attempt.pk))
                        | Q(ref_type=financial_reference, ref_id=str(attempt.operation_id))
                    ).values_list("event_key", flat=True)
                ),
            }
        )
        print(
            f"Integrated {attempt.chain_id} {attempt.operation_type} {attempt.pk} {attempt.status}",
            flush=True,
        )

    def sweep(self, wallet):
        if wallet.chain_id == "TON":
            asset = Asset.objects.get(asset_key=wallet.asset_key)
            gas = None
            if not asset.is_native:
                gas = get_or_create_gas_intent(
                    wallet, idempotency_key=f"integrated-gas:{wallet.pk}"
                )
                execute_gas_intent(gas.pk)
                attempt = self.signed(
                    OnchainTransactionAttempt.objects.get(
                        operation_type="GAS_TOPUP", operation_id=gas.pk
                    )
                )
                execute_attempt(attempt.pk, "integrated-worker")
                self.settle(attempt)
            amount = user_balances(CUSTOMER, wallet.asset_key)["available"]
            job = SweepJob.objects.create(
                user_wallet=wallet,
                asset_key=wallet.asset_key,
                balance_snapshot=amount,
                sweep_round=1,
                idempotency_key=f"integrated-sweep:{wallet.pk}",
                gas_topup_intent=gas,
            )
            attempt = create_attempt(
                operation_type="SWEEP",
                operation_id=job.pk,
                chain_id="TON",
                asset_key=wallet.asset_key,
                source=wallet.deposit_address,
                destination=self.roots["TON"][0][1],
                amount=amount,
            )
            attempt = self.signed(execute_attempt(attempt.pk, "integrated-worker"))
            execute_attempt(attempt.pk, "integrated-worker")
            return self.settle(attempt)
        job = (
            SweepJob.objects.filter(user_wallet=wallet)
            .exclude(status__in={"CONFIRMED", "FAILED"})
            .first()
        )
        if job is None:
            result = get_indexer(wallet.chain_id).get_balance(
                wallet.deposit_address, asset_key=wallet.asset_key
            )
            triggered, job_id, reason = trigger_sweep(wallet, "integrated-balance-check", result)
            assert triggered, reason
            job = SweepJob.objects.get(pk=job_id)
        if job.gas_topup_intent_id:
            gas = self.signed(
                OnchainTransactionAttempt.objects.get(
                    operation_type="GAS_TOPUP", operation_id=job.gas_topup_intent_id
                )
            )
            execute_attempt(gas.pk, "integrated-worker")
            self.settle(gas)
            advance_sweep(job.pk, "integrated-worker")
        attempt = self.signed(
            OnchainTransactionAttempt.objects.get(operation_type="SWEEP", operation_id=job.pk)
        )
        execute_attempt(attempt.pk, "integrated-worker")
        return self.settle(attempt)

    def withdrawal(self, asset, amount, suffix, *, broadcast=True):
        chain = Asset.objects.get(asset_key=asset).chain_id
        destination = self.destinations[chain]
        req = create_request(
            CUSTOMER,
            chain,
            destination,
            amount,
            asset_key=asset,
            idempotency_key=f"integrated:{suffix}:{asset}",
        )
        approve("integrated-administrative-reviewer", req.pk)
        process_withdrawal("integrated-administrative-reviewer", req.pk)
        attempt = self.signed(
            OnchainTransactionAttempt.objects.get(operation_type="WITHDRAWAL", operation_id=req.pk)
        )
        if broadcast:
            execute_attempt(attempt.pk, "integrated-worker")
            self.settle(attempt)
        return attempt

    def overlap(self, left, right, label):
        from custody.signer_adapter import SelfHostedMpcAdapter

        barrier = threading.Barrier(2)
        dispatch_barrier = threading.Barrier(2)
        local = threading.local()
        dispatches = {}
        original_execute = SelfHostedMpcAdapter.execute_signing_session

        def coordinated_dispatch(adapter, session_id):
            # Finish genuine network preparation independently, then dispatch
            # both original MPC requests together. All protocol/RPC work is real.
            if not getattr(local, "dispatched", False):
                local.dispatched = True
                dispatch_barrier.wait(timeout=60)
                dispatches[session_id] = datetime.now(timezone.utc).isoformat()
            return original_execute(adapter, session_id)

        def worker(arg):
            close_old_connections()
            try:
                start = time.monotonic()
                barrier.wait(timeout=10)
                a = self.withdrawal(*arg, label)
                session = MpcSigningSession.objects.get(attempt=a)
                return {
                    "chain": a.chain_id,
                    "attempt": a.pk,
                    "start": start,
                    "end": time.monotonic(),
                    "signing_start": session.started_at.isoformat(),
                    "signing_end": session.completed_at.isoformat(),
                    "mpc_dispatch": dispatches[str(session.session_id)],
                }
            finally:
                close_old_connections()

        with (
            patch.object(SelfHostedMpcAdapter, "execute_signing_session", coordinated_dispatch),
            ThreadPoolExecutor(max_workers=2) as pool,
        ):
            windows = list(pool.map(worker, (left, right)))
        assert max(w["start"] for w in windows) < min(w["end"] for w in windows)
        assert max(w["signing_start"] for w in windows) < min(w["signing_end"] for w in windows)
        assert max(w["mpc_dispatch"] for w in windows) < min(w["signing_end"] for w in windows)
        self.evidence["overlap"].append({"label": label, "windows": windows})

    def conservation(self):
        for journal in LedgerTransaction.objects.all():
            postings = list(journal.postings.select_related("account"))
            assert postings and all(p.account.asset_key == journal.asset_key for p in postings)
            assert sum((p.amount for p in postings), Decimal(0)) == 0
            if journal.event_type in {"NETWORK_FEE", "ATA_RENT", "TOKEN_GAS"}:
                if journal.ref_type == "OnchainTransactionAttempt":
                    attempt = OnchainTransactionAttempt.objects.get(pk=journal.ref_id)
                    assert (
                        journal.asset_key
                        == Chain.objects.get(chain_id=attempt.chain_id).native_asset_key
                    )
                elif journal.ref_type == "TON_TRANSACTION":
                    assert journal.asset_key == "TON"
        assert (
            not LedgerPosting.objects.filter(account__bucket="RESERVED")
            .values("account_id")
            .annotate(total=__import__("django.db.models", fromlist=["Sum"]).Sum("amount"))
            .filter(total__lt=0)
            .exists()
        )


def adversarial(h):
    """Faults act on genuine operations in the shared environment."""
    from custody.ledger import InsufficientFunds

    token_balances = {
        key: user_balances(CUSTOMER, key)
        for key in ("INTEGRATED-ETH", "INTEGRATED-TRX", "INTEGRATED-SOL", "INTEGRATED-TON")
    }
    for key in token_balances:
        chain = Asset.objects.get(asset_key=key).chain_id
        with pytest.raises(InsufficientFunds):
            create_request(
                CUSTOMER,
                chain,
                h.destinations[chain],
                Decimal("1.5"),
                asset_key=key,
                idempotency_key=f"same-symbol-rejected:{key}",
            )
        assert user_balances(CUSTOMER, key) == token_balances[key]
    with pytest.raises(DatabaseError, match="financial identity"), transaction.atomic():
        Asset.objects.filter(asset_key="INTEGRATED-ETH").update(chain_id="TRX", decimals=18)
    h.withdrawal("SOL", Decimal("0.001"), "during-other-asset-financial-failure")
    assert all(user_balances(CUSTOMER, key) == balance for key, balance in token_balances.items())
    h.evidence["faults"].append(
        {
            "fault": "CROSS_ASSET_SPEND_AND_REGISTRY_REASSIGNMENT",
            "all_same_symbol_assets_separate": True,
            "unrelated_chain_continues": True,
        }
    )
    from custody.mpc_binding import local_root_keyset
    from custody.mpc_signing import _consume_completed
    from test_dkg import request

    original_rpc = RequestsTransport.rpc
    lost = h.withdrawal("SOL", Decimal("0.001"), "lost-response", broadcast=False)
    original = (lost.signed_payload, lost.network_tx_id)

    def lose_response(transport, url, method, params):
        response = original_rpc(transport, url, method, params)
        if method == "sendTransaction" and url == h.validators["SOL"].url:
            raise __import__("requests").Timeout("response lost after actual validator acceptance")
        return response

    with patch.object(RequestsTransport, "rpc", lose_response), pytest.raises(AmbiguousBroadcast):
        execute_attempt(lost.pk, "lost-response-worker")
    assert user_balances(CUSTOMER, "SOL")["reserved"] == lost.amount
    h.withdrawal("ETH", Decimal("0.001"), "during-solana-ambiguity")
    h.validators["SOL"].wait(lost.network_tx_id)

    def withhold_finalized_history(transport, url, method, params):
        response = original_rpc(transport, url, method, params)
        return None if method == "getTransaction" and url == h.validators["SOL"].url else response

    with patch.object(RequestsTransport, "rpc", withhold_finalized_history):
        assert reconcile_attempt(lost.pk).status == "RECONCILIATION_REQUIRED"
        assert user_balances(CUSTOMER, "SOL")["reserved"] == lost.amount
        h.withdrawal("ETH", Decimal("0.001"), "during-missing-solana-finalized-history")
    h.settle(lost)
    session = MpcSigningSession.objects.get(attempt=lost)
    journals = LedgerTransaction.objects.count()
    for _ in range(2):
        _consume_completed(lost.pk, session.pk)
    lost.refresh_from_db()
    assert (lost.signed_payload, lost.network_tx_id) == original
    assert LedgerTransaction.objects.count() == journals
    h.evidence["faults"].append(
        {
            "fault": "SOLANA_LOST_RESPONSE_DUPLICATE_COMPLETION",
            "attempt": lost.pk,
            "same_bytes_and_once_settlement": True,
            "missing_finalized_history_preserved_reservation": True,
        }
    )

    ton = h.withdrawal("TON", Decimal("0.01"), "network-mismatch", broadcast=False)
    with patch.dict(settings.MPC_TON_NETWORK, {"zerostate_root_hash": "a5" * 32}):
        with pytest.raises(ValueError):
            local_root_keyset(ton)
        h.withdrawal("SOL", Decimal("0.001"), "during-ton-genesis-mismatch")
        assert user_balances(CUSTOMER, "TON")["reserved"] == ton.amount
    hot = HotWallet.objects.get(chain_id="TON")
    foreign = h.roots["SOL"][0][0]
    HotWallet.objects.filter(pk=hot.pk).update(
        mpc_keyset=foreign, signing_key_ref=f"keyset:{foreign.keyset_id}"
    )
    try:
        with pytest.raises(ValueError, match="reviewed active"):
            local_root_keyset(ton)
    finally:
        HotWallet.objects.filter(pk=hot.pk).update(
            mpc_keyset=hot.mpc_keyset, signing_key_ref=hot.signing_key_ref
        )
    execute_attempt(ton.pk, "original-ton-worker")
    h.settle(ton)
    h.evidence["faults"].append(
        {"fault": "TON_CHANGED_GENESIS_AND_SOLANA_KEYSET", "attempt": ton.pk}
    )

    for chain in ("ETH", "SOL", "TON"):
        s = MpcSigningSession.objects.filter(attempt__chain_id=chain, status="COMPLETED").first()
        code, stored = request(
            h.net, "coordinator", "custody", f"/v1/sign-sessions/{s.session_id}", method="GET"
        )
        assert code == 200
        fields = (
            "session_id",
            "attempt_id",
            "keyset_id",
            "algorithm",
            "payload_type",
            "payload_hex",
            "message_fingerprint",
            "operation_type",
            "chain",
            "asset",
            "expected_source",
            "derivation_reference",
        )
        authorization = {k: stored[k] for k in fields}
        if chain == "TON":
            authorization["ton_authorization"] = stored["ton_authorization"]
        assert authorization["session_id"] == str(s.session_id)
        assert authorization["keyset_id"] == str(s.keyset.keyset_id)
        assert authorization["payload_hex"] == bytes(s.signing_payload).hex()
        assert authorization["attempt_id"] == s.attempt_id
        assert (
            request(h.net, "coordinator", "custody", "/v1/sign-sessions", authorization)[0] == 200
        )
        for changes in (
            {"chain": "TRON"},
            {"asset": "INTEGRATED-TRX"},
            {"keyset_id": str(h.roots["TRX"][0][0].keyset_id)},
        ):
            code, _ = request(
                h.net, "coordinator", "custody", "/v1/sign-sessions", {**authorization, **changes}
            )
            assert code in {400, 409, 422}
    h.evidence["faults"].append({"fault": "CROSS_CHAIN_AUTHORIZATION_REPLAY", "rejected": True})

    # A real Django worker dies after durable signature consumption, before
    # broadcast. Its replacement uses the same original operation and bytes.
    req = create_request(
        CUSTOMER,
        "ETH",
        h.destinations["ETH"],
        Decimal("0.001"),
        asset_key="ETH",
        idempotency_key="worker-kill-after-signed",
    )
    approve("integrated-reviewer", req.pk)
    process_withdrawal("integrated-reviewer", req.pk)
    a = OnchainTransactionAttempt.objects.get(operation_type="WITHDRAWAL", operation_id=req.pk)
    original_session = MpcSigningSession.objects.get(attempt=a)
    ctx = multiprocessing.get_context("fork")
    receiving, sending = ctx.Pipe(duplex=False)
    pause = ctx.Event()

    def worker(stop_after_signature):
        close_old_connections()
        try:
            if stop_after_signature:
                current = h.signed(OnchainTransactionAttempt.objects.get(pk=a.pk))
                sending.send((current.signed_payload, current.network_tx_id, current.sequence))
                pause.wait(210)
            else:
                execute_attempt(a.pk, "replacement-process-worker")
        finally:
            close_old_connections()

    connection.close()
    killed = ctx.Process(target=worker, args=(True,))
    killed.start()
    try:
        assert receiving.poll(210), "worker did not durably consume the original signature"
        original_bytes = receiving.recv()
    finally:
        killed.kill()
        killed.join(timeout=10)
    assert killed.exitcode == -9
    a.refresh_from_db()
    assert a.status == "SIGNED" and not a.broadcast_started_at
    assert (a.signed_payload, a.network_tx_id, a.sequence) == original_bytes
    assert user_balances(CUSTOMER, "ETH")["reserved"] == req.amount
    connection.close()
    replacements = [ctx.Process(target=worker, args=(False,)) for _ in range(2)]
    for replacement in replacements:
        replacement.start()
    for replacement in replacements:
        replacement.join(timeout=30)
        if replacement.is_alive():
            replacement.kill()
            replacement.join(timeout=10)
        assert replacement.exitcode == 0
    a.refresh_from_db()
    assert (a.signed_payload, a.network_tx_id, a.sequence) == original_bytes
    assert MpcSigningSession.objects.get(attempt=a).session_id == original_session.session_id
    h.settle(a)
    h.evidence["faults"].append(
        {
            "fault": "DJANGO_WORKER_SIGKILL_AFTER_SIGNED_BEFORE_BROADCAST",
            "attempt": a.pk,
            "same_session_and_bytes": True,
            "duplicate_replacement_workers": 2,
            "settled_once": True,
        }
    )

    expired = h.withdrawal("SOL", Decimal("0.001"), "real-blockhash-expiry", broadcast=False)
    original_expired = (expired.signed_payload, expired.network_tx_id, expired.last_valid_block)
    h.withdrawal("ETH", Decimal("0.001"), "during-solana-expiry")
    deadline = time.monotonic() + 180
    while (
        h.validators["SOL"].rpc("getBlockHeight", [{"commitment": "finalized"}])
        <= expired.last_valid_block
    ):
        assert time.monotonic() < deadline, "original Solana blockhash did not actually expire"
        time.sleep(0.5)
    assert reconcile_attempt(expired.pk).status == "RECONCILIATION_REQUIRED"
    expired.refresh_from_db()
    assert (
        expired.signed_payload,
        expired.network_tx_id,
        expired.last_valid_block,
    ) == original_expired
    assert user_balances(CUSTOMER, "SOL")["reserved"] == expired.amount
    h.evidence["faults"].append(
        {
            "fault": "SOLANA_ACTUAL_BLOCKHASH_EXPIRY_WITHOUT_FINALIZED_EXECUTION",
            "attempt": expired.pk,
            "last_valid_block": expired.last_valid_block,
            "reserved": str(expired.amount),
            "no_replacement_authorization": True,
        }
    )

    req = create_request(
        CUSTOMER,
        "ETH",
        h.destinations["ETH"],
        Decimal("0.001"),
        asset_key="ETH",
        idempotency_key="coordinator-in-signing",
    )
    approve("integrated-reviewer", req.pk)
    process_withdrawal("integrated-reviewer", req.pk)
    a = OnchainTransactionAttempt.objects.get(operation_type="WITHDRAWAL", operation_id=req.pk)
    s = MpcSigningSession.objects.get(attempt=a)
    original = (s.session_id, s.crypto_execution_id, s.transaction_identity, a.sequence)
    assert s.crypto_execution_id and a.status == "SIGNING"
    from custody.signer_adapter import SelfHostedMpcAdapter

    observed = SelfHostedMpcAdapter().get_signing_session(str(s.session_id))
    deadline = time.monotonic() + 10
    while observed["status"] == "STARTING" and time.monotonic() < deadline:
        time.sleep(0.01)
        observed = SelfHostedMpcAdapter().get_signing_session(str(s.session_id))
    assert observed["status"] == "IN_PROGRESS"
    h.net.stop("coordinator")
    h.net.start("coordinator")
    execute_attempt(a.pk, "restart-worker")
    s.refresh_from_db()
    a.refresh_from_db()
    assert (s.session_id, s.crypto_execution_id, s.transaction_identity, a.sequence) == original
    assert user_balances(CUSTOMER, "ETH")["reserved"] == req.amount
    h.withdrawal("TON", Decimal("0.005"), "after-coordinator-restart")
    h.evidence["faults"].append(
        {
            "fault": "COORDINATOR_RESTART_DURING_SIGNING",
            "attempt": a.pk,
            "execution": str(s.crypto_execution_id),
            "status": a.status,
            "coordinator_status_before_restart": observed["status"],
            "reservation_preserved": str(req.amount),
        }
    )

    for role in ("signer-b", "signer-c"):
        h.net.stop(role)
    try:
        req = create_request(
            CUSTOMER,
            "TON",
            h.destinations["TON"],
            Decimal("0.001"),
            asset_key="TON",
            idempotency_key="insufficient-quorum",
        )
        approve("integrated-reviewer", req.pk)
        process_withdrawal("integrated-reviewer", req.pk)
        a = OnchainTransactionAttempt.objects.get(operation_type="WITHDRAWAL", operation_id=req.pk)
        for _ in range(2):
            execute_attempt(a.pk, "duplicate-quorum-worker")
        a.refresh_from_db()
        assert not a.signed_payload
        assert user_balances(CUSTOMER, "TON")["reserved"] == req.amount
        h.evidence["faults"].append(
            {
                "fault": "INSUFFICIENT_QUORUM",
                "attempt": a.pk,
                "no_local_key_fallback": True,
                "reserved": str(req.amount),
            }
        )
    finally:
        for role in ("signer-b", "signer-c"):
            h.net.start(role)


@pytest.mark.django_db(transaction=True)
def test_shared_four_chain_custody_concurrency_isolation_and_durability(tmp_path):
    assert connection.vendor == "postgresql"
    # Explicit local debugging only. CI always creates fresh private fixtures.
    # Preserve original encrypted stores after a failed local harness assertion.
    if os.environ.get("PHASE6FD_DEV_RESUME"):
        tmp_path = Path(os.environ["PHASE6FD_DEV_RESUME"]).resolve()
        tmp_path.mkdir(parents=True, exist_ok=True)
    service_root = tmp_path / "private-services"
    if os.environ.get("PHASE6FD_DEV_RESUME") and service_root.exists():
        net = Processes.__new__(Processes)
        net.root, net.running = service_root, {}
        net.configs = {
            role: dict(
                line.split("=", 1)
                for line in (service_root / role / "service.env").read_text().splitlines()
            )
            for role in ROLES[:4]
        }
        net.ports = {
            role: int(config["MPC_BIND_ADDR"].rsplit(":", 1)[1])
            for role, config in net.configs.items()
        }
        net.bin = (
            Path(os.environ.get("CARGO_TARGET_DIR", str(REPO / "mpc-side/target"))).resolve()
            / "debug"
        )
    else:
        net = Processes(service_root)
    container = os.environ.get("PHASE6FC_LOCALTON_CONTAINER", "phase6fc-localton")
    ton = capture(container, tmp_path / "public-genesis")
    paths = tmp_path / "public-genesis"
    policy = {
        **ton.identity,
        "trusted_endpoints": ["http://127.0.0.1:18002/api/v2/jsonRPC"],
        "artifacts": {
            "lite_client": str(paths / "lite-client"),
            "global_config": str(paths / "global.config.json"),
            "zerostate": str(paths / "zerostate.boc"),
            "basestate": str(paths / "basestate0.boc"),
            "settings": str(paths / "localton-settings.json"),
        },
    }
    h = Integrated(tmp_path, net, ton)
    validator_root = tmp_path / "validator-runs" / str(uuid4())
    admin = None
    completed = False
    try:
        for role in ROLES[:4]:
            net.start(role)
        with (
            settings_for(net),
            patch.dict(os.environ, {"CUSTODY_INDEXER_MODE": "live"}),
            override_settings(
                MPC_SIGNER_BACKEND="self_hosted_mpc",
                MPC_INTEGRATION_ENVIRONMENT="development",
                MPC_EVM_INTEGRATION_ENABLED=True,
                MPC_EVM_DEVELOPMENT_CHAINS={"ETH": 31337},
                MPC_TRON_INTEGRATION_ENABLED=True,
                MPC_SOLANA_INTEGRATION_ENABLED=True,
                MPC_TON_INTEGRATION_ENABLED=True,
                MPC_TON_NETWORK=policy,
                CUSTODY_DEMO_MODE=False,
                CUSTODY_TX_MODE="live",
                CUSTODY_INDEXER_MODE="live",
            ),
        ):
            # EVM stays active through every heavy-validator stage. PostgreSQL,
            # all public roots and encrypted signer stores stay intact throughout.
            h.roots_for("ETH", "EVM")
            evm = LocalChain("shanghai", 31337)
            settings.MPC_EVM_GENESIS_HASHES = {
                "ETH": evm.rpc("eth_getBlockByNumber", ["0x0", False])["hash"]
            }
            h.validators["ETH"] = evm
            ew = h.configure(
                "ETH",
                "evm",
                "ETH",
                evm.url,
                {**EVM_CAPS, "topup_amount": "0.03"},
                {
                    "evm_chain_id": 31337,
                    "genesis_hash": settings.MPC_EVM_GENESIS_HASHES["ETH"],
                    "endpoint": evm.url,
                },
            )
            faucet = evm.rpc("eth_accounts", [])[0]
            hot = h.roots["ETH"][0][1]
            for target, units in ((hot, 5 * 10**18), (ew.deposit_address, 2 * 10**18)):
                evm.rpc(
                    "eth_sendTransaction", [{"from": faucet, "to": target, "value": hex(units)}]
                )
            tokenfile = tmp_path / "erc20.bytecode"
            subprocess.run(["node", str(ROOT / "evm/compile.cjs"), str(tokenfile)], check=True)
            deployment = evm.rpc(
                "eth_sendTransaction",
                [
                    {
                        "from": faucet,
                        "gas": hex(1000000),
                        "data": "0x" + tokenfile.read_text() + faucet[2:].rjust(64, "0"),
                    }
                ],
            )
            contract = evm.rpc("eth_getTransactionReceipt", [deployment])["contractAddress"]
            et = h.token("ETH", "ERC20", contract)
            evm.rpc(
                "eth_sendTransaction",
                [
                    {
                        "from": faucet,
                        "to": contract,
                        "gas": hex(100000),
                        "data": "0xa9059cbb"
                        + ew.deposit_address[2:].rjust(64, "0")
                        + (1000000).to_bytes(32, "big").hex(),
                    }
                ],
            )
            h.destinations = {"ETH": faucet}
            h.credit(ew, Decimal(2))
            h.credit(et, Decimal(1))
            h.sweep(ew)
            h.sweep(et)

            h.roots_for("TRX", "TRON")
            hot, deposit = [item[1] for item in h.roots["TRX"]]
            tron = TronValidator(validator_root / "tron", [(hot, 10000000000)])
            h.validators["TRX"] = tron
            settings.MPC_TRON_NETWORK = tron.policy
            tw = h.configure("TRX", "tron", "TRX", tron.url, TRON_CAPS, tron.policy)
            h.destinations["TRX"] = tron.faucet_address
            tx = tron.post(
                "/wallet/createtransaction",
                {
                    "owner_address": tron.faucet_address,
                    "to_address": deposit,
                    "amount": 20000000,
                    "visible": True,
                },
            )
            tron.faucet_sign_broadcast(tx)
            provider = HTTPProvider(tron.url)
            provider.sess.trust_env = False
            tc = Tron(provider=provider)
            tokenfile = tmp_path / "trc20.json"
            subprocess.run(["node", str(ROOT / "tron/compile.cjs"), str(tokenfile)], check=True)
            info = json.loads(tokenfile.read_text())
            import base58
            from custody.tron_wire import address_bytes

            contract = Contract(
                name="AcceptanceToken",
                abi=info["abi"],
                bytecode=bytes.fromhex(
                    info["bytecode"] + address_bytes(tron.faucet_address)[1:].hex().rjust(64, "0")
                ),
            )
            deployed = (
                tc.trx.deploy_contract(tron.faucet_address, contract)
                .fee_limit(100000000)
                .build()
                .sign(tron.faucet)
            )
            assert deployed.broadcast()["result"]
            receipt = tron.wait_info(deployed.txid)
            token_address = base58.b58encode_check(
                bytes.fromhex(receipt["contract_address"])
            ).decode()
            tt = h.token("TRX", "TRC20", token_address)
            transfer = (
                tc.get_contract(token_address)
                .functions.transfer(deposit, 1000000)
                .with_owner(tron.faucet_address)
                .fee_limit(50000000)
                .build()
                .sign(tron.faucet)
            )
            assert transfer.broadcast()["result"]
            tron.wait_info(transfer.txid)
            h.credit(tw, Decimal(20))
            h.credit(tt, Decimal(1))
            h.sweep(tw)
            h.sweep(tt)
            net.stop("signer-a")
            h.overlap(("ETH", Decimal("0.001")), ("TRX", Decimal(1)), "EVM_TRON_BC_QUORUM")
            net.start("signer-a")
            h.withdrawal("INTEGRATED-ETH", Decimal("0.1"), "erc20")
            h.withdrawal("INTEGRATED-TRX", Decimal("0.1"), "trc20")
            # Real RPC outage: preserve signed bytes/reservation on TRON while
            # EVM continues signing, broadcasting and settling on the same DB.
            uncertain = h.withdrawal("TRX", Decimal(1), "rpc-outage", broadcast=False)
            original = (uncertain.signed_payload, uncertain.network_tx_id)
            tron.process.send_signal(__import__("signal").SIGSTOP)
            try:
                with pytest.raises(Exception):
                    execute_attempt(uncertain.pk, "outage-worker")
                assert user_balances(CUSTOMER, "TRX")["reserved"] == Decimal(1)
                h.withdrawal("ETH", Decimal("0.001"), "during-tron-outage")
            finally:
                tron.process.send_signal(__import__("signal").SIGCONT)
            uncertain.refresh_from_db()
            assert (uncertain.signed_payload, uncertain.network_tx_id) == original
            # No auto-replacement or assumption of nonexecution: explicitly
            # reconcile the original persisted bytes before any further action.
            h.evidence["faults"].append(
                {
                    "fault": "TRON_RPC_STOP",
                    "attempt": uncertain.pk,
                    "reserved": str(user_balances(CUSTOMER, "TRX")["reserved"]),
                    "other_chain_confirmed": True,
                }
            )
            tron.close()
            del h.validators["TRX"]

            h.roots_for("SOL", "SOLANA")
            sol = SolanaValidator(validator_root / "solana")
            h.validators["SOL"] = sol
            settings.MPC_SOLANA_NETWORK = sol.policy
            sw = h.configure(
                "SOL",
                "solana",
                "SOL",
                sol.url,
                {
                    "max_fee_lamports": "20000",
                    "max_ata_rent_lamports": "3000000",
                    "native_reserve_lamports": "0",
                    "topup_amount": "0.01",
                },
                sol.policy,
            )
            h.destinations["SOL"] = str(sol.faucet.pubkey())
            sol.fund(h.roots["SOL"][0][1], 5 * 10**9)
            sol.fund(sw.deposit_address, 200000000)
            sol.create_mint()
            st = h.token("SOL", "SPL", str(sol.mint.pubkey()))
            sol.mint_to(str(sol.faucet.pubkey()), 1000000)
            sol.token_transfer(sw.deposit_address, 1000000)
            h.credit(sw, Decimal("0.2"))
            h.sweep(sw)
            h.credit(st, Decimal(1))
            h.sweep(st)
            h.overlap(("ETH", Decimal("0.001")), ("SOL", Decimal("0.001")), "EVM_SOLANA")
            h.withdrawal("INTEGRATED-SOL", Decimal("0.1"), "spl")

            h.roots_for("TON", "TON")
            nw = h.configure(
                "TON",
                "ton",
                "TON",
                policy["trusted_endpoints"][0],
                {"topup_amount": "0.13"},
                ton.identity,
            )
            admin = subprocess.Popen(
                ["node", str(ROOT / "ton/admin.cjs")],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                text=True,
            )

            def command(action, **kwargs):
                admin.stdin.write(json.dumps({"action": action, **kwargs}) + "\n")
                admin.stdin.flush()
                result = json.loads(admin.stdout.readline())
                assert "error" not in result, result
                return result["result"]

            fixture = command("identity")
            h.destinations["TON"] = fixture["admin"]

            def wait_account(address, predicate):
                deadline = time.monotonic() + 90
                while time.monotonic() < deadline:
                    cp, block = ton.checkpoint()
                    state = ton.account(address, cp)
                    if predicate(state):
                        return block
                    time.sleep(0.2)
                pytest.fail("TON actual account effect did not finalize")

            # Fixture faucet calls return before finality. Do not race its
            # original wallet sequence when funding two independent accounts.
            for target in (h.roots["TON"][0][1], fixture["admin"]):
                cp, _ = ton.checkpoint()
                previous = ton.account(target, cp)["balance"]
                fund(container, target, 5)
                wait_account(
                    target, lambda s: s["balance"] >= max(5_000_000_000, previous + 4_900_000_000)
                )

            seqno = 0

            def send(action, **kwargs):
                nonlocal seqno
                _, block = ton.checkpoint()
                message = command(
                    action, seqno=seqno, valid_until=block.info.gen_utime + 120, **kwargs
                )
                p = tmp_path / "fixture-message.boc"
                p.write_bytes(bytes.fromhex(message["boc"]))
                ton.command("sendfile " + str(p))
                seqno += 1
                # Fixture SDK provides the external admin; wait for its exact
                # state seqno, never infer custody terminal delivery from it.
                wait_account(
                    fixture["admin"],
                    lambda s: (
                        s["status"] == "active"
                        and s["data"].begin_parse().load_bit() is not None
                        and _admin_seqno(s["data"]) == seqno
                    ),
                )

            def _admin_seqno(data):
                parser = data.begin_parse()
                parser.load_bit()
                return parser.load_uint(32)

            wait_account(fixture["admin"], lambda s: s["balance"] >= 5 * 10**9)
            send("deploy")
            wait_account(fixture["master"], lambda s: s["status"] == "active")
            send("native", owner=nw.deposit_address, amount="200000000", memo=nw.memo)
            wait_account(nw.deposit_address, lambda s: s["balance"] >= 200000000)
            h.credit(nw, Decimal("0.2"))
            h.sweep(nw)
            send("mint", owner=fixture["admin"], amount="1000000")
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
                    "provenance": "pinned reference fixture; operator-approved decimals",
                }
            }
            nt = h.token("TON", "TEP74", fixture["master"])
            send("jetton", owner=nw.deposit_address, amount="1000000", memo=nw.memo)
            wait_account(
                jetton_wallet_address(nw.deposit_address, fixture["master"]),
                lambda s: s["status"] == "active",
            )
            h.credit(nt, Decimal(1))
            h.sweep(nt)
            h.overlap(("ETH", Decimal("0.001")), ("TON", Decimal("0.05")), "EVM_TON")
            h.withdrawal("INTEGRATED-TON", Decimal("0.1"), "jetton")
            assert MpcKeyset.objects.count() == 8
            assert MpcKeyset.objects.values("public_key").distinct().count() == 8
            assert MpcKeyset.objects.values("dkg_result_fingerprint").distinct().count() == 8
            adversarial(h)
            # Preserve every family simultaneously while all service processes
            # restart. Finalized original bytes and financial outcomes are stable.
            before = list(
                MpcSigningSession.objects.values_list(
                    "session_id", "crypto_execution_id", "transaction_identity"
                )
            )
            originals = list(
                OnchainTransactionAttempt.objects.values_list(
                    "pk", "signed_payload", "network_tx_id", "sequence"
                )
            )
            journals = LedgerTransaction.objects.count()
            cursors = list(
                UserWallet.objects.values(
                    "id",
                    "chain_id",
                    "asset_key",
                    "last_scanned_block",
                    "solana_scan_cursor",
                    "ton_scan_cursor",
                )
            )
            root_pins = list(MpcKeyset.objects.values("keyset_id", "network_bindings"))
            for role in ROLES[:4]:
                net.stop(role)
            for role in ROLES[:4]:
                net.start(role)
            close_old_connections()
            assert before == list(
                MpcSigningSession.objects.values_list(
                    "session_id", "crypto_execution_id", "transaction_identity"
                )
            )
            assert originals == list(
                OnchainTransactionAttempt.objects.values_list(
                    "pk", "signed_payload", "network_tx_id", "sequence"
                )
            )
            assert cursors == list(
                UserWallet.objects.values(
                    "id",
                    "chain_id",
                    "asset_key",
                    "last_scanned_block",
                    "solana_scan_cursor",
                    "ton_scan_cursor",
                )
            )
            assert root_pins == list(MpcKeyset.objects.values("keyset_id", "network_bindings"))
            h.evidence["durable_cursors"] = cursors
            h.evidence["original_root_network_bindings"] = root_pins
            for a in OnchainTransactionAttempt.objects.filter(status="CONFIRMED"):
                reconcile_attempt(a.pk)
            assert LedgerTransaction.objects.count() == journals
            h.evidence["faults"].append(
                {
                    "fault": "ALL_MPC_PROCESSES_RESTART",
                    "original_identities_preserved": True,
                    "journal_count_unchanged": journals,
                }
            )
            h.conservation()
            recorded = {row["attempt"] for row in h.evidence["operations"]}
            for a in OnchainTransactionAttempt.objects.exclude(pk__in=recorded):
                h.record(a)
                if a.operation_type == "WITHDRAWAL" and a.status != "CONFIRMED":
                    assert (
                        LedgerTransaction.objects.filter(
                            event_key=f"withdrawal:{a.operation_id}:reserve"
                        ).count()
                        == 1
                    )
                    assert not LedgerTransaction.objects.filter(
                        event_key__in=[
                            f"withdrawal:{a.operation_id}:release",
                            f"withdrawal:{a.operation_id}:settle",
                        ]
                    ).exists()
            h.evidence["assets"] = list(
                Asset.objects.filter(asset_key__in=h.wallets).values(
                    "asset_key",
                    "chain_id",
                    "symbol",
                    "is_native",
                    "token_standard",
                    "contract_address",
                    "decimals",
                    "metadata_fingerprint",
                    "financial_identity_locked",
                )
            )
            h.evidence["ledger"] = {
                "transactions": LedgerTransaction.objects.count(),
                "postings": LedgerPosting.objects.count(),
                "conservation": True,
                "balances": {
                    asset: {k: str(v) for k, v in user_balances(CUSTOMER, asset).items()}
                    for asset in h.wallets
                },
                "journals": list(
                    LedgerTransaction.objects.values(
                        "event_key", "event_type", "asset_key", "ref_type", "ref_id"
                    )
                ),
            }
            completed = True
    finally:
        h.evidence["completed"] = completed
        h.evidence["wall_seconds"] = time.monotonic() - h.started
        destination = REPO / "work/integrated-review/public-evidence.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(h.evidence, indent=2, default=str))
        for validator in h.validators.values():
            validator.close()
        net.close()
        if admin:
            admin.terminate()
            admin.wait(timeout=10)
