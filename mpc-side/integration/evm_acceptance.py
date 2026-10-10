"""Django executor acceptance against real CGGMP services and two disposable Ganache chains.

The caller supplies Phase 6D's module-scoped fresh-prime fixture. No cryptographic
signing is mocked, and no share is read or reconstructed by this scenario.
"""

import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

import pytest
import requests
from custody.ledger import ensure_accounts, post_transaction, user_balances
from custody.models import (
    Asset,
    HotWallet,
    LedgerAccount,
    MpcKeyset,
    MpcSigningSession,
    OnchainTransactionAttempt,
)
from custody.mpc_binding import UnsupportedMpcDerivation, local_root_keyset
from custody.mpc_identity import address_from_public_key
from custody.native_tx import AmbiguousBroadcast, RequestsTransport
from custody.outbound import execute_attempt
from custody.reconciliation import reconcile_attempt
from custody.token_metadata import verify_token_asset
from custody.withdrawals import approve, create_request, process_withdrawal
from django.db import close_old_connections, connection
from django.test import override_settings
from eth_account import Account
from ops.models import Chain, NodeEndpoint
from test_network import settings_for

EVM = Path(__file__).parent / "evm"
CAPS = {
    "max_gas_limit": 200000,
    "max_fee_per_gas": 100_000_000_000,
    "max_priority_fee_per_gas": 10_000_000_000,
    "max_legacy_gas_price": 100_000_000_000,
    "max_total_fee_base_units": 10**17,
    "topup_amount": "0.005",
}


class LocalChain:
    def __init__(self, hardfork, chain_id):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        binary = EVM / "node_modules/.bin/ganache"
        assert binary.exists(), "npm ci --prefix mpc-side/integration/evm is required"
        self.process = subprocess.Popen(
            [
                str(binary),
                "--server.host",
                "127.0.0.1",
                "--server.port",
                str(self.port),
                "--chain.chainId",
                str(chain_id),
                "--chain.hardfork",
                hardfork,
                "--wallet.totalAccounts",
                "2",
                "--logging.quiet",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                self.rpc("eth_chainId", [])
                return
            except requests.RequestException:
                assert self.process.poll() is None, "disposable EVM process exited"
                time.sleep(0.05)
        self.close()
        pytest.fail("isolated EVM RPC did not become ready")

    def rpc(self, method, params):
        response = requests.post(
            self.url,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            },
            timeout=10,
        )
        response.raise_for_status()
        body = response.json()
        assert "error" not in body, body.get("error")
        return body["result"]

    def close(self):
        self.process.terminate()
        self.process.wait(timeout=10)


@contextmanager
def isolated_chains():
    chains = []
    try:
        chains.append(LocalChain("berlin", 31337))
        chains.append(LocalChain("shanghai", 31338))
        yield chains
    finally:
        for chain in chains:
            chain.close()


def fund_ledger(user_id, asset_key):
    ensure_accounts(user_id, asset_key)
    available = LedgerAccount.objects.get(owner_id=user_id, asset_key=asset_key, bucket="AVAILABLE")
    clearing = LedgerAccount.objects.get(
        owner_type="SYSTEM", asset_key=asset_key, bucket="CUSTODY_CLEARING"
    )
    post_transaction(
        event_key=f"acceptance:{user_id}:{asset_key}",
        event_type="TEST_FUNDING",
        asset_key=asset_key,
        ref_type="Acceptance",
        ref_id=user_id,
        postings=[(available, Decimal(10)), (clearing, Decimal(-10))],
    )


def approved_attempt(chain_id, asset_key, source, suffix, amount=Decimal("0.001")):
    user = f"acceptance-{suffix}"
    fund_ledger(user, asset_key)
    withdrawal = create_request(
        user,
        chain_id,
        "0x" + "22" * 20,
        amount,
        asset_key=asset_key,
        idempotency_key=f"acceptance-{suffix}",
    )
    approve("acceptance-reviewer", withdrawal.pk)
    # Use the business workflow for initial claim, preparation, nonce and session.
    process_withdrawal("acceptance-reviewer", withdrawal.pk)
    attempt = OnchainTransactionAttempt.objects.get(
        operation_type="WITHDRAWAL", operation_id=withdrawal.pk
    )
    assert attempt.from_address.lower() == source.lower()
    return withdrawal, attempt


def wait_signed(attempt):
    deadline = time.monotonic() + 210
    while time.monotonic() < deadline:
        attempt.refresh_from_db()
        if attempt.status == "SIGNED":
            return attempt
        assert attempt.status == "SIGNING", (attempt.status, attempt.error_code)
        execute_attempt(attempt.pk, "system:mpc_advancement")
        time.sleep(0.1)
    pytest.fail("real distributed EVM signature did not complete")


def run_evm_acceptance(net, tmp_path):
    assert connection.vendor == "postgresql", "real Phase 6E acceptance requires PostgreSQL"
    keyset = MpcKeyset.objects.create(
        keyset_id=net.aux_context["keyset_id"],
        algorithm="CGGMP24_ECDSA",
        curve="secp256k1",
        scope="EVM",
        threshold=2,
        party_count=3,
        derivation_version="cggmp_hd_v1",
        status="ACTIVE",
        participant_identities=net.aux_context["participants"],
        public_key=net.aux_state["group_public_key"],
        dkg_execution_id=net.aux_context["execution_id"],
        dkg_result_fingerprint=net.aux_state["result_fingerprint"],
    )
    source = address_from_public_key("ETH", keyset.public_key)
    with (
        isolated_chains() as chains,
        settings_for(net),
        override_settings(
            MPC_SIGNER_BACKEND="self_hosted_mpc",
            MPC_EVM_INTEGRATION_ENABLED=True,
            MPC_INTEGRATION_ENVIRONMENT="development",
            MPC_EVM_DEVELOPMENT_CHAINS={"ETH": 31337, "BASE": 31338},
            MPC_EVM_GENESIS_HASHES={
                alias: chain.rpc("eth_getBlockByNumber", ["0x0", False])["hash"]
                for alias, chain in zip(("ETH", "BASE"), chains, strict=True)
            },
            CUSTODY_DEMO_MODE=False,
            CUSTODY_TX_MODE="live",
        ),
    ):
        for runtime, native, chain, numeric in zip(
            ("ETH", "BASE"), ("ETH", "ETH-BASE"), chains, (31337, 31338), strict=True
        ):
            Chain.objects.update_or_create(
                chain_id=runtime,
                defaults={
                    "display_name": "Disposable Phase 6E chain",
                    "kind": "evm",
                    "is_testnet": True,
                    "native_asset_key": native,
                    "evm_chain_id": numeric,
                    "min_confirmations": 2,
                    "gas_settings": CAPS,
                    "enabled": True,
                },
            )
            Asset.objects.update_or_create(
                asset_key=native,
                defaults={
                    "chain_id": runtime,
                    "symbol": "ETH",
                    "decimals": 18,
                    "is_native": True,
                    "enabled": True,
                    "withdrawal_supported": True,
                    "sweep_supported": True,
                },
            )
            NodeEndpoint.objects.filter(chain_id=runtime, kind="rpc").update(enabled=False)
            NodeEndpoint.objects.create(
                chain_id=runtime,
                name="phase6e-loopback",
                url=chain.url,
                kind="rpc",
                enabled=True,
                is_primary=True,
            )
            HotWallet.objects.update_or_create(
                chain_id=runtime,
                defaults={
                    "address": source,
                    "mpc_keyset": keyset,
                    "signing_key_ref": f"keyset:{keyset.keyset_id}",
                },
            )
            faucet = chain.rpc("eth_accounts", [])[0]
            chain.rpc("eth_sendTransaction", [{"from": faucet, "to": source, "value": hex(10**19)}])

        net.stop("signer-a")
        try:
            # Legacy: genuine Berlin chain; B+C sign while A is unavailable.
            _, legacy = approved_attempt("ETH", "ETH", source, "legacy")
            legacy = wait_signed(legacy)
            legacy_session = MpcSigningSession.objects.get(attempt=legacy)
            assert legacy_session.payload_type == "EVM_LEGACY_DIGEST"
            assert legacy_session.selected_signers == ["signer-b", "signer-c"]
            assert (
                Account.recover_transaction(bytes.fromhex(legacy.signed_payload)).lower()
                == source.lower()
            )
            execute_attempt(legacy.pk, "worker")
            chains[0].rpc("evm_mine", [])
            assert reconcile_attempt(legacy.pk).status == "CONFIRMED"

            # Typed native: persist completion, kill coordinator before Django consumes it.
            _, typed = approved_attempt("BASE", "ETH-BASE", source, "typed")
            deadline = time.monotonic() + 210
            with patch(
                "custody.mpc_signing._consume_completed",
                side_effect=RuntimeError("injected worker death"),
            ):
                while time.monotonic() < deadline:
                    try:
                        execute_attempt(typed.pk, "worker")
                    except RuntimeError as exc:
                        assert str(exc) == "injected worker death"
                        break
                    time.sleep(0.1)
                else:
                    pytest.fail("real typed completion was not persisted")
            session = MpcSigningSession.objects.get(attempt=typed)
            execution_id = session.crypto_execution_id
            assert session.status == "COMPLETED" and session.signature_consumed_at is None
            net.stop("coordinator")
            net.start("coordinator")
            typed = wait_signed(typed)
            session.refresh_from_db()
            assert session.crypto_execution_id == execution_id
            assert session.payload_type == "EVM_EIP1559_DIGEST"

            # Concurrent workers: one owns the committed signed bytes and RPC submission.
            calls, entered, release = [], threading.Event(), threading.Event()
            original_rpc = RequestsTransport.rpc

            def counted_rpc(transport, url, method, params):
                if method == "eth_sendRawTransaction":
                    calls.append(params[0])
                    entered.set()
                    assert release.wait(10)
                return original_rpc(transport, url, method, params)

            def worker():
                close_old_connections()
                try:
                    # Django override_settings is process-wide and survives thread entry.
                    return execute_attempt(typed.pk, "worker").status
                finally:
                    close_old_connections()

            with (
                patch.object(RequestsTransport, "rpc", counted_rpc),
                ThreadPoolExecutor(max_workers=2) as pool,
            ):
                first = pool.submit(worker)
                assert entered.wait(10)
                second = pool.submit(worker)
                assert second.result(timeout=10) == "BROADCASTING"
                release.set()
                assert first.result(timeout=10) == "BROADCASTED"
            assert calls == ["0x" + typed.signed_payload]
            chains[1].rpc("evm_mine", [])
            assert reconcile_attempt(typed.pk).status == "CONFIRMED"

            # Existing ERC20 executor, real deployed token and emitted Transfer event.
            bytecode = tmp_path / "token.bytecode"
            subprocess.run(["node", str(EVM / "compile.cjs"), str(bytecode)], check=True)
            deployment = chains[1].rpc(
                "eth_sendTransaction",
                [
                    {
                        "from": chains[1].rpc("eth_accounts", [])[0],
                        "gas": hex(2_000_000),
                        "data": "0x" + bytecode.read_text() + source[2:].lower().rjust(64, "0"),
                    }
                ],
            )
            contract = chains[1].rpc("eth_getTransactionReceipt", [deployment])["contractAddress"]
            asset = Asset.objects.create(
                asset_key="ACCEPT-BASE",
                chain_id="BASE",
                symbol="ACCEPT",
                decimals=6,
                is_native=False,
                token_standard="ERC20",
                contract_address=contract,
                enabled=True,
                withdrawal_supported=True,
                sweep_supported=True,
            )
            verify_token_asset(asset.asset_key)
            withdrawal, token = approved_attempt(
                "BASE", asset.asset_key, source, "token", Decimal("1.25")
            )
            token = wait_signed(token)
            token_session = MpcSigningSession.objects.get(attempt=token)
            # Chain accepts the bytes and the response is lost. Reconcile without re-signing.
            submissions = []

            def lost_response(transport, url, method, params):
                value = original_rpc(transport, url, method, params)
                if method == "eth_sendRawTransaction":
                    submissions.append(params[0])
                    raise requests.Timeout("injected lost response after chain acceptance")
                return value

            with patch.object(RequestsTransport, "rpc", lost_response):
                with pytest.raises(AmbiguousBroadcast):
                    execute_attempt(token.pk, "worker")
                assert execute_attempt(token.pk, "worker").status == "RECONCILIATION_REQUIRED"
            assert submissions == ["0x" + token.signed_payload]
            assert user_balances(withdrawal.user_id, asset.asset_key)["reserved"] == Decimal("1.25")
            chains[1].rpc("evm_mine", [])
            assert reconcile_attempt(token.pk).status == "CONFIRMED"
            assert reconcile_attempt(token.pk).status == "CONFIRMED"
            token_session.refresh_from_db()
            assert MpcSigningSession.objects.filter(attempt=token).count() == 1
            assert user_balances(withdrawal.user_id, asset.asset_key)["reserved"] == 0
            balance = chains[1].rpc(
                "eth_call",
                [
                    {
                        "to": contract,
                        "data": "0x70a08231" + token.to_address[2:].lower().rjust(64, "0"),
                    },
                    "latest",
                ],
            )
            assert int(balance, 16) == 1_250_000

            # An unsupported address/path fails before creating any coordinator session.
            HotWallet.objects.filter(chain_id="BASE").update(signing_key_ref="m/44'/60'/0'/0/77")
            with pytest.raises(UnsupportedMpcDerivation):
                local_root_keyset(token)
            HotWallet.objects.filter(chain_id="BASE").update(
                signing_key_ref=f"keyset:{keyset.keyset_id}"
            )

            # Only B remains: no alternate execution/session may be manufactured.
            net.stop("signer-c")
            try:
                _, single = approved_attempt("BASE", "ETH-BASE", source, "one-signer")
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    single = execute_attempt(single.pk, "worker")
                    if single.status == "RECONCILIATION_REQUIRED":
                        break
                    time.sleep(0.1)
                assert single.status == "RECONCILIATION_REQUIRED" and not single.signed_payload
                assert MpcSigningSession.objects.filter(attempt=single).count() == 1
            finally:
                net.start("signer-c")
        finally:
            net.start("signer-a")
