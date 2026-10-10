"""PostgreSQL Solana boundary regressions; simulated coordinator is not acceptance."""

import base64
import copy
import hashlib
import uuid
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from django.core.management import call_command
from ops.models import NodeEndpoint
from solders.hash import Hash
from solders.keypair import Keypair
from solders.message import Message
from solders.system_program import TransferParams, transfer

from custody.ledger import user_balances
from custody.models import (
    LedgerTransaction,
    MpcKeyset,
    MpcSigningSession,
)
from custody.mpc_binding import local_root_keyset, transaction_identity, verify_coordinator_keyset
from custody.mpc_signing import _default_consumer, advance_mpc_signing, coordinator_request
from custody.mpc_solana_network import verify_solana_endpoint
from custody.native_tx import ReconciliationResult, ReconciliationState, SolanaNativeExecutor
from custody.outbound import create_attempt, execute_attempt
from custody.reconciliation import reconcile_attempt
from custody.solana_wire import assemble_signature, validate_message
from custody.withdrawals import approve, create_request

from .solana_fixture import SolRpc, configure, finalized, fund, root


@pytest.fixture
def sol_context(db, settings):
    private, keyset = root(23)
    source = str(private.pubkey())
    destination = str(Keypair.from_seed(bytes([24]) * 32).pubkey())
    genesis = str(Hash.from_bytes(bytes([99]) * 32))
    configure(keyset, source)
    settings.MPC_SOLANA_INTEGRATION_ENABLED = True
    settings.MPC_SOLANA_NETWORK = {
        "network": "isolated-v1",
        "genesis_hash": genesis,
        "genesis_source": "validator-genesis-artifact",
        "genesis_artifact_sha256": "ab" * 32,
        "trusted_endpoints": ["http://127.0.0.1:8899"],
    }
    settings.MPC_INTEGRATION_ENVIRONMENT = "development"
    settings.MPC_SIGNER_BACKEND = "self_hosted_mpc"
    settings.CUSTODY_DEMO_MODE = False
    settings.CUSTODY_TX_MODE = "live"
    settings.CUSTODY_INDEXER_MODE = "live"
    rpc = SolRpc(source, destination, genesis)
    fund("sol-policy")
    request = create_request(
        "sol-policy", "SOL", destination, Decimal("1"), idempotency_key="sol-policy"
    )
    approve("admin", request.pk)
    attempt = create_attempt(
        operation_type="WITHDRAWAL",
        operation_id=request.pk,
        chain_id="SOL",
        asset_key="SOL",
        source=source,
        destination=destination,
        amount=Decimal("1"),
    )
    prepared = SolanaNativeExecutor(rpc).prepare("SOL", "SOL", source, destination, Decimal("1"))
    attempt.prepared_metadata = prepared.unsigned_payload
    attempt.fee_metadata = prepared.fee_metadata
    attempt.last_valid_block = prepared.last_valid_block
    attempt.status = "SIGNING"
    attempt.save()
    identity = transaction_identity(attempt, keyset)
    session = MpcSigningSession.objects.create(
        attempt=attempt,
        keyset=keyset,
        session_id=uuid.uuid4(),
        algorithm="FROST_ED25519",
        payload_type="SOLANA_MESSAGE",
        signing_payload=prepared.signing_payload,
        message_fingerprint=hashlib.sha256(prepared.signing_payload).hexdigest(),
        transaction_identity=identity,
        coordinator_request_id=hashlib.sha256(
            __import__("json").dumps(identity, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    )
    return SimpleNamespace(
        private=private,
        keyset=keyset,
        source=source,
        destination=destination,
        rpc=rpc,
        attempt=attempt,
        session=session,
        request=request,
        prepared=prepared,
    )


def complete(context):
    session = context.session
    session.crypto_execution_id = uuid.uuid4()
    session.selected_signers = ["signer-a", "signer-b"]
    session.status = "COMPLETED"
    session.signature_result = {
        "logical_session_id": str(session.session_id),
        "crypto_execution_id": str(session.crypto_execution_id),
        "keyset_id": str(context.keyset.keyset_id),
        "selected_signers": session.selected_signers,
        "algorithm": "FROST_ED25519",
        "payload_fingerprint": session.message_fingerprint,
        "verified": True,
        "signature_hex": bytes(context.private.sign_message(bytes(session.signing_payload))).hex(),
    }
    session.save()
    from custody.mpc_signing import _consume_completed

    return _consume_completed(context.attempt.pk, session.pk)


def test_frost_import_activation_rechecks_original_receipts_and_disables_provisioning(sol_context):
    ctx = sol_context
    verify_coordinator_keyset(ctx.keyset, ctx.keyset.dkg_public_evidence)
    # FROST requires no CGGMP auxiliary evidence.
    ctx.keyset.status = "CREATING"
    ctx.keyset.save()
    with patch(
        "custody.signer_adapter.SelfHostedMpcAdapter.get_keyset",
        return_value=ctx.keyset.dkg_public_evidence,
    ):
        call_command("mpc_keyset", "import-dkg", keyset_id=str(ctx.keyset.keyset_id))
        call_command("mpc_keyset", "activate", keyset_id=str(ctx.keyset.keyset_id))
    ctx.keyset.refresh_from_db()
    assert ctx.keyset.status == "ACTIVE" and not ctx.keyset.active_for_new_wallets
    altered = copy.deepcopy(ctx.keyset.dkg_public_evidence)
    altered["participant_agreement"][2]["public_key_package"] = [9]
    with pytest.raises(ValueError):
        verify_coordinator_keyset(ctx.keyset, altered)


@pytest.mark.parametrize(
    "field,value",
    [
        ("algorithm", "CGGMP24_ECDSA"),
        ("curve", "secp256k1"),
        ("threshold", 3),
        ("status", "RETIRED"),
        ("public_key", "ab" * 31),
    ],
)
def test_root_binding_rejects_inconsistent_local_evidence(sol_context, field, value):
    MpcKeyset.objects.filter(pk=sol_context.keyset.pk).update(**{field: value}) if field not in {
        "algorithm",
        "curve",
    } else None
    if field in {"algorithm", "curve"}:
        sol_context.keyset.__dict__[field] = value
        with pytest.raises(ValueError):
            verify_coordinator_keyset(sol_context.keyset, sol_context.keyset.dkg_public_evidence)
    else:
        with pytest.raises(ValueError):
            local_root_keyset(sol_context.attempt)


def test_exact_message_frost_consumer_without_ecdsa_fields(sol_context):
    ctx = sol_context
    request = coordinator_request(ctx.attempt, ctx.session)
    assert bytes.fromhex(request["payload_hex"]) == ctx.prepared.signing_payload
    assert len(ctx.prepared.signing_payload) != 32
    assert request["expected_source"] == ctx.source
    attempt = complete(ctx)
    ctx.session.refresh_from_db()
    assert _default_consumer(attempt, ctx.session) == (
        attempt.signed_payload,
        attempt.network_tx_id,
    )
    assert len(bytes.fromhex(ctx.session.signature_result["signature_hex"])) == 64
    assert ctx.session.signature_consumed_at


@pytest.mark.parametrize(
    "tamper", ["amount", "blockhash", "fee_payer", "hidden_account", "extra_signer", "program"]
)
def test_serialized_message_tampering_rejected(sol_context, tamper):
    ctx = sol_context
    other = Keypair.from_seed(bytes([26]) * 32).pubkey()
    from solders.instruction import AccountMeta, Instruction

    ix = transfer(
        TransferParams(
            from_pubkey=ctx.private.pubkey(),
            to_pubkey=other
            if tamper == "hidden_account"
            else __import__("solders.pubkey", fromlist=["Pubkey"]).Pubkey.from_string(
                ctx.destination
            ),
            lamports=2 if tamper == "amount" else 10**9,
        )
    )
    if tamper in {"program", "extra_signer"}:
        ix = Instruction(
            other if tamper == "program" else ix.program_id,
            ix.data,
            [*ix.accounts, AccountMeta(other, True, True)]
            if tamper == "extra_signer"
            else ix.accounts,
        )
    message = bytes(
        Message.new_with_blockhash(
            [ix],
            other if tamper == "fee_payer" else ctx.private.pubkey(),
            Hash.new_unique() if tamper == "blockhash" else Hash.from_string(ctx.rpc.blockhash),
        )
    )
    with pytest.raises(ValueError):
        validate_message(
            base64.b64encode(message).decode(),
            ctx.source,
            ctx.destination,
            10**9,
            ctx.rpc.blockhash,
        )


@pytest.mark.parametrize("signature", ["00" * 64, "01" * 63, "ab" * 65, "FF" * 64])
def test_malformed_or_noncanonical_frost_signature_rejected(sol_context, signature):
    with pytest.raises(ValueError):
        assemble_signature(
            sol_context.attempt.prepared_metadata["message"],
            sol_context.keyset.public_key,
            signature,
        )


@pytest.mark.parametrize(
    "change", ["disabled", "mainnet", "devnet", "untrusted", "wrong_genesis", "self_pin"]
)
def test_solana_network_independent_activation(sol_context, settings, change):
    if change == "disabled":
        settings.MPC_SOLANA_INTEGRATION_ENABLED = False
    elif change == "mainnet":
        settings.MPC_SOLANA_NETWORK["genesis_hash"] = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
    elif change == "devnet":
        settings.MPC_SOLANA_NETWORK["network"] = "devnet"
    elif change == "untrusted":
        NodeEndpoint.objects.filter(chain_id="SOL", enabled=True).update(
            url="http://127.0.0.1:9999"
        )
    elif change == "wrong_genesis":
        sol_context.rpc.genesis = str(Hash.new_unique())
    else:
        settings.MPC_SOLANA_NETWORK["genesis_source"] = "rpc"
    with pytest.raises(ValueError):
        verify_solana_endpoint("SOL", "http://127.0.0.1:8899", sol_context.rpc)


def test_expiration_null_history_never_releases_or_resigns(sol_context):
    ctx = sol_context
    signed = complete(ctx)
    signed.status = "RECONCILIATION_REQUIRED"
    signed.save()
    ctx.rpc.height = 500
    with patch("custody.reconciliation._executor", return_value=SolanaNativeExecutor(ctx.rpc)):
        result = reconcile_attempt(signed.pk)
        assert result.status == "RECONCILIATION_REQUIRED"
    assert user_balances("sol-policy", "SOL")["reserved"] == 1
    original = (result.signed_payload, result.network_tx_id, ctx.session.crypto_execution_id)
    with (
        patch("custody.signer_adapter.assert_mpc_backend_runtime_safe"),
        patch("custody.mpc_signing.advance_mpc_signing") as signing,
    ):
        result = execute_attempt(signed.pk, "worker")
        signing.assert_not_called()
    ctx.session.refresh_from_db()
    assert (
        result.signed_payload,
        result.network_tx_id,
        ctx.session.crypto_execution_id,
    ) == original
    assert MpcSigningSession.objects.filter(attempt=result).count() == 1


def test_shared_expired_result_is_nonterminal_even_for_other_executor(sol_context):
    signed = complete(sol_context)
    signed.status = "BROADCASTED"
    signed.save()
    executor = Mock()
    executor.reconcile.return_value = ReconciliationResult(ReconciliationState.EXPIRED)
    with patch("custody.reconciliation._executor", return_value=executor):
        assert reconcile_attempt(signed.pk).status == "RECONCILIATION_REQUIRED"
    assert user_balances("sol-policy", "SOL")["reserved"] == 1


@pytest.mark.parametrize("error", [None, {"InstructionError": [0, "InvalidArgument"]}])
def test_finalized_success_failure_and_cost_journals_settle_once(sol_context, error):
    ctx = sol_context
    signed = complete(ctx)
    signed.status = "BROADCASTED"
    signed.save()
    proof = finalized(signed.signed_payload, error=error)
    ctx.rpc.status, ctx.rpc.transaction = proof.status, proof.response
    with patch("custody.reconciliation._executor", return_value=SolanaNativeExecutor(ctx.rpc)):
        result = reconcile_attempt(signed.pk)
        reconcile_attempt(signed.pk)
    assert result.status == ("FAILED" if error else "CONFIRMED")
    assert user_balances("sol-policy", "SOL")["reserved"] == 0
    assert (
        LedgerTransaction.objects.filter(event_key=f"solana:{signed.pk}:network_fee").count() == 1
    )
    assert (
        LedgerTransaction.objects.filter(
            event_key=f"withdrawal:{ctx.request.pk}:{'release' if error else 'settle'}"
        ).count()
        == 1
    )


@pytest.mark.parametrize(
    "tamper", ["slot", "message", "fee", "effect", "missing_tx", "missing_status"]
)
def test_incomplete_or_mismatched_finality_cannot_settle(sol_context, tamper):
    ctx = sol_context
    signed = complete(ctx)
    signed.status = "BROADCASTED"
    signed.save()
    proof = finalized(signed.signed_payload)
    ctx.rpc.status, ctx.rpc.transaction = proof.status, proof.response
    if tamper == "slot":
        ctx.rpc.transaction["slot"] = 21
    elif tamper == "message":
        ctx.rpc.transaction["transaction"][0] = base64.b64encode(b"bad").decode()
    elif tamper == "fee":
        ctx.rpc.transaction["meta"]["fee"] = 5001
    elif tamper == "effect":
        ctx.rpc.transaction["meta"]["postBalances"][0] += 1
    elif tamper == "missing_tx":
        ctx.rpc.transaction = None
    else:
        ctx.rpc.status = None
    with patch("custody.reconciliation._executor", return_value=SolanaNativeExecutor(ctx.rpc)):
        result = reconcile_attempt(signed.pk)
    assert result.status == "RECONCILIATION_REQUIRED"
    assert user_balances("sol-policy", "SOL")["reserved"] == 1


def test_expired_before_frost_start_calls_no_coordinator(sol_context):
    ctx = sol_context
    ctx.rpc.height = 201
    client = Mock()
    with (
        patch("custody.signer_adapter.assert_mpc_backend_runtime_safe"),
        patch("custody.native_tx.RequestsTransport", return_value=ctx.rpc),
    ):
        result = advance_mpc_signing(ctx.attempt.pk, client)
    assert result.status == "RECONCILIATION_REQUIRED"
    client.create_signing_session.assert_not_called()
    assert MpcSigningSession.objects.filter(attempt=result).count() == 1


@pytest.mark.parametrize(
    "problem",
    ["mint", "owner", "delegate", "frozen", "extensions", "token2022", "balance", "decimals"],
)
def test_classic_spl_account_policy_rejects_unsupported_state(sol_context, problem):
    import struct

    from solders.pubkey import Pubkey

    from custody.solana_policy import validate_token_account
    from custody.token_metadata import CLASSIC_TOKEN_PROGRAM, TOKEN_2022_PROGRAM

    mint = str(Keypair.from_seed(bytes([27]) * 32).pubkey())
    data = bytearray(165)
    data[:32] = bytes(Pubkey.from_string(mint))
    data[32:64] = bytes(Pubkey.from_string(sol_context.source))
    struct.pack_into("<Q", data, 64, 5_000_000)
    data[108] = 1
    program = CLASSIC_TOKEN_PROGRAM
    if problem == "mint":
        data[0] ^= 1
    elif problem == "owner":
        data[32] ^= 1
    elif problem == "delegate":
        struct.pack_into("<I", data, 72, 1)
    elif problem == "frozen":
        data[108] = 2
    elif problem == "extensions":
        data += b"extension"
    elif problem == "token2022":
        program = TOKEN_2022_PROGRAM
    elif problem == "balance":
        data[108] = 0
    elif problem == "decimals":
        data[108] = 3
    account = {
        "owner": program,
        "executable": False,
        "lamports": 2039280,
        "data": [base64.b64encode(data).decode(), "base64"],
    }
    with pytest.raises(ValueError):
        validate_token_account(account, sol_context.source, mint, 6)


def test_multiple_system_transfers_have_distinct_exactly_once_deposit_journals(sol_context):
    from solders.pubkey import Pubkey
    from solders.transaction import Transaction

    from custody.deposits import ingest_event
    from custody.models import UserWallet
    from custody.solana_deposits import transfer_events

    ctx = sol_context
    wallet = UserWallet.objects.create(
        user_id="sol-deposit-units",
        chain_id="SOL",
        asset_key="SOL",
        deposit_address=ctx.destination,
        derivation_path="fixture",
    )
    donor = Keypair.from_seed(bytes([28]) * 32)
    tx = Transaction.new_signed_with_payer(
        [
            transfer(
                TransferParams(
                    from_pubkey=donor.pubkey(),
                    to_pubkey=Pubkey.from_string(ctx.destination),
                    lamports=300_000_000,
                )
            ),
            transfer(
                TransferParams(
                    from_pubkey=donor.pubkey(),
                    to_pubkey=Pubkey.from_string(ctx.destination),
                    lamports=700_000_000,
                )
            ),
        ],
        donor.pubkey(),
        [donor],
        Hash.from_string(ctx.rpc.blockhash),
    )
    keys = [str(k) for k in tx.message.account_keys]
    pre = [20 * 10**9] * len(keys)
    post = list(pre)
    post[0] -= 10**9 + 5000
    post[keys.index(ctx.destination)] += 10**9
    meta = {
        "err": None,
        "fee": 5000,
        "preBalances": pre,
        "postBalances": post,
        "innerInstructions": [],
    }
    asset = __import__("custody.models", fromlist=["Asset"]).Asset.objects.get(asset_key="SOL")
    events = transfer_events(tx, meta, 20, str(tx.signatures[0]), wallet, asset)
    assert [ev.event_index for ev in events] == ["ix:0", "ix:1"]
    for _ in range(2):
        for ev in events:
            ingest_event(wallet, ev)
    assert user_balances(wallet.user_id, "SOL")["available"] == 1
    assert (
        LedgerTransaction.objects.filter(event_type="DEPOSIT_CREDIT", ref_type="Deposit").count()
        == 2
    )


def test_rent_refunds_and_positive_deltas_are_not_native_deposits(sol_context):
    from solders.transaction import Transaction

    from custody.models import Asset
    from custody.solana_deposits import transfer_events

    donor = Keypair.from_seed(bytes([29]) * 32)
    tx = Transaction.new_signed_with_payer([], donor.pubkey(), [donor], Hash.new_unique())
    wallet = SimpleNamespace(deposit_address=sol_context.destination)
    assert (
        transfer_events(
            tx,
            {"err": None, "preBalances": [0], "postBalances": [10**9]},
            20,
            str(tx.signatures[0]),
            wallet,
            Asset.objects.get(asset_key="SOL"),
        )
        == []
    )


def test_completed_signature_recovery_after_blockhash_expiry_never_starts_rounds(sol_context):
    ctx = sol_context
    complete(ctx)
    # Reproduce worker death before consumption using the same stored completion.
    ctx.attempt.refresh_from_db()
    ctx.session.refresh_from_db()
    original_execution = ctx.session.crypto_execution_id
    ctx.session.signature_consumed_at = None
    ctx.session.save()
    ctx.attempt.status = "RECONCILIATION_REQUIRED"
    ctx.attempt.signed_payload = ""
    ctx.attempt.network_tx_id = None
    ctx.attempt.save()
    ctx.rpc.height = 500
    client = Mock()
    client.get_keyset.return_value = ctx.keyset.dkg_public_evidence
    with (
        patch("custody.signer_adapter.assert_mpc_backend_runtime_safe"),
        patch("custody.native_tx.RequestsTransport", return_value=ctx.rpc),
    ):
        result = advance_mpc_signing(ctx.attempt.pk, client)
    assert result.status == "SIGNED"
    client.execute_signing_session.assert_not_called()
    client.create_signing_session.assert_not_called()
    ctx.session.refresh_from_db()
    assert ctx.session.crypto_execution_id == original_execution
    with (
        patch("custody.signer_adapter.assert_mpc_backend_runtime_safe"),
        patch("custody.outbound._executor", return_value=SolanaNativeExecutor(ctx.rpc)),
    ):
        with pytest.raises(ValueError):
            execute_attempt(result.pk, "worker")
    result.refresh_from_db()
    assert result.status == "RECONCILIATION_REQUIRED"
    assert user_balances("sol-policy", "SOL")["reserved"] == 1


@pytest.mark.django_db(transaction=True)
def test_competing_reconciliation_workers_settle_original_solana_once(sol_context):
    from concurrent.futures import ThreadPoolExecutor

    from django.db import close_old_connections, connection

    if connection.vendor != "postgresql":
        pytest.fail("Solana concurrency regression requires PostgreSQL")
    ctx = sol_context
    signed = complete(ctx)
    signed.status = "BROADCASTED"
    signed.save()
    proof = finalized(signed.signed_payload)
    ctx.rpc.status, ctx.rpc.transaction = proof.status, proof.response

    def worker():
        close_old_connections()
        try:
            return reconcile_attempt(signed.pk).status
        finally:
            close_old_connections()

    with (
        patch("custody.reconciliation._executor", return_value=SolanaNativeExecutor(ctx.rpc)),
        ThreadPoolExecutor(max_workers=3) as pool,
    ):
        list(pool.map(lambda _: worker(), range(3)))
    signed.refresh_from_db()
    assert signed.status == "CONFIRMED"
    assert (
        LedgerTransaction.objects.filter(event_key=f"withdrawal:{ctx.request.pk}:settle").count()
        == 1
    )
    assert (
        LedgerTransaction.objects.filter(event_key=f"solana:{signed.pk}:network_fee").count() == 1
    )


def test_bounded_backfill_cursor_and_credits_commit_together(sol_context, monkeypatch):
    from solders.transaction import Transaction

    from custody.indexer_service import scan_wallet
    from custody.models import UserWallet
    from custody.solana_deposits import scan_root_wallet

    private, keyset = root(24)
    wallet = UserWallet.objects.create(
        user_id="sol-backfill",
        chain_id="SOL",
        asset_key="SOL",
        deposit_address=str(private.pubkey()),
        derivation_path=f"keyset:{keyset.keyset_id}",
        derivation_version="mpc_root_v1",
        mpc_keyset=keyset,
    )
    donor = Keypair.from_seed(bytes([31]) * 32)
    summaries = []
    proofs = {}
    for slot in range(501, 0, -1):
        tx = Transaction.new_signed_with_payer(
            [
                transfer(
                    TransferParams(
                        from_pubkey=donor.pubkey(), to_pubkey=private.pubkey(), lamports=1_000_000
                    )
                )
            ],
            donor.pubkey(),
            [donor],
            Hash.from_bytes(slot.to_bytes(32, "little")),
        )
        signature = str(tx.signatures[0])
        proof = finalized(bytes(tx).hex(), slot=slot, amount=1_000_000)
        summaries.append({"signature": signature, "slot": slot, "err": None})
        proofs[signature] = proof

    class ScanRpc(SolRpc):
        def rpc(self, url, method, params):
            if method == "getFirstAvailableBlock":
                return 0
            if method == "getSlot":
                return 600
            if method == "getSignaturesForAddress":
                before = params[1].get("before")
                start = (
                    0
                    if not before
                    else next(i for i, s in enumerate(summaries) if s["signature"] == before) + 1
                )
                return summaries[start : start + 100]
            if method == "getSignatureStatuses":
                return {"value": [proofs[params[0][0]].status]}
            if method == "getTransaction":
                return proofs[params[0]].response
            return super().rpc(url, method, params)

    rpc = ScanRpc(sol_context.source, wallet.deposit_address, sol_context.rpc.genesis)
    monkeypatch.setenv("CUSTODY_INDEXER_MODE", "live")
    with (
        patch(
            "custody.indexer.sol.SolIndexer.get_balance",
            side_effect=lambda address, **kw: scan_root_wallet(
                "SOL", address, "SOL", kw.get("after_block"), transport=rpc
            ),
        ),
        patch("custody.indexer_service.trigger_sweep", return_value=(False, None, "test")),
    ):
        first = scan_wallet(wallet)
        assert first["outcome"] == "backfill"
        wallet.refresh_from_db()
        assert wallet.solana_scan_cursor and wallet.last_scanned_block is None
        assert user_balances(wallet.user_id, "SOL")["available"] == Decimal("0.4")
        second = scan_wallet(wallet)
        wallet.refresh_from_db()
        assert second["new_deposits"] == 101
        assert wallet.last_scanned_block == 600 and wallet.solana_scan_cursor == {}
        assert user_balances(wallet.user_id, "SOL")["available"] == Decimal("0.501")
        # Repeat the overlap: durable event uniqueness retains the exact credit count.
        scan_wallet(wallet)
        assert user_balances(wallet.user_id, "SOL")["available"] == Decimal("0.501")


def test_missing_finalized_deposit_history_keeps_cursor_and_ledger_unchanged(
    sol_context, monkeypatch
):
    from custody.indexer.base import IndexerUnavailable
    from custody.models import UserWallet
    from custody.solana_deposits import scan_root_wallet

    private, keyset = root(24)
    wallet = UserWallet.objects.create(
        user_id="sol-history-gap",
        chain_id="SOL",
        asset_key="SOL",
        deposit_address=str(private.pubkey()),
        derivation_path=f"keyset:{keyset.keyset_id}",
        derivation_version="mpc_root_v1",
        mpc_keyset=keyset,
    )
    rpc = sol_context.rpc
    rpc.responses.update(
        {
            "getFirstAvailableBlock": 0,
            "getSlot": 30,
            "getSignaturesForAddress": [
                {"signature": str(private.sign_message(b"fixture")), "slot": 20, "err": None}
            ],
        }
    )
    monkeypatch.setenv("CUSTODY_INDEXER_MODE", "live")
    with pytest.raises(IndexerUnavailable):
        scan_root_wallet("SOL", wallet.deposit_address, "SOL", None, transport=rpc)
    wallet.refresh_from_db()
    assert wallet.solana_scan_cursor == {} and wallet.last_scanned_block is None
    assert not LedgerTransaction.objects.filter(ref_type="Deposit").exists()


@pytest.mark.parametrize("remaining", [1, 890879])
def test_preparation_rejects_nonzero_source_below_rent_minimum(sol_context, remaining):
    from custody.native_tx import InsufficientBalance

    ctx = sol_context
    ctx.rpc.responses["getAccountInfo"] = {
        "value": {
            "owner": "11111111111111111111111111111111",
            "executable": False,
            "data": ["", "base64"],
            "lamports": 1_000_000_000 + 5000 + remaining,
        }
    }
    with pytest.raises(InsufficientBalance, match="source remainder"):
        SolanaNativeExecutor(ctx.rpc).prepare(
            "SOL", "SOL", ctx.source, ctx.destination, Decimal("1")
        )
    swept = SolanaNativeExecutor(ctx.rpc).prepare(
        "SOL", "SOL", ctx.source, ctx.destination, Decimal("1"), sweep=True
    )
    assert swept.base_unit_amount == 1_000_000_000 + remaining - 890880
    assert swept.fee_metadata["source_rent_minimum_lamports"] == "890880"


@pytest.mark.parametrize(
    "tamper", [None, "mint", "owner", "index", "amount", "rent", "rollback", "token2022"]
)
def test_classic_finalized_token_effects_require_consistent_metadata(sol_context, tamper):
    from solders.transaction import Transaction

    from custody.solana_settlement import validate_effect
    from custody.solana_wire import build_message
    from custody.spl import derive_ata
    from custody.token_metadata import CLASSIC_TOKEN_PROGRAM, TOKEN_2022_PROGRAM

    ctx = sol_context
    mint = str(Keypair().pubkey())
    message = build_message(
        ctx.source, ctx.destination, 500, ctx.rpc.blockhash, mint=mint, decimals=9
    )
    # Populate exactly the approved message rather than a separate reconstruction.
    signed, _ = assemble_signature(
        base64.b64encode(message).decode(),
        ctx.keyset.public_key,
        bytes(ctx.private.sign_message(message)).hex(),
    )
    tx = Transaction.from_bytes(bytes.fromhex(signed))
    keys = [str(k) for k in tx.message.account_keys]
    source = keys.index(derive_ata(ctx.source, mint))
    destination = keys.index(derive_ata(ctx.destination, mint))
    raw = {
        "message": base64.b64encode(message).decode(),
        "recentBlockhash": ctx.rpc.blockhash,
        "mint": mint,
        "sourceAta": keys[source],
        "destinationAta": keys[destination],
        "createDestinationAta": False,
    }

    def balance(index, owner, units):
        return {
            "accountIndex": index,
            "mint": mint,
            "programId": CLASSIC_TOKEN_PROGRAM,
            "owner": owner,
            "uiTokenAmount": {"amount": str(units), "decimals": 9},
        }

    pre = [10_000_000] * len(keys)
    post = list(pre)
    post[0] -= 5000
    meta = {
        "err": None,
        "fee": 5000,
        "preBalances": pre,
        "postBalances": post,
        "preTokenBalances": [
            balance(source, ctx.source, 1000),
            balance(destination, ctx.destination, 0),
        ],
        "postTokenBalances": [
            balance(source, ctx.source, 500),
            balance(destination, ctx.destination, 500),
        ],
    }
    prepared = SimpleNamespace(
        unsigned_payload=raw,
        from_address=ctx.source,
        to_address=ctx.destination,
        base_unit_amount=500,
        asset_key="SOL",
        fee_metadata={"fee_lamports": "5000", "ata_rent_lamports": "0"},
    )
    if tamper == "mint":
        meta["postTokenBalances"][1]["mint"] = str(Keypair().pubkey())
    elif tamper == "owner":
        meta["postTokenBalances"][1]["owner"] = ctx.source
    elif tamper == "index":
        meta["postTokenBalances"][1]["accountIndex"] = source
    elif tamper == "amount":
        meta["postTokenBalances"][1]["uiTokenAmount"]["amount"] = "501"
    elif tamper == "rent":
        post[destination] += 1
    elif tamper == "rollback":
        meta["err"] = {"InstructionError": [0, "InsufficientFunds"]}
    elif tamper == "token2022":
        meta["postTokenBalances"][1]["programId"] = TOKEN_2022_PROGRAM
    if tamper:
        with pytest.raises(ValueError):
            validate_effect(prepared, tx, meta)
    else:
        assert validate_effect(prepared, tx, meta)["effect"] == "classic_transfer_checked"
