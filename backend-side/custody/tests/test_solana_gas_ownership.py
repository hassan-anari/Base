"""Final Solana gas authorization and durable retry regressions (PostgreSQL)."""

import copy
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from django.db import close_old_connections, connection
from ops.models import Chain

from custody.gas_station import admin_topup, execute_gas_intent, get_or_create_gas_intent
from custody.ledger import user_balances
from custody.models import (
    GasTopupIntent,
    HotWallet,
    MpcSigningSession,
    OnchainTransactionAttempt,
    UserWallet,
)
from custody.mpc_binding import MpcBindingError, validate_custody_intent
from custody.native_tx import AmbiguousBroadcast, SolanaNativeExecutor
from custody.outbound import create_attempt, execute_attempt
from custody.reconciliation import reconcile_attempt

from .solana_fixture import root
from .test_phase6fb_solana import complete, sol_context  # noqa: F401


@pytest.fixture
def grant(sol_context):  # noqa: F811 - imported pytest fixture
    ctx = sol_context
    _, recipient_keyset = root(24)
    wallet = UserWallet.objects.create(
        user_id="gas-recipient",
        chain_id="SOL",
        asset_key="SOL",
        deposit_address=ctx.destination,
        mpc_keyset=recipient_keyset,
        derivation_path=f"keyset:{recipient_keyset.keyset_id}",
        derivation_version="mpc_root_v1",
    )
    chain = Chain.objects.get(chain_id="SOL")
    chain.gas_settings = {**chain.gas_settings, "topup_amount": "0.01"}
    chain.save()
    intent = get_or_create_gas_intent(wallet, idempotency_key="owned-grant")
    return SimpleNamespace(ctx=ctx, wallet=wallet, keyset=recipient_keyset, intent=intent)


def attempt_for(grant):
    GasTopupIntent.objects.filter(pk=grant.intent.pk).update(status="PROCESSING")
    return create_attempt(
        operation_type="GAS_TOPUP",
        operation_id=grant.intent.pk,
        chain_id="SOL",
        asset_key="SOL",
        source=grant.ctx.source,
        destination=grant.wallet.deposit_address,
        amount=grant.intent.amount,
    )


def corrupt(grant, problem):
    wallet, keyset = grant.wallet, grant.keyset
    if problem == "unbound":
        wallet.mpc_keyset = None
    elif problem == "wrong_keyset":
        wallet.mpc_keyset = grant.ctx.keyset
        wallet.derivation_path = f"keyset:{grant.ctx.keyset.keyset_id}"
    elif problem in {"address", "case"}:
        wallet.deposit_address = (
            grant.ctx.source if problem == "address" else wallet.deposit_address.swapcase()
        )
        GasTopupIntent.objects.filter(pk=grant.intent.pk).update(to_address=wallet.deposit_address)
    elif problem == "child":
        wallet.derivation_path += "/0"
    elif problem == "derivation_version":
        wallet.derivation_version = "frost_keyset_v1"
    elif problem == "inactive_wallet":
        wallet.status = "RETIRED"
    elif problem == "retired":
        keyset.status = "RETIRED"
    elif problem == "malformed":
        keyset.dkg_public_evidence = {}
    elif problem == "receipt":
        evidence = copy.deepcopy(keyset.dkg_public_evidence)
        evidence["participant_agreement"][2]["group_public_key"] = grant.ctx.keyset.public_key
        keyset.dkg_public_evidence = evidence
    elif problem == "original_public_key":
        keyset.public_key = grant.ctx.keyset.public_key
    elif problem == "wrong_family":
        keyset.algorithm, keyset.curve, keyset.scope, keyset.derivation_version = (
            "CGGMP24_ECDSA",
            "secp256k1",
            "EVM",
            "cggmp_hd_v1",
        )
    elif problem in {"unbound_record", "conflicting_record"}:
        _, other = root(24)
        UserWallet.objects.create(
            user_id="conflicting-token-record",
            chain_id="SOL",
            asset_key="CLASSIC-SPL",
            deposit_address=wallet.deposit_address,
            mpc_keyset=other if problem == "conflicting_record" else None,
            derivation_path=f"keyset:{other.keyset_id}",
            derivation_version="mpc_root_v1",
        )
    else:
        field, value = {
            "threshold": ("threshold", 3),
            "party_count": ("party_count", 2),
        }[problem]
        setattr(keyset, field, value)
    keyset.save()
    wallet.save()


@pytest.mark.parametrize("route", ["administrative", "automatic"])
@pytest.mark.parametrize(
    "problem",
    [
        "unbound",
        "wrong_keyset",
        "address",
        "case",
        "child",
        "derivation_version",
        "inactive_wallet",
        "retired",
        "malformed",
        "receipt",
        "original_public_key",
        "wrong_family",
        "threshold",
        "party_count",
        "unbound_record",
        "conflicting_record",
    ],
)
def test_unauthorized_funding_has_no_signing_or_broadcast(grant, route, problem):
    corrupt(grant, problem)
    sessions_before = MpcSigningSession.objects.count()
    coordinator = Mock()
    executor = SolanaNativeExecutor(grant.ctx.rpc)
    with (
        patch("custody.signer_adapter.assert_mpc_backend_runtime_safe"),
        patch("custody.signer_adapter.get_adapter", return_value=coordinator),
        patch("custody.outbound._executor", return_value=executor),
        patch.object(executor, "broadcast") as broadcast,
    ):
        with pytest.raises(ValueError):
            if route == "administrative":
                admin_topup(
                    "admin", "SOL", grant.wallet.deposit_address, Decimal("0.01"), "admin-grant"
                )
            else:
                execute_gas_intent(grant.intent.pk)
    assert MpcSigningSession.objects.count() == sessions_before
    assert not coordinator.mock_calls
    broadcast.assert_not_called()
    assert not any(method == "sendTransaction" for _, method, _ in grant.ctx.rpc.calls)
    attempts = OnchainTransactionAttempt.objects.filter(operation_type="GAS_TOPUP")
    assert not attempts.exclude(signed_payload="").exists()
    assert not MpcSigningSession.objects.filter(attempt__in=attempts).exists()


def test_valid_root_and_all_matching_records_are_checked(grant):
    attempt = attempt_for(grant)
    validate_custody_intent(attempt)
    duplicate = UserWallet.objects.create(
        user_id="same-authority-token",
        chain_id="SOL",
        asset_key="CLASSIC-SPL",
        deposit_address=grant.wallet.deposit_address,
        mpc_keyset=grant.keyset,
        derivation_path=grant.wallet.derivation_path,
        derivation_version="mpc_root_v1",
    )
    validate_custody_intent(attempt)
    duplicate.mpc_keyset = None
    duplicate.save()
    with pytest.raises(MpcBindingError):
        validate_custody_intent(attempt)
    # Even individually coherent evidence for a different root cannot override a record.
    _, other = root(24)
    duplicate.mpc_keyset, duplicate.derivation_path = other, f"keyset:{other.keyset_id}"
    duplicate.save()
    with pytest.raises(MpcBindingError, match="conflicting"):
        validate_custody_intent(attempt)


def test_hot_destination_requires_root_and_does_not_hide_invalid_user_record(grant):
    attempt = attempt_for(grant)
    attempt.to_address = grant.ctx.source
    GasTopupIntent.objects.filter(pk=grant.intent.pk).update(to_address=attempt.to_address)
    validate_custody_intent(attempt)
    hot = HotWallet.objects.get(chain_id="SOL")
    hot.mpc_keyset = None
    hot.save()
    with pytest.raises(MpcBindingError):
        validate_custody_intent(attempt)
    hot.mpc_keyset = grant.ctx.keyset
    hot.save()
    UserWallet.objects.create(
        user_id="unbound-hot-record",
        chain_id="SOL",
        asset_key="CLASSIC-SPL",
        deposit_address=hot.address,
        derivation_path="unbound",
    )
    with pytest.raises(MpcBindingError):
        validate_custody_intent(attempt)


def signed_grant(grant):
    attempt = attempt_for(grant)
    ctx = grant.ctx
    prepared = SolanaNativeExecutor(ctx.rpc).prepare(
        "SOL", "SOL", ctx.source, grant.wallet.deposit_address, grant.intent.amount
    )
    attempt.prepared_metadata, attempt.fee_metadata = (
        prepared.unsigned_payload,
        prepared.fee_metadata,
    )
    attempt.last_valid_block, attempt.status = prepared.last_valid_block, "SIGNING"
    attempt.save()
    from custody.mpc_binding import identity_fingerprint, transaction_identity

    session = ctx.session
    session.attempt = attempt
    session.signing_payload = prepared.signing_payload
    session.message_fingerprint = hashlib.sha256(prepared.signing_payload).hexdigest()
    session.transaction_identity = transaction_identity(attempt, ctx.keyset)
    session.coordinator_request_id = identity_fingerprint(session.transaction_identity)
    session.save()
    ctx.attempt = attempt
    return complete(ctx)


def test_signed_grant_revalidates_destination_before_broadcast(grant):
    signed = signed_grant(grant)
    original = (signed.signed_payload, signed.network_tx_id)
    sessions_before = MpcSigningSession.objects.count()
    grant.wallet.mpc_keyset = None
    grant.wallet.save()
    executor = SolanaNativeExecutor(grant.ctx.rpc)
    with (
        patch("custody.signer_adapter.assert_mpc_backend_runtime_safe"),
        patch("custody.outbound._executor", return_value=executor),
        patch.object(executor, "broadcast") as broadcast,
        patch("custody.mpc_signing.advance_mpc_signing") as signing,
    ):
        assert execute_attempt(signed.pk, "worker").status == "RECONCILIATION_REQUIRED"
        broadcast.assert_not_called()
        signing.assert_not_called()
    signed.refresh_from_db()
    assert (signed.signed_payload, signed.network_tx_id) == original
    assert MpcSigningSession.objects.count() == sessions_before


@pytest.mark.django_db(transaction=True)
def test_concurrent_funding_then_ambiguous_expiry_preserves_original_intent(grant):
    assert connection.vendor == "postgresql"
    signed = signed_grant(grant)
    session = MpcSigningSession.objects.get(attempt=signed)
    original = (
        signed.pk,
        session.session_id,
        session.crypto_execution_id,
        signed.signed_payload,
        signed.network_tx_id,
    )
    reserved = user_balances("sol-policy", "SOL")["reserved"]
    entered, release = threading.Event(), threading.Event()
    executor = SolanaNativeExecutor(grant.ctx.rpc)

    def lost_response(*args):
        entered.set()
        assert release.wait(15)
        raise AmbiguousBroadcast("accepted response lost")

    def worker():
        close_old_connections()
        try:
            return execute_attempt(signed.pk, "system:gas_station")
        finally:
            close_old_connections()

    with (
        patch("custody.signer_adapter.assert_mpc_backend_runtime_safe"),
        patch("custody.outbound._executor", return_value=executor),
        patch.object(executor, "broadcast", side_effect=lost_response) as broadcast,
        ThreadPoolExecutor(max_workers=2) as pool,
    ):
        first = pool.submit(worker)
        assert entered.wait(15)
        assert pool.submit(worker).result(timeout=15).status == "BROADCASTING"
        release.set()
        with pytest.raises(AmbiguousBroadcast):
            first.result(timeout=15)
        broadcast.assert_called_once()
    grant.ctx.rpc.height = 500
    with patch("custody.reconciliation._executor", return_value=executor):
        assert reconcile_attempt(signed.pk).status == "RECONCILIATION_REQUIRED"
    with patch("custody.mpc_signing.advance_mpc_signing") as signing:
        for _ in range(3):
            assert not execute_gas_intent(grant.intent.pk)
        signing.assert_not_called()
    assert (
        get_or_create_gas_intent(grant.wallet, idempotency_key="owned-grant").pk == grant.intent.pk
    )
    grant.intent.refresh_from_db()
    signed.refresh_from_db()
    session.refresh_from_db()
    assert grant.intent.status == "RECONCILIATION_REQUIRED"
    assert (
        signed.pk,
        session.session_id,
        session.crypto_execution_id,
        signed.signed_payload,
        signed.network_tx_id,
    ) == original
    assert user_balances("sol-policy", "SOL")["reserved"] == reserved == 1
    assert OnchainTransactionAttempt.objects.filter(operation_type="GAS_TOPUP").count() == 1
    assert MpcSigningSession.objects.filter(attempt=signed).count() == 1
