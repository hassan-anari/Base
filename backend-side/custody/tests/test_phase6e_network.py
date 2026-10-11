"""Network authorization regressions; no cryptographic acceptance claim from these mocks."""

from decimal import Decimal
from unittest.mock import Mock, patch

import pytest
import requests
from ops.models import Chain, NodeEndpoint

from custody.ledger import user_balances
from custody.models import Asset, MpcSigningSession, SourceAccountSequence
from custody.mpc_evm_network import (
    PUBLIC_TESTNETS,
    MpcNetworkError,
    authorize_evm_network,
    verify_evm_rpc_endpoints,
)
from custody.mpc_signing import advance_mpc_signing
from custody.native_tx import EvmNativeExecutor, PreparationError, RequestsTransport
from custody.outbound import execute_attempt
from custody.reconciliation import reconcile_attempt
from custody.signer_adapter import assert_mpc_backend_runtime_safe
from custody.token_tx import Erc20Executor

from .test_phase6_signing import CoordinatorClient
from .test_phase6_signing import context as context
from .test_phase6_signing import integration_settings as integration_settings

RAW_RPC = RequestsTransport.rpc


def preparing(context):
    context.session.delete()
    context.attempt.status = "PREPARING"
    context.attempt.sequence = None
    context.attempt.prepared_metadata = {}
    context.attempt.save()


def complete(context):
    client = CoordinatorClient(context)
    advance_mpc_signing(context.attempt.pk, client)
    client.complete()
    advance_mpc_signing(context.attempt.pk, client)
    context.attempt.refresh_from_db()
    assert context.attempt.status == "SIGNED"
    return client


@pytest.mark.parametrize("numeric", [1, 10, 56, 137, 42161, 8453, 43114])
def test_mislabeled_mainnet_rejected_before_preparation_or_signing(context, settings, numeric):
    preparing(context)
    settings.MPC_EVM_DEVELOPMENT_CHAINS = {"ETH": numeric}
    NodeEndpoint.objects.filter(chain_id="ETH", enabled=True).update(url="http://127.0.0.1:8545")
    Chain.objects.filter(chain_id="ETH").update(evm_chain_id=numeric, is_testnet=True)
    with (
        patch("custody.outbound._executor") as executor,
        patch("custody.signer_adapter.get_adapter") as coordinator,
    ):
        with pytest.raises(MpcNetworkError, match="testnet allowlist"):
            execute_attempt(context.attempt.pk, "worker")
        executor.assert_not_called()
        coordinator.assert_not_called()
    assert not SourceAccountSequence.objects.filter(chain_id="ETH").exists()
    assert not MpcSigningSession.objects.filter(attempt=context.attempt).exists()
    assert user_balances("phase6e", "ETH")["reserved"] == 1


@pytest.mark.parametrize("numeric", [10, 250, 324, 1101, 1337, 999, 31339, 11155112])
def test_matching_rpc_cannot_authorize_disallowed_development_identity(context, settings, numeric):
    settings.MPC_EVM_DEVELOPMENT_CHAINS = {"ETH": numeric}
    Chain.objects.filter(chain_id="ETH").update(evm_chain_id=numeric)
    NodeEndpoint.objects.filter(chain_id="ETH", enabled=True).update(url="http://127.0.0.1:8545")
    transport = Mock()
    transport.rpc.return_value = hex(numeric)
    with pytest.raises(MpcNetworkError, match="testnet allowlist"):
        verify_evm_rpc_endpoints("ETH", transport)
    transport.rpc.assert_not_called()


@pytest.mark.parametrize("state", ["SIGNING", "SIGNED"])
def test_mainnet_override_cannot_execute_session_or_broadcast(context, settings, state):
    context.attempt.status = state
    context.attempt.save()
    settings.MPC_EVM_DEVELOPMENT_CHAINS = {"ETH": 10}
    Chain.objects.filter(chain_id="ETH").update(evm_chain_id=10)
    NodeEndpoint.objects.filter(chain_id="ETH", enabled=True).update(url="http://127.0.0.1:8545")
    client = CoordinatorClient(context)
    with pytest.raises(MpcNetworkError, match="testnet allowlist"):
        advance_mpc_signing(context.attempt.pk, client)
    assert not client.creates and not client.executes
    with patch("custody.outbound._executor") as executor:
        with pytest.raises(MpcNetworkError, match="testnet allowlist"):
            execute_attempt(context.attempt.pk, "worker")
        executor.assert_not_called()
    context.attempt.refresh_from_db()
    context.session.refresh_from_db()
    assert context.attempt.sequence == 7 and context.session.crypto_execution_id is None
    assert not SourceAccountSequence.objects.filter(chain_id="ETH").exists()
    assert user_balances("phase6e", "ETH")["reserved"] == 1


@pytest.mark.parametrize("alias,numeric", list(PUBLIC_TESTNETS.items()))
def test_reviewed_public_testnet_identity_accepted(context, settings, alias, numeric):
    settings.MPC_INTEGRATION_ENVIRONMENT = "testnet"
    settings.MPC_EVM_DEVELOPMENT_CHAINS = {}
    settings.MPC_EVM_GENESIS_HASHES = {}
    native = Asset.objects.filter(chain_id=alias, is_native=True).first()
    key = native.asset_key if native else f"TEST-{alias}"
    Asset.objects.update_or_create(
        asset_key=key,
        defaults={"chain_id": alias, "is_native": True, "decimals": 18, "enabled": True},
    )
    Chain.objects.update_or_create(
        chain_id=alias,
        defaults={
            "display_name": alias,
            "kind": "evm",
            "is_testnet": True,
            "enabled": True,
            "evm_chain_id": numeric,
            "native_asset_key": key,
        },
    )
    NodeEndpoint.objects.filter(chain_id=alias, kind="rpc").update(enabled=False)
    NodeEndpoint.objects.create(
        chain_id=alias, name="reviewed-testnet", kind="rpc", url="https://testnet.example/rpc"
    )
    assert_mpc_backend_runtime_safe(alias)
    transport = Mock()
    transport.rpc.return_value = hex(numeric)
    verify_evm_rpc_endpoints(alias, transport)
    assert authorize_evm_network(alias).evm_chain_id == numeric


@pytest.mark.parametrize(
    "environment,authorization",
    [
        ("testnet", {"ETH": 31337}),
        ("development", {}),
        ("development", {"ETH": "31337"}),
        ("development", {"ETH": True}),
    ],
)
def test_custom_identity_requires_exact_development_authorization(
    context, settings, environment, authorization
):
    settings.MPC_INTEGRATION_ENVIRONMENT = environment
    settings.MPC_EVM_DEVELOPMENT_CHAINS = authorization
    with pytest.raises(MpcNetworkError, match="testnet allowlist"):
        assert_mpc_backend_runtime_safe("ETH")


@pytest.mark.parametrize(
    "url",
    [
        "https://mainnet.example/rpc",
        "http://10.0.0.1:8545",
        "http://localhost:8545",
        "http://127.0.0.1.evil.example:8545",
        "http://user:password@127.0.0.1:8545",
        "http://127.0.0.1:8545/#external",
    ],
)
def test_custom_network_rejects_nonliteral_or_nonloopback_endpoints(context, url):
    NodeEndpoint.objects.filter(chain_id="ETH", enabled=True).update(url=url)
    with pytest.raises(MpcNetworkError, match="literal loopback"):
        execute_attempt(context.attempt.pk, "worker")
    context.session.refresh_from_db()
    assert context.session.crypto_execution_id is None
    assert context.attempt.sequence == 7


@pytest.mark.parametrize("numeric", [31337, 31338])
@pytest.mark.parametrize("url", ["http://127.0.0.1:8545", "http://[::1]:8545"])
def test_explicit_loopback_development_chain_accepted(context, settings, url, numeric):
    settings.MPC_EVM_DEVELOPMENT_CHAINS = {"ETH": numeric}
    Chain.objects.filter(chain_id="ETH").update(evm_chain_id=numeric)
    NodeEndpoint.objects.filter(chain_id="ETH", enabled=True).update(url=url)
    assert_mpc_backend_runtime_safe("ETH")
    transport = Mock()
    transport.rpc.side_effect = lambda url, method, params: (
        {"hash": "0x" + "11" * 32} if method == "eth_getBlockByNumber" else hex(numeric)
    )
    verify_evm_rpc_endpoints("ETH", transport)


@pytest.mark.parametrize("genesis", [None, "0x0", "0x" + "00" * 32, "0x" + "AA" * 32])
def test_isolated_evm_unknown_genesis_fails_closed(context, settings, genesis):
    settings.MPC_EVM_GENESIS_HASHES = {} if genesis is None else {"ETH": genesis}
    with pytest.raises(MpcNetworkError, match="approved genesis"):
        verify_evm_rpc_endpoints("ETH", Mock())
    assert user_balances("phase6e", "ETH")["reserved"] == 1


def test_same_numeric_evm_changed_genesis_cannot_rebind_root(context, settings):
    from custody.mpc_binding import MpcBindingError, local_root_keyset

    local_root_keyset(context.attempt)
    settings.MPC_EVM_GENESIS_HASHES = {"ETH": "0x" + "22" * 32}
    with pytest.raises(MpcBindingError, match="cannot be replaced"):
        local_root_keyset(context.attempt)
    assert user_balances("phase6e", "ETH")["reserved"] == 1


def test_matching_numeric_evm_wrong_rpc_genesis_rejected(context):
    transport = Mock()
    transport.rpc.side_effect = lambda url, method, params: (
        {"hash": "0x" + "22" * 32} if method == "eth_getBlockByNumber" else "0x7a69"
    )
    with pytest.raises(MpcNetworkError, match="RPC genesis"):
        verify_evm_rpc_endpoints("ETH", transport)


def test_signed_evm_original_confirmation_requirement_cannot_be_reduced(context):
    complete(context)
    original = (
        context.attempt.signed_payload,
        context.attempt.sequence,
        context.session.session_id,
    )
    Chain.objects.filter(chain_id="ETH").update(min_confirmations=1)
    with patch("custody.reconciliation._executor") as executor:
        with pytest.raises(ValueError, match="immutable MPC transaction identity"):
            reconcile_attempt(context.attempt.pk)
        executor.assert_not_called()
    context.attempt.refresh_from_db()
    assert context.attempt.status == "RECONCILIATION_REQUIRED"
    assert (
        context.attempt.signed_payload,
        context.attempt.sequence,
        context.session.session_id,
    ) == original
    assert user_balances("phase6e", "ETH")["reserved"] == 1


@pytest.mark.parametrize("receipt_status,event_count", [("0x0", 0), ("0x1", 1)])
def test_native_deposit_requires_successful_matching_receipt(context, receipt_status, event_count):
    from custody.indexer.evm_live import evm_get_balance

    txid, block_hash = "0x" + "ab" * 32, "0x" + "cd" * 32

    def rpc(url, method, params):
        if method == "eth_chainId":
            return "0x7a69"
        if method == "eth_blockNumber":
            return "0xe"
        if method == "eth_getBalance":
            return "0x0"
        if method == "eth_getBlockByNumber":
            if params == ["0x0", False]:
                return {"hash": "0x" + "11" * 32}
            return {
                "number": params[0],
                "hash": block_hash,
                "parentHash": block_hash,
                "transactions": [
                    {"to": context.attempt.from_address, "value": "0x64", "hash": txid}
                ]
                if params[0] == "0x2"
                else [],
            }
        assert method == "eth_getTransactionReceipt"
        return {
            "status": receipt_status,
            "transactionHash": txid,
            "blockHash": block_hash,
            "blockNumber": "0x2",
        }

    with patch("custody.native_tx.RequestsTransport.rpc", side_effect=rpc):
        events = evm_get_balance("ETH", context.attempt.from_address).deposit_events
    assert len(events) == event_count
    if events:
        assert events[0].block_hash == block_hash


def test_is_testnet_flag_is_required_but_not_sufficient(context):
    Chain.objects.filter(chain_id="ETH").update(evm_chain_id=11155111, is_testnet=False)
    with pytest.raises(MpcNetworkError):
        assert_mpc_backend_runtime_safe("ETH")


def test_mislabeled_mainnet_rpc_rejected_before_nonce_or_mpc(context):
    preparing(context)
    Chain.objects.filter(chain_id="ETH").update(evm_chain_id=11155111)
    NodeEndpoint.objects.filter(chain_id="ETH", enabled=True).update(
        url="https://optimism-mainnet.example/rpc"
    )
    with patch("custody.outbound._executor") as executor:
        executor.return_value.transport.rpc.return_value = "0xa"
        with pytest.raises(MpcNetworkError, match="RPC chain ID"):
            execute_attempt(context.attempt.pk, "worker")
        executor.return_value.prepare.assert_not_called()
        executor.return_value.broadcast.assert_not_called()
    assert not SourceAccountSequence.objects.filter(chain_id="ETH").exists()
    assert not MpcSigningSession.objects.filter(attempt=context.attempt).exists()


def test_fallback_mismatch_prevents_mpc_execution_and_preserves_session(context):
    NodeEndpoint.objects.create(
        chain_id="ETH", name="fallback", kind="rpc", url="http://127.0.0.1:18546"
    )
    client = CoordinatorClient(context)
    with patch(
        "custody.native_tx.RequestsTransport.rpc",
        side_effect=lambda url, method, params: "0xa" if url.endswith("18546") else "0x7a69",
    ):
        assert advance_mpc_signing(context.attempt.pk, client).status == "RECONCILIATION_REQUIRED"
        assert advance_mpc_signing(context.attempt.pk, client).status == "RECONCILIATION_REQUIRED"
    assert not client.creates and not client.executes
    context.attempt.refresh_from_db()
    assert context.attempt.sequence == 7
    assert MpcSigningSession.objects.filter(attempt=context.attempt).count() == 1
    assert user_balances("phase6e", "ETH")["reserved"] == 1


def test_actual_failover_endpoint_is_checked_after_ambiguous_primary_broadcast(context):
    client = complete(context)
    original = (context.attempt.signed_payload, context.attempt.sequence, context.session.pk)
    NodeEndpoint.objects.filter(chain_id="ETH", enabled=True).update(is_primary=True)
    NodeEndpoint.objects.create(
        chain_id="ETH", name="fallback", kind="rpc", url="http://127.0.0.1:18546"
    )
    calls = []
    fallback_checks = 0

    def rpc(url, method, params):
        nonlocal fallback_checks
        calls.append((url, method, params))
        if method == "eth_chainId":
            if url.endswith("18546"):
                fallback_checks += 1
                return "0x7a69" if fallback_checks == 1 else "0xa"
            return "0x7a69"
        if method == "eth_getBlockByNumber":
            return {"hash": "0x" + "11" * 32}
        assert method == "eth_sendRawTransaction" and url.endswith("18545")
        raise requests.Timeout("ambiguous primary response")

    transport = Mock()
    transport.rpc.side_effect = rpc
    with patch("custody.outbound._executor", return_value=EvmNativeExecutor(transport)):
        with pytest.raises(MpcNetworkError, match="RPC chain ID"):
            execute_attempt(context.attempt.pk, "worker")
        assert execute_attempt(context.attempt.pk, "worker").status == "RECONCILIATION_REQUIRED"
    context.attempt.refresh_from_db()
    assert (
        context.attempt.signed_payload,
        context.attempt.sequence,
        context.session.pk,
    ) == original
    sends = [c for c in calls if c[1] == "eth_sendRawTransaction"]
    assert len(sends) == 1 and sends[0][2] == ["0x" + original[0]]
    assert len(client.executes) == 1
    assert user_balances("phase6e", "ETH")["reserved"] == 1


def test_fallback_mismatch_before_preparation_allocates_no_nonce(context):
    preparing(context)
    NodeEndpoint.objects.create(
        chain_id="ETH", name="fallback", kind="rpc", url="http://127.0.0.1:18546"
    )
    with patch("custody.outbound._executor") as executor:
        executor.return_value.transport.rpc.side_effect = lambda url, method, params: (
            "0xa" if url.endswith("18546") else "0x7a69"
        )
        with pytest.raises(MpcNetworkError, match="RPC chain ID"):
            execute_attempt(context.attempt.pk, "worker")
        executor.return_value.prepare.assert_not_called()
        executor.return_value.broadcast.assert_not_called()
    assert not SourceAccountSequence.objects.filter(chain_id="ETH").exists()
    assert not MpcSigningSession.objects.filter(attempt=context.attempt).exists()


def test_network_uncertainty_resumes_same_existing_crypto_execution(context):
    client = CoordinatorClient(context)
    advance_mpc_signing(context.attempt.pk, client)
    context.session.refresh_from_db()
    execution = context.session.crypto_execution_id
    with patch("custody.native_tx.RequestsTransport.rpc", return_value="0xa"):
        assert advance_mpc_signing(context.attempt.pk, client).status == "RECONCILIATION_REQUIRED"
    client.complete()
    assert advance_mpc_signing(context.attempt.pk, client).status == "SIGNED"
    context.session.refresh_from_db()
    context.attempt.refresh_from_db()
    assert context.session.crypto_execution_id == execution
    assert context.attempt.sequence == 7
    assert len(client.creates) == len(client.executes) == 1
    assert MpcSigningSession.objects.filter(attempt=context.attempt).count() == 1
    assert user_balances("phase6e", "ETH")["reserved"] == 1


@pytest.mark.parametrize("field,value", [("nonce", 8), ("chainId", 10), ("gasPrice", 1)])
def test_signed_recovery_rejects_changed_persisted_unsigned_identity(context, field, value):
    client = complete(context)
    context.attempt.prepared_metadata[field] = value
    context.attempt.save()
    with patch("custody.outbound._executor") as executor:
        assert execute_attempt(context.attempt.pk, "worker").status == "RECONCILIATION_REQUIRED"
        executor.return_value.broadcast.assert_not_called()
    assert len(client.executes) == 1
    assert user_balances("phase6e", "ETH")["reserved"] == 1


def test_reconciliation_never_settles_from_wrong_network(context):
    complete(context)
    context.attempt.status = "RECONCILIATION_REQUIRED"
    context.attempt.save()
    transport = Mock()
    transport.rpc.return_value = "0xa"
    with patch("custody.reconciliation._executor", return_value=EvmNativeExecutor(transport)):
        with pytest.raises(MpcNetworkError, match="RPC chain ID"):
            reconcile_attempt(context.attempt.pk)
    assert [c.args[1] for c in transport.rpc.call_args_list] == ["eth_chainId"]
    assert user_balances("phase6e", "ETH")["reserved"] == 1


@pytest.mark.parametrize("token", [False, True])
def test_executor_checks_actual_endpoint_before_chain_specific_preparation(context, token):
    transport = Mock()
    transport.rpc.return_value = "0xa"
    executor = Erc20Executor(transport) if token else EvmNativeExecutor(transport)
    asset = Mock(chain_id="ETH", decimals=18, contract_address="0x" + "44" * 20)
    with patch("custody.token_tx.assert_verified_token", return_value=asset):
        with pytest.raises(MpcNetworkError, match="RPC chain ID"):
            executor.prepare(
                "ETH", "ETH", context.attempt.from_address, context.attempt.to_address, Decimal(1)
            )
    assert [c.args[1] for c in transport.rpc.call_args_list] == ["eth_chainId"]


def test_rpc_redirect_cannot_change_the_verified_endpoint(context):
    response = Mock(status_code=302)
    with patch("custody.native_tx.requests.post", return_value=response) as post:
        with pytest.raises(PreparationError, match="redirects"):
            RAW_RPC(RequestsTransport(), "http://127.0.0.1:18545", "eth_chainId", [])
        assert post.call_args.kwargs["allow_redirects"] is False
