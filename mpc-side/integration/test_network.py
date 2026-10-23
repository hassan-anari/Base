"""All assertions cross real TLS sockets to independently running binaries."""

import hashlib
import http.client
import json
import ssl
import uuid

import pytest
import requests
from custody.signer_adapter import SelfHostedMpcAdapter, assert_mpc_backend_runtime_safe
from django.core.checks import run_checks
from django.test import override_settings
from environment import ROLES, Processes


@pytest.fixture(scope="module")
def network(tmp_path_factory):
    services = Processes(tmp_path_factory.mktemp("phase6b") / "services")
    try:
        for role in ROLES[:4]:
            services.start(role)
        yield services
    finally:
        services.close()


def settings_for(network, role="custody", ca_role="custody", destination="coordinator"):
    identity = network.root / role / "identity"
    return override_settings(
        MPC_COORDINATOR_URL=f"https://localhost:{network.ports[destination]}",
        MPC_CLIENT_CERT=str(identity / "tls.crt"),
        MPC_CLIENT_KEY=str(identity / "tls.key"),
        MPC_CA_CERT=str(network.root / ca_role / "identity" / "ca.crt"),
        MPC_REQUEST_TIMEOUT_SECONDS=5,
        MPC_HD_SIGNER_CERTIFICATES={
            party: str(network.root / party / "identity" / "tls.crt") for party in ROLES[1:4]
        },
    )


def raw_request(
    network,
    destination="coordinator",
    role="custody",
    path="/health",
    version=ssl.TLSVersion.TLSv1_3,
    ca_role="custody",
    headers=None,
    hostname="localhost",
):
    context = ssl.create_default_context(cafile=str(network.root / ca_role / "identity" / "ca.crt"))
    context.minimum_version = context.maximum_version = version
    if role:
        identity = network.root / role / "identity"
        context.load_cert_chain(identity / "tls.crt", identity / "tls.key")
    connection = http.client.HTTPSConnection(
        hostname, network.ports[destination], context=context, timeout=5
    )
    try:
        connection.connect()
        negotiated = connection.sock.version()
        connection.request("GET", path, headers=headers or {})
        response = connection.getresponse()
        data = response.read()
        return response.status, json.loads(data) if data else None, negotiated
    finally:
        connection.close()


def assert_quorum(network):
    with settings_for(network):
        response = SelfHostedMpcAdapter()._request("GET", "/v1/health/quorum")
    assert set(response) == {"healthy", "required", "party_count", "signable", "signers"}
    assert (
        response["healthy"],
        response["required"],
        response["party_count"],
        response["signable"],
    ) == (3, 2, 3, False)
    assert response["signers"] == [
        {
            "signer_identity": role,
            "protocol_version": "phase6-v1",
            "supported_algorithms": ["CGGMP24_ECDSA", "FROST_ED25519"],
            "service_ready": True,
        }
        for role in ROLES[1:4]
    ]


def test_django_created_exact_contract_idempotency_and_restart(network):
    assert_quorum(network)
    payload = {
        "session_id": str(uuid.uuid4()),
        "attempt_id": 1,
        "keyset_id": str(uuid.uuid4()),
        "algorithm": "CGGMP24_ECDSA",
        "payload_type": "EVM_LEGACY_DIGEST",
        "payload_hex": "ab" * 32,
        "message_fingerprint": hashlib.sha256(bytes.fromhex("ab" * 32)).hexdigest(),
        "operation_type": "WITHDRAWAL",
        "chain": "ETH",
        "asset": "ETH",
        "expected_source": "0x0000000000000000000000000000000000000001",
        "derivation_reference": None,
    }
    with settings_for(network):
        client = SelfHostedMpcAdapter()
        created = client.create_signing_session(payload)
        assert set(created) == set(payload) | {
            "status",
            "selected_signers",
            "crypto_execution_id",
            "signature",
            "error_code",
        }
        assert created == payload | {
            "status": "CREATED",
            "selected_signers": [],
            "crypto_execution_id": created["crypto_execution_id"],
            "signature": None,
            "error_code": None,
        }
        assert uuid.UUID(created["crypto_execution_id"]).version == 4
        assert client.create_signing_session(payload) == created
        assert client.get_signing_session(payload["session_id"]) == created
        with pytest.raises(requests.HTTPError, match="409"):
            client.create_signing_session(payload | {"attempt_id": 2})
        for role in ROLES[:4]:
            network.stop(role)
        for role in ROLES[:4]:
            network.start(role)
        assert client.create_signing_session(payload) == created
        assert client.get_signing_session(payload["session_id"]) == created
    assert_quorum(network)
    assert raw_request(network)[2] == "TLSv1.3"
    # An authenticated CREATED session still has no cryptographic execution.
    with override_settings(MPC_SIGNER_BACKEND="self_hosted_mpc"):
        assert any(check.id == "custody.E011" for check in run_checks())
        with pytest.raises(RuntimeError):
            assert_mpc_backend_runtime_safe()


@pytest.mark.parametrize(
    "role,ca_role,version",
    [
        (None, "custody", ssl.TLSVersion.TLSv1_3),
        ("wrong-ca", "custody", ssl.TLSVersion.TLSv1_3),
        ("custody", "wrong-ca", ssl.TLSVersion.TLSv1_3),
        ("unknown", "custody", ssl.TLSVersion.TLSv1_3),
        ("ambiguous", "custody", ssl.TLSVersion.TLSv1_3),
        ("expired", "custody", ssl.TLSVersion.TLSv1_3),
        ("custody", "custody", ssl.TLSVersion.TLSv1_2),
    ],
)
@pytest.mark.parametrize("destination", ["coordinator", "signer-a", "signer-b", "signer-c"])
def test_invalid_tls_credentials_fail(network, role, ca_role, version, destination):
    with pytest.raises((OSError, http.client.HTTPException)):
        raw_request(network, destination=destination, role=role, ca_role=ca_role, version=version)


@pytest.mark.parametrize("role", ["coordinator", "signer-a", "signer-b", "signer-c"])
@pytest.mark.parametrize(
    "path",
    ["/health", "/v1/sign-sessions/00000000-0000-0000-0000-000000000000", "/v1/health/quorum"],
)
def test_non_custody_cannot_access_custody_endpoints(network, role, path):
    status, _, _ = raw_request(
        network,
        role=role,
        path=path,
        headers={
            "X-MPC-Identity": "custody",
            "X-Forwarded-Client-Cert": "spiffe://wallet-mpc/custody",
        },
    )
    assert status == 403


@pytest.mark.parametrize("destination", ["signer-a", "signer-b", "signer-c"])
def test_signer_internal_role_authorization(network, destination):
    status, metadata, tls = raw_request(
        network, destination=destination, role="coordinator", path="/internal/v1/capabilities"
    )
    assert status == 200 and tls == "TLSv1.3"
    assert set(metadata) == {
        "signer_identity",
        "protocol_version",
        "supported_algorithms",
        "service_ready",
    }
    assert metadata["signer_identity"] == destination
    for role in ("custody", "signer-a", "signer-b", "signer-c"):
        assert (
            raw_request(
                network,
                destination=destination,
                role=role,
                path="/internal/v1/capabilities",
                headers={"X-MPC-Identity": "coordinator"},
            )[0]
            == 403
        )


def test_signer_a_cannot_impersonate_b_with_valid_hostname(network):
    network.stop("coordinator")
    original = network.configs["coordinator"]["MPC_SIGNER_B_ADDR"]
    # Both certificates are valid for localhost and signed by the trusted CA.
    network.configs["coordinator"]["MPC_SIGNER_B_ADDR"] = network.configs["coordinator"][
        "MPC_SIGNER_A_ADDR"
    ]
    try:
        network.start("coordinator")
        with settings_for(network), pytest.raises(requests.HTTPError, match="503"):
            SelfHostedMpcAdapter()._request("GET", "/v1/health/quorum")
    finally:
        network.stop("coordinator")
        network.configs["coordinator"]["MPC_SIGNER_B_ADDR"] = original
        network.start("coordinator")
    assert_quorum(network)


def test_django_rejects_signer_as_coordinator(network):
    with (
        settings_for(network, destination="signer-a"),
        pytest.raises(ssl.SSLCertVerificationError, match="identity"),
    ):
        SelfHostedMpcAdapter()._request("GET", "/health")


def test_coordinator_verifies_destination_dns(network):
    network.stop("coordinator")
    original = network.configs["coordinator"]["MPC_SIGNER_A_SERVER_NAME"]
    network.configs["coordinator"]["MPC_SIGNER_A_SERVER_NAME"] = "invalid.example"
    try:
        network.start("coordinator")
        with settings_for(network), pytest.raises(requests.HTTPError, match="503"):
            SelfHostedMpcAdapter()._request("GET", "/v1/health/quorum")
    finally:
        network.stop("coordinator")
        network.configs["coordinator"]["MPC_SIGNER_A_SERVER_NAME"] = original
        network.start("coordinator")
    assert_quorum(network)
