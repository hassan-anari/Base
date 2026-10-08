"""Acceptance gate: three independent signer binaries, direct TLS 1.3 DKG peers.

The public round1 fixture is used only for hostile envelope injection. Successful
DKG, persistence and restart always use three real production signer processes.
"""

import hashlib
import http.client
import json
import os
import ssl
import struct
import subprocess
import uuid

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from environment import ROLES, Processes

PARTIES = ROLES[1:4]


@pytest.fixture
def dkg_network(tmp_path):
    services = Processes(tmp_path / "services")
    try:
        for role in ROLES[:4]:
            services.start(role)
        yield services
    finally:
        services.close()


def request(net, destination, role, path, body=None, method="POST"):
    identity = net.root / role / "identity"
    context = ssl.create_default_context(cafile=str(identity / "ca.crt"))
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(identity / "tls.crt", identity / "tls.key")
    connection = http.client.HTTPSConnection(
        "localhost", net.ports[destination], context=context, timeout=30
    )
    try:
        connection.request(
            method,
            path,
            body=json.dumps(body) if body is not None else None,
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        data = response.read()
        assert connection.sock is None or connection.sock.version() == "TLSv1.3"
        return response.status, json.loads(data) if data else None
    finally:
        connection.close()


def dkg_request():
    return {
        "session_id": str(uuid.uuid4()),
        "execution_id": str(uuid.uuid4()),
        "keyset_id": str(uuid.uuid4()),
        "algorithm": "FROST_ED25519",
        "curve": "ed25519",
        "scope": "SOLANA",
        "derivation_version": "frost_keyset_v1",
        "threshold": 2,
        "party_count": 3,
        "participants": list(PARTIES),
    }


def control(net, party, action, binding):
    return request(net, party, "coordinator", f"/internal/v1/dkg/{action}", binding)


def execute(net, binding):
    assert request(net, "coordinator", "custody", "/v1/dkg-sessions", binding)[0] == 200
    return request(
        net, "coordinator", "custody", f"/v1/dkg-sessions/{binding['session_id']}/execute"
    )


def encrypted_files(net, binding):
    return {
        party: (net.root / party / "storage" / f"{binding['keyset_id']}.share.enc").read_bytes()
        for party in PARTIES
    }


def inspect_local_share(net, party, binding, ciphertext):
    """Inspect a single store independently; never combine/reconstruct keys."""
    assert ciphertext.startswith(b"WMPCSHARE2")
    identity = {"keyset_id": binding["keyset_id"], "party_id": party, "algorithm": "FROST_ED25519"}
    aad = json.dumps([2, identity], separators=(",", ":")).encode()
    wrapping = (net.root / party / "identity" / "wrapping.key").read_bytes()
    stored = json.loads(AESGCM(wrapping).decrypt(ciphertext[10:22], ciphertext[22:], aad))
    assert stored["format_version"] == 1 and stored["protocol_version"] == "phase6-v1"
    assert {key: stored[key] for key in identity} == identity
    blob = json.loads(bytes(stored["protocol_share"]))
    assert blob["format_version"] == 1 and blob["request"] == binding
    assert blob["key_package"]
    # The entire serialized private package must be absent from metadata/logs.
    for path in (net.root / "coordinator" / "storage").rglob("*"):
        if path.is_file():
            assert bytes(stored["protocol_share"]) not in path.read_bytes()
            assert json.dumps(blob["key_package"]).encode() not in path.read_bytes()
    for role in ROLES[:4]:
        assert bytes(stored["protocol_share"]) not in (net.root / role / "service.log").read_bytes()
    return hashlib.sha256(bytes(blob["key_package"])).hexdigest()


def assert_completed(net, binding, session):
    assert session["status"] == "COMPLETED"
    public = session["group_public_key"]
    assert len(public) == 64
    reports = []
    for party in PARTIES:
        status, report = control(net, party, "report", binding)
        assert status == 200
        assert report == {
            "request": binding,
            "party_id": party,
            "status": "COMPLETED",
            "share_format_version": 1,
            "group_public_key": public,
            "public_key_package": report["public_key_package"],
            "verification_share": report["verification_share"],
            "durable": True,
        }
        assert report["public_key_package"] and report["verification_share"]
        reports.append(report)
    assert session["participant_agreement"] == reports
    return public


def test_real_three_party_dkg_encryption_and_restart(dkg_network):
    net = dkg_network
    binding = dkg_request()
    assert len({net.running[p].pid for p in PARTIES}) == 3
    assert len({net.configs[p]["MPC_TLS_KEY"] for p in PARTIES}) == 3
    status, session = execute(net, binding)
    assert status == 200
    public = assert_completed(net, binding, session)
    encrypted = encrypted_files(net, binding)
    assert len(set(encrypted.values())) == 3
    assert len({inspect_local_share(net, p, binding, encrypted[p]) for p in PARTIES}) == 3
    state = json.loads((net.root / "coordinator" / "storage" / "coordinator.json").read_text())
    assert set(state) == {"signing", "dkg"}
    assert set(state["dkg"][binding["session_id"]]) == set(binding) | {
        "status",
        "group_public_key",
        "result_fingerprint",
        "participant_agreement",
    }
    for party in PARTIES:
        assert len(list((net.root / party / "storage").glob("*.share.enc"))) == 1
        assert (
            net.root / party / "storage" / f"{binding['keyset_id']}.share.enc"
        ).stat().st_mode & 0o777 == 0o600
    before = {
        p: (
            net.root / p / "storage" / "executions" / f"{binding['execution_id']}.state"
        ).read_bytes()
        for p in PARTIES
    }
    for role in ROLES[:4]:
        net.stop(role)
    for role in ROLES[:4]:
        net.start(role)
    assert assert_completed(net, binding, session) == public
    assert execute(net, binding) == (200, session)
    assert encrypted_files(net, binding) == encrypted
    for p in PARTIES:
        assert control(net, p, "start", binding)[1]["status"] == "COMPLETED"
        assert control(net, p, "round1", binding)[0] == 409
        assert (
            (
                net.root / p / "storage" / "executions" / f"{binding['execution_id']}.state"
            ).read_bytes()
            == before[p]
            == b"COMPLETED"
        )


def envelope(binding, **changes):
    result = {
        "logical_session_id": binding["session_id"],
        "crypto_execution_id": binding["execution_id"],
        "keyset_id": binding["keyset_id"],
        "protocol": "FROST_ED25519",
        "sender": "signer-a",
        "recipient": "signer-b",
        "round": 1,
        "sequence": 1,
        "payload": [0],
    }
    result.update(changes)
    fields = [
        b"phase6-v1",
        uuid.UUID(result["logical_session_id"]).bytes,
        uuid.UUID(result["crypto_execution_id"]).bytes,
        uuid.UUID(result["keyset_id"]).bytes,
        result["protocol"].encode(),
        result["sender"].encode(),
        result["recipient"].encode(),
        struct.pack(">H", result["round"]),
        struct.pack(">Q", result["sequence"]),
        bytes(result["payload"]),
    ]
    digest = hashlib.sha256(b"wallet-mpc/protocol-envelope/v1\0")
    for field in fields:
        digest.update(struct.pack(">Q", len(field)))
        digest.update(field)
    result["payload_digest"] = digest.hexdigest()
    return result


@pytest.mark.parametrize(
    "change",
    [
        {"sender": "signer-c"},
        {"recipient": "signer-c"},
        {"logical_session_id": str(uuid.uuid4())},
        {"crypto_execution_id": str(uuid.uuid4())},
        {"keyset_id": str(uuid.uuid4())},
        {"round": 2},
        {"round": 3},
        {"sequence": 2},
        {"protocol": "CGGMP24_ECDSA"},
        {"payload_digest": "0" * 64},
    ],
)
def test_wrong_message_binding_rejected(dkg_network, change):
    net = dkg_network
    binding = dkg_request()
    assert control(net, "signer-b", "start", binding)[0] == 200
    public_package = json.loads(
        subprocess.check_output([str(net.bin / "examples" / "frost_round1_fixture")])
    )
    message = envelope(
        binding,
        payload=public_package,
        **{k: v for k, v in change.items() if k != "payload_digest"},
    )
    message.update({k: v for k, v in change.items() if k == "payload_digest"})
    assert request(net, "signer-b", "signer-a", "/internal/v1/dkg/message", message)[0] == 409
    assert control(net, "signer-b", "finalize", binding)[0] == 409
    assert not list((net.root / "signer-b" / "storage").glob("*.share.enc"))


def test_accepted_round1_replay_and_conflicting_duplicate_rejected(dkg_network):
    net = dkg_network
    binding = dkg_request()
    assert control(net, "signer-b", "start", binding)[0] == 200
    fixture = subprocess.check_output([str(net.bin / "examples" / "frost_round1_fixture")])
    public_package = json.loads(fixture)
    message = envelope(binding, payload=public_package)
    assert request(net, "signer-b", "signer-a", "/internal/v1/dkg/message", message) == (
        200,
        {"accepted": True},
    )
    assert request(net, "signer-b", "signer-a", "/internal/v1/dkg/message", message)[0] == 409
    conflict = envelope(
        binding,
        payload=json.loads(
            subprocess.check_output([str(net.bin / "examples" / "frost_round1_fixture")])
        ),
    )
    assert conflict["payload"] != message["payload"]
    assert request(net, "signer-b", "signer-a", "/internal/v1/dkg/message", conflict)[0] == 409
    net.stop("signer-b")
    net.start("signer-b")
    assert request(net, "signer-b", "signer-a", "/internal/v1/dkg/message", message)[0] == 409
    assert control(net, "signer-b", "start", binding)[0] == 409


@pytest.mark.parametrize("role", ["custody", "coordinator"])
def test_coordinator_and_custody_cannot_send_private_rounds(dkg_network, role):
    binding = dkg_request()
    assert (
        request(dkg_network, "signer-b", role, "/internal/v1/dkg/message", envelope(binding))[0]
        == 403
    )


@pytest.mark.parametrize("role", ["custody", "signer-a", "signer-b", "signer-c"])
def test_only_coordinator_can_control_dkg(dkg_network, role):
    assert request(dkg_network, "signer-b", role, "/internal/v1/dkg/start", dkg_request())[0] == 403


def test_missing_signer_cannot_complete_or_silently_retry(dkg_network):
    net = dkg_network
    binding = dkg_request()
    net.stop("signer-c")
    assert execute(net, binding)[0] == 409
    path = f"/v1/dkg-sessions/{binding['session_id']}"
    status, session = request(net, "coordinator", "custody", path, method="GET")
    assert status == 200 and session["status"] == "RECONCILIATION_REQUIRED"
    assert session["group_public_key"] is None and session["participant_agreement"] == []
    net.start("signer-c")
    assert execute(net, binding)[0] == 409
    assert request(net, "coordinator", "custody", path + "/reconcile")[0] == 409
    for p in PARTIES:
        assert not list((net.root / p / "storage").glob("*.share.enc"))
    net.stop("coordinator")
    net.start("coordinator")
    assert (
        request(net, "coordinator", "custody", path, method="GET")[1]["status"]
        == "RECONCILIATION_REQUIRED"
    )


def test_conflicting_repeat_dkg_and_execution_reuse_rejected(dkg_network):
    net = dkg_network
    binding = dkg_request()
    assert execute(net, binding)[0] == 200
    encrypted = encrypted_files(net, binding)
    variants = [
        binding | {"execution_id": str(uuid.uuid4())},
        binding | {"session_id": str(uuid.uuid4()), "execution_id": str(uuid.uuid4())},
        dkg_request() | {"execution_id": binding["execution_id"]},
    ]
    for conflict in variants:
        assert request(net, "coordinator", "custody", "/v1/dkg-sessions", conflict)[0] == 409
        for party in PARTIES:
            assert control(net, party, "start", conflict)[0] == 409
    assert encrypted_files(net, binding) == encrypted


def test_restart_lost_ephemeral_state_aborts_and_never_finalizes(dkg_network):
    net = dkg_network
    binding = dkg_request()
    for p in PARTIES:
        assert control(net, p, "start", binding)[0] == 200
    for p in PARTIES:
        assert control(net, p, "round1", binding)[0] == 200
    for p in PARTIES:
        net.stop(p)
    for p in PARTIES:
        net.start(p)
        assert control(net, p, "report", binding)[1]["status"] == "ABORTED_AFTER_RESTART"
        for action in ("start", "round1", "round2", "finalize"):
            assert control(net, p, action, binding)[0] == 409
        assert not list((net.root / p / "storage").glob("*.share.enc"))
    assert execute(net, binding)[0] == 409


def test_reconcile_completed_signers_after_coordinator_interrupt(dkg_network):
    net = dkg_network
    binding = dkg_request()
    assert request(net, "coordinator", "custody", "/v1/dkg-sessions", binding)[0] == 200
    # Drive real controls independently to exercise public result reconciliation.
    for action in ("start", "round1", "round2", "finalize"):
        for p in PARTIES:
            assert control(net, p, action, binding)[0] == 200
    encrypted = encrypted_files(net, binding)
    net.stop("coordinator")
    net.start("coordinator")
    status, session = request(
        net, "coordinator", "custody", f"/v1/dkg-sessions/{binding['session_id']}/reconcile"
    )
    assert status == 200
    assert_completed(net, binding, session)
    assert encrypted_files(net, binding) == encrypted


@pytest.mark.parametrize("mismatch", ["role", "dns"])
def test_signer_peer_destination_mismatch_rejected(dkg_network, mismatch):
    net = dkg_network
    net.stop("signer-a")
    if mismatch == "role":
        net.configs["signer-a"]["MPC_SIGNER_B_ADDR"] = net.configs["signer-a"]["MPC_SIGNER_C_ADDR"]
    else:
        net.configs["signer-a"]["MPC_SIGNER_B_SERVER_NAME"] = "invalid.example"
    net.start("signer-a")
    binding = dkg_request()
    assert execute(net, binding)[0] == 409
    for p in PARTIES:
        assert not list((net.root / p / "storage").glob("*.share.enc"))
    status, session = request(
        net, "coordinator", "custody", f"/v1/dkg-sessions/{binding['session_id']}", method="GET"
    )
    assert status == 200 and session["status"] == "RECONCILIATION_REQUIRED"


@pytest.mark.parametrize("fault", ["party_transplant", "corruption", "wrapping_key"])
def test_restart_rejects_invalid_encrypted_key_package(dkg_network, fault):
    net = dkg_network
    binding = dkg_request()
    assert execute(net, binding)[0] == 200
    encrypted = encrypted_files(net, binding)
    net.stop("signer-b")
    target = net.root / "signer-b" / "storage" / f"{binding['keyset_id']}.share.enc"
    if fault == "party_transplant":
        target.write_bytes(encrypted["signer-a"])
    elif fault == "corruption":
        target.write_bytes(encrypted["signer-b"][:-1])
    else:
        (net.root / "signer-b" / "identity" / "wrapping.key").write_bytes(os.urandom(32))
    with pytest.raises(RuntimeError, match="DKG recovery failed"):
        net.start("signer-b")
    assert net.running["signer-b"].poll() is not None
    assert execute(net, binding)[0] == 409


def test_incomplete_partial_persistence_never_completes(dkg_network):
    net = dkg_network
    binding = dkg_request()
    assert request(net, "coordinator", "custody", "/v1/dkg-sessions", binding)[0] == 200
    for action in ("start", "round1", "round2"):
        for party in PARTIES:
            assert control(net, party, action, binding)[0] == 200
    assert control(net, "signer-a", "finalize", binding)[0] == 200
    saved = (net.root / "signer-a" / "storage" / f"{binding['keyset_id']}.share.enc").read_bytes()
    for role in ROLES[:4]:
        net.stop(role)
    for role in ROLES[:4]:
        net.start(role)
    path = f"/v1/dkg-sessions/{binding['session_id']}"
    assert request(net, "coordinator", "custody", path + "/reconcile")[0] == 409
    assert execute(net, binding)[0] == 409
    assert (
        request(net, "coordinator", "custody", path, method="GET")[1]["status"]
        == "RECONCILIATION_REQUIRED"
    )
    assert (
        net.root / "signer-a" / "storage" / f"{binding['keyset_id']}.share.enc"
    ).read_bytes() == saved
    for p in PARTIES[1:]:
        assert not list((net.root / p / "storage").glob("*.share.enc"))


def test_secret_message_parse_errors_do_not_echo_payload(dkg_network):
    net = dkg_network
    marker = "TEST_PRIVATE_PACKAGE_MUST_NEVER_BE_ECHOED"
    status, response = request(
        net, "signer-b", "signer-a", "/internal/v1/dkg/message", {marker: marker}
    )
    assert status == 409 and response == {"error": "DKG rejected"}
    for role in ROLES[:4]:
        assert marker not in (net.root / role / "service.log").read_text()
