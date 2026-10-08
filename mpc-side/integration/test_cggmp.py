"""Real-process CGGMP keygen acceptance. Auxiliary generation/signing remain pending."""

import hashlib
import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from environment import ROLES, Processes
from test_dkg import request

PARTIES = ROLES[1:4]


@pytest.fixture
def cggmp_network(tmp_path):
    services = Processes(tmp_path / "services")
    try:
        for role in ROLES[:4]:
            services.start(role)
        yield services
    finally:
        services.close()


def binding(scope="EVM"):
    return {
        "session_id": str(uuid.uuid4()),
        "execution_id": str(uuid.uuid4()),
        "keyset_id": str(uuid.uuid4()),
        "algorithm": "CGGMP24_ECDSA",
        "curve": "secp256k1",
        "scope": scope,
        "derivation_version": "cggmp_hd_v1",
        "threshold": 2,
        "party_count": 3,
        "participants": list(PARTIES),
    }


def control(net, party, action, context, role="coordinator"):
    return request(net, party, role, f"/internal/v1/cggmp/keygen/{action}", context)


def create(net, context):
    return request(net, "coordinator", "custody", "/v1/dkg-sessions", context)


def advance(net, context, action="execute"):
    return request(
        net, "coordinator", "custody", f"/v1/dkg-sessions/{context['session_id']}/{action}"
    )


def wait_keygen(net, context):
    deadline = time.monotonic() + 130
    while time.monotonic() < deadline:
        status, result = request(
            net, "coordinator", "custody", f"/v1/dkg-sessions/{context['session_id']}", method="GET"
        )
        assert status == 200
        if result["status"] != "IN_PROGRESS":
            return result
        time.sleep(0.1)
    pytest.fail("CGGMP keygen did not reach a durable terminal state")


def execute(net, context):
    assert create(net, context)[0] == 200
    assert advance(net, context)[0] == 200
    result = wait_keygen(net, context)
    assert result["status"] == "KEYGEN_COMPLETED", result
    return result


def inspect_core(net, party, context):
    path = net.root / party / "storage" / f"{context['keyset_id']}.share.enc"
    ciphertext = path.read_bytes()
    identity = {"keyset_id": context["keyset_id"], "party_id": party, "algorithm": "CGGMP24_ECDSA"}
    aad = json.dumps([2, identity], separators=(",", ":")).encode()
    wrapping = (net.root / party / "identity" / "wrapping.key").read_bytes()
    assert ciphertext.startswith(b"WMPCSHARE2")
    stored = json.loads(AESGCM(wrapping).decrypt(ciphertext[10:22], ciphertext[22:], aad))
    assert {key: stored[key] for key in identity} == identity
    assert stored["protocol_version"] == "phase6-v1"
    blob = json.loads(bytes(stored["protocol_share"]))
    assert blob["request"] == context and blob["kind"] == "CGGMP24_CORE_V1"
    core = json.loads(bytes(blob["core"]))
    assert core["i"] == PARTIES.index(party)
    # Inspect independently, never aggregate private shares.
    secret = bytes(blob["core"])
    for role in ROLES[:4]:
        assert secret not in (net.root / role / "service.log").read_bytes()
    for file in (net.root / "coordinator" / "storage").rglob("*.json"):
        assert secret not in file.read_bytes()
    return ciphertext, hashlib.sha256(secret).hexdigest()


@pytest.mark.parametrize("scope", ["EVM", "TRON"])
def test_distributed_keygen_encrypted_local_cores_and_restart(cggmp_network, scope):
    net = cggmp_network
    context = binding(scope)
    assert len({net.running[party].pid for party in PARTIES}) == 3
    result = execute(net, context)
    ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256K1(), bytes.fromhex(result["group_public_key"])
    )
    assert len(result["group_public_key"]) == 66
    reports = result["participant_agreement"]
    assert len(reports) == 3
    for party, report in zip(PARTIES, reports):
        assert report["party_id"] == party and report["durable"]
        assert report["group_public_key"] == result["group_public_key"]
        assert report["public_key_package"] == reports[0]["public_key_package"]
        assert control(net, party, "report", context) == (200, report)
    inspected = {p: inspect_core(net, p, context) for p in PARTIES}
    assert len({v[0] for v in inspected.values()}) == 3
    assert len({v[1] for v in inspected.values()}) == 3
    for party in PARTIES:
        net.stop(party)
        net.start(party)
        assert control(net, party, "report", context)[1] == reports[PARTIES.index(party)]
        assert inspect_core(net, party, context) == inspected[party]
    net.stop("coordinator")
    net.start("coordinator")
    for party in PARTIES:
        net.stop(party)
    assert advance(net, context) == (200, result)
    assert create(net, context) == (200, result)


@pytest.mark.parametrize(
    "field,value",
    [
        ("threshold", 1),
        ("threshold", 3),
        ("party_count", 2),
        ("participants", ["signer-b", "signer-a", "signer-c"]),
        ("participants", ["signer-a", "signer-a", "signer-c"]),
        ("participants", ["signer-a", "signer-b", "unknown"]),
        ("algorithm", "FROST_ED25519"),
        ("curve", "ed25519"),
        ("scope", "SOLANA"),
        ("derivation_version", "unknown"),
        ("session_id", str(uuid.UUID(int=0))),
        ("execution_id", str(uuid.UUID(int=0))),
        ("keyset_id", str(uuid.UUID(int=0))),
    ],
)
def test_invalid_keygen_binding_rejected_at_network_boundary(cggmp_network, field, value):
    context = binding()
    context[field] = value
    assert create(cggmp_network, context)[0] == 400
    assert control(cggmp_network, "signer-a", "prepare", context)[0] == 409
    assert not list((cggmp_network.root / "signer-a" / "storage" / "executions").glob("*.state"))


@pytest.mark.parametrize("role", ["custody", "signer-a", "signer-b", "signer-c"])
def test_only_coordinator_can_dispatch_keygen(cggmp_network, role):
    assert control(cggmp_network, "signer-a", "prepare", binding(), role=role)[0] == 403


def test_concurrent_duplicates_launch_one_execution(cggmp_network):
    net = cggmp_network
    context = binding()
    with ThreadPoolExecutor(max_workers=8) as pool:
        creates = list(pool.map(lambda _: create(net, context), range(8)))
        starts = list(pool.map(lambda _: advance(net, context), range(8)))
    assert all(status == 200 for status, _ in creates + starts)
    result = wait_keygen(net, context)
    assert result["status"] == "KEYGEN_COMPLETED"
    for party in PARTIES:
        directory = net.root / party / "storage"
        assert len(list((directory / "executions").glob("*.state"))) == 1
        assert len(list(directory.glob("*.share.enc"))) == 1
    assert advance(net, context) == (200, result)


def test_concurrent_distinct_keysets(cggmp_network):
    net = cggmp_network
    contexts = [binding(), binding("TRON")]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda context: execute(net, context), contexts))
    assert results[0]["group_public_key"] != results[1]["group_public_key"]
    for party in PARTIES:
        assert len(list((net.root / party / "storage").glob("*.share.enc"))) == 2


def test_unavailable_party_is_ambiguous_and_cannot_restart(cggmp_network):
    net = cggmp_network
    context = binding()
    net.stop("signer-c")
    assert create(net, context)[0] == 200
    assert advance(net, context)[0] == 200
    result = wait_keygen(net, context)
    assert result["status"] == "RECONCILIATION_REQUIRED"
    assert result["group_public_key"] is None
    net.start("signer-c")
    assert advance(net, context)[0] == 409
    assert advance(net, context, "reconcile")[0] == 409
    assert control(net, "signer-a", "prepare", context)[0] == 409
    replacement = context | {"execution_id": str(uuid.uuid4())}
    assert control(net, "signer-a", "prepare", replacement)[0] == 409


@pytest.mark.parametrize("fault", ["ciphertext", "wrapping-key"])
def test_corrupt_or_wrong_key_fails_signer_restart(cggmp_network, fault):
    net = cggmp_network
    context = binding()
    execute(net, context)
    net.stop("signer-a")
    path = net.root / "signer-a" / "storage" / f"{context['keyset_id']}.share.enc"
    if fault == "ciphertext":
        data = bytearray(path.read_bytes())
        data[-1] ^= 1
        path.write_bytes(data)
    else:
        (net.root / "signer-a" / "identity" / "wrapping.key").write_bytes(b"z" * 32)
    with pytest.raises(RuntimeError, match="CGGMP keygen recovery failed"):
        net.start("signer-a")


def test_reused_and_conflicting_execution_bindings_rejected(cggmp_network):
    net = cggmp_network
    context = binding()
    result = execute(net, context)
    for party in PARTIES:
        assert control(net, party, "start", context)[0] == 409
        assert control(net, party, "prepare", context)[0] == 409
        assert control(net, party, "report", context | {"scope": "TRON"})[0] == 409
        reused = binding() | {"execution_id": context["execution_id"]}
        assert control(net, party, "prepare", reused)[0] == 409
    assert create(net, context | {"scope": "TRON"})[0] == 409
    assert advance(net, context) == (200, result)


def test_core_only_keyset_cannot_claim_signing_completion(cggmp_network):
    net = cggmp_network
    context = binding()
    execute(net, context)
    payload = bytes(range(32))
    signing = {
        "session_id": str(uuid.uuid4()),
        "attempt_id": 1,
        "keyset_id": context["keyset_id"],
        "algorithm": "CGGMP24_ECDSA",
        "payload_type": "EVM_LEGACY_DIGEST",
        "payload_hex": payload.hex(),
        "message_fingerprint": hashlib.sha256(payload).hexdigest(),
        "operation_type": "WITHDRAWAL",
        "chain": "ETH",
        "asset": "ETH",
        "expected_source": "0x123",
        "derivation_reference": None,
    }
    assert request(net, "coordinator", "custody", "/v1/sign-sessions", signing)[0] == 200
    status, _ = request(
        net, "coordinator", "custody", f"/v1/sign-sessions/{signing['session_id']}/execute"
    )
    assert status == 400
    assert (
        request(
            net,
            "coordinator",
            "custody",
            f"/v1/sign-sessions/{signing['session_id']}",
            method="GET",
        )[1]["signature"]
        is None
    )


def message_fixture(net, context):
    import subprocess

    fixture = json.loads(
        subprocess.check_output(
            [str(net.bin / "examples" / "cggmp_round1_fixture"), json.dumps(context)], timeout=10
        )
    )
    payload = json.dumps(fixture["msg"], separators=(",", ":")).encode()
    tag = hashlib.sha256(json.dumps(context, separators=(",", ":")).encode()).hexdigest()
    wire = {
        "logical_session_id": context["session_id"],
        "crypto_execution_id": context["execution_id"],
        "keyset_id": context["keyset_id"],
        "protocol": f"CGGMP24_KEYGEN:{tag}/broadcast",
        "sender": "signer-b",
        "recipient": "signer-a",
        "round": fixture["round"],
        "sequence": 0,
        "payload": list(payload),
        "payload_digest": "",
    }
    return bind_wire(wire)


def bind_wire(wire):
    import struct

    digest = hashlib.sha256(b"wallet-mpc/protocol-envelope/v1\0")
    fields = [
        b"phase6-v1",
        uuid.UUID(wire["logical_session_id"]).bytes,
        uuid.UUID(wire["crypto_execution_id"]).bytes,
        uuid.UUID(wire["keyset_id"]).bytes,
        wire["protocol"].encode(),
        wire["sender"].encode(),
        wire["recipient"].encode(),
        struct.pack(">H", wire["round"]),
        struct.pack(">Q", wire["sequence"]),
        bytes(wire["payload"]),
    ]
    for field in fields:
        digest.update(struct.pack(">Q", len(field)))
        digest.update(field)
    wire["payload_digest"] = digest.hexdigest()
    return wire


def inject(net, role, wire):
    return request(net, "signer-a", role, "/internal/v1/cggmp/keygen/message", wire)


def test_exact_conflicting_and_new_sequence_round_replays(cggmp_network):
    net = cggmp_network
    context = binding()
    assert control(net, "signer-a", "prepare", context)[0] == 200
    wire = message_fixture(net, context)
    assert inject(net, "signer-b", wire)[0] == 200
    assert inject(net, "signer-b", wire)[0] == 409
    conflict = message_fixture(net, context)
    assert conflict["payload"] != wire["payload"]
    assert inject(net, "signer-b", conflict)[0] == 409
    assert inject(net, "signer-b", bind_wire(wire | {"sequence": 1}))[0] == 409
    net.stop("signer-a")
    net.start("signer-a")
    assert inject(net, "signer-b", wire)[0] == 409
    assert control(net, "signer-a", "start", context)[0] == 409


@pytest.mark.parametrize(
    "change",
    [
        {"sender": "signer-c"},
        {"recipient": "signer-c"},
        {"logical_session_id": str(uuid.uuid4())},
        {"crypto_execution_id": str(uuid.uuid4())},
        {"keyset_id": str(uuid.uuid4())},
        {"protocol": "CGGMP24_KEYGEN:wrong/broadcast"},
        {"round": 100},
        {"sequence": 64},
    ],
)
def test_authenticated_protocol_binding_is_immutable(cggmp_network, change):
    net = cggmp_network
    context = binding()
    assert control(net, "signer-a", "prepare", context)[0] == 200
    wire = message_fixture(net, context)
    assert inject(net, "signer-b", bind_wire(wire | change))[0] == 409
    assert inject(net, "coordinator", wire)[0] == 403
    assert inject(net, "custody", wire)[0] == 403
    assert inject(net, "signer-b", wire | {"payload_digest": "0" * 64})[0] == 409
    assert inject(net, "signer-b", wire)[0] == 200


def test_interrupted_keygen_never_substitutes_new_execution(cggmp_network):
    net = cggmp_network
    context = binding()
    assert create(net, context)[0] == 200
    for party in PARTIES:
        assert control(net, party, "prepare", context)[0] == 200
    assert control(net, "signer-a", "start", context)[0] == 200
    net.stop("signer-a")
    net.start("signer-a")
    assert control(net, "signer-a", "report", context)[1]["status"] == "RECONCILIATION_REQUIRED"
    assert control(net, "signer-a", "start", context)[0] == 409
    assert (
        control(net, "signer-a", "prepare", context | {"execution_id": str(uuid.uuid4())})[0] == 409
    )
    assert advance(net, context)[0] == 200
    assert wait_keygen(net, context)["status"] == "RECONCILIATION_REQUIRED"
    assert advance(net, context)[0] == 409
    assert all(not list((net.root / p / "storage").glob("*.share.enc")) for p in PARTIES)


def test_coordinator_rejects_tampered_public_completion_on_restart(cggmp_network):
    net = cggmp_network
    context = binding()
    execute(net, context)
    net.stop("coordinator")
    path = net.root / "coordinator" / "storage" / "coordinator.json"
    data = json.loads(path.read_text())
    data["dkg"][context["session_id"]]["result_fingerprint"] = "0" * 64
    path.write_text(json.dumps(data))
    with pytest.raises(RuntimeError, match="stored CGGMP result mismatch"):
        net.start("coordinator")
