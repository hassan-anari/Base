"""Fresh-prime distributed auxiliary generation through independent TLS services."""

import copy
import hashlib
import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from environment import ROLES, Processes
from test_cggmp import PARTIES, binding, execute
from test_dkg import request


def aux_control(net, party, action, context, role="coordinator"):
    return request(net, party, role, f"/internal/v1/cggmp/aux/{action}", context)


def advance_aux(net, context, action="execute"):
    return request(
        net,
        "coordinator",
        "custody",
        f"/v1/dkg-sessions/{context['session_id']}/auxiliary/{action}",
    )


def get_keyset(net, context):
    return request(
        net, "coordinator", "custody", f"/v1/dkg-sessions/{context['session_id']}", method="GET"
    )[1]


@pytest.fixture(scope="module")
def auxiliary_network(tmp_path_factory):
    net = Processes(tmp_path_factory.mktemp("cggmp-aux") / "services")
    try:
        for role in ROLES[:4]:
            net.start(role)
        context = binding()
        core = execute(net, context)
        cores = {
            p: (net.root / p / "storage" / f"{context['keyset_id']}.share.enc").read_bytes()
            for p in PARTIES
        }
        started = time.monotonic()
        with ThreadPoolExecutor(max_workers=4) as pool:
            claims = list(pool.map(lambda _: advance_aux(net, context), range(4)))
        assert all(code == 200 for code, _ in claims)
        executions = {state["auxiliary"]["request"]["execution_id"] for _, state in claims}
        assert len(executions) == 1
        deadline = started + 1815
        while time.monotonic() < deadline:
            state = get_keyset(net, context)
            auxiliary = state["auxiliary"]
            assert state["participant_agreement"] == core["participant_agreement"]
            if auxiliary["status"] != "IN_PROGRESS":
                break
            assert not auxiliary["internally_signable"]
            time.sleep(1)
        else:
            pytest.fail("fresh-prime auxiliary protocol exceeded bounded deadline")
        if auxiliary["status"] != "AUXILIARY_COMPLETED":
            for party in PARTIES:
                print(party, (net.root / party / "service.log").read_text())
        assert auxiliary["status"] == "AUXILIARY_COMPLETED", auxiliary
        assert auxiliary["internally_signable"]
        costs = {
            r["party_id"]: r["prime_generation_ms"] for r in auxiliary["participant_agreement"]
        }
        print(
            f"Fresh prime generation milliseconds: {costs}; total {time.monotonic() - started:.3f}s"
        )
        net.aux_context = context
        net.aux_state = state
        net.aux_cores = cores
        yield net
    finally:
        net.close()


def inspect_aux(net, party):
    context = net.aux_context
    path = net.root / party / "storage" / "cggmp-aux" / f"{context['keyset_id']}.share.enc"
    ciphertext = path.read_bytes()
    identity = {"keyset_id": context["keyset_id"], "party_id": party, "algorithm": "CGGMP24_ECDSA"}
    aad = json.dumps([2, identity], separators=(",", ":")).encode()
    key = (net.root / party / "identity" / "wrapping.key").read_bytes()
    stored = json.loads(AESGCM(key).decrypt(ciphertext[10:22], ciphertext[22:], aad))
    blob = json.loads(bytes(stored["protocol_share"]))
    assert blob["kind"] == "CGGMP24_AUX_V1" and blob["format_version"] == 1
    assert blob["party_id"] == party and blob["protocol_version"] == "phase6-v1"
    assert blob["request"] == net.aux_state["auxiliary"]["request"]
    aux = json.loads(bytes(blob["aux"]))
    assert len(aux["N"]) == 3 and len(aux["pedersen_params"]) == 3
    secret = bytes(blob["aux"])
    for role in ROLES[:4]:
        assert secret not in (net.root / role / "service.log").read_bytes()
    for file in (net.root / "coordinator" / "storage").rglob("*.json"):
        assert secret not in file.read_bytes()
    return ciphertext, hashlib.sha256(secret).hexdigest()


def test_auxiliary_artifacts_are_separate_create_once_and_reload(auxiliary_network):
    net = auxiliary_network
    receipts = net.aux_state["auxiliary"]["participant_agreement"]
    assert len({r["public_parameters_fingerprint"] for r in receipts}) == 1
    secrets = set()
    for party, receipt in zip(PARTIES, receipts):
        assert receipt["party_id"] == party and receipt["durable"]
        assert receipt["prime_generation_ms"] > 0
        ciphertext, fingerprint = inspect_aux(net, party)
        secrets.add(fingerprint)
        core_path = net.root / party / "storage" / f"{net.aux_context['keyset_id']}.share.enc"
        assert core_path.read_bytes() == net.aux_cores[party]
        net.stop(party)
        net.start(party)
        assert inspect_aux(net, party)[0] == ciphertext
        context = net.aux_state["auxiliary"]["request"]
        assert aux_control(net, party, "report", context) == (200, receipt)
        assert aux_control(net, party, "start", context)[0] == 409
        assert aux_control(net, party, "prepare", context)[0] == 409
    assert len(secrets) == 3
    net.stop("coordinator")
    net.start("coordinator")
    assert advance_aux(net, net.aux_context) == (200, net.aux_state)
    for party in PARTIES:
        net.stop(party)
    try:
        assert advance_aux(net, net.aux_context) == (200, net.aux_state)
    finally:
        for party in PARTIES:
            net.start(party)


@pytest.mark.parametrize(
    "field", ["execution_id", "group_public_key", "keyset_id", "core_execution", "scope"]
)
def test_auxiliary_artifact_binding_cannot_change(auxiliary_network, field):
    net = auxiliary_network
    context = copy.deepcopy(net.aux_state["auxiliary"]["request"])
    if field == "execution_id":
        context[field] = str(uuid.uuid4())
    elif field == "group_public_key":
        context[field] = "02" + "00" * 32
    elif field == "keyset_id":
        context["dkg"][field] = str(uuid.uuid4())
    elif field == "core_execution":
        context["dkg"]["execution_id"] = str(uuid.uuid4())
    else:
        context["dkg"]["scope"] = "TRON"
    assert aux_control(net, "signer-a", "report", context)[0] == 409
    assert aux_control(net, "signer-a", "prepare", context)[0] == 409


@pytest.mark.parametrize("role", ["custody", "signer-a", "signer-b", "signer-c"])
def test_auxiliary_controls_require_coordinator_certificate(auxiliary_network, role):
    net = auxiliary_network
    assert (
        aux_control(net, "signer-a", "report", net.aux_state["auxiliary"]["request"], role)[0]
        == 403
    )


@pytest.mark.parametrize("fault", ["ciphertext", "transplant", "wrapping-key"])
def test_corrupt_auxiliary_material_rejected_on_restart(auxiliary_network, fault):
    net = auxiliary_network
    path = (
        net.root
        / "signer-a"
        / "storage"
        / "cggmp-aux"
        / f"{net.aux_context['keyset_id']}.share.enc"
    )
    wrap = net.root / "signer-a" / "identity" / "wrapping.key"
    saved, saved_wrap = path.read_bytes(), wrap.read_bytes()
    net.stop("signer-a")
    try:
        if fault == "ciphertext":
            corrupted = bytearray(saved)
            corrupted[-1] ^= 1
            path.write_bytes(corrupted)
        elif fault == "transplant":
            other = net.root / "signer-b" / "storage" / "cggmp-aux" / path.name
            path.write_bytes(other.read_bytes())
        else:
            wrap.write_bytes(b"x" * 32)
        with pytest.raises(RuntimeError, match="CGGMP (auxiliary|keygen) recovery failed"):
            net.start("signer-a")
    finally:
        net.stop("signer-a")
        path.write_bytes(saved)
        wrap.write_bytes(saved_wrap)
        net.start("signer-a")


def test_incomplete_auxiliary_receipts_never_create_false_readiness(auxiliary_network):
    net = auxiliary_network
    path = net.root / "coordinator" / "storage" / "coordinator.json"
    net.stop("coordinator")
    saved = path.read_bytes()
    try:
        data = json.loads(saved)
        data["dkg"][net.aux_context["session_id"]]["auxiliary"]["participant_agreement"].pop()
        path.write_text(json.dumps(data))
        with pytest.raises(RuntimeError, match="incomplete auxiliary receipts"):
            net.start("coordinator")
    finally:
        net.stop("coordinator")
        path.write_bytes(saved)
        net.start("coordinator")


def signing_request(net, payload_type="EVM_LEGACY_DIGEST", digest=None):
    from coincurve import PublicKey
    from eth_utils import keccak

    group = net.aux_state["group_public_key"]
    address = (
        "0x" + keccak(PublicKey(bytes.fromhex(group)).format(compressed=False)[1:])[-20:].hex()
    )
    digest = digest or bytes(range(32))
    return {
        "session_id": str(uuid.uuid4()),
        "attempt_id": 1,
        "keyset_id": net.aux_context["keyset_id"],
        "algorithm": "CGGMP24_ECDSA",
        "payload_type": payload_type,
        "payload_hex": digest.hex(),
        "message_fingerprint": hashlib.sha256(digest).hexdigest(),
        "operation_type": "WITHDRAWAL",
        "chain": "ETH",
        "asset": "ETH",
        "expected_source": address,
        "derivation_reference": None,
    }


def sign_control(net, party, action, execution, role="coordinator"):
    return request(net, party, role, f"/internal/v1/cggmp/sign/{action}", execution)


def sign_state(net, context):
    return request(
        net, "coordinator", "custody", f"/v1/sign-sessions/{context['session_id']}", method="GET"
    )[1]


def advance_sign(net, context, action="execute"):
    return request(
        net, "coordinator", "custody", f"/v1/sign-sessions/{context['session_id']}/{action}"
    )


def wait_sign(net, context):
    deadline = time.monotonic() + 205
    while time.monotonic() < deadline:
        state = sign_state(net, context)
        if state["status"] not in ("STARTING", "IN_PROGRESS"):
            return state
        time.sleep(0.1)
    pytest.fail("interactive signing exceeded bounded deadline")


def verify_independently(net, context, state):
    from coincurve import PublicKey, ecdsa

    signature = state["signature"]
    assert signature["verified"] and signature["selected_signers"] == state["selected_signers"]
    assert signature["crypto_execution_id"] == state["crypto_execution_id"]
    assert signature["logical_session_id"] == context["session_id"]
    assert signature["keyset_id"] == context["keyset_id"]
    assert signature["payload_fingerprint"] == context["message_fingerprint"]
    compact = bytes.fromhex(signature["signature_hex"])
    assert compact[:32].hex() == signature["r"] and compact[32:].hex() == signature["s"]
    assert (
        0
        < int(signature["s"], 16)
        <= int("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0", 16)
    )
    assert signature["recovery_id"] == signature["y_parity"] in (0, 1)
    digest = bytes.fromhex(context["payload_hex"])
    group = PublicKey(bytes.fromhex(net.aux_state["group_public_key"]))
    der = ecdsa.cdata_to_der(ecdsa.deserialize_compact(compact))
    assert group.verify(der, digest, hasher=None)
    assert not group.verify(der, hashlib.sha256(digest).digest(), hasher=None)
    recovered = PublicKey.from_signature_and_message(
        compact + bytes([signature["recovery_id"]]), digest, hasher=None
    )
    assert recovered.format() == group.format()
    return signature


@pytest.mark.parametrize(
    "pair", [("signer-a", "signer-b"), ("signer-a", "signer-c"), ("signer-b", "signer-c")]
)
@pytest.mark.parametrize("payload_type", ["EVM_LEGACY_DIGEST", "EVM_EIP1559_DIGEST"])
def test_all_pairs_sign_exact_prehash_and_offline_unselected(auxiliary_network, pair, payload_type):
    net = auxiliary_network
    # Fresh payloads per session; this acceptance boundary only receives custody digests.
    context = signing_request(net, payload_type, hashlib.sha256(uuid.uuid4().bytes).digest())
    assert request(net, "coordinator", "custody", "/v1/sign-sessions", context)[0] == 200
    offline = next(p for p in PARTIES if p not in pair)
    net.stop(offline)
    try:
        assert advance_sign(net, context)[0] == 200
        state = wait_sign(net, context)
        assert state["status"] == "COMPLETED", state
        assert state["selected_signers"] == list(pair)
        verify_independently(net, context, state)
        net.stop("coordinator")
        net.start("coordinator")
        assert advance_sign(net, context) == (200, state)
        for party in pair:
            net.stop(party)
            net.start(party)
        assert advance_sign(net, context) == (200, state)
        execution = {
            "request": context,
            "crypto_execution_id": state["crypto_execution_id"],
            "selected_signers": list(pair),
            "auxiliary": net.aux_state["auxiliary"]["request"],
        }
        for party in pair:
            assert (
                sign_control(net, party, "report", execution)[1]["signature"] == state["signature"]
            )
            assert sign_control(net, party, "start", execution)[0] == 409
            assert sign_control(net, party, "prepare", execution)[0] == 409
    finally:
        net.start(offline)


def test_duplicate_concurrent_calls_and_distinct_sessions(auxiliary_network):
    net = auxiliary_network
    contexts = [
        signing_request(net, digest=hashlib.sha256(uuid.uuid4().bytes).digest()) for _ in range(2)
    ]
    with ThreadPoolExecutor(max_workers=8) as pool:
        creates = list(
            pool.map(
                lambda _: request(net, "coordinator", "custody", "/v1/sign-sessions", contexts[0]),
                range(8),
            )
        )
        starts = list(pool.map(lambda _: advance_sign(net, contexts[0]), range(8)))
    assert all(code == 200 for code, _ in creates + starts)
    assert len({state["crypto_execution_id"] for _, state in creates + starts}) == 1
    assert request(net, "coordinator", "custody", "/v1/sign-sessions", contexts[1])[0] == 200
    assert advance_sign(net, contexts[1])[0] == 200
    for context in contexts:
        state = wait_sign(net, context)
        assert state["status"] == "COMPLETED", state
        verify_independently(net, context, state)
        for party in state["selected_signers"]:
            consumed = (
                net.root
                / party
                / "storage"
                / "cggmp-signing"
                / f"{state['crypto_execution_id']}.consumed"
            )
            assert json.loads(consumed.read_text())["request"] == context


def test_single_available_signer_never_starts_nonce_generation(auxiliary_network):
    net = auxiliary_network
    context = signing_request(net)
    assert request(net, "coordinator", "custody", "/v1/sign-sessions", context)[0] == 200
    net.stop("signer-b")
    net.stop("signer-c")
    try:
        assert advance_sign(net, context)[0] == 200
        state = wait_sign(net, context)
        assert state["status"] == "RECONCILIATION_REQUIRED" and state["signature"] is None
        assert not (
            net.root / "signer-a" / "storage" / "cggmp-signing" / f"{context['session_id']}.json"
        ).exists()
        assert advance_sign(net, context)[0] == 409
    finally:
        net.start("signer-b")
        net.start("signer-c")


@pytest.mark.parametrize(
    "change",
    [
        {"payload_hex": "00" * 31},
        {"payload_hex": "FF" * 32},
        {"message_fingerprint": "00" * 32},
        {"payload_type": "TRON_TXID"},
        {"payload_type": "SOLANA_MESSAGE"},
        {"chain": "TRON"},
        {"operation_type": "ARBITRARY_ORACLE"},
        {"expected_source": "0x" + "00" * 20},
        {"derivation_reference": "m/0"},
        {"attempt_id": 0},
    ],
)
def test_invalid_custody_digest_context_rejected(auxiliary_network, change):
    net = auxiliary_network
    context = signing_request(net) | change
    status, _ = request(net, "coordinator", "custody", "/v1/sign-sessions", context)
    if status == 200:
        assert advance_sign(net, context)[0] == 400
        assert sign_state(net, context)["signature"] is None
    else:
        assert status == 400


def test_consumed_execution_crash_and_binding_replays_fail_closed(auxiliary_network):
    net = auxiliary_network
    context = signing_request(net)
    status, state = request(net, "coordinator", "custody", "/v1/sign-sessions", context)
    assert status == 200
    execution = {
        "request": context,
        "crypto_execution_id": state["crypto_execution_id"],
        "selected_signers": ["signer-a", "signer-b"],
        "auxiliary": net.aux_state["auxiliary"]["request"],
    }
    for party in execution["selected_signers"]:
        assert sign_control(net, party, "prepare", execution)[0] == 200
    assert sign_control(net, "signer-a", "start", execution)[0] == 200
    consumed = (
        net.root
        / "signer-a"
        / "storage"
        / "cggmp-signing"
        / f"{state['crypto_execution_id']}.consumed"
    )
    assert json.loads(consumed.read_text()) == execution
    time.sleep(0.1)
    net.stop("signer-a")
    net.start("signer-a")
    assert (
        sign_control(net, "signer-a", "report", execution)[1]["status"] == "RECONCILIATION_REQUIRED"
    )
    assert sign_control(net, "signer-a", "start", execution)[0] == 409
    assert sign_control(net, "signer-a", "prepare", execution)[0] == 409
    assert (
        sign_control(
            net, "signer-a", "prepare", execution | {"crypto_execution_id": str(uuid.uuid4())}
        )[0]
        == 409
    )
    for mutation in (
        {"crypto_execution_id": str(uuid.uuid4())},
        {"selected_signers": ["signer-a"]},
        {"selected_signers": ["signer-a", "signer-c"]},
        {"request": context | {"session_id": str(uuid.uuid4())}},
        {
            "request": context
            | {
                "payload_hex": "ab" * 32,
                "message_fingerprint": hashlib.sha256(bytes.fromhex("ab" * 32)).hexdigest(),
            }
        },
    ):
        assert sign_control(net, "signer-a", "report", execution | mutation)[0] == 409
    assert sign_control(net, "signer-b", "abort", execution)[0] == 200
    assert sign_control(net, "signer-a", "report", execution, "signer-b")[0] == 403


def test_aux_transport_accepts_distinct_same_round_and_rejects_sequence_replays(auxiliary_network):
    import subprocess

    from test_cggmp import bind_wire

    net = auxiliary_network
    context = binding()
    result = execute(net, context)
    auxiliary = {
        "dkg": context,
        "execution_id": str(uuid.uuid4()),
        "group_public_key": result["group_public_key"],
        "public_key_package": result["participant_agreement"][0]["public_key_package"],
    }
    assert aux_control(net, "signer-a", "prepare", auxiliary)[0] == 200
    transcript = hashlib.sha256(json.dumps(auxiliary, separators=(",", ":")).encode()).hexdigest()

    def wire(byte, sequence):
        fixture = json.loads(subprocess.check_output([str(net.bin / "examples" / "cggmp_aux_message_fixture"), str(byte)]))
        return bind_wire({
            "logical_session_id": context["session_id"],
            "crypto_execution_id": auxiliary["execution_id"],
            "keyset_id": context["keyset_id"],
            "protocol": f"CGGMP24_AUX:{transcript}/broadcast",
            "sender": "signer-b",
            "recipient": "signer-a",
            "round": fixture["round"],
            "sequence": sequence,
            "payload": list(json.dumps(fixture["msg"], separators=(",", ":")).encode()),
            "payload_digest": "",
        })

    def inject(role, message):
        return request(net, "signer-a", role, "/internal/v1/cggmp/aux/message", message)[0]

    assert inject("signer-b", wire(42, 0)) == 200
    assert inject("signer-b", wire(42, 0)) == 409
    assert inject("signer-b", wire(43, 0)) == 409
    assert inject("signer-b", wire(42, 1)) == 409
    assert inject("signer-b", wire(43, 1)) == 200
    for mutation in (
        {"sender": "signer-c"}, {"recipient": "signer-c"}, {"round": 99}, {"sequence": 256},
        {"crypto_execution_id": str(uuid.uuid4())}, {"logical_session_id": str(uuid.uuid4())},
        {"keyset_id": str(uuid.uuid4())}, {"protocol": "CGGMP24_AUX:wrong/broadcast"},
    ):
        assert inject("signer-b", bind_wire(wire(44, 2) | mutation)) == 409
    assert inject("coordinator", wire(44, 2)) == 403
    assert inject("signer-b", wire(44, 2) | {"payload_digest": "00" * 32}) == 409
    net.stop("signer-a")
    net.start("signer-a")
    assert inject("signer-b", wire(44, 2)) == 409
    assert aux_control(net, "signer-a", "start", auxiliary)[0] == 409
    assert aux_control(net, "signer-a", "prepare", auxiliary | {"execution_id": str(uuid.uuid4())})[0] == 409
