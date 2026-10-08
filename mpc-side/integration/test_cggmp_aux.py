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
        net, "coordinator", "custody", f"/v1/dkg-sessions/{context['session_id']}/auxiliary/{action}"
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
        assert auxiliary["status"] == "AUXILIARY_COMPLETED", auxiliary
        assert auxiliary["internally_signable"]
        costs = {r["party_id"]: r["prime_generation_ms"] for r in auxiliary["participant_agreement"]}
        print(f"Fresh prime generation milliseconds: {costs}; total {time.monotonic() - started:.3f}s")
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


@pytest.mark.parametrize("field", ["execution_id", "group_public_key", "keyset_id", "core_execution", "scope"])
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
    assert aux_control(net, "signer-a", "report", net.aux_state["auxiliary"]["request"], role)[0] == 403


@pytest.mark.parametrize("fault", ["ciphertext", "transplant", "wrapping-key"])
def test_corrupt_auxiliary_material_rejected_on_restart(auxiliary_network, fault):
    net = auxiliary_network
    path = net.root / "signer-a" / "storage" / "cggmp-aux" / f"{net.aux_context['keyset_id']}.share.enc"
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
