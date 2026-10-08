"""Real-process FROST signing; helpers encode public material only."""

import concurrent.futures
import hashlib
import json
import os
import subprocess
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from environment import ROLES, Processes
from solders.pubkey import Pubkey
from test_dkg import PARTIES, dkg_request, encrypted_files, execute, request


@pytest.fixture
def signing_network(tmp_path):
    net = Processes(tmp_path / "services")
    try:
        for role in ROLES[:4]:
            net.start(role)
        binding = dkg_request()
        status, dkg = execute(net, binding)
        assert status == 200 and dkg["status"] == "COMPLETED"
        yield net, binding, dkg
    finally:
        net.close()


def sign_request(dkg, message=b"Phase 6C.2 exact custody message"):
    return {
        "session_id": str(uuid.uuid4()),
        "attempt_id": 1,
        "keyset_id": dkg["keyset_id"],
        "algorithm": "FROST_ED25519",
        "payload_type": "SOLANA_MESSAGE",
        "payload_hex": message.hex(),
        "message_fingerprint": hashlib.sha256(message).hexdigest(),
        "operation_type": "WITHDRAWAL",
        "chain": "SOL",
        "asset": "SOL",
        "expected_source": str(Pubkey.from_bytes(bytes.fromhex(dkg["group_public_key"]))),
        "derivation_reference": None,
    }


def create(net, payload):
    return request(net, "coordinator", "custody", "/v1/sign-sessions", payload)


def sign_path(payload):
    return f"/v1/sign-sessions/{payload['session_id']}"


def run_sign(net, payload):
    assert create(net, payload)[0] == 200
    return request(net, "coordinator", "custody", sign_path(payload) + "/execute")


def assert_signature(payload, session, dkg, selected):
    assert session["status"] == "COMPLETED" and session["error_code"] is None
    assert session["selected_signers"] == list(selected)
    result = session["signature"]
    assert result == {
        "logical_session_id": payload["session_id"],
        "crypto_execution_id": session["crypto_execution_id"],
        "keyset_id": payload["keyset_id"],
        "selected_signers": list(selected),
        "algorithm": "FROST_ED25519",
        "payload_fingerprint": payload["message_fingerprint"],
        "signature_hex": result["signature_hex"],
        "verified": True,
    }
    signature = bytes.fromhex(result["signature_hex"])
    assert len(signature) == 64 and len(result["signature_hex"]) == 128
    public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(dkg["group_public_key"]))
    public.verify(signature, bytes.fromhex(payload["payload_hex"]))
    with pytest.raises(Exception):
        public.verify(signature, bytes.fromhex(payload["payload_hex"]) + b"changed")


def execution(payload, session, dkg, selected=PARTIES[:2]):
    binding = {key: dkg[key] for key in dkg_request()}
    return {
        "request": payload,
        "crypto_execution_id": session["crypto_execution_id"],
        "selected_signers": list(selected),
        "dkg": binding,
        "group_public_key": dkg["group_public_key"],
        "public_key_package": dkg["participant_agreement"][0]["public_key_package"],
    }


def sign_control(net, party, action, binding, package=None, **changes):
    control = {
        "execution": binding,
        "sender": "coordinator",
        "recipient": party,
        "round": {"round1": 1, "round2": 2}.get(action, 0),
        "signing_package": package,
    }
    control.update(changes)
    return request(net, party, "coordinator", f"/internal/v1/sign/{action}", control)


def package_for(net, binding, reports, message=None):
    data = {
        "commitments": {report["sender"]: report["commitments"] for report in reports},
        "message": list(message or bytes.fromhex(binding["request"]["payload_hex"])),
    }
    return json.loads(
        subprocess.check_output(
            [str(net.bin / "examples" / "frost_signing_package")], input=json.dumps(data).encode()
        )
    )


def manual_round1(net, dkg):
    payload = sign_request(dkg)
    status, session = create(net, payload)
    assert status == 200
    binding = execution(payload, session, dkg)
    reports = []
    for party in binding["selected_signers"]:
        status, report = sign_control(net, party, "round1", binding)
        assert status == 200 and report["status"] == "NONCES_CREATED"
        reports.append(report)
    return payload, session, binding, reports


@pytest.mark.parametrize(
    "selected", [("signer-a", "signer-b"), ("signer-a", "signer-c"), ("signer-b", "signer-c")]
)
def test_all_pairs_same_group_and_restart(signing_network, selected):
    net, dkg_binding, dkg = signing_network
    before = encrypted_files(net, dkg_binding)
    # All signers restart after real DKG, then one is unavailable during signing.
    for party in PARTIES:
        net.stop(party)
    for party in selected:
        net.start(party)
    payload = sign_request(dkg)
    status, completed = run_sign(net, payload)
    assert status == 200
    assert_signature(payload, completed, dkg, selected)
    assert request(net, "coordinator", "custody", sign_path(payload), method="GET") == (
        200,
        completed,
    )
    assert run_sign(net, payload) == (200, completed)
    saved = (net.root / "coordinator" / "storage" / "coordinator.json").read_bytes()
    records = {p: list((net.root / p / "storage" / "signing").glob("*.json")) for p in selected}
    assert all(len(paths) == 1 for paths in records.values())
    tombstones = {
        p: (
            net.root / p / "storage" / "executions" / f"{completed['crypto_execution_id']}.state"
        ).read_bytes()
        for p in selected
    }
    for role in ROLES[:4]:
        net.stop(role)
    net.start("coordinator")
    assert run_sign(net, payload) == (200, completed)
    net.stop("coordinator")
    for role in ROLES[:4]:
        net.start(role)
    assert run_sign(net, payload) == (200, completed)
    assert (net.root / "coordinator" / "storage" / "coordinator.json").read_bytes() == saved
    assert encrypted_files(net, dkg_binding) == before
    for party in selected:
        assert (
            (
                net.root
                / party
                / "storage"
                / "executions"
                / f"{completed['crypto_execution_id']}.state"
            ).read_bytes()
            == tombstones[party]
            == b"COMPLETED"
        )


def test_three_pairs_share_one_dkg_group(signing_network):
    net, _, dkg = signing_network
    for omitted in reversed(PARTIES):
        net.stop(omitted)
        selected = [p for p in PARTIES if p != omitted]
        payload = sign_request(dkg, message=os.urandom(80))
        status, completed = run_sign(net, payload)
        assert status == 200
        assert_signature(payload, completed, dkg, selected)
        net.start(omitted)


def test_one_party_no_signature_or_nonce_creation(signing_network):
    net, _, dkg = signing_network
    for party in PARTIES[1:]:
        net.stop(party)
    payload = sign_request(dkg)
    assert run_sign(net, payload)[0] == 409
    result = request(net, "coordinator", "custody", sign_path(payload), method="GET")[1]
    assert result["signature"] is None and result["status"] == "RECONCILIATION_REQUIRED"
    assert result["selected_signers"] == []
    assert not list((net.root / "signer-a" / "storage" / "signing").glob("*.json"))
    net.start("signer-b")
    assert run_sign(net, payload)[0] == 409


@pytest.mark.parametrize(
    "change",
    [
        {"keyset_id": str(uuid.uuid4())},
        {"message_fingerprint": "00" * 32},
        {"expected_source": "wrong"},
        {"algorithm": "CGGMP24_ECDSA"},
        {"payload_type": "TRON_TXID"},
        {"chain": "ETH"},
        {"operation_type": ""},
        {"asset": ""},
        {"attempt_id": 0},
        {"session_id": str(uuid.UUID(int=0))},
        {"derivation_reference": "unverified-derivation"},
        {"payload_hex": "éé"},
    ],
)
def test_custody_context_rejected(signing_network, change):
    net, _, dkg = signing_network
    payload = sign_request(dkg) | change
    if change.get("algorithm") == "CGGMP24_ECDSA":
        # Legacy CREATED metadata compatibility remains; execution is FROST-only.
        assert create(net, payload)[0] == 200
        assert request(net, "coordinator", "custody", sign_path(payload) + "/execute")[0] == 400
    else:
        assert create(net, payload)[0] == 400


@pytest.mark.parametrize("role", ["coordinator", "signer-a", "signer-b", "signer-c"])
def test_only_custody_can_create_signing_session(signing_network, role):
    net, _, dkg = signing_network
    assert request(net, "coordinator", role, "/v1/sign-sessions", sign_request(dkg))[0] == 403


@pytest.mark.parametrize("role", ["custody", "signer-a", "signer-b", "signer-c"])
def test_only_coordinator_can_control_signing(signing_network, role):
    net, _, dkg = signing_network
    payload = sign_request(dkg)
    _, session = create(net, payload)
    binding = execution(payload, session, dkg)
    assert (
        request(net, "signer-b", role, "/internal/v1/sign/round1", {"execution": binding})[0] == 403
    )


@pytest.mark.parametrize(
    "field",
    [
        "session",
        "execution",
        "keyset",
        "sender",
        "recipient",
        "round",
        "fingerprint",
        "selected",
        "dkg_execution",
        "group",
        "public_package",
    ],
)
def test_wrong_round_identity_and_crypto_evidence(signing_network, field):
    net, _, dkg = signing_network
    _, _, original, reports = manual_round1(net, dkg)
    changed = json.loads(json.dumps(original))
    kwargs = {}
    if field == "session":
        changed["request"]["session_id"] = str(uuid.uuid4())
    elif field == "execution":
        changed["crypto_execution_id"] = str(uuid.uuid4())
    elif field == "keyset":
        changed["request"]["keyset_id"] = str(uuid.uuid4())
    elif field == "sender":
        kwargs["sender"] = "signer-a"
    elif field == "recipient":
        kwargs["recipient"] = "signer-c"
    elif field == "round":
        kwargs["round"] = 1
    elif field == "fingerprint":
        changed["request"]["message_fingerprint"] = "00" * 32
    elif field == "selected":
        changed["selected_signers"] = ["signer-a", "signer-c"]
    elif field == "dkg_execution":
        changed["dkg"]["execution_id"] = str(uuid.uuid4())
    elif field == "group":
        changed["group_public_key"] = "00" * 32
    elif field == "public_package":
        changed["public_key_package"][-1] ^= 1
    assert (
        sign_control(
            net, "signer-b", "round2", changed, package_for(net, original, reports), **kwargs
        )[0]
        == 409
    )
    assert sign_control(net, "signer-b", "report", original)[1]["signature_share"] is None


def test_exact_package_duplicate_conflict_and_execution_reuse(signing_network):
    net, _, dkg = signing_network
    _, _, binding, reports = manual_round1(net, dkg)
    for party in binding["selected_signers"]:
        assert sign_control(net, party, "round1", binding)[0] == 409
    bad_message = package_for(net, binding, reports, b"conflicting exact message")
    assert sign_control(net, "signer-a", "round2", binding, bad_message)[0] == 409
    wrong_commitments = package_for(net, binding, [reports[0]])
    assert sign_control(net, "signer-a", "round2", binding, wrong_commitments)[0] == 409
    _, _, _, other_reports = manual_round1(net, dkg)
    swapped = package_for(net, binding, [other_reports[0], reports[1]])
    assert sign_control(net, "signer-a", "round2", binding, swapped)[0] == 409
    package = package_for(net, binding, reports)
    for party in binding["selected_signers"]:
        status, result = sign_control(net, party, "round2", binding, package)
        assert status == 200 and result["status"] == "SHARE_PRODUCED"
        assert sign_control(net, party, "round2", binding, package)[0] == 409
        assert sign_control(net, party, "round2", binding, bad_message)[0] == 409
        reused = binding | {"request": binding["request"] | {"session_id": str(uuid.uuid4())}}
        assert sign_control(net, party, "round1", reused)[0] == 409
        fresh_execution = binding | {"crypto_execution_id": str(uuid.uuid4())}
        assert sign_control(net, party, "round1", fresh_execution)[0] == 409


def test_concurrent_create_execute_one_execution(signing_network):
    net, _, dkg = signing_network
    payload = sign_request(dkg)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        created = list(pool.map(lambda _: create(net, payload), range(8)))
        results = list(
            pool.map(
                lambda _: request(net, "coordinator", "custody", sign_path(payload) + "/execute"),
                range(8),
            )
        )
    assert all(status == 200 for status, _ in created + results)
    assert len({result["crypto_execution_id"] for _, result in created + results}) == 1
    completed = request(net, "coordinator", "custody", sign_path(payload), method="GET")[1]
    assert_signature(payload, completed, dkg, PARTIES[:2])
    for party in PARTIES[:2]:
        files = list((net.root / party / "storage" / "signing").glob("*.json"))
        assert len(files) == 1 and json.loads(files[0].read_text())["status"] == "SHARE_PRODUCED"
    assert not list((net.root / "signer-c" / "storage" / "signing").glob("*.json"))


def test_concurrent_distinct_messages_use_distinct_nonces(signing_network):
    net, _, dkg = signing_network
    payloads = [sign_request(dkg, message=os.urandom(80)) for _ in range(4)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda payload: run_sign(net, payload), payloads))
    assert len({result["crypto_execution_id"] for _, result in results}) == 4
    for payload, (status, result) in zip(payloads, results):
        assert status == 200
        assert_signature(payload, result, dkg, PARTIES[:2])
    for party in PARTIES[:2]:
        reports = [
            json.loads(p.read_text())
            for p in (net.root / party / "storage" / "signing").glob("*.json")
        ]
        assert len(reports) == 4
        assert len({bytes(r["commitments"]) for r in reports}) == 4


def test_concurrent_round1_and_crash_nonce_never_reused(signing_network):
    net, _, dkg = signing_network
    payload = sign_request(dkg)
    _, session = create(net, payload)
    binding = execution(payload, session, dkg)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(lambda _: sign_control(net, "signer-a", "round1", binding), range(2))
        )
    assert sorted(status for status, _ in results) == [200, 409]
    commitment = next(r["commitments"] for status, r in results if status == 200)
    net.running["signer-a"].kill()
    net.running["signer-a"].wait(timeout=5)
    net.stop("signer-a")
    net.start("signer-a")
    assert (
        sign_control(net, "signer-a", "report", binding)[1]["status"] == "RECONCILIATION_REQUIRED"
    )
    assert sign_control(net, "signer-a", "round1", binding)[0] == 409
    assert sign_control(net, "signer-a", "round2", binding, [0])[0] == 409
    assert run_sign(net, payload)[0] == 409
    other = sign_request(dkg)
    _, created = create(net, other)
    new_binding = execution(other, created, dkg)
    status, fresh = sign_control(net, "signer-a", "round1", new_binding)
    assert status == 200 and fresh["commitments"] != commitment


def set_reconciliation(net, payload, selected, *, restart=True):
    net.stop("coordinator")
    path = net.root / "coordinator" / "storage" / "coordinator.json"
    state = json.loads(path.read_text())
    state["signing"][payload["session_id"]].update(
        status="IN_PROGRESS", selected_signers=list(selected)
    )
    path.write_text(json.dumps(state))
    if restart:
        net.start("coordinator")


@pytest.mark.parametrize("fault", [None, "invalid_share", "conflicting_package"])
def test_reconcile_persisted_real_shares_after_crash(signing_network, fault):
    net, _, dkg = signing_network
    payload, _, binding, reports = manual_round1(net, dkg)
    package = package_for(net, binding, reports)
    for party in binding["selected_signers"]:
        assert sign_control(net, party, "round2", binding, package)[0] == 200
    if fault:
        party = "signer-b"
        net.stop(party)
        path = net.root / party / "storage" / "signing" / f"{binding['crypto_execution_id']}.json"
        report = json.loads(path.read_text())
        if fault == "invalid_share":
            report["signature_share"] = [0] * 32
        else:
            report["signing_package"] = package_for(net, binding, reports, b"other message")
        path.write_text(json.dumps(report))
        net.start(party)
    set_reconciliation(net, payload, binding["selected_signers"])
    assert (
        request(net, "coordinator", "custody", sign_path(payload), method="GET")[1]["status"]
        == "RECONCILIATION_REQUIRED"
    )
    assert run_sign(net, payload)[0] == 409
    status, result = request(net, "coordinator", "custody", sign_path(payload) + "/reconcile")
    if fault:
        assert status == 409
        assert (
            request(net, "coordinator", "custody", sign_path(payload), method="GET")[1]["signature"]
            is None
        )
    else:
        assert status == 200
        assert_signature(payload, result, dkg, PARTIES[:2])


def test_keyset_eligibility_requires_encrypted_package(signing_network):
    net, dkg_binding, dkg = signing_network
    path = net.root / "signer-a" / "storage" / f"{dkg_binding['keyset_id']}.share.enc"
    path.write_bytes(path.read_bytes()[:-1])
    payload = sign_request(dkg)
    status, completed = run_sign(net, payload)
    assert status == 200
    assert_signature(payload, completed, dkg, PARTIES[1:])
    assert not list((net.root / "signer-a" / "storage" / "signing").glob("*.json"))


def rewrite_blob(net, party, binding, mutate):
    path = net.root / party / "storage" / f"{binding['keyset_id']}.share.enc"
    raw = path.read_bytes()
    identity = {"keyset_id": binding["keyset_id"], "party_id": party, "algorithm": "FROST_ED25519"}
    aad = json.dumps([2, identity], separators=(",", ":")).encode()
    wrapper = AESGCM((net.root / party / "identity" / "wrapping.key").read_bytes())
    stored = json.loads(wrapper.decrypt(raw[10:22], raw[22:], aad))
    blob = json.loads(bytes(stored["protocol_share"]))
    mutate(blob)
    stored["protocol_share"] = list(json.dumps(blob).encode())
    nonce = os.urandom(12)
    path.write_bytes(
        b"WMPCSHARE2" + nonce + wrapper.encrypt(nonce, json.dumps(stored).encode(), aad)
    )


def test_legacy_phase6c1_public_material_recovery(signing_network):
    net, binding, _ = signing_network
    for role in ROLES[:4]:
        net.stop(role)
    for party in PARTIES:
        rewrite_blob(net, party, binding, lambda blob: blob.pop("public_key_package"))
        path = net.root / party / "storage" / "dkg" / f"{binding['keyset_id']}.json"
        report = json.loads(path.read_text())
        report.pop("public_key_package")
        report.pop("verification_share")
        path.write_text(json.dumps(report))
    state_path = net.root / "coordinator" / "storage" / "coordinator.json"
    state = json.loads(state_path.read_text())
    for report in state["dkg"][binding["session_id"]]["participant_agreement"]:
        report.pop("public_key_package")
        report.pop("verification_share")
    state_path.write_text(json.dumps(state))
    for role in ROLES[:4]:
        net.start(role)
    status, upgraded = execute(net, binding)
    assert status == 200
    assert all(
        r["verification_share"] and r["public_key_package"] is None
        for r in upgraded["participant_agreement"]
    )
    for role in ROLES[:4]:
        net.stop(role)
    for role in ROLES[:4]:
        net.start(role)
    # The durable authenticated verification shares suffice after another restart.
    payload = sign_request(upgraded)
    status, completed = run_sign(net, payload)
    assert status == 200
    assert_signature(payload, completed, upgraded, PARTIES[:2])


def test_public_material_from_another_dkg_rejected(signing_network):
    net, binding, dkg = signing_network
    status, other = execute(net, dkg_request())
    assert status == 200 and other["group_public_key"] != dkg["group_public_key"]
    net.stop("signer-b")
    rewrite_blob(
        net,
        "signer-b",
        binding,
        lambda blob: blob.update(
            public_key_package=other["participant_agreement"][0]["public_key_package"]
        ),
    )
    with pytest.raises(RuntimeError, match="DKG recovery failed"):
        net.start("signer-b")


@pytest.mark.parametrize("fault", ["signature", "metadata"])
def test_restart_reverifies_authoritative_completed_result(signing_network, fault):
    net, _, dkg = signing_network
    payload = sign_request(dkg)
    status, completed = run_sign(net, payload)
    assert status == 200
    assert_signature(payload, completed, dkg, PARTIES[:2])
    net.stop("coordinator")
    path = net.root / "coordinator" / "storage" / "coordinator.json"
    state = json.loads(path.read_text())
    result = state["signing"][payload["session_id"]]["signature"]
    if fault == "signature":
        result["signature_hex"] = "00" * 64
    else:
        result["crypto_execution_id"] = str(uuid.uuid4())
    path.write_text(json.dumps(state))
    with pytest.raises(RuntimeError, match="invalid completed signing result"):
        net.start("coordinator")
