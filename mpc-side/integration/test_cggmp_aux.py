"""Fresh-prime distributed auxiliary generation through independent TLS services."""

import base64
import copy
import hashlib
import json
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from environment import ROLES, Processes
from test_cggmp import PARTIES, binding, execute
from test_dkg import request


def proof_wire(body):
    encoded = body.copy()
    encoded["wire_version"] = 1
    encoded["payload_base64"] = base64.b64encode(bytes(encoded.pop("payload"))).decode("ascii")
    return encoded


def proof_request(net, destination, role, path, body):
    return request(net, destination, role, path, proof_wire(body))


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


def print_proof_sizes(net):
    pattern = re.compile(
        r"^CGGMP proof delivery: path=/internal/v1/cggmp/aux/message "
        r"round=1 decoded_bytes=\d+ http_bytes=\d+ exceeded_old_payload_limit=(?:true|false)$",
        re.MULTILINE,
    )
    for party in PARTIES:
        metadata = pattern.findall((net.root / party / "service.log").read_text())
        assert metadata, "missing auxiliary round-one size diagnostics"
        print(party, metadata[0])


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
        print_proof_sizes(net)
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
    scope = net.aux_context["scope"]
    if scope == "TRON":
        from tronpy.keys import PublicKey as TronPublicKey

        raw_public = PublicKey(bytes.fromhex(group)).format(compressed=False)[1:]
        address = TronPublicKey(raw_public).to_base58check_address()
        payload_type = "TRON_TXID"
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
        "chain": "TRON" if scope == "TRON" else "ETH",
        "asset": "TRX" if scope == "TRON" else "ETH",
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
    status, response = request(net, "coordinator", "custody", "/v1/sign-sessions", context)
    assert status == 200, response
    offline = next(p for p in PARTIES if p not in pair)
    net.stop(offline)
    try:
        assert advance_sign(net, context)[0] == 200
        state = wait_sign(net, context)
        assert state["status"] == "COMPLETED", state
        assert state["selected_signers"] == list(pair)
        verify_independently(net, context, state)
        net.completed_sign_context = context
        net.completed_sign_state = state
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


def assert_root_signing_requires_trusted_custody_credentials(net):
    """Original root contract uses custody mTLS, not a child machine grant."""
    context = signing_request(net, digest=hashlib.sha256(uuid.uuid4().bytes).digest())
    assert not (
        net.root / "coordinator" / "storage" / "coordinator.hd" / f"{context['keyset_id']}.root"
    ).exists()
    for role in ("coordinator", "signer-a", "signer-b", "signer-c"):
        status, response = request(net, "coordinator", role, "/v1/sign-sessions", context)
        assert status == 403, response
    # Trust the genuine server CA while presenting the invalid client identity.
    # Thus wrong-ca rejection tests client authentication, not server distrust.
    trusted_ca = net.root / "custody" / "identity" / "ca.crt"
    url = f"https://localhost:{net.ports['coordinator']}/v1/sign-sessions"
    for role in ("wrong-ca", "expired", "ambiguous", "unknown"):
        identity = net.root / role / "identity"
        # Invalid chains/expiry produce TLS alerts; invalid URI identities can
        # close the authenticated connection before HTTP. Neither creates state.
        with pytest.raises(requests.exceptions.ConnectionError):
            requests.post(
                url,
                json=context,
                timeout=5,
                verify=str(trusted_ca),
                cert=(str(identity / "tls.crt"), str(identity / "tls.key")),
            )
    assert (
        request(
            net,
            "coordinator",
            "custody",
            f"/v1/sign-sessions/{context['session_id']}",
            method="GET",
        )[0]
        == 404
    )
    status, response = request(net, "coordinator", "custody", "/v1/sign-sessions", context)
    assert status == 200, response
    assert advance_sign(net, context)[0] == 200
    state = wait_sign(net, context)
    assert state["status"] == "COMPLETED", state
    verify_independently(net, context, state)
    print(
        "ROOT_CUSTODY_CREDENTIAL_REGRESSION valid_root_signature=true "
        "invalid_credentials_rejected=true"
    )


def test_root_signing_requires_trusted_custody_credentials(auxiliary_network):
    assert_root_signing_requires_trusted_custody_credentials(auxiliary_network)


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
        fixture = json.loads(
            subprocess.check_output(
                [str(net.bin / "examples" / "cggmp_aux_message_fixture"), str(byte)]
            )
        )
        return bind_wire(
            {
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
            }
        )

    def inject(role, message):
        return proof_request(net, "signer-a", role, "/internal/v1/cggmp/aux/message", message)[0]

    encoded = proof_wire(wire(42, 0))
    for malformed in (
        encoded | {"wire_version": 2},
        encoded | {"payload_base64": "!invalid!"},
        encoded | {"payload_base64": "AA==\n"},
        encoded | {"payload_base64": base64.b64encode(b"x" * (512 * 1024 + 1)).decode("ascii")},
        wire(42, 0),
    ):
        assert (
            request(net, "signer-a", "signer-b", "/internal/v1/cggmp/aux/message", malformed)[0]
            == 400
        )
    assert inject("signer-b", wire(42, 0)) == 200
    assert inject("signer-b", wire(42, 0)) == 409
    assert inject("signer-b", wire(43, 0)) == 409
    assert inject("signer-b", wire(42, 1)) == 409
    assert inject("signer-b", wire(43, 1)) == 200
    for mutation in (
        {"sender": "signer-c"},
        {"recipient": "signer-c"},
        {"round": 99},
        {"sequence": 256},
        {"crypto_execution_id": str(uuid.uuid4())},
        {"logical_session_id": str(uuid.uuid4())},
        {"keyset_id": str(uuid.uuid4())},
        {"protocol": "CGGMP24_AUX:wrong/broadcast"},
    ):
        assert inject("signer-b", bind_wire(wire(44, 2) | mutation)) == 409
    assert inject("coordinator", wire(44, 2)) == 403
    assert inject("signer-b", wire(44, 2) | {"payload_digest": "00" * 32}) == 409
    code, running = aux_control(net, "signer-a", "start", auxiliary)
    assert code == 200 and running["status"] == "IN_PROGRESS"
    time.sleep(0.1)
    net.stop("signer-a")
    net.start("signer-a")
    code, interrupted = aux_control(net, "signer-a", "report", auxiliary)
    assert code == 200 and interrupted["status"] == "RECONCILIATION_REQUIRED"
    assert not interrupted["durable"]
    assert inject("signer-b", wire(44, 2)) == 409
    assert aux_control(net, "signer-a", "start", auxiliary)[0] == 409
    assert (
        aux_control(net, "signer-a", "prepare", auxiliary | {"execution_id": str(uuid.uuid4())})[0]
        == 409
    )


@pytest.fixture(scope="module")
def tron_auxiliary_network(tmp_path_factory):
    net = Processes(tmp_path_factory.mktemp("cggmp-tron") / "services")
    try:
        for role in ROLES[:4]:
            net.start(role)
        context = binding("TRON")
        execute(net, context)
        started = time.monotonic()
        assert advance_aux(net, context)[0] == 200
        while time.monotonic() < started + 1815:
            state = get_keyset(net, context)
            if state["auxiliary"]["status"] != "IN_PROGRESS":
                break
            time.sleep(1)
        else:
            pytest.fail("TRON fresh auxiliary protocol exceeded bounded deadline")
        if state["auxiliary"]["status"] != "AUXILIARY_COMPLETED":
            for party in PARTIES:
                print(party, (net.root / party / "service.log").read_text())
        assert state["auxiliary"]["status"] == "AUXILIARY_COMPLETED", state
        print_proof_sizes(net)
        costs = {
            r["party_id"]: r["prime_generation_ms"]
            for r in state["auxiliary"]["participant_agreement"]
        }
        print(f"TRON fresh prime milliseconds: {costs}; total {time.monotonic() - started:.3f}s")
        net.aux_context, net.aux_state = context, state
        yield net
    finally:
        net.close()


@pytest.mark.parametrize(
    "pair", [("signer-a", "signer-b"), ("signer-a", "signer-c"), ("signer-b", "signer-c")]
)
def test_tron_exact_txid_all_pairs(tron_auxiliary_network, pair):
    net = tron_auxiliary_network
    # The custody input is the already computed raw_data hash, passed unchanged.
    txid = hashlib.sha256(b"custody TRON raw_data contract" + uuid.uuid4().bytes).digest()
    context = signing_request(net, digest=txid)
    assert context["payload_type"] == "TRON_TXID" and context["chain"] == "TRON"
    assert request(net, "coordinator", "custody", "/v1/sign-sessions", context)[0] == 200
    offline = next(p for p in PARTIES if p not in pair)
    net.stop(offline)
    try:
        assert advance_sign(net, context)[0] == 200
        state = wait_sign(net, context)
        assert state["status"] == "COMPLETED", state
        assert state["selected_signers"] == list(pair)
        verify_independently(net, context, state)
    finally:
        net.start(offline)


@pytest.mark.parametrize("typed", [False, True])
def test_existing_evm_custody_digest_contract(auxiliary_network, typed):
    from custody.mpc_payload import evm_signing_digest

    net = auxiliary_network
    unsigned = {
        "nonce": 0,
        "gas": 21000,
        "to": "0x" + "11" * 20,
        "value": 1,
        "data": b"",
        "chainId": 1,
    }
    if typed:
        unsigned |= {"maxFeePerGas": 2_000_000_000, "maxPriorityFeePerGas": 1_000_000_000}
    else:
        unsigned["gasPrice"] = 1_000_000_000
    payload_type, digest = evm_signing_digest(unsigned)
    context = signing_request(net, payload_type, digest)
    assert request(net, "coordinator", "custody", "/v1/sign-sessions", context)[0] == 200
    assert advance_sign(net, context)[0] == 200
    state = wait_sign(net, context)
    assert state["status"] == "COMPLETED", state
    verify_independently(net, context, state)


def test_missing_auxiliary_material_is_ineligible(auxiliary_network):
    net = auxiliary_network
    context = signing_request(net)
    execution = {
        "request": context,
        "crypto_execution_id": str(uuid.uuid4()),
        "selected_signers": ["signer-a", "signer-b"],
        "auxiliary": net.aux_state["auxiliary"]["request"],
    }
    path = (
        net.root
        / "signer-a"
        / "storage"
        / "cggmp-aux"
        / f"{net.aux_context['keyset_id']}.share.enc"
    )
    hidden = path.with_suffix(".unavailable")
    path.rename(hidden)
    try:
        assert sign_control(net, "signer-a", "probe", execution)[0] == 409
        assert sign_control(net, "signer-a", "prepare", execution)[0] == 409
        assert not (
            net.root / "signer-a" / "storage" / "cggmp-signing" / f"{context['session_id']}.json"
        ).exists()
    finally:
        hidden.rename(path)


def test_conflicting_signer_completion_rejected_on_restart(auxiliary_network):
    net = auxiliary_network
    context = net.completed_sign_context
    party = net.completed_sign_state["selected_signers"][0]
    path = net.root / party / "storage" / "cggmp-signing" / f"{context['session_id']}.completed"
    net.stop(party)
    saved = path.read_bytes()
    try:
        data = json.loads(saved)
        data["signature"]["r"] = "00" * 32
        path.write_text(json.dumps(data))
        with pytest.raises(RuntimeError, match="CGGMP signing recovery failed"):
            net.start(party)
    finally:
        net.stop(party)
        path.write_bytes(saved)
        net.start(party)


def signing_wire(net, execution, byte, sequence):
    import subprocess

    from test_cggmp import bind_wire

    fixture = json.loads(
        subprocess.check_output(
            [
                str(net.bin / "examples" / "cggmp_aux_message_fixture"),
                str(byte),
                "sign",
            ]
        )
    )
    transcript = hashlib.sha256(json.dumps(execution, separators=(",", ":")).encode()).hexdigest()
    return bind_wire(
        {
            "logical_session_id": execution["request"]["session_id"],
            "crypto_execution_id": execution["crypto_execution_id"],
            "keyset_id": execution["request"]["keyset_id"],
            "protocol": f"CGGMP24_SIGN:{transcript}/broadcast",
            "sender": "signer-b",
            "recipient": "signer-a",
            "round": fixture["round"],
            "sequence": sequence,
            "payload": list(json.dumps(fixture["msg"], separators=(",", ":")).encode()),
            "payload_digest": "",
        }
    )


def test_signing_transport_replay_and_invalid_partial_signature(auxiliary_network):
    from test_cggmp import bind_wire

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
    message_path = "/internal/v1/cggmp/sign/message"
    forged = signing_wire(net, execution, 42, 200)
    assert proof_request(net, "signer-a", "signer-b", message_path, forged)[0] == 200
    assert proof_request(net, "signer-a", "signer-b", message_path, forged)[0] == 409
    conflict = signing_wire(net, execution, 43, 200)
    assert proof_request(net, "signer-a", "signer-b", message_path, conflict)[0] == 409
    replay = signing_wire(net, execution, 42, 201)
    assert proof_request(net, "signer-a", "signer-b", message_path, replay)[0] == 409
    for mutation in (
        {"sender": "signer-c"},
        {"recipient": "signer-c"},
        {"round": 99},
        {"sequence": 256},
        {"crypto_execution_id": str(uuid.uuid4())},
        {"logical_session_id": str(uuid.uuid4())},
        {"keyset_id": str(uuid.uuid4())},
        {"protocol": "CGGMP24_SIGN:wrong/broadcast"},
    ):
        changed = bind_wire(signing_wire(net, execution, 44, 202) | mutation)
        assert proof_request(net, "signer-a", "signer-b", message_path, changed)[0] == 409
    assert proof_request(net, "signer-a", "coordinator", message_path, forged)[0] == 403
    for party in execution["selected_signers"]:
        assert sign_control(net, party, "start", execution)[0] == 200
    deadline = time.monotonic() + 185
    while time.monotonic() < deadline:
        code, report = sign_control(net, "signer-a", "report", execution)
        assert code == 200
        if report["status"] != "IN_PROGRESS":
            break
        time.sleep(0.1)
    assert report["status"] == "RECONCILIATION_REQUIRED" and report["signature"] is None
    # Attempting dispatch/recovery cannot overwrite the original consumed execution.
    assert advance_sign(net, context)[0] == 200
    uncertain = wait_sign(net, context)
    assert uncertain["crypto_execution_id"] == state["crypto_execution_id"]
    assert uncertain["status"] == "RECONCILIATION_REQUIRED" and uncertain["signature"] is None
    assert advance_sign(net, context)[0] == 409
    assert advance_sign(net, context, "reconcile")[0] == 409
    for party in execution["selected_signers"]:
        sign_control(net, party, "abort", execution)


def test_coordinator_restart_reconciles_existing_public_signature(auxiliary_network):
    net = auxiliary_network
    context = signing_request(net, digest=hashlib.sha256(uuid.uuid4().bytes).digest())
    assert request(net, "coordinator", "custody", "/v1/sign-sessions", context)[0] == 200
    assert advance_sign(net, context)[0] == 200
    deadline = time.monotonic() + 205
    while time.monotonic() < deadline:
        state = sign_state(net, context)
        if state["status"] == "COMPLETED":
            break
        if state["selected_signers"] and all(
            (
                net.root
                / p
                / "storage"
                / "cggmp-signing"
                / f"{state['crypto_execution_id']}.consumed"
            ).exists()
            for p in state["selected_signers"]
        ):
            break
        time.sleep(0.01)
    execution = {
        "request": context,
        "crypto_execution_id": state["crypto_execution_id"],
        "selected_signers": state["selected_signers"],
        "auxiliary": net.aux_state["auxiliary"]["request"],
    }
    net.stop("coordinator")
    try:
        while time.monotonic() < deadline:
            reports = [sign_control(net, p, "report", execution) for p in state["selected_signers"]]
            if all(code == 200 and report["status"] == "COMPLETED" for code, report in reports):
                break
            time.sleep(0.1)
        else:
            pytest.fail("signers did not persist public completion with coordinator offline")
    finally:
        net.start("coordinator")
    reopened = sign_state(net, context)
    assert reopened["crypto_execution_id"] == state["crypto_execution_id"]
    if reopened["status"] == "RECONCILIATION_REQUIRED":
        assert advance_sign(net, context)[0] == 409
        status, reopened = advance_sign(net, context, "reconcile")
        assert status == 200
    assert reopened["status"] == "COMPLETED"
    verify_independently(net, context, reopened)
    assert advance_sign(net, context) == (200, reopened)


def test_partial_auxiliary_persistence_cannot_claim_readiness(tmp_path):
    net = Processes(tmp_path / "partial-aux")
    try:
        for role in ROLES[:4]:
            net.start(role)
        context = binding()
        execute(net, context)
        core_path = net.root / "signer-a" / "storage" / f"{context['keyset_id']}.share.enc"
        core = core_path.read_bytes()
        artifact = net.root / "signer-a" / "storage" / "cggmp-aux" / core_path.name
        assert advance_aux(net, context)[0] == 200
        auxiliary = get_keyset(net, context)["auxiliary"]["request"]
        preparation_deadline = time.monotonic() + 30
        while time.monotonic() < preparation_deadline:
            reports = [aux_control(net, p, "report", auxiliary) for p in PARTIES]
            if all(code == 200 and report["status"] == "IN_PROGRESS" for code, report in reports):
                break
            time.sleep(0.05)
        else:
            pytest.fail("all three auxiliary workers were not started")
        # Inject only AFTER preparation, while fresh primes are being generated.
        # The conflict then blocks final persistence, not initial reservation.
        artifact.write_bytes(b"conflicting immutable auxiliary artifact")
        deadline = time.monotonic() + 1815
        while time.monotonic() < deadline:
            state = get_keyset(net, context)
            if state["auxiliary"]["status"] != "IN_PROGRESS":
                break
            time.sleep(1)
        else:
            pytest.fail("partial persistence did not reach bounded uncertain state")
        assert state["auxiliary"]["status"] == "RECONCILIATION_REQUIRED"
        assert not state["auxiliary"]["internally_signable"]
        assert artifact.read_bytes() == b"conflicting immutable auxiliary artifact"
        assert core_path.read_bytes() == core
        for party in PARTIES:
            code, report = aux_control(net, party, "report", auxiliary)
            assert code == 200 and report["prime_generation_ms"] > 0
        auxiliary = state["auxiliary"]["request"]
        execution_id = auxiliary["execution_id"]
        artifact.unlink()
        for role in ROLES[:4]:
            net.stop(role)
            net.start(role)
        reopened = get_keyset(net, context)["auxiliary"]
        assert reopened["status"] == "RECONCILIATION_REQUIRED"
        assert not reopened["internally_signable"]
        assert reopened["request"]["execution_id"] == execution_id
        assert advance_aux(net, context)[0] == 409
        assert advance_aux(net, context, "reconcile")[0] == 409
        assert get_keyset(net, context)["auxiliary"]["request"]["execution_id"] == execution_id
        assert aux_control(net, "signer-a", "prepare", auxiliary)[0] == 409
        assert (
            aux_control(
                net, "signer-a", "prepare", auxiliary | {"execution_id": str(uuid.uuid4())}
            )[0]
            == 409
        )
    finally:
        net.close()


@pytest.mark.django_db(transaction=True)
def test_phase6e_real_evm_custody_acceptance(auxiliary_network, tmp_path):
    from evm_acceptance import run_evm_acceptance

    run_evm_acceptance(auxiliary_network, tmp_path)


@pytest.mark.django_db(transaction=True)
def test_phase6f_real_tron_custody_acceptance(tron_auxiliary_network, tmp_path):
    from tron_acceptance import run_tron_acceptance

    run_tron_acceptance(tron_auxiliary_network, tmp_path)


@pytest.mark.django_db(transaction=True)
def test_phase6g_authenticated_root_path_reservations(auxiliary_network):
    """Real DKG/aux/mTLS evidence; path reservations still confer no spendability."""
    from custody.models import MpcDerivationReservation, MpcKeyset, UserWallet
    from custody.mpc_provisioning import register_provisioning_root, reserve_derivation_path
    from django.db import close_old_connections, connection
    from django.test import override_settings
    from evm_acceptance import LocalChain
    from ops.models import Chain, NodeEndpoint
    from test_network import settings_for

    assert connection.vendor == "postgresql"
    net = auxiliary_network
    keyset = MpcKeyset.objects.create(
        keyset_id=net.aux_context["keyset_id"],
        algorithm="CGGMP24_ECDSA",
        curve="secp256k1",
        scope="EVM",
        derivation_version="cggmp_hd_v1",
        status="ACTIVE",
        participant_identities=net.aux_context["participants"],
        public_key=net.aux_state["group_public_key"],
        dkg_execution_id=net.aux_context["execution_id"],
        dkg_result_fingerprint=net.aux_state["result_fingerprint"],
    )
    chain = LocalChain("berlin", 31337)
    try:
        genesis = chain.rpc("eth_getBlockByNumber", ["0x0", False])["hash"]
        Chain.objects.filter(chain_id="ETH").update(
            enabled=True, kind="evm", is_testnet=True, evm_chain_id=31337
        )
        NodeEndpoint.objects.filter(chain_id="ETH", kind="rpc").update(enabled=False)
        NodeEndpoint.objects.create(
            chain_id="ETH",
            name="phase6g-isolated",
            kind="rpc",
            url=chain.url,
            enabled=True,
            is_primary=True,
        )
        with (
            settings_for(net),
            override_settings(
                MPC_SIGNER_BACKEND="self_hosted_mpc",
                MPC_EVM_INTEGRATION_ENABLED=True,
                MPC_INTEGRATION_ENVIRONMENT="development",
                MPC_EVM_DEVELOPMENT_CHAINS={"ETH": 31337},
                MPC_EVM_GENESIS_HASHES={"ETH": genesis},
                CUSTODY_DEMO_MODE=False,
                CUSTODY_TX_MODE="live",
            ),
        ):
            root = register_provisioning_root(
                keyset_id=keyset.keyset_id, chain_id="ETH", ownership_scope="isolated-acceptance"
            )
            assert len(root.dkg_public_evidence["participant_agreement"]) == 3
            before = UserWallet.objects.count()

            def worker(index):
                close_old_connections()
                try:
                    return reserve_derivation_path(
                        keyset_id=keyset.keyset_id,
                        ownership_scope="isolated-acceptance",
                        customer_ref=f"customer-{index % 16}",
                        idempotency_key=f"request-{index % 16}",
                    ).pk
                finally:
                    close_old_connections()

            with ThreadPoolExecutor(max_workers=4) as pool:
                assigned = list(pool.map(worker, range(32)))
            assert len(set(assigned)) == 16
            original = worker(0)
            net.stop("coordinator")
            connection.close()
            assert worker(0) == original
            net.start("coordinator")
            recovered = register_provisioning_root(
                keyset_id=keyset.keyset_id, chain_id="ETH", ownership_scope="isolated-acceptance"
            )
            assert recovered.root_identity == root.root_identity
            assert recovered.dkg_public_evidence == root.dkg_public_evidence
            assert recovered.next_index == 16
            assert MpcDerivationReservation.objects.count() == 16
            assert UserWallet.objects.count() == before
    finally:
        if "coordinator" not in net.running:
            net.start("coordinator")
        chain.close()


@pytest.mark.django_db(transaction=True)
def test_phase6gb_real_tron_child_custody(tron_auxiliary_network, tmp_path):
    from tron_acceptance import run_tron_acceptance

    run_tron_acceptance(tron_auxiliary_network, tmp_path, child_wallets=True)


@pytest.mark.django_db(transaction=True)
def test_phase6gb_real_evm_child_custody(auxiliary_network, tmp_path):
    from child_acceptance import run_evm_child_acceptance

    run_evm_child_acceptance(auxiliary_network, tmp_path)
    # Run immediately after permanent child attestation, independently of pytest
    # ordering: the original root must still sign with trusted custody mTLS.
    assert_root_signing_requires_trusted_custody_credentials(auxiliary_network)


def test_phase6gb_root_dedication_requires_original_custody_authority(auxiliary_network):
    """R2: real legacy signatures survive coordinator-only dedication and restart."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from custody.mpc_request_auth import authorize_root_dedication, dedication_statement

    net = auxiliary_network

    def root_request(dkg, state, namespace="lifecycle-acceptance"):
        return {
            "auxiliary": state["auxiliary"]["request"],
            "scope": {
                "ownership_scope": namespace,
                "chain_id": "ETH",
                "purpose": "DEPOSIT",
                "wallet_class": "HOT",
                "derivation_version": "cggmp_slip10_nonhardened_v1",
                "root_identity": {
                    "keyset_id": dkg["keyset_id"],
                    "chain_id": "ETH",
                    "scope": "EVM",
                    "algorithm": dkg["algorithm"],
                    "public_key": state["group_public_key"],
                    "dkg_execution_id": dkg["execution_id"],
                    "dkg_fingerprint": state["result_fingerprint"],
                    "network": {"evm_chain_id": 31337, "genesis_hash": "0x" + "11" * 32},
                },
            },
        }

    def authorize(statement, role="custody"):
        identity = net.root / role / "identity"
        if role == "custody":
            return authorize_root_dedication(statement, identity / "tls.crt", identity / "tls.key")
        certificate = x509.load_pem_x509_certificate((identity / "tls.crt").read_bytes())
        key = serialization.load_pem_private_key((identity / "tls.key").read_bytes(), None)
        message = (
            b"Wallet-MPC/CUSTODY_HD_DEDICATION_V1\0"
            + json.dumps(
                statement, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode()
        )
        return {
            "certificate_chain_der_hex": [
                certificate.public_bytes(serialization.Encoding.DER).hex()
            ],
            "signature_der_hex": key.sign(message, ec.ECDSA(hashes.SHA256())).hex(),
        }

    def snapshot():
        return {
            str(path.relative_to(net.root)): path.read_bytes()
            for party in PARTIES
            for path in (net.root / party / "storage" / "cggmp-hd").glob("*")
        }

    def sign_legacy(offline=None):
        context = signing_request(net)
        assert request(net, "coordinator", "custody", "/v1/sign-sessions", context)[0] == 200
        if offline:
            net.stop(offline)
        try:
            assert advance_sign(net, context)[0] == 200
            state = wait_sign(net, context)
            assert state["status"] == "COMPLETED", state["status"]
            verify_independently(net, context, state)
        finally:
            if offline:
                net.start(offline)
        return context

    sign_legacy()
    sign_legacy("signer-a")  # All three signers now hold authentic root-use history.
    hd = root_request(net.aux_context, net.aux_state)
    before = snapshot()
    for party in PARTIES:
        assert request(net, party, "coordinator", "/internal/v1/cggmp/hd/attest", hd)[0] == 400
    assert snapshot() == before
    # Even a valid custody dedication cannot retroactively relabel a used root.
    historical_statement = dedication_statement(hd)
    envelope = {
        "statement": historical_statement,
        "custody_authorization": authorize(historical_statement),
    }
    for party in PARTIES:
        assert (
            request(net, party, "coordinator", "/internal/v1/cggmp/hd/attest", envelope)[0] == 409
        )
    assert snapshot() == before
    sign_legacy()
    for party in PARTIES:
        net.stop(party)
        net.start(party)
    sign_legacy()
    assert not any(
        (net.root / p / "storage" / "cggmp-hd" / f"{net.aux_context['keyset_id']}.root").exists()
        for p in PARTIES
    )

    # Fresh independent real DKG/auxiliary root is eligible for authorized dedication.
    dkg = binding()
    execute(net, dkg)
    assert advance_aux(net, dkg)[0] == 200
    deadline = time.monotonic() + 1815
    while time.monotonic() < deadline:
        state = get_keyset(net, dkg)
        if state["auxiliary"]["status"] != "IN_PROGRESS":
            break
        time.sleep(1)
    assert state["auxiliary"]["status"] == "AUXILIARY_COMPLETED"
    fresh = dedication_statement(root_request(dkg, state, "authorized-fresh"))
    valid = {"statement": fresh, "custody_authorization": authorize(fresh)}
    before = snapshot()
    faults = []
    for fault in (
        "missing",
        "signature",
        "coordinator",
        "wrong-ca",
        "expired",
        "wrong-keyset",
        "replay-root",
        "purpose",
        "original-role",
        "role",
        "namespace",
        "network",
    ):
        altered = copy.deepcopy(valid)
        if fault == "missing":
            del altered["custody_authorization"]
        elif fault == "signature":
            altered["custody_authorization"]["signature_der_hex"] = "00" * 70
        elif fault in ("coordinator", "wrong-ca", "expired"):
            altered["custody_authorization"] = authorize(fresh, fault)
        elif fault == "wrong-keyset":
            altered["statement"]["dedication_id"] = str(uuid.uuid4())
        elif fault == "replay-root":
            altered["statement"] = historical_statement
        elif fault == "purpose":
            altered["statement"]["request"]["scope"]["purpose"] = "WITHDRAWAL"
        elif fault == "original-role":
            altered["statement"]["original_role"] = "HISTORICAL_ROOT"
        elif fault == "role":
            altered["statement"]["target_role"] = "ROOT_ONLY"
        elif fault == "namespace":
            altered["statement"]["request"]["scope"]["ownership_scope"] = "intruder"
        else:
            altered["statement"]["request"]["scope"]["root_identity"]["network"]["genesis_hash"] = (
                "0x" + "12" * 32
            )
        statuses = [
            request(net, p, "coordinator", "/internal/v1/cggmp/hd/attest", altered)[0]
            for p in PARTIES
        ]
        assert all(s in (400, 409) for s in statuses), (fault, statuses)
        assert snapshot() == before
        faults.append(fault)
    status, evidence = request(
        net, "coordinator", "custody", f"/v1/keysets/{dkg['keyset_id']}/hd-attestation", valid
    )
    assert status == 200, evidence
    assert all(r["signer_signature"] for r in evidence["participant_agreement"])
    receipts = snapshot()
    for party in PARTIES:
        net.stop(party)
        net.start(party)
    assert snapshot() == receipts
    # Real signer probes must reject root-only fallback, even without coordinator HD guard.
    fallback = signing_request(net)
    fallback["keyset_id"] = dkg["keyset_id"]
    from types import SimpleNamespace
    from unittest.mock import patch

    from custody.chain_registry import ChainKind
    from custody.mpc_identity import address_from_public_key

    with patch(
        "custody.mpc_identity.get_chain_spec", return_value=SimpleNamespace(kind=ChainKind.EVM)
    ):
        fallback["expected_source"] = address_from_public_key("ETH", state["group_public_key"])
    probe = {
        "request": fallback,
        "crypto_execution_id": str(uuid.uuid4()),
        "selected_signers": ["signer-a", "signer-b"],
        "auxiliary": state["auxiliary"]["request"],
    }
    for party in PARTIES[:2]:
        assert sign_control(net, party, "probe", probe)[0] == 409
    for party in PARTIES:
        assert request(net, party, "coordinator", "/internal/v1/cggmp/hd/attest", valid)[0] == 200
    assert snapshot() == receipts
    conflicting = copy.deepcopy(fresh)
    conflicting["request"]["scope"]["ownership_scope"] = "conflicting"
    for party in PARTIES:
        assert (
            request(
                net,
                party,
                "coordinator",
                "/internal/v1/cggmp/hd/attest",
                {"statement": conflicting, "custody_authorization": authorize(conflicting)},
            )[0]
            == 409
        )
    assert snapshot() == receipts
    sign_legacy()
    print(
        "R2_ROOT_LIFECYCLE "
        + json.dumps(
            {
                "legacy_before_after_restart": "COMPLETED",
                "coordinator_only_rejected": 3,
                "no_unauthorized_mutation": True,
                "fresh_authorized_dedication": True,
                "dedicated_restart_root_fallback_rejected": True,
                "negative_cases": faults,
                "original_receipts_recovered": True,
            }
        )
    )
