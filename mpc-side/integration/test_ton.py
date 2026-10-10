"""Authenticated independent-process FROST + actual TVM, never network finality."""

import hashlib
import json
import subprocess
import uuid
from copy import deepcopy
from pathlib import Path

import pytest
from custody.ton_effects import execution_from_boc, terminal_transfer_effect
from custody.ton_policy import prepare_authorization
from custody.ton_wire import (
    JETTON_WALLET_CODE_HASH,
    Cell,
    assemble_signature,
    jetton_wallet_address,
    validate_authorization,
    verify_jetton_wallet,
    verify_wallet_state,
    wallet_address,
)
from environment import REPO, ROLES, Processes
from test_dkg import PARTIES, dkg_request, execute, request
from test_signing import assert_signature, create, execution, run_sign, sign_control


class Tvm:
    def __init__(self):
        self.process = subprocess.Popen(
            ["node", str(Path(__file__).parent / "ton/tvm.cjs")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.now = 1900000000
        self.treasury = self.call("init")["treasury"]

    def call(self, action, **kwargs):
        self.process.stdin.write(json.dumps(dict(action=action, **kwargs)) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        assert line, self.process.stderr.read()
        result = json.loads(line)
        assert "error" not in result, result.get("error")
        return result["result"]

    def authorize(self, public, destination, amount=100000000, **kwargs):
        source = wallet_address(public, -777)
        state = self.call("state", address=source)
        seq = verify_wallet_state(
            source,
            public,
            -777,
            status=state["status"],
            code=Cell.one_from_boc(bytes.fromhex(state["code"])) if state["code"] else None,
            data=Cell.one_from_boc(bytes.fromhex(state["data"])) if state["data"] else None,
        )
        a = prepare_authorization(
            public_key=public,
            global_id=-777,
            source=source,
            destination=destination,
            amount_units=amount,
            seqno=seq,
            valid_until=self.now + 120,
            chain_time=self.now,
            balance_nanoton=int(state["balance"]),
            deployed=state["status"] == "active",
            destination_active=self.call("state", address=destination)["status"] == "active",
            **kwargs,
        )["ton_authorization"]
        sdk = self.call("sdk", authorization=a, public_key=public.hex())
        assert sdk["address"] == source
        assert sdk["signing_hash"] == validate_authorization(a, public).hex()
        return a

    def close(self):
        self.process.terminate()
        self.process.wait(timeout=10)


def signed(net, binding, dkg, a, selected=PARTIES[:2], operation="WITHDRAWAL", execute=True):
    public = bytes.fromhex(dkg["group_public_key"])
    digest = validate_authorization(a, public)
    payload = {
        "session_id": str(uuid.uuid4()),
        "attempt_id": 1,
        "keyset_id": binding["keyset_id"],
        "algorithm": "FROST_ED25519",
        "payload_type": "TON_V5R1_CELL_HASH",
        "payload_hex": digest.hex(),
        "message_fingerprint": hashlib.sha256(digest).hexdigest(),
        "operation_type": operation,
        "chain": "TON",
        "asset": a["jetton_master"] or "TON",
        "expected_source": wallet_address(public, -777),
        "derivation_reference": None,
        "ton_authorization": a,
    }
    status, session = run_sign(net, payload) if execute else create(net, payload)
    assert status == 200, session
    if not execute:
        return None, None, session, payload
    assert_signature(payload, session, dkg, selected)
    raw, message_hash = assemble_signature(a, public.hex(), session["signature"]["signature_hex"])
    return raw, message_hash, session, payload


def test_ton_frost_all_pairs_tvm_native_jetton_restart_expiry(tmp_path):
    net, tvm = Processes(tmp_path / "private-services"), Tvm()
    evidence = {"category": "MPC_AND_TVM_ONLY", "network_finality": False, "operations": []}
    try:
        for role in ROLES[:4]:
            net.start(role)
        binding = dkg_request()
        binding["scope"] = "TON"
        status, dkg = execute(net, binding)
        assert status == 200 and dkg["status"] == "COMPLETED", dkg
        public = bytes.fromhex(dkg["group_public_key"])
        source = wallet_address(public, -777)
        evidence.update(
            public_key=public.hex(), dkg_fingerprint=dkg["result_fingerprint"], source=source
        )
        tvm.call("fund", address=source, amount="5000000000")
        for index, omitted in enumerate(reversed(PARTIES)):
            net.stop(omitted)
            selected = [p for p in PARTIES if p != omitted]
            a = tvm.authorize(public, tvm.treasury, comment=b"native-invoice")
            raw, message_hash, session, payload = signed(
                net, binding, dkg, a, selected, "SWEEP" if index == 2 else "WITHDRAWAL"
            )
            result = tvm.call("send", boc=raw)
            executions = [execution_from_boc(t["boc"]) for t in result["transactions"]]
            effect = terminal_transfer_effect(a, source, message_hash, executions)
            assert effect["terminal"], effect
            assert not terminal_transfer_effect(a, source, message_hash, executions[:1])["terminal"]
            assert tvm.call("state", address=source)["status"] == "active"
            with pytest.raises(AssertionError):
                tvm.call("send", boc=raw)  # original seqno cannot transfer twice
            assert run_sign(net, payload) == (200, session)
            evidence["operations"].append(
                dict(
                    pair=selected,
                    execution=session["crypto_execution_id"],
                    message_hash=message_hash,
                    seqno=a["seqno"],
                    effect=effect,
                )
            )
            net.start(omitted)
        master = tvm.call("master")["address"]
        tvm.call("mint", owner=source, amount="1000000")
        jw = jetton_wallet_address(source, master)
        assert tvm.call("wallet-address", owner=source)["address"] == jw
        state = tvm.call("state", address=jw)
        assert (
            verify_jetton_wallet(
                jw,
                source,
                master,
                Cell.one_from_boc(bytes.fromhex(state["code"])),
                Cell.one_from_boc(bytes.fromhex(state["data"])),
                jw,
            )
            == 1000000
        )
        for query in (100, 101):
            a = tvm.authorize(
                public,
                tvm.treasury,
                amount=250000,
                jetton_master=master,
                query_id=query,
                jetton_balance=int(tvm.call("jetton-data", address=jw)["balance"]),
            )
            raw, h, session, payload = signed(
                net, binding, dkg, a, operation="SWEEP" if query == 101 else "WITHDRAWAL"
            )
            result = tvm.call("send", boc=raw)
            executions = [execution_from_boc(t["boc"]) for t in result["transactions"]]
            effect = terminal_transfer_effect(a, source, h, executions)
            assert effect["terminal"], effect
            assert not terminal_transfer_effect(a, source, h, executions[:2])["terminal"]
            recipient = jetton_wallet_address(tvm.treasury, master)
            data = tvm.call("jetton-data", address=recipient)
            assert (
                data["owner"] == tvm.treasury
                and data["master"] == master
                and data["code_hash"] == JETTON_WALLET_CODE_HASH
            )
            assert int(data["balance"]) == (query - 99) * 250000
            evidence["operations"].append(
                dict(
                    query_id=query,
                    execution=session["crypto_execution_id"],
                    message_hash=h,
                    effect=effect,
                )
            )
        before_spoof = int(tvm.call("jetton-data", address=jw)["balance"])
        rejected = []
        for field, value in [
            ("wallet_version", "V4R2"),
            ("code_hash", "00" * 32),
            ("wallet_id", 0),
            ("seqno", a["seqno"] + 1),
            ("send_mode", 1),
            ("valid_until", 0),
            ("amount", "250001"),
            ("destination", "0:" + "33" * 32),
            ("jetton_master", "0:" + "44" * 32),
        ]:
            invalid = deepcopy(payload)
            invalid["session_id"] = str(uuid.uuid4())
            invalid["ton_authorization"][field] = value
            status, failed = create(net, invalid)
            if status == 200:
                status, failed = request(
                    net,
                    "coordinator",
                    "custody",
                    "/v1/sign-sessions/" + invalid["session_id"] + "/execute",
                )
            assert status >= 400 and not failed.get("signature"), (field, status, failed)
            rejected.append(field)
        evidence["authenticated_ton_authorization_mutations_rejected"] = rejected
        for notification in (True, False):
            spoof = tvm.call("spoof-jetton", address=jw, notification=notification)
            executions = [execution_from_boc(t["boc"]) for t in spoof["transactions"]]
            assert any(e.account == jw and not e.successful for e in executions)
            assert int(tvm.call("jetton-data", address=jw)["balance"]) == before_spoof
        evidence["spoofed_jetton_notification_and_internal_transfer_rejected"] = True
        # A deliberately corrupted recipient state exercises real TVM failure
        # and bounce rollback. Live preparation rejects this ownership state.
        recipient = jetton_wallet_address(tvm.treasury, master)
        tvm.call("corrupt-jetton-owner", address=recipient)
        corrupted = tvm.call("state", address=recipient)
        with pytest.raises(ValueError):
            verify_jetton_wallet(
                recipient,
                tvm.treasury,
                master,
                Cell.one_from_boc(bytes.fromhex(corrupted["code"])),
                Cell.one_from_boc(bytes.fromhex(corrupted["data"])),
                recipient,
            )
        before = int(tvm.call("jetton-data", address=jw)["balance"])
        a = tvm.authorize(
            public,
            tvm.treasury,
            amount=10000,
            jetton_master=master,
            query_id=102,
            jetton_balance=before,
        )
        raw, h, _, _ = signed(net, binding, dkg, a)
        bounced = tvm.call("send", boc=raw)
        executions = [execution_from_boc(t["boc"]) for t in bounced["transactions"]]
        assert not terminal_transfer_effect(a, source, h, executions)["terminal"]
        assert any(getattr(e.inbound.info, "bounced", False) for e in executions)
        assert int(tvm.call("jetton-data", address=jw)["balance"]) == before
        evidence["jetton_bounce"] = dict(
            message_hash=h,
            sender_balance_before=before,
            sender_balance_after=before,
            recipient_effect_unproven=True,
            transaction_hashes=[e.tx_hash for e in executions],
        )
        a = tvm.authorize(public, recipient, comment=b"native-bounce")
        raw, h, _, _ = signed(net, binding, dkg, a)
        executions = [
            execution_from_boc(t["boc"]) for t in tvm.call("send", boc=raw)["transactions"]
        ]
        assert any(getattr(e.inbound.info, "bounced", False) for e in executions)
        assert not terminal_transfer_effect(a, source, h, executions)["terminal"]
        evidence["native_bounce"] = dict(message_hash=h, terminal=False)
        for role in ROLES[:4]:
            net.stop(role)
        for role in ROLES[:4]:
            net.start(role)
        assert run_sign(net, payload) == (200, session)
        a = tvm.authorize(public, tvm.treasury)
        raw, h, session, _ = signed(net, binding, dkg, a)
        tvm.now = a["valid_until"] + 1
        tvm.call("time", now=tvm.now)
        with pytest.raises(AssertionError):
            tvm.call("send", boc=raw)
        assert tvm.authorize(public, tvm.treasury)["seqno"] == a["seqno"]
        # Interrupt after an actual independent signer persists its nonce
        # tombstone. Restart must never regenerate a nonce for that execution.
        a = tvm.authorize(public, tvm.treasury)
        _, _, pending, interrupted = signed(net, binding, dkg, a, execute=False)
        control = execution(interrupted, pending, dkg)
        assert sign_control(net, "signer-a", "round1", control)[0] == 200
        net.running["signer-a"].kill()
        net.running["signer-a"].wait(timeout=5)
        net.stop("signer-a")
        net.start("signer-a")
        assert (
            sign_control(net, "signer-a", "report", control)[1]["status"]
            == "RECONCILIATION_REQUIRED"
        )
        assert sign_control(net, "signer-a", "round1", control)[0] == 409
        assert run_sign(net, interrupted)[0] == 409
        evidence["nonce_interruption"] = dict(
            execution=pending["crypto_execution_id"], restart_rejected=True
        )
        evidence.update(
            jetton_master=master, restart=True, expiry_rejected=True, duplicate_rejected=True
        )
        destination = REPO / "work/ton-review/mpc-tvm-evidence.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(evidence, indent=2))
    finally:
        net.close()
        tvm.close()
