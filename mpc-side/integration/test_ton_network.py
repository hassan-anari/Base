"""Actual validator-produced blocks, consensus proofs, inclusion and Jetton chain."""

import json
import os
import subprocess
import time
from pathlib import Path

from custody.ton_effects import terminal_transfer_effect
from custody.ton_policy import prepare_authorization
from custody.ton_wire import (
    jetton_wallet_address,
    verify_jetton_wallet,
    verify_wallet_state,
    wallet_address,
)
from environment import REPO, ROLES, Processes
from test_dkg import dkg_request, execute
from test_ton import signed
from ton.localnet import capture, fund


def test_ton_actual_validator_native_and_jetton(tmp_path):
    container = os.environ.get("PHASE6FC_LOCALTON_CONTAINER", "phase6fc-localton")
    client = capture(container, tmp_path / "public-genesis")
    admin = subprocess.Popen(
        ["node", str(Path(__file__).parent / "ton/admin.cjs")],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    net = Processes(tmp_path / "private-mpc")
    evidence = {
        "category": "ISOLATED_VALIDATOR_NETWORK",
        "identity": client.identity,
        "operations": [],
    }

    def admin_call(action, **kwargs):
        admin.stdin.write(json.dumps(dict(action=action, **kwargs)) + "\n")
        admin.stdin.flush()
        reply = json.loads(admin.stdout.readline())
        assert "error" not in reply, reply
        return reply["result"]

    def wait_account(address, condition):
        for _ in range(30):
            cp, block = client.checkpoint()
            state = client.account(address, cp)
            if condition(state):
                return cp, block, state
            time.sleep(1)
        raise AssertionError("validator account effect unavailable")

    def submit(raw):
        p = tmp_path / "public-message.boc"
        p.write_bytes(bytes.fromhex(raw))
        client.command("sendfile " + str(p))

    try:
        for role in ROLES[:4]:
            net.start(role)
        binding = dkg_request()
        binding["scope"] = "TON"
        status, dkg = execute(net, binding)
        assert status == 200 and dkg["status"] == "COMPLETED"
        public = bytes.fromhex(dkg["group_public_key"])
        source = wallet_address(public, -777)
        fixture = admin_call("identity")
        fund(container, source, 5)
        wait_account(source, lambda s: s["balance"] >= 5_000_000_000)
        fund(container, fixture["admin"], 5)
        _, block, _ = wait_account(fixture["admin"], lambda s: s["balance"] >= 5_000_000_000)
        deploy = admin_call("deploy", seqno=0, valid_until=block.info.gen_utime + 120)
        submit(deploy["boc"])
        wait_account(fixture["master"], lambda s: s["status"] == "active")
        for index, token in enumerate((False, True, True, False)):
            bounce_test = index == 3
            if index == 1:
                cp, block, _ = wait_account(fixture["admin"], lambda s: s["status"] == "active")
                mint = admin_call(
                    "mint",
                    seqno=1,
                    valid_until=block.info.gen_utime + 120,
                    owner=source,
                    amount="1000000",
                )
                submit(mint["boc"])
                wait_account(
                    jetton_wallet_address(source, fixture["master"]),
                    lambda s: s["status"] == "active",
                )
            cp, block, state = wait_account(source, lambda s: s["balance"] >= 1_000_000_000)
            seq = verify_wallet_state(
                source, public, -777, status=state["status"], code=state["code"], data=state["data"]
            )
            kwargs = {}
            if token:
                jw = jetton_wallet_address(source, fixture["master"])
                js = client.account(jw, cp)
                balance = verify_jetton_wallet(
                    jw, source, fixture["master"], js["code"], js["data"], jw
                )
                client.jetton_getters(source, fixture["master"], jw, js["data"], balance, cp)
                kwargs = dict(
                    jetton_master=fixture["master"], query_id=100 + index, jetton_balance=balance
                )
            a = prepare_authorization(
                public_key=public,
                global_id=-777,
                source=source,
                destination=fixture["master"] if bounce_test else fixture["admin"],
                amount_units=250000 if token else 100000000,
                seqno=seq,
                valid_until=block.info.gen_utime + 120,
                chain_time=block.info.gen_utime,
                balance_nanoton=state["balance"],
                deployed=state["status"] == "active",
                destination_active=True,
                comment=b"force-native-bounce" if bounce_test else b"",
                **kwargs,
            )["ton_authorization"]
            floor = block.extra.custom.shard_hashes[0].list[0].seq_no
            raw, h, session, _ = signed(
                net, binding, dkg, a, operation="SWEEP" if index == 2 else "WITHDRAWAL"
            )
            submit(raw)
            for _ in range(30):
                cp, block = client.checkpoint()
                history, complete = client.shard_history(
                    cp, block, after_seqno=floor, max_blocks=128
                )
                assert complete
                txs = client.transactions(history)
                effect = terminal_transfer_effect(a, source, h, [e for _, e in txs])
                if bounce_test and any(
                    e.account == source and getattr(e.inbound.info, "bounced", False)
                    for _, e in txs
                ):
                    assert not effect["terminal"]
                    break
                if effect["terminal"]:
                    break
                time.sleep(1)
            else:
                raise AssertionError(effect)
            if token:
                rw = jetton_wallet_address(fixture["admin"], fixture["master"])
                rs = client.account(rw, cp)
                assert (
                    verify_jetton_wallet(
                        rw, fixture["admin"], fixture["master"], rs["code"], rs["data"], rw
                    )
                    == index * 250000
                )
            evidence["operations"].append(
                dict(
                    native=not token,
                    bounce=bounce_test,
                    message_hash=h,
                    execution_id=session["crypto_execution_id"],
                    checkpoint=cp,
                    effect=effect,
                    blocks=[i for i, _ in history],
                    transaction_inclusions=[
                        dict(
                            block=i,
                            account=e.account,
                            lt=str(e.lt),
                            transaction_hash=e.tx_hash,
                            inbound_message_hash=e.inbound_hash,
                        )
                        for i, e in txs
                        if e.account in {source, fixture["master"]}
                    ],
                )
            )
        evidence.update(
            dkg_fingerprint=dkg["result_fingerprint"],
            source=source,
            master=fixture["master"],
            content_hash=fixture["content_hash"],
        )
        out = REPO / "work/ton-review/validator-network-evidence.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(evidence, indent=2))
    finally:
        net.close()
        admin.terminate()
        admin.wait(timeout=10)
