"""TON proofs using the pinned upstream lite-client and independent cell checks.

ADNL transports untrusted bytes. The official client verifies consensus proofs
(including Simplex/election transitions) from local genesis. Python binds those
verified masterchain roots to full shard blocks and transaction cells. This
restricted milestone deliberately rejects shard splits/merges and nonzero WC.
"""

import asyncio
import hashlib
import json
import re
import subprocess
import tempfile
import time
from pathlib import Path

from pytoniq_core import Block, Cell, ShardStateUnsplit, StateInit

from .ton_wire import normalize_address, wallet_id

LITE_CLIENT_SHA256 = "da7a4c01c0253106d7360eabec356ab4f17ca7c8f5fa5ab118aecf32432dc2b9"
MC_SHARD = -(2**63)


class TonProofError(ValueError):
    pass


def block_text(b):
    if (
        type(b.get("workchain")) is not int
        or b["workchain"] not in (-1, 0)
        or type(b.get("seqno")) is not int
        or not 0 <= b["seqno"] < 2**32
    ):
        raise TonProofError("TON block identity shape invalid")
    for name in ("root_hash", "file_hash"):
        if not isinstance(b.get(name), str) or not re.fullmatch("[0-9a-f]{64}", b[name]):
            raise TonProofError("TON block hash shape invalid")
    return (
        f"({b['workchain']},8000000000000000,{b['seqno']}):"
        f"{b['root_hash'].upper()}:{b['file_hash'].upper()}"
    )


def checked_block(raw, identity, global_id):
    if len(raw) > 16_000_000 or hashlib.sha256(raw).hexdigest() != identity["file_hash"]:
        raise TonProofError("TON block file hash mismatch")
    cell = Cell.one_from_boc(raw)
    if cell.hash.hex() != identity["root_hash"]:
        raise TonProofError("TON block root hash mismatch")
    b = Block.deserialize(cell.begin_parse())
    if (
        b.global_id != global_id
        or b.info.seqno != identity["seqno"]
        or b.info.shard.workchain_id != identity["workchain"]
        or b.info.shard.shard_pfx_bits != 0
    ):
        raise TonProofError("TON block network/shard identity mismatch")
    if b.info.after_merge or b.info.before_split or b.info.after_split:
        raise TonProofError("TON split/merge proof path requires review")
    return b


class TonProofClient:
    def __init__(self, *, binary, config, zerostate, basestate, settings_file, identity):
        self.binary = Path(binary)
        self.config = Path(config)
        self.identity = identity
        if hashlib.sha256(self.binary.read_bytes()).hexdigest() != LITE_CLIENT_SHA256:
            raise TonProofError("unreviewed TON proof executable")
        wallet_id(identity["global_id"])
        self.fee_config = {}
        for path, prefix in ((zerostate, "zerostate"), (basestate, "basechain_zerostate")):
            raw = Path(path).read_bytes()
            cell = Cell.one_from_boc(raw)
            if (
                cell.hash.hex() != identity[prefix + "_root_hash"]
                or hashlib.sha256(raw).hexdigest() != identity[prefix + "_file_hash"]
            ):
                raise TonProofError("TON local genesis artifact mismatch")
            state = ShardStateUnsplit.deserialize(cell.begin_parse())
            if state.global_id != identity["global_id"]:
                raise TonProofError("TON genesis global ID mismatch")
            if prefix == "zerostate":
                self.fee_config = {
                    n: state.custom.config.config[n].to_cell().hash for n in (18, 20, 21, 24, 25)
                }
        raw = Path(settings_file).read_bytes()
        if (
            hashlib.sha256(raw).hexdigest() != identity["settings_sha256"]
            or json.loads(raw)["network"]["global_id"] != identity["global_id"]
        ):
            raise TonProofError("TON genesis settings provenance mismatch")
        cfg = json.loads(self.config.read_text())
        z = cfg["validator"]["zero_state"]
        import base64

        if (
            z["workchain"] != -1
            or z["shard"] != MC_SHARD
            or z["seqno"] != 0
            or base64.b64decode(z["root_hash"]).hex() != identity["zerostate_root_hash"]
            or base64.b64decode(z["file_hash"]).hex() != identity["zerostate_file_hash"]
        ):
            raise TonProofError("TON transport genesis configuration mismatch")
        if cfg["validator"].get("init_block") != z or cfg["validator"].get("hardforks"):
            raise TonProofError("TON transport may not introduce an RPC checkpoint or hard fork")
        if len(cfg["liteservers"]) != 1 or cfg["liteservers"][0]["ip"] != 2130706433:
            raise TonProofError("TON liteserver must be one pinned loopback endpoint")
        self.cfg = cfg

    def command(self, command, *, submission=False):
        # Commands are generated solely from canonical addresses/block identities
        # or private tempfile paths; no shell interpretation or arbitrary RPC API.
        r = subprocess.run(
            [
                str(self.binary),
                "-C",
                str(self.config),
                "-v",
                "3" if submission else "0",
                "-t",
                "20",
                "-c",
                command,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if r.returncode or len(r.stdout) > 4_000_000:
            raise TonProofError("TON proof command failed")
        return r.stdout + r.stderr if submission else r.stdout

    async def _fetch(self, method, data):
        from pytoniq import LiteClient

        client = LiteClient.from_config(self.cfg, ls_i=0, trust_level=2, timeout=20)
        try:
            await client.connect()
            return await client.liteserver_request(method, data)
        finally:
            await client.close()

    def fetch(self, method, data):
        return asyncio.run(self._fetch(method, data))

    @staticmethod
    def tl_id(b):
        return dict(
            workchain=b["workchain"],
            shard=MC_SHARD,
            seqno=b["seqno"],
            root_hash=b["root_hash"],
            file_hash=b["file_hash"],
        )

    def raw_block(self, identity):
        r = self.fetch("getBlock", {"id": self.tl_id(identity)})
        return r["data"]

    def checkpoint(self):
        r = self.fetch("getMasterchainInfo", {})
        if (
            any(
                r["init"][name] != self.identity["zerostate_" + name]
                for name in ("root_hash", "file_hash")
            )
            or r["init"]["workchain"] != -1
        ):
            raise TonProofError("running TON network zero-state mismatch")
        b = r["last"]
        identity = {k: b[k] for k in ("workchain", "seqno", "root_hash", "file_hash")}
        if identity["workchain"] != -1 or identity["seqno"] <= 0:
            raise TonProofError("TON masterchain checkpoint identity invalid")
        identity, block = self.verify_checkpoint(identity)
        if not -5 <= time.time() - block.info.gen_utime <= 30:
            raise TonProofError("TON masterchain checkpoint is not fresh")
        return identity, block

    def verify_fee_config(self, checkpoint):
        # saveconfig executes the upstream ConfigInfo proof checks against the
        # verified MC root. These prices are pinned independently in local genesis.
        with tempfile.TemporaryDirectory(prefix="ton-config-") as root:
            path = Path(root) / "config.boc"
            out = self.command("saveconfig " + str(path) + " " + block_text(checkpoint))
            if "saved configuration dictionary into file" not in out or not path.exists():
                raise TonProofError("TON proven fee configuration unavailable")
            config = Cell.one_from_boc(path.read_bytes()).begin_parse().load_hashmap(32)
            for number, expected in self.fee_config.items():
                value = config[number]
                if (
                    value.remaining_bits
                    or value.remaining_refs != 1
                    or value.load_ref().hash != expected
                ):
                    raise TonProofError("TON fee/storage prices changed from reviewed genesis")

    def verify_checkpoint(self, identity):
        origin = dict(
            workchain=-1,
            seqno=0,
            root_hash=self.identity["zerostate_root_hash"],
            file_hash=self.identity["zerostate_file_hash"],
        )
        out = self.command("blkproofchain " + block_text(origin) + " " + block_text(identity))
        if "valid complete proof chain: last block is " + block_text(identity) not in out:
            raise TonProofError("TON signed masterchain proof incomplete")
        block = checked_block(self.raw_block(identity), identity, self.identity["global_id"])
        return identity, block

    def account(self, address, checkpoint):
        address = normalize_address(address).raw
        if not address.startswith("0:"):
            raise TonProofError("TON account workchain unsupported")
        anchor = block_text(checkpoint)
        out = self.command("getaccount " + address + " " + anchor)
        if "account state is empty" in out:
            return dict(
                status="uninit", balance=0, code=None, data=None, last_lt=0, last_hash="0" * 64
            )
        balance = re.search(r"account balance is ([0-9]+)ng(?:\n|$)", out)
        last = re.search(r"last transaction lt = ([0-9]+) hash = ([0-9A-F]{64})", out)
        if not balance or not last:
            raise TonProofError("TON verified account evidence missing")
        status = (
            "active"
            if "state:(account_active" in out
            else "uninit"
            if "state:account_uninit" in out
            else "frozen"
        )
        code = data = None
        if status == "active":
            with tempfile.TemporaryDirectory(prefix="ton-state-") as root:
                path = Path(root) / "state.boc"
                out = self.command("saveaccount " + str(path) + " " + address + " " + anchor)
                if (
                    "written StateInit of account " + address
                ).lower() not in out.lower() or not path.exists():
                    raise TonProofError("TON verified StateInit unavailable")
                init = StateInit.deserialize(Cell.one_from_boc(path.read_bytes()).begin_parse())
                code, data = init.code, init.data
        return dict(
            status=status,
            balance=int(balance[1]),
            code=code,
            data=data,
            last_lt=int(last[1]),
            last_hash=last[2].lower(),
        )

    def jetton_getters(self, owner, master, address, data, balance, checkpoint):
        from .ton_wire import JETTON_WALLET_CODE_HASH, Builder

        owner = normalize_address(owner).raw
        master = normalize_address(master).raw
        address = normalize_address(address).raw
        arg = Builder().store_address(owner).end_cell().bits.to01()
        out = self.command(
            "runmethod "
            + master
            + " "
            + block_text(checkpoint)
            + " get_wallet_address b{"
            + arg
            + "}"
        )
        expected = Builder().store_address(address).end_cell()
        serialized = expected.get_descriptors().hex() + expected.get_data_bytes().hex()
        expected_line = "result:  [ CS{Cell{" + serialized + "} bits: 0..267; refs: 0..0} ] "
        if expected_line not in out.splitlines():
            raise TonProofError("Jetton locally executed get_wallet_address mismatch")
        out = self.command(
            "runmethod " + address + " " + block_text(checkpoint) + " get_wallet_data"
        )
        cell = data.get_descriptors().hex() + data.get_data_bytes().hex()
        start = 4 + 8 * ((balance.bit_length() + 7) // 8)
        prefix = (
            f"result:  [ {balance} CS{{Cell{{{cell}}} bits: {start}..{start + 267}; refs: 0..0}} "
        )
        expected_line = (
            prefix
            + f"CS{{Cell{{{cell}}} bits: {start + 267}..{start + 534}; refs: 0..0}} "
            + "C{"
            + JETTON_WALLET_CODE_HASH.upper()
            + "} ] "
        )
        if expected_line not in out.splitlines():
            raise TonProofError("Jetton locally executed get_wallet_data mismatch")

    def shard_history(self, checkpoint, block, *, after_seqno=0, max_blocks=128):
        identity = self.shard_head(block)
        history, _, complete = self.history_from(
            identity, after_seqno=after_seqno, max_blocks=max_blocks
        )
        return history, complete

    @staticmethod
    def shard_head(block):
        tree = block.extra.custom.shard_hashes.get(0)
        if tree is None or len(tree.list) != 1:
            raise TonProofError("TON reviewed single shard required")
        desc = tree.list[0]
        identity = dict(
            workchain=0,
            seqno=desc.seq_no,
            root_hash=desc.root_hash.hex(),
            file_hash=desc.file_hash.hex(),
        )
        return identity

    def history_from(self, identity, *, after_seqno, max_blocks=128):
        if type(after_seqno) is not int or after_seqno < 0 or not 1 <= max_blocks <= 128:
            raise TonProofError("TON bounded history request invalid")
        return asyncio.run(self._history_from(identity, after_seqno, max_blocks))

    async def _history_from(self, identity, after_seqno, max_blocks):
        from pytoniq import LiteClient

        client = LiteClient.from_config(self.cfg, ls_i=0, trust_level=2, timeout=20)
        result = []
        try:
            await client.connect()
            while identity["seqno"] > after_seqno and len(result) < max_blocks:
                response = await client.liteserver_request("getBlock", {"id": self.tl_id(identity)})
                block = checked_block(response["data"], identity, self.identity["global_id"])
                result.append((identity, block))
                prev = block.info.prev_ref.prev
                if prev.seqno != identity["seqno"] - 1:
                    raise TonProofError("TON shard ancestry gap")
                identity = dict(
                    workchain=0,
                    seqno=prev.seqno,
                    root_hash=prev.root_hash.hex(),
                    file_hash=prev.file_hash.hex(),
                )
            return result, identity, identity["seqno"] == after_seqno
        finally:
            await client.close()

    @staticmethod
    def transactions(history):
        from .ton_effects import execution_from_boc

        result = []
        for identity, block in history:
            accounts = block.extra.account_blocks[0] or {}
            for key, account in accounts.items():
                if account.account_addr != format(key, "064x"):
                    raise TonProofError("TON account block address mismatch")
                for lt, t in account.transactions[0].items():
                    e = execution_from_boc(t.cell.to_boc().hex())
                    if e.account != "0:" + account.account_addr or e.lt != lt:
                        raise TonProofError("TON transaction account/lt inclusion mismatch")
                    result.append((identity, e))
        return result
