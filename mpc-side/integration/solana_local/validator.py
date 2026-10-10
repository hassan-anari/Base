"""Disposable local Agave validator; genesis identity comes from local ledger bytes."""

import base64
import hashlib
import os
import socket
import subprocess
import time
from pathlib import Path

import requests
from custody.solana_wire import instructions
from custody.spl import derive_ata
from custody.token_metadata import CLASSIC_TOKEN_PROGRAM
from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.system_program import CreateAccountParams, TransferParams, create_account, transfer
from solders.transaction import Transaction


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Validator:
    def __init__(self, root):
        self.root = root
        root.mkdir(parents=True)
        self.bin = Path(os.environ["PHASE6FB_SOLANA_BIN"])
        self.faucet = Keypair()
        self.mint = Keypair()
        self.port = free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.session = requests.Session()
        self.session.trust_env = False
        log = (root / "validator.log").open("wb")
        self.process = subprocess.Popen(
            [
                str(self.bin / "solana-test-validator"),
                "--ledger",
                str(root / "ledger"),
                "--mint",
                str(self.faucet.pubkey()),
                "--bind-address",
                "127.0.0.1",
                "--rpc-port",
                str(self.port),
                "--faucet-port",
                str(free_port()),
                "--gossip-port",
                str(free_port()),
                "--limit-ledger-size",
                "1000000",
            ],
            stdout=log,
            stderr=log,
        )
        log.close()
        try:
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise RuntimeError((root / "validator.log").read_text()[-3000:])
                try:
                    if self.rpc("getHealth", []) == "ok":
                        break
                except requests.RequestException:
                    pass
                time.sleep(0.2)
            else:
                raise RuntimeError("disposable Solana validator did not become ready")
            # Offline ledger tool, never the untrusted RPC response, establishes the pin.
            genesis = subprocess.check_output(
                [
                    str(self.bin / "agave-ledger-tool"),
                    "genesis-hash",
                    "--ledger",
                    str(root / "ledger"),
                ],
                text=True,
            ).strip()
            artifact = hashlib.sha256((root / "ledger/genesis.bin").read_bytes()).hexdigest()
            self.policy = {
                "network": "isolated-v1",
                "genesis_hash": genesis,
                "genesis_source": "validator-genesis-artifact",
                "genesis_artifact_sha256": artifact,
                "trusted_endpoints": [self.url],
            }
            assert self.rpc("getGenesisHash", []) == genesis
        except BaseException:
            self.close()
            raise

    def rpc(self, method, params):
        response = self.session.post(
            self.url,
            json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
            timeout=15,
            allow_redirects=False,
        )
        response.raise_for_status()
        body = response.json()
        if body.get("error"):
            raise ValueError(body["error"])
        return body["result"]

    def blockhash(self):
        return self.rpc("getLatestBlockhash", [{"commitment": "finalized"}])["value"]["blockhash"]

    def send(self, ixs, signers=None):
        signers = signers or [self.faucet]
        tx = Transaction.new_signed_with_payer(
            ixs, self.faucet.pubkey(), signers, Hash.from_string(self.blockhash())
        )
        signature = self.rpc(
            "sendTransaction", [base64.b64encode(bytes(tx)).decode(), {"encoding": "base64"}]
        )
        self.wait(signature)
        return signature

    def wait(self, signature):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            status = self.rpc(
                "getSignatureStatuses", [[signature], {"searchTransactionHistory": True}]
            )["value"][0]
            if status and status.get("confirmationStatus") == "finalized":
                response = self.rpc(
                    "getTransaction", [signature, {"encoding": "base64", "commitment": "finalized"}]
                )
                assert response
                return status, response
            time.sleep(0.2)
        raise RuntimeError("local Solana signature did not finalize")

    def fund(self, address, lamports):
        return self.send(
            [
                transfer(
                    TransferParams(
                        from_pubkey=self.faucet.pubkey(),
                        to_pubkey=Pubkey.from_string(address),
                        lamports=lamports,
                    )
                )
            ]
        )

    def create_mint(self):
        program = Pubkey.from_string(CLASSIC_TOKEN_PROGRAM)
        rent = self.rpc("getMinimumBalanceForRentExemption", [82])
        return self.send(
            [
                create_account(
                    CreateAccountParams(
                        from_pubkey=self.faucet.pubkey(),
                        to_pubkey=self.mint.pubkey(),
                        lamports=rent,
                        space=82,
                        owner=program,
                    )
                ),
                Instruction(
                    program,
                    bytes([20, 6]) + bytes(self.faucet.pubkey()) + b"\x00",
                    [AccountMeta(self.mint.pubkey(), False, True)],
                ),
            ],
            [self.faucet, self.mint],
        )

    def mint_to(self, owner, units):
        from custody.solana_wire import SYSTEM_PROGRAM
        from custody.spl import ASSOCIATED_TOKEN_PROGRAM

        payer = self.faucet.pubkey()
        owner_key = Pubkey.from_string(owner)
        mint = self.mint.pubkey()
        ata = Pubkey.from_string(derive_ata(owner, str(mint)))
        token = Pubkey.from_string(CLASSIC_TOKEN_PROGRAM)
        create = Instruction(
            Pubkey.from_string(ASSOCIATED_TOKEN_PROGRAM),
            b"\x01",
            [
                AccountMeta(payer, True, True),
                AccountMeta(ata, False, True),
                AccountMeta(owner_key, False, False),
                AccountMeta(mint, False, False),
                AccountMeta(Pubkey.from_string(SYSTEM_PROGRAM), False, False),
                AccountMeta(token, False, False),
            ],
        )
        mint_ix = Instruction(
            token,
            b"\x07" + units.to_bytes(8, "little"),
            [
                AccountMeta(mint, False, True),
                AccountMeta(ata, False, True),
                AccountMeta(payer, True, False),
            ],
        )
        return self.send([create, mint_ix])

    def token_transfer(self, destination, units):
        return self.send(
            instructions(
                str(self.faucet.pubkey()),
                destination,
                units,
                mint=str(self.mint.pubkey()),
                decimals=6,
                create_ata=True,
            )
        )

    def close(self):
        self.session.close()
        self.process.terminate()
        try:
            self.process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
