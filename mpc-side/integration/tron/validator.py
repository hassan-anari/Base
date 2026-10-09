"""Pinned disposable java-tron validator. No public peers or production funds.

The only complete private key here is a disposable consensus/faucet key; custody
addresses are supplied as public DKG identities and always signed by real MPC.
"""

import hashlib
import json
import os
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import requests
from custody.mpc_tron_network import ISOLATED_PARENT
from custody.tron_wire import block_identity
from tronpy.keys import PrivateKey

JAR_SHA256 = "faef7f4d89b9f154632bbab2db1712c25f02ee37b356013e098558ea994accec"
RELEASE = "GreatVoyage-v4.8.2.3"


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Validator:
    def __init__(self, directory, holders):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True)
        jar = Path(os.environ["PHASE6F_TRON_JAR"]).resolve()
        assert hashlib.sha256(jar.read_bytes()).hexdigest() == JAR_SHA256
        # Fixed disposable faucet/consensus key, never a custody signer.
        self.faucet = PrivateKey(bytes.fromhex("01".rjust(64, "0")))
        self.faucet_address = self.faucet.public_key.to_base58check_address()
        full, solid, p2p, grpc = [free_port() for _ in range(4)]
        assets = [
            {
                "accountName": "Zion",
                "accountType": "AssetIssue",
                "address": self.faucet_address,
                "balance": "99000000000000000",
            },
            {
                "accountName": "Sun",
                "accountType": "AssetIssue",
                "address": "TXmVpin5vq5gdZsciyyjdZgKRUju4st1wM",
                "balance": "0",
            },
            {
                "accountName": "Blackhole",
                "accountType": "AssetIssue",
                "address": "TLsV52sRDL79HXGGm9yzwKibb6BeruhUzy",
                "balance": "-9223372036854775808",
            },
        ]
        assets += [
            {
                "accountName": f"Custody-{index}",
                "accountType": "Normal",
                "address": address,
                "balance": str(balance),
            }
            for index, (address, balance) in enumerate(holders)
        ]
        config = {
            "storage": {
                "db": {"engine": "ROCKSDB", "directory": "database"},
                "txCache": {"estimatedTransactions": 100},
            },
            "node": {
                "discovery": {"enable": False, "persist": False, "external": {"ip": "127.0.0.1"}},
                "listen": {"port": p2p},
                "active": [],
                "passive": [],
                "fastForward": [],
                "openPrintLog": False,
                "maxConnections": 0,
                "minConnections": 0,
                "minActiveConnections": 0,
                "p2p": {"version": 101},
                "http": {
                    "fullNodeEnable": True,
                    "solidityEnable": True,
                    "fullNodePort": full,
                    "solidityPort": solid,
                },
                "rpc": {
                    "enable": False,
                    "solidityEnable": False,
                    "port": grpc,
                    "minEffectiveConnection": 0,
                },
                "jsonrpc": {"httpFullNodeEnable": False, "httpSolidityEnable": False},
            },
            "seed": {"node": {"ip": {"list": []}}},
            "sync": {"node": {"count": 0}},
            "genesis": {
                "block": {
                    "assets": assets,
                    "witnesses": [
                        {
                            "address": self.faucet_address,
                            "url": "http://127.0.0.1",
                            "voteCount": 100,
                        }
                    ],
                    "timestamp": "0",
                    "parentHash": "0x" + ISOLATED_PARENT,
                }
            },
            "localwitness": [self.faucet.hex()],
            "block": {"needSyncCheck": False},
            "vm": {"supportConstant": True, "estimateEnergy": True, "constantCallTimeoutMs": 1000},
            "committee": {
                "allowCreationOfContracts": 1,
                "allowSameTokenName": 1,
                "allowTvmTransferTrc10": 1,
                "allowTvmConstantinople": 1,
                "allowTvmSolidity059": 1,
                "allowTvmIstanbul": 1,
            },
            "trx": {"reference": {"block": "solid"}},
        }
        config_path = self.directory / "validator.json"
        config_path.write_text(json.dumps(config))
        config_path.chmod(0o600)
        self.full_url, self.solid_url = f"http://127.0.0.1:{full}", f"http://127.0.0.1:{solid}"
        self.gateway = self._gateway()
        self.url = f"http://127.0.0.1:{self.gateway.server_port}"
        self.log = (self.directory / "validator.log").open("wb")
        java = os.environ.get("PHASE6F_JAVA", "java")
        self.process = subprocess.Popen(
            [
                java,
                "-Xms256m",
                "-Xmx1024m",
                "-jar",
                str(jar),
                "-c",
                str(config_path),
                "--witness",
                "-d",
                str(self.directory / "data"),
            ],
            cwd=self.directory,
            stdout=self.log,
            stderr=subprocess.STDOUT,
        )
        self.session = requests.Session()
        self.session.trust_env = False  # Literal loopback fixture only, never external RPC.
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            try:
                assert self.process.poll() is None, (
                    "isolated java-tron exited; inspect validator.log"
                )
                genesis = self.post("/wallet/getblockbynum", {"num": 0})
                _, genesis_id, _ = block_identity(genesis)
                checkpoint = self.post("/wallet/getblockbynum", {"num": 1})
                height, checkpoint_id, _ = block_identity(checkpoint)
                solid_head, _, _ = block_identity(self.post("/walletsolidity/getnowblock", {}))
                if height == 1 and solid_head >= 1:
                    self.policy = {
                        "network": "isolated-v1",
                        "genesis_block_id": genesis_id,
                        "checkpoint_height": 1,
                        "checkpoint_block_id": checkpoint_id,
                        "trusted_endpoints": [self.url],
                    }
                    return
            except (requests.RequestException, KeyError, ValueError):
                pass
            time.sleep(0.1)
        self.close()
        raise RuntimeError("isolated java-tron did not produce solidified blocks")

    def _gateway(self):
        full_url, solid_url = self.full_url, self.solid_url

        class Gateway(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                session = requests.Session()
                session.trust_env = False
                target = solid_url if self.path.startswith("/walletsolidity/") else full_url
                try:
                    response = session.post(
                        target + self.path,
                        data=self.rfile.read(int(self.headers["Content-Length"])),
                        headers={"Content-Type": "application/json"},
                        timeout=15,
                    )
                    self.send_response(response.status_code)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(response.content)
                except requests.RequestException:
                    self.send_response(503)
                    self.end_headers()
                finally:
                    session.close()

        server = ThreadingHTTPServer(("127.0.0.1", 0), Gateway)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def post(self, path, body):
        response = self.session.post(self.url + path, json=body, timeout=15)
        response.raise_for_status()
        return response.json()

    def wait_info(self, txid):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            info = self.post("/walletsolidity/gettransactioninfobyid", {"value": txid})
            if info.get("id") == txid and info.get("blockNumber") is not None:
                return info
            time.sleep(0.1)
        raise RuntimeError("isolated TRON transaction not solidified within deadline")

    def faucet_sign_broadcast(self, tx):
        tx["signature"] = [self.faucet.sign_msg_hash(bytes.fromhex(tx["txID"])).hex()]
        result = self.post("/wallet/broadcasttransaction", tx)
        assert result.get("result") is True, result
        return self.wait_info(tx["txID"])

    def close(self):
        if hasattr(self, "process"):
            self.process.terminate()
            self.process.wait(timeout=20)
        self.gateway.shutdown()
        self.gateway.server_close()
        self.log.close()
