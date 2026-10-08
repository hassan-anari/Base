"""Ephemeral private PKI and isolated configurations for four real services."""

import argparse
import os
import socket
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

REPO = Path(__file__).resolve().parents[2]
ROLES = ("coordinator", "signer-a", "signer-b", "signer-c", "custody")


def private_file(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(data)
    path.chmod(0o600)


def private_key_bytes(key):
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def ca():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Phase 6B ephemeral test CA")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), True
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def issue(directory, role, issuer, *, expired=False, uris=None):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    issuer_key, issuer_cert = issuer
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, role)]))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now - timedelta(days=1) if expired else now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.DNSName(role)]
                + [
                    x509.UniformResourceIdentifier(uri)
                    for uri in (uris or [f"spiffe://wallet-mpc/{role}"])
                ]
            ),
            False,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            False,
        )
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False), True
        )
        .sign(issuer_key, hashes.SHA256())
    )
    private_file(directory / "tls.key", private_key_bytes(key))
    private_file(directory / "tls.crt", cert.public_bytes(serialization.Encoding.PEM))
    private_file(directory / "ca.crt", issuer_cert.public_bytes(serialization.Encoding.PEM))


def free_ports():
    sockets = [socket.socket() for _ in range(4)]
    try:
        for sock in sockets:
            sock.bind(("127.0.0.1", 0))
        return {role: sock.getsockname()[1] for role, sock in zip(ROLES, sockets)}
    finally:
        for sock in sockets:
            sock.close()


def configure(root, *, compose=False):
    root = root.resolve()
    if root.exists():
        raise ValueError("use a new directory; never overwrite existing identities or storage")
    root.mkdir(parents=True, mode=0o700)
    issuer = ca()
    # The issuer key is never mounted into a service.
    private_file(root / "issuer" / "ca.key", private_key_bytes(issuer[0]))
    for role in ROLES:
        issue(root / role / "identity", role, issuer)
    for role in ("unknown", "expired", "ambiguous"):
        issue(
            root / role / "identity",
            role if role == "unknown" else "custody",
            issuer,
            expired=role == "expired",
            uris=["spiffe://wallet-mpc/custody", "spiffe://wallet-mpc/coordinator"]
            if role == "ambiguous"
            else None,
        )
    issue(root / "wrong-ca" / "identity", "custody", ca())
    ports = {role: 8443 for role in ROLES[:4]} if compose else free_ports()
    configs = {}
    for index, role in enumerate(ROLES[:4]):
        node = root / role
        (node / "storage").mkdir(mode=0o700)
        identity = Path("/run/identity") if compose else node / "identity"
        storage = Path("/data") if compose else node / "storage"
        env = {
            "MPC_INSECURE_LOCAL_DEV": "false",
            "MPC_BIND_ADDR": f"{'0.0.0.0' if compose else '127.0.0.1'}:{ports[role]}",
            "MPC_TLS_CA": str(identity / "ca.crt"),
            "MPC_TLS_CERT": str(identity / "tls.crt"),
            "MPC_TLS_KEY": str(identity / "tls.key"),
        }
        if role == "coordinator":
            env["MPC_COORDINATOR_STATE"] = str(storage / "coordinator.json")
            for signer_index, suffix in enumerate("ABC", start=1):
                signer = f"signer-{suffix.lower()}"
                addr = f"172.28.6.{11 + signer_index}" if compose else "127.0.0.1"
                env[f"MPC_SIGNER_{suffix}_ADDR"] = f"{addr}:{ports[signer]}"
                env[f"MPC_SIGNER_{suffix}_SERVER_NAME"] = signer if compose else "localhost"
        else:
            private_file(node / "identity" / "wrapping.key", os.urandom(32))
            env.update(
                MPC_PARTY_ID=role,
                MPC_CERTIFICATE_IDENTITY=f"spiffe://wallet-mpc/{role}",
                MPC_SHARE_STORAGE_DIR=str(storage),
                MPC_WRAPPING_KEY_FILE=str(identity / "wrapping.key"),
                MPC_SUPPORTED_ALGORITHMS="CGGMP24_ECDSA,FROST_ED25519",
                MPC_TRUSTED_PEERS="spiffe://wallet-mpc/coordinator=coordinator",
            )
        configs[role] = env
        private_file(
            node / "service.env", "".join(f"{key}={value}\n" for key, value in env.items()).encode()
        )
    return configs, ports


class Processes:
    def __init__(self, root):
        self.root = root
        self.configs, self.ports = configure(root)
        target = Path(os.environ.get("CARGO_TARGET_DIR", str(REPO / "mpc-side" / "target")))
        self.bin = target.resolve() / "debug"
        self.running = {}

    def start(self, role):
        binary = "wallet-mpc-coordinator" if role == "coordinator" else "wallet-mpc-signer"
        log = (self.root / role / "service.log").open("ab")
        try:
            process = subprocess.Popen(
                [str(self.bin / binary)],
                env=os.environ | self.configs[role],
                stdout=log,
                stderr=log,
            )
        finally:
            log.close()
        self.running[role] = process
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError((self.root / role / "service.log").read_text())
            try:
                with socket.create_connection(("127.0.0.1", self.ports[role]), timeout=0.1):
                    return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError(f"{role} failed to listen")

    def stop(self, role):
        process = self.running.pop(role, None)
        if process:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def close(self):
        for role in list(self.running):
            self.stop(role)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--compose", action="store_true")
    args = parser.parse_args()
    configure(args.directory, compose=args.compose)
    print(f"Generated private test identities/configurations in {args.directory.resolve()}")
