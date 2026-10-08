"""Exercise the isolated Django transport against the mounted development stack."""

import argparse
import hashlib
import os
import sys
import time
import uuid
from pathlib import Path

import django
import requests
from django.test import override_settings

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend-side"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mpc_exchange.settings")
django.setup()

from custody.signer_adapter import SelfHostedMpcAdapter  # noqa: E402

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("directory", type=Path)
parser.add_argument("--url", default="https://localhost:8443")
args = parser.parse_args()
identity = args.directory.resolve() / "custody" / "identity"
payload = {
    "session_id": str(uuid.uuid4()),
    "attempt_id": 1,
    "keyset_id": str(uuid.uuid4()),
    "algorithm": "CGGMP24_ECDSA",
    "payload_type": "EVM_LEGACY_DIGEST",
    "payload_hex": "ab" * 32,
    "message_fingerprint": hashlib.sha256(bytes.fromhex("ab" * 32)).hexdigest(),
    "operation_type": "TRANSPORT_TEST",
    "chain": "ETH",
    "asset": "ETH",
    "expected_source": "0x0000000000000000000000000000000000000001",
    "derivation_reference": None,
}
with override_settings(
    MPC_COORDINATOR_URL=args.url,
    MPC_CA_CERT=str(identity / "ca.crt"),
    MPC_CLIENT_CERT=str(identity / "tls.crt"),
    MPC_CLIENT_KEY=str(identity / "tls.key"),
    MPC_REQUEST_TIMEOUT_SECONDS=10,
):
    client = SelfHostedMpcAdapter()
    deadline = time.monotonic() + 20
    while True:
        try:
            quorum = client._request("GET", "/v1/health/quorum")
            break
        except (OSError, requests.HTTPError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.25)
    assert quorum["healthy"] == 3 and quorum["signable"] is False
    assert [signer["signer_identity"] for signer in quorum["signers"]] == [
        "signer-a",
        "signer-b",
        "signer-c",
    ]
    created = client.create_signing_session(payload)
    assert created["status"] == "CREATED" and created["signature"] is None
    assert client.create_signing_session(payload) == created
    assert client.get_signing_session(payload["session_id"]) == created
    print("Django TLS 1.3 mTLS -> coordinator -> signer A/B/C: authenticated capabilities OK")
    print("Signing-session CREATED, exact UUID idempotency and persisted GET: OK; signing disabled")
