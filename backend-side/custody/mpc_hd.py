"""Independent public SLIP-10 verification and immutable issuance evidence.

Only public points and original attested chain codes are used. The Rust signers
and coordinator use pinned upstream hd-wallet; this check uses libsecp256k1.
"""

import hashlib
import hmac
import json
import uuid

from coincurve import PublicKey

from .mpc_binding import PARTICIPANTS, MpcBindingError
from .mpc_identity import address_from_public_key
from .mpc_provisioning import VERSION

ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def fingerprint(domain, value):
    return hashlib.sha256(
        domain.encode()
        + b"\0"
        + json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def public_child(public_key, chain_code, index):
    if type(index) is not int or not 0 <= index < 1 << 31:
        raise MpcBindingError("hardened or invalid child index")
    try:
        public = PublicKey(bytes.fromhex(public_key))
        chain = bytes.fromhex(chain_code)
        if public.format().hex() != public_key or len(chain) != 32 or chain.hex() != chain_code:
            raise ValueError
        for child_index in (0, index):
            encoded_index = child_index.to_bytes(4, "big")
            data = public.format() + encoded_index
            while True:
                material = hmac.digest(chain, data, "sha512")
                shift = int.from_bytes(material[:32], "big")
                if shift < ORDER:
                    try:
                        derived = public.add(material[:32]) if shift else public
                        break
                    except ValueError:
                        pass  # SLIP-10 retries an invalid/infinity child at SAME index.
                data = b"\1" + material[32:] + encoded_index
            public, chain = derived, material[32:]
        result = public.format().hex()
        if result == public_key:
            raise ValueError
        return result
    except (TypeError, ValueError):
        raise MpcBindingError("invalid original HD public material") from None


def hd_scope(root):
    return {
        field: getattr(root, field)
        for field in (
            "ownership_scope",
            "chain_id",
            "purpose",
            "wallet_class",
            "derivation_version",
            "root_identity",
        )
    }


def verify_hd_evidence(root, evidence):
    try:
        if set(evidence) != {"root", "participant_agreement"}:
            raise ValueError
        original = evidence["root"]
        request = original["request"]
        auxiliary = root.dkg_public_evidence["auxiliary"]["request"]
        chain = original["chain_code"]
        if (
            set(original) != {"request", "chain_code", "extended_identity"}
            or request != {"auxiliary": auxiliary, "scope": hd_scope(root)}
            or len(bytes.fromhex(chain)) != 32
            or bytes.fromhex(chain).hex() != chain
            or original["extended_identity"] != fingerprint("CGGMP24_HD_ROOT_V1", [request, chain])
        ):
            raise ValueError
        receipts = evidence["participant_agreement"]
        if len(receipts) != 3:
            raise ValueError
        for party, report in zip(PARTICIPANTS, receipts, strict=True):
            if (
                report != {"root": original, "party_id": party, "durable": True}
                or report["durable"] is not True
            ):
                raise ValueError
        return original
    except (KeyError, TypeError, ValueError):
        raise MpcBindingError("missing or mismatched authenticated original HD evidence") from None


def child_request(reservation, original):
    if (
        type(reservation.child_index) is not int
        or not 0 <= reservation.child_index < 1 << 31
        or reservation.derivation_path != f"m/0/{reservation.child_index}"
        or reservation.root.derivation_version != VERSION
    ):
        raise MpcBindingError("noncanonical original child reservation")
    return {
        "root": original,
        "reservation_id": str(reservation.pk),
        "customer_ref": reservation.customer_ref,
        "idempotency_key": reservation.idempotency_key,
        "child_index": reservation.child_index,
        "derivation_path": reservation.derivation_path,
    }


def verify_child_evidence(reservation, hd_evidence, evidence):
    original = verify_hd_evidence(reservation.root, hd_evidence)
    try:
        expected_request = child_request(reservation, original)
        child = evidence["child"]
        public_key = public_child(
            reservation.root.keyset.public_key, original["chain_code"], reservation.child_index
        )
        address = address_from_public_key(reservation.root.chain_id, public_key)
        if reservation.root.keyset.scope == "EVM":
            address = address.lower()
        if set(evidence) != {"child", "participant_agreement"} or child != {
            "request": expected_request,
            "public_key": public_key,
            "address": address,
        }:
            raise ValueError
        receipts = evidence["participant_agreement"]
        if len(receipts) != 3:
            raise ValueError
        for party, report in zip(PARTICIPANTS, receipts, strict=True):
            if (
                report != {"child": child, "party_id": party, "durable": True}
                or report["durable"] is not True
            ):
                raise ValueError
        uuid.UUID(expected_request["reservation_id"])
        return child
    except (KeyError, TypeError, ValueError):
        raise MpcBindingError("missing or mismatched spendable child evidence") from None


def child_reference(child):
    return f"child:{child['request']['reservation_id']}:{fingerprint('CGGMP24_CHILD_V1', child)}"
