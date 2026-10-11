"""Phase 6G internal path allocation. No address issuance or signing capability.

Only authenticated original DKG evidence can establish a namespace. Allocation
uses PostgreSQL row locks; it performs no cryptography, RPC or financial posting.
Callers must supply their trusted deployment ownership scope, never a tenant
identifier accepted without authorization from an external request.
"""

from django.db import connection, transaction

from .chain_registry import ChainKind, get_chain_spec
from .models import MpcDerivationReservation, MpcKeyset, MpcProvisioningRoot
from .mpc_binding import MpcBindingError, _freeze_root_network, verify_coordinator_keyset

VERSION = "cggmp_slip10_nonhardened_v1"
CAPACITY = 1 << 31


class ProvisioningError(MpcBindingError):
    pass


def _postgres():
    if connection.vendor != "postgresql":
        raise ProvisioningError("durable MPC path allocation requires PostgreSQL")


def _text(value, limit, name):
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > limit:
        raise ProvisioningError(f"invalid {name}")
    return value


def _identity(keyset, chain_id):
    binding = keyset.network_bindings.get(chain_id)
    if len(keyset.network_bindings) != 1 or not binding or binding.get("legacy_unverified"):
        raise ProvisioningError("allocation root requires one original verified network")
    expected = {
        "scope": keyset.scope,
        "algorithm": keyset.algorithm,
        "public_key": keyset.public_key,
        "dkg_execution_id": str(keyset.dkg_execution_id),
        "dkg_fingerprint": keyset.dkg_result_fingerprint,
        "network": binding.get("network"),
    }
    if binding != expected or not expected["network"]:
        raise ProvisioningError("original root network/DKG identity mismatch")
    return {"keyset_id": str(keyset.keyset_id), "chain_id": chain_id, **expected}


def register_provisioning_root(*, keyset_id, chain_id, ownership_scope):
    """Authenticate a dedicated HOT/DEPOSIT root and freeze its allocation scope.

    Existing multi-network roots cannot become provisioning roots. This does not
    activate a keyset, select it for new wallets, or assert HD chain-code evidence.
    """
    _postgres()
    ownership_scope = _text(ownership_scope, 64, "ownership scope")
    spec = get_chain_spec(chain_id)
    if spec.kind not in {ChainKind.EVM, ChainKind.TRON}:
        raise ProvisioningError("only reviewed secp256k1 path reservations are supported")
    from .signer_adapter import SelfHostedMpcAdapter

    metadata = SelfHostedMpcAdapter().get_keyset(str(keyset_id))
    with transaction.atomic():
        keyset = MpcKeyset.objects.select_for_update().get(keyset_id=keyset_id)
        if keyset.status != "ACTIVE" or keyset.scope != (
            "EVM" if spec.kind is ChainKind.EVM else "TRON"
        ):
            raise ProvisioningError("allocation root must be active in the matching chain family")
        verify_coordinator_keyset(keyset, metadata)
        _freeze_root_network(keyset, spec)
        keyset.refresh_from_db()
        identity = _identity(keyset, spec.chain_id)
        root, created = MpcProvisioningRoot.objects.get_or_create(
            keyset=keyset,
            defaults={
                "ownership_scope": ownership_scope,
                "chain_id": spec.chain_id,
                "root_identity": identity,
                "dkg_public_evidence": metadata,
            },
        )
        if not created and (
            root.ownership_scope != ownership_scope or root.root_identity != identity
        ):
            raise ProvisioningError("original provisioning ownership/network cannot be replaced")
        return root


def reserve_derivation_path(*, keyset_id, ownership_scope, customer_ref, idempotency_key):
    """Reserve m/0/index once. Same retry returns the original reservation.

    The leading non-hardened 0 is the versioned DEPOSIT purpose; the root is
    dedicated to that purpose/network/owner. Tokens are deliberately absent:
    a future verified account can expose multiple same-chain asset views for
    the SAME beneficial owner without allocating another key or another ledger.
    """
    _postgres()
    ownership_scope = _text(ownership_scope, 64, "ownership scope")
    customer_ref = _text(customer_ref, 64, "customer reference")
    idempotency_key = _text(idempotency_key, 128, "idempotency key")
    with transaction.atomic():
        # Always lock the original keyset before its namespace, matching registration.
        keyset = MpcKeyset.objects.select_for_update().get(keyset_id=keyset_id)
        root = MpcProvisioningRoot.objects.select_for_update().get(keyset=keyset)
        if root.ownership_scope != ownership_scope:
            raise ProvisioningError("provisioning ownership scope mismatch")
        if root.root_identity != _identity(keyset, root.chain_id):
            raise ProvisioningError("provisioning root identity mismatch")
        existing = MpcDerivationReservation.objects.filter(
            root=root, idempotency_key=idempotency_key
        ).first()
        if existing:
            if existing.customer_ref != customer_ref:
                raise ProvisioningError("idempotency key was used with different parameters")
            return existing
        if keyset.status != "ACTIVE":
            raise ProvisioningError("retired or unavailable roots cannot allocate new paths")
        if root.next_index >= CAPACITY:
            raise ProvisioningError("non-hardened derivation index space exhausted")
        reservation = MpcDerivationReservation.objects.create(
            root=root,
            customer_ref=customer_ref,
            idempotency_key=idempotency_key,
            child_index=root.next_index,
            derivation_path=f"m/0/{root.next_index}",
        )
        # DB insertion trigger advances the counter inside this same transaction.
        return reservation
