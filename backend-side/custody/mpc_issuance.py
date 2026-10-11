"""Recoverable internal customer-account issuance. No caller-selected paths.

Existing customer IDs are global ledger principals. ownership_scope is a trusted
operator deployment namespace, never an external tenant/authentication claim.
"""

from django.db import connection, transaction

from .models import (
    Asset,
    HotWallet,
    MpcCustodyAccount,
    MpcHdRootEvidence,
    MpcKeyset,
    MpcProvisioningRoot,
    UserWallet,
)
from .mpc_binding import MpcBindingError
from .mpc_hd import child_request, hd_scope, verify_child_evidence, verify_hd_evidence
from .mpc_provisioning import (
    ProvisioningError,
    _identity,
    _postgres,
    _text,
    reserve_derivation_path,
)


def _network(root):
    if root.keyset.scope == "EVM":
        from .mpc_evm_network import network_identity
    else:
        from .mpc_tron_network import network_identity
    if network_identity(root.chain_id) != root.root_identity["network"]:
        raise ProvisioningError("original HD/account network cannot be replaced")


def _runtime(root):
    from .mpc_tron_network import verify_mpc_rpc_endpoints
    from .native_tx import RequestsTransport
    from .signer_adapter import assert_mpc_backend_runtime_safe

    _network(root)
    assert_mpc_backend_runtime_safe(root.chain_id)
    verify_mpc_rpc_endpoints(root.chain_id, RequestsTransport())
    if root.root_identity != _identity(root.keyset, root.chain_id):
        raise ProvisioningError("original provisioning network/key identity mismatch")


def attest_original_hd(*, keyset_id, ownership_scope, client=None):
    from .signer_adapter import SelfHostedMpcAdapter

    _postgres()
    if connection.in_atomic_block:
        raise ProvisioningError("HD attestation requires a durably committed original namespace")
    root = MpcProvisioningRoot.objects.select_related("keyset").get(keyset__keyset_id=keyset_id)
    if root.ownership_scope != _text(ownership_scope, 64, "ownership scope"):
        raise ProvisioningError("provisioning ownership scope mismatch")
    _runtime(root)
    # Dedicated DEPOSIT HD roots cannot disable a legitimate historical root
    # account. Registered namespaces also block new root-only wallet bindings.
    if (
        HotWallet.objects.filter(mpc_keyset_id=root.pk).exists()
        or UserWallet.objects.filter(mpc_keyset_id=root.pk, custody_account__isnull=True).exists()
    ):
        raise ProvisioningError(
            "historical root wallet remains root-only; use a fresh dedicated root"
        )
    client = client or SelfHostedMpcAdapter()
    evidence = client.attest_hd(str(keyset_id), hd_scope(root))
    verify_hd_evidence(root, evidence)
    with transaction.atomic():
        MpcKeyset.objects.select_for_update().get(pk=root.pk)
        locked = MpcProvisioningRoot.objects.select_for_update().get(pk=root.pk)
        if locked.root_identity != root.root_identity:
            raise ProvisioningError("original HD identity changed")
        stored, created = MpcHdRootEvidence.objects.get_or_create(
            root=locked, defaults={"evidence": evidence}
        )
        if not created and stored.evidence != evidence:
            raise ProvisioningError("original chain code/evidence cannot be replaced")
        return stored


def issue_customer_account(
    *, keyset_id, ownership_scope, customer_ref, idempotency_key, client=None
):
    from .signer_adapter import SelfHostedMpcAdapter

    _postgres()
    if connection.in_atomic_block:
        raise ProvisioningError("issuance requires a durable claim outside caller transactions")
    ownership_scope = _text(ownership_scope, 64, "ownership scope")
    customer_ref = _text(customer_ref, 64, "customer reference")
    idempotency_key = _text(idempotency_key, 128, "idempotency key")
    root = MpcProvisioningRoot.objects.select_related("keyset").get(keyset__keyset_id=keyset_id)
    if root.ownership_scope != ownership_scope:
        raise ProvisioningError("provisioning ownership scope mismatch")
    _runtime(root)
    hd = MpcHdRootEvidence.objects.get(root=root)
    original = verify_hd_evidence(root, hd.evidence)
    # Persist the authoritative claim BEFORE RPC. Crashes/partial signer commits
    # recover this reservation UUID; another retry key cannot reassign the customer.
    with transaction.atomic():
        keyset = MpcKeyset.objects.select_for_update().get(pk=root.pk)
        MpcProvisioningRoot.objects.select_for_update().get(pk=root.pk)
        reservation = reserve_derivation_path(
            keyset_id=keyset_id,
            ownership_scope=ownership_scope,
            customer_ref=customer_ref,
            idempotency_key=idempotency_key,
        )
        account = (
            MpcCustodyAccount.objects.select_for_update()
            .filter(chain_id=root.chain_id, customer_ref=customer_ref)
            .first()
        )
        if account and (
            account.reservation_id != reservation.pk or account.ownership_scope != ownership_scope
        ):
            raise ProvisioningError(
                "customer already has a canonical account; use its original retry identity"
            )
        if account is None:
            if keyset.status != "ACTIVE":
                raise ProvisioningError("unavailable root cannot issue a new account")
            account = MpcCustodyAccount.objects.create(
                reservation=reservation,
                chain_id=root.chain_id,
                customer_ref=customer_ref,
                ownership_scope=ownership_scope,
            )
        if account.status == "ISSUED":
            verified_account(account)
            return account
    request = child_request(reservation, original)
    evidence = (client or SelfHostedMpcAdapter()).approve_child(str(keyset_id), request)
    child = verify_child_evidence(reservation, hd.evidence, evidence)
    with transaction.atomic():
        keyset = MpcKeyset.objects.select_for_update().get(pk=root.pk)
        MpcProvisioningRoot.objects.select_for_update().get(pk=root.pk)
        account = MpcCustodyAccount.objects.select_for_update().get(pk=account.pk)
        if account.status == "ISSUED":
            if account.evidence != evidence:
                raise ProvisioningError("conflicting child issuance evidence")
            return account
        if keyset.status != "ACTIVE":
            raise ProvisioningError("unavailable root cannot complete new issuance")
        account.public_key, account.address, account.evidence, account.status = (
            child["public_key"],
            child["address"],
            evidence,
            "ISSUED",
        )
        account.save(update_fields=["public_key", "address", "evidence", "status"])
        return account


def verified_account(account):
    reservation = account.reservation
    root = reservation.root
    if (
        account.status != "ISSUED"
        or account.customer_ref != reservation.customer_ref
        or account.ownership_scope != root.ownership_scope
        or account.chain_id != root.chain_id
        or root.root_identity != _identity(root.keyset, root.chain_id)
    ):
        raise MpcBindingError("account lacks original immutable ownership/network")
    _network(root)
    hd = MpcHdRootEvidence.objects.get(root=root)
    child = verify_child_evidence(reservation, hd.evidence, account.evidence)
    if (account.public_key, account.address) != (child["public_key"], child["address"]):
        raise MpcBindingError("persisted child public key/address mismatch")
    return child


def attach_account_asset(*, account_id, customer_ref, ownership_scope, asset_key):
    from .config import validate_chain_asset
    from .token_metadata import assert_verified_token

    _postgres()
    with transaction.atomic():
        account = (
            MpcCustodyAccount.objects.select_for_update()
            .select_related("reservation__root__keyset")
            .get(pk=account_id)
        )
        if account.customer_ref != customer_ref or account.ownership_scope != ownership_scope:
            raise ProvisioningError("account owner mismatch")
        verified_account(account)
        validate_chain_asset(account.chain_id, asset_key, "deposit")
        asset = Asset.objects.select_for_update().get(
            asset_key=asset_key, chain_id=account.chain_id, enabled=True
        )
        if not asset.is_native:
            assert_verified_token(asset_key)
        wallet, created = UserWallet.objects.get_or_create(
            custody_account=account,
            asset_key=asset_key,
            defaults={
                "user_id": account.customer_ref,
                "chain_id": account.chain_id,
                "deposit_address": account.address,
                "derivation_path": account.reservation.derivation_path,
                "address_index": 0,
                "mpc_keyset": account.reservation.root.keyset,
                "derivation_version": "mpc_child_v1",
            },
        )
        if not created:
            validate_child_wallet(wallet, account.chain_id, account.address)
        return wallet


def validate_child_wallet(wallet, chain_id, source_address):
    account = wallet.custody_account
    child = verified_account(account)
    keyset = account.reservation.root.keyset
    normalize = str.lower if keyset.scope == "EVM" else str
    if (
        wallet.user_id != account.customer_ref
        or wallet.chain_id != account.chain_id
        or chain_id != account.chain_id
        or wallet.mpc_keyset_id != keyset.pk
        or wallet.derivation_version != "mpc_child_v1"
        or wallet.derivation_path != account.reservation.derivation_path
        or normalize(wallet.deposit_address) != account.address
        or normalize(source_address) != account.address
    ):
        raise MpcBindingError("child wallet ownership/path/source mismatch")
    return keyset, child


def provision_asset_wallet(*, chain_id, customer_ref, asset_key, address_index=0):
    from django.conf import settings

    if address_index != 0:
        raise ProvisioningError("MPC accounts accept no caller-selected address index/path")
    selection = settings.MPC_PROVISIONING_ROOTS.get(chain_id)
    if not isinstance(selection, dict) or set(selection) != {"keyset_id", "ownership_scope"}:
        raise ProvisioningError("no explicitly approved provisioning root for this network")
    selected_root = MpcProvisioningRoot.objects.get(keyset__keyset_id=selection["keyset_id"])
    if selected_root.chain_id != chain_id:
        raise ProvisioningError("approved root belongs to another network")
    account = issue_customer_account(
        keyset_id=selection["keyset_id"],
        ownership_scope=selection["ownership_scope"],
        customer_ref=customer_ref,
        idempotency_key=f"account:{customer_ref}",
    )
    if account.chain_id != chain_id:
        raise ProvisioningError("approved root belongs to another network")
    return attach_account_asset(
        account_id=account.pk,
        customer_ref=customer_ref,
        ownership_scope=selection["ownership_scope"],
        asset_key=asset_key,
    )
