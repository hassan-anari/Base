"""PostgreSQL and independent public verification; not MPC acceptance fixtures."""

import copy
import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from unittest.mock import patch

import pytest
from django.db import DatabaseError, close_old_connections, connection, transaction

from custody.models import HotWallet, MpcCustodyAccount, MpcHdRootEvidence, UserWallet
from custody.mpc_binding import MpcBindingError
from custody.mpc_hd import (
    fingerprint,
    hd_scope,
    public_child,
    verify_child_evidence,
    verify_hd_evidence,
)
from custody.mpc_identity import address_from_public_key
from custody.mpc_issuance import attach_account_asset, attest_original_hd, issue_customer_account
from custody.mpc_provisioning import ProvisioningError, register_provisioning_root
from custody.tests.test_phase6g_provisioning import (
    fixture_freeze,
    fixture_keyset,
    metadata_for,
)
from custody.tests.test_phase6g_provisioning import root as provisioning_root_fixture

PARTIES = ["signer-a", "signer-b", "signer-c"]
pytestmark = pytest.mark.django_db(transaction=True)


class PublicFixtureClient:
    """Synthetic public data solely for DB/service negative and recovery tests."""

    def __init__(self, root):
        request = {
            "auxiliary": root.dkg_public_evidence["auxiliary"]["request"],
            "scope": hd_scope(root),
        }
        self.original = {
            "request": request,
            "chain_code": "13" * 32,
            "extended_identity": fingerprint("CGGMP24_HD_ROOT_V1", [request, "13" * 32]),
        }
        self.root = root

    def attest_hd(self, keyset, scope):
        assert scope == hd_scope(self.root)
        return {
            "root": self.original,
            "participant_agreement": [
                {"root": self.original, "party_id": party, "durable": True} for party in PARTIES
            ],
        }

    def approve_child(self, keyset, request):
        public = public_child(
            self.root.keyset.public_key, self.original["chain_code"], request["child_index"]
        )
        child = {
            "request": request,
            "public_key": public,
            "address": address_from_public_key(self.root.chain_id, public).lower(),
        }
        return {
            "child": child,
            "participant_agreement": [
                {"child": child, "party_id": party, "durable": True} for party in PARTIES
            ],
        }


root = provisioning_root_fixture


@pytest.fixture
def hd(root):
    client = PublicFixtureClient(root)
    with patch("custody.mpc_issuance._runtime"), patch("custody.mpc_issuance._network"):
        attest_original_hd(
            keyset_id=root.keyset.keyset_id, ownership_scope=root.ownership_scope, client=client
        )
        yield root, client


def issue(hd, customer="customer", retry="request"):
    root, client = hd
    return issue_customer_account(
        keyset_id=root.keyset.keyset_id,
        ownership_scope=root.ownership_scope,
        customer_ref=customer,
        idempotency_key=retry,
        client=client,
    )


@pytest.mark.django_db(transaction=True)
def test_parallel_issuance_one_original_owner(hd):
    def worker(i):
        close_old_connections()
        try:
            account = issue(hd, customer=f"customer-{i % 16}", retry=f"retry-{i % 16}")
            return account.pk, account.address
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(worker, range(64)))
    assert len(set(results)) == 16
    assert len({address for _, address in results}) == 16
    assert MpcCustodyAccount.objects.filter(status="ISSUED").count() == 16
    assert UserWallet.objects.count() == 0


@pytest.mark.django_db(transaction=True)
def test_lost_child_response_recovers_original_claim(hd):
    _, client = hd
    original = client.approve_child

    def lost(*args):
        original(*args)
        raise TimeoutError("response lost after independent approvals")

    with patch.object(client, "approve_child", side_effect=lost), pytest.raises(TimeoutError):
        issue(hd)
    account = MpcCustodyAccount.objects.get()
    reservation = account.reservation_id
    assert account.status == "PROVISIONING"
    close_old_connections()
    recovered = issue(hd)
    assert recovered.pk == account.pk and recovered.reservation_id == reservation
    assert recovered.status == "ISSUED"
    assert issue(hd).pk == recovered.pk


@pytest.mark.django_db(transaction=True)
def test_conflicting_customer_retry_scope_and_reassignment(hd):
    account = issue(hd)
    with pytest.raises(ProvisioningError):
        issue(hd, customer="intruder")
    with pytest.raises(ProvisioningError):
        issue(hd, retry="replacement")
    with pytest.raises(ProvisioningError):
        issue_customer_account(
            keyset_id=hd[0].keyset.keyset_id,
            ownership_scope="other-tenant",
            customer_ref="customer",
            idempotency_key="request",
            client=hd[1],
        )
    for field, value in (
        ("customer_ref", "other"),
        ("address", "0x" + "aa" * 20),
        ("status", "PROVISIONING"),
        ("public_key", hd[0].keyset.public_key),
    ):
        with pytest.raises(DatabaseError), transaction.atomic():
            MpcCustodyAccount.objects.filter(pk=account.pk).update(**{field: value})


@pytest.mark.django_db(transaction=True)
def test_independent_hd_evidence_and_child_negative_cases(hd):
    root, client = hd
    account = issue(hd)
    original = MpcHdRootEvidence.objects.get(root=root).evidence
    for field, value in (("chain_code", "21" * 32), ("extended_identity", "11" * 32)):
        evidence = copy.deepcopy(original)
        evidence["root"][field] = value
        with pytest.raises(MpcBindingError):
            verify_hd_evidence(root, evidence)
    for field, value in (("address", "0x" + "12" * 20), ("public_key", root.keyset.public_key)):
        evidence = copy.deepcopy(account.evidence)
        evidence["child"][field] = value
        with pytest.raises(MpcBindingError):
            verify_child_evidence(account.reservation, original, evidence)
    for field, value in (
        ("derivation_path", "m/0/0'"),
        ("child_index", 1 << 31),
        ("customer_ref", "other"),
    ):
        evidence = copy.deepcopy(account.evidence)
        evidence["child"]["request"][field] = value
        with pytest.raises(MpcBindingError):
            verify_child_evidence(account.reservation, original, evidence)
    evidence = copy.deepcopy(account.evidence)
    evidence["participant_agreement"].pop()
    with pytest.raises(MpcBindingError):
        verify_child_evidence(account.reservation, original, evidence)
    with pytest.raises(DatabaseError), transaction.atomic():
        MpcHdRootEvidence.objects.filter(root=root).update(evidence={})


@pytest.mark.django_db(transaction=True)
def test_asset_attachment_preserves_canonical_owner(hd):
    account = issue(hd)
    wallet = attach_account_asset(
        account_id=account.pk,
        customer_ref=account.customer_ref,
        ownership_scope=account.ownership_scope,
        asset_key="ETH",
    )
    assert (
        attach_account_asset(
            account_id=account.pk,
            customer_ref=account.customer_ref,
            ownership_scope=account.ownership_scope,
            asset_key="ETH",
        ).pk
        == wallet.pk
    )
    assert wallet.derivation_version == "mpc_child_v1"
    for values in (
        {"user_id": "another"},
        {"custody_account_id": None},
        {"derivation_path": "m/0/1"},
        {"deposit_address": "0x" + "22" * 20},
    ):
        with pytest.raises(DatabaseError), transaction.atomic():
            UserWallet.objects.filter(pk=wallet.pk).update(**values)
    with pytest.raises(ProvisioningError):
        attach_account_asset(
            account_id=account.pk,
            customer_ref="other-tenant",
            ownership_scope=account.ownership_scope,
            asset_key="ETH",
        )
    with pytest.raises(DatabaseError), transaction.atomic():
        UserWallet.objects.create(
            user_id="competitor",
            chain_id="ETH",
            asset_key="ETH",
            derivation_path="legacy",
            deposit_address=account.address.upper(),
        )


@pytest.mark.parametrize("index", [-1, 1 << 31, True, "0"])
def test_hardened_and_noninteger_derivation_rejected(index):
    with pytest.raises(MpcBindingError):
        public_child(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "12" * 32, index
        )


def test_outer_transaction_cannot_rollback_a_published_claim(hd):
    with transaction.atomic(), pytest.raises(ProvisioningError, match="durable claim"):
        issue(hd)
    assert not MpcCustodyAccount.objects.exists()


def test_historical_root_binding_is_preserved_and_not_attested():
    keyset = fixture_keyset()
    legacy, _ = HotWallet.objects.update_or_create(
        chain_id="ETH",
        defaults={
            "address": "0x" + "13" * 20,
            "mpc_keyset": keyset,
            "signing_key_ref": f"keyset:{keyset.keyset_id}",
        },
    )
    with (
        patch(
            "custody.signer_adapter.SelfHostedMpcAdapter.get_keyset",
            return_value=metadata_for(keyset),
        ),
        patch("custody.mpc_provisioning._freeze_root_network", side_effect=fixture_freeze),
    ):
        root = register_provisioning_root(
            keyset_id=keyset.keyset_id, chain_id="ETH", ownership_scope="legacy"
        )
    client = PublicFixtureClient(root)
    with patch("custody.mpc_issuance._runtime"), patch.object(client, "attest_hd") as rpc:
        with pytest.raises(ProvisioningError, match="historical root wallet"):
            attest_original_hd(keyset_id=keyset.keyset_id, ownership_scope="legacy", client=client)
        rpc.assert_not_called()
    legacy.refresh_from_db()
    assert legacy.mpc_keyset == keyset and not MpcHdRootEvidence.objects.exists()


def test_dedicated_root_cannot_acquire_a_competing_root_only_binding(root):
    with pytest.raises(DatabaseError, match="dedicated DEPOSIT"), transaction.atomic():
        HotWallet.objects.create(chain_id="ETH", address="0x" + "13" * 20, mpc_keyset=root.keyset)
    with pytest.raises(DatabaseError, match="dedicated DEPOSIT"), transaction.atomic():
        UserWallet.objects.create(
            user_id="intruder",
            chain_id="ETH",
            asset_key="ETH",
            address_index=0,
            deposit_address="0x" + "13" * 20,
            mpc_keyset=root.keyset,
        )


def test_attestation_requires_original_committed_namespace(root):
    with transaction.atomic(), pytest.raises(ProvisioningError, match="durably committed"):
        attest_original_hd(keyset_id=root.keyset.keyset_id, ownership_scope=root.ownership_scope)


def test_legacy_cross_asset_insert_racing_issuance_cannot_create_two_owners(hd):
    root, client = hd
    address = address_from_public_key(
        "ETH", public_child(root.keyset.public_key, client.original["chain_code"], 0)
    ).lower()
    held, release, approved = threading.Event(), threading.Event(), threading.Event()
    original = client.approve_child

    def approve(*args):
        evidence = original(*args)
        approved.set()
        return evidence

    def legacy_writer():
        close_old_connections()
        try:
            with transaction.atomic():
                UserWallet.objects.create(
                    user_id="legacy-owner",
                    chain_id="ETH",
                    asset_key="legacy-token-view",
                    derivation_path="legacy",
                    deposit_address=address.upper(),
                )
                held.set()
                assert release.wait(10)
        finally:
            close_old_connections()

    def issuer():
        close_old_connections()
        try:
            return issue(hd)
        finally:
            close_old_connections()

    with patch.object(client, "approve_child", approve), ThreadPoolExecutor(max_workers=2) as pool:
        legacy = pool.submit(legacy_writer)
        assert held.wait(10)
        issuance = pool.submit(issuer)
        assert approved.wait(10)
        with pytest.raises(FutureTimeoutError):
            issuance.result(timeout=0.25)
        release.set()
        legacy.result(timeout=10)
        with pytest.raises(DatabaseError, match="historical financial owner"):
            issuance.result(timeout=10)
    assert MpcCustodyAccount.objects.get().status == "PROVISIONING"
    assert UserWallet.objects.get().user_id == "legacy-owner"


def test_stale_snapshot_isolation_cannot_bypass_address_claim_guard(hd):
    with (
        transaction.atomic(),
        connection.cursor() as cursor,
        pytest.raises(DatabaseError, match="READ COMMITTED"),
    ):
        cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        UserWallet.objects.create(
            user_id="legacy",
            chain_id="ETH",
            asset_key="ETH",
            derivation_path="legacy",
            deposit_address="0x" + "ad" * 20,
        )
