"""PostgreSQL and independent public verification; not MPC acceptance fixtures."""

import copy
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from django.db import DatabaseError, close_old_connections, connection, transaction

from custody.models import HotWallet, MpcCustodyAccount, MpcHdRootEvidence, UserWallet
from custody.mpc_binding import MpcBindingError
from custody.mpc_hd import (
    child_request,
    fingerprint,
    hd_scope,
    public_child,
    verify_child_evidence,
    verify_hd_evidence,
)
from custody.mpc_identity import address_from_public_key
from custody.mpc_issuance import attach_account_asset, attest_original_hd, issue_customer_account
from custody.mpc_provisioning import ProvisioningError, register_provisioning_root
from custody.mpc_receipts import receipt_message
from custody.tests.test_phase6g_provisioning import (
    fixture_freeze,
    fixture_keyset,
    metadata_for,
)
from custody.tests.test_phase6g_provisioning import root as provisioning_root_fixture

PARTIES = ["signer-a", "signer-b", "signer-c"]
pytestmark = pytest.mark.django_db(transaction=True)


_RECEIPT_KEYS = {party: ec.generate_private_key(ec.SECP256R1()) for party in PARTIES}


@pytest.fixture(autouse=True)
def signer_receipt_trust(settings, tmp_path):
    pins = {}
    for party, key in _RECEIPT_KEYS.items():
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, party)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier(f"spiffe://wallet-mpc/{party}")]
                ),
                False,
            )
            .sign(key, hashes.SHA256())
        )
        path = tmp_path / f"{party}.crt"
        path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        pins[party] = str(path)
    settings.MPC_HD_SIGNER_CERTIFICATES = pins


def signed_reports(kind, identity):
    reports = []
    for party, key in _RECEIPT_KEYS.items():
        statement = {kind: identity, "party_id": party, "durable": True}
        reports.append(
            statement
            | {
                "signer_signature": key.sign(
                    receipt_message(kind, statement), ec.ECDSA(hashes.SHA256())
                ).hex()
            }
        )
    return reports


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
        self.root_reports = signed_reports("root", self.original)
        self.children = {}

    def attest_hd(self, keyset, request):
        assert request == self.original["request"]
        return {
            "root": self.original,
            "participant_agreement": self.root_reports,
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
            "participant_agreement": self.children.setdefault(
                str(request), signed_reports("child", child)
            ),
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


@pytest.mark.parametrize("existing_view", [False, True])
def test_asset_attachment_waits_on_keyset_before_account(existing_view, hd):
    account = issue(hd)
    root, _ = hd
    if existing_view:
        attach_account_asset(
            account_id=account.pk,
            customer_ref=account.customer_ref,
            ownership_scope=account.ownership_scope,
            asset_key="ETH",
        )
    locking = threading.Event()
    pid = []

    def worker():
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                pid.append(cursor.fetchone()[0])

            def observe(execute, sql, params, many, context):
                if "FOR UPDATE" in sql:
                    locking.set()
                return execute(sql, params, many, context)

            with patch("custody.mpc_issuance._network"), connection.execute_wrapper(observe):
                return attach_account_asset(
                    account_id=account.pk,
                    customer_ref=account.customer_ref,
                    ownership_scope=account.ownership_scope,
                    asset_key="ETH",
                ).pk
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=1) as pool:
        with transaction.atomic():
            MpcKeyset = root.keyset.__class__
            MpcKeyset.objects.select_for_update().get(pk=root.pk)
            pending = pool.submit(worker)
            assert locking.wait(5)
            deadline = time.monotonic() + 5
            while True:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT cardinality(pg_blocking_pids(%s))", [pid[0]])
                    if cursor.fetchone()[0]:
                        break
                assert time.monotonic() < deadline
                time.sleep(0.01)
            # The worker is now demonstrably blocked at the keyset. It must
            # not already own an account lock that reverses issuance ordering.
            MpcCustodyAccount.objects.select_for_update(nowait=True).get(pk=account.pk)
        assert pending.result(timeout=5)
    assert UserWallet.objects.filter(custody_account=account).count() == 1


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


def test_malicious_coordinator_recomputes_all_root_child_reports_without_signers(root):
    """R1 reproduction: every public hash/point/address agrees with a substituted CC."""
    client = PublicFixtureClient(root)
    original_reports = copy.deepcopy(client.root_reports)
    client.original["chain_code"] = "42" * 32
    client.original["extended_identity"] = fingerprint(
        "CGGMP24_HD_ROOT_V1", [client.original["request"], client.original["chain_code"]]
    )
    client.root_reports = [
        report | {"root": copy.deepcopy(client.original)} for report in original_reports
    ]
    # The attacker can produce *all* matching public reports, but cannot re-sign them.
    forged = client.attest_hd(str(root.keyset.keyset_id), client.original["request"])
    with pytest.raises(MpcBindingError, match="signer-origin"):
        verify_hd_evidence(root, forged)
    with patch("custody.mpc_issuance._runtime"), pytest.raises(MpcBindingError):
        attest_original_hd(
            keyset_id=root.keyset.keyset_id, ownership_scope=root.ownership_scope, client=client
        )
    assert not MpcHdRootEvidence.objects.exists()
    assert not MpcCustodyAccount.objects.filter(status="ISSUED").exists()
    assert not UserWallet.objects.exists()
    # Also exercise a fully consistent forged child on a pinned genuine root.
    authentic = PublicFixtureClient(root)
    with patch("custody.mpc_issuance._runtime"), patch("custody.mpc_issuance._network"):
        attest_original_hd(
            keyset_id=root.keyset.keyset_id, ownership_scope=root.ownership_scope, client=authentic
        )
        approve = authentic.approve_child

        def fabricate(keyset, request):
            result = approve(keyset, request)
            for report in result["participant_agreement"]:
                report["signer_signature"] = "30" * 70
            return result

        with (
            patch.object(authentic, "approve_child", side_effect=fabricate),
            pytest.raises(MpcBindingError),
        ):
            issue_customer_account(
                keyset_id=root.keyset.keyset_id,
                ownership_scope=root.ownership_scope,
                customer_ref="victim",
                idempotency_key="victim-original",
                client=authentic,
            )
        assert MpcCustodyAccount.objects.get().status == "PROVISIONING"
        assert not UserWallet.objects.exists()
    print("R1_REJECTED recomputed_root=true recomputed_child=true issued=0 asset_wallets=0")


@pytest.mark.parametrize(
    "attack", ["missing", "another_signer", "coordinator_key", "unknown_pin", "replay_customer"]
)
def test_independent_receipt_origin_and_replay_fail_closed(hd, settings, attack):
    from custody.mpc_issuance import verified_account

    root, client = hd
    account = issue(hd)
    evidence = copy.deepcopy(account.evidence)
    if attack == "missing":
        del evidence["participant_agreement"][0]["signer_signature"]
    elif attack == "another_signer":
        evidence["participant_agreement"][0]["signer_signature"] = evidence[
            "participant_agreement"
        ][1]["signer_signature"]
    elif attack == "coordinator_key":
        statement = {
            k: v for k, v in evidence["participant_agreement"][0].items() if k != "signer_signature"
        }
        evidence["participant_agreement"][0]["signer_signature"] = (
            ec.generate_private_key(ec.SECP256R1())
            .sign(receipt_message("child", statement), ec.ECDSA(hashes.SHA256()))
            .hex()
        )
    elif attack == "unknown_pin":
        settings.MPC_HD_SIGNER_CERTIFICATES = {}
    else:
        evidence["child"]["request"]["customer_ref"] = "other"
        for report in evidence["participant_agreement"]:
            report["child"] = evidence["child"]
    with pytest.raises(MpcBindingError):
        verify_child_evidence(account.reservation, root.mpchdrootevidence.evidence, evidence)
    account.evidence = evidence
    # Model-level writes and every read/exposure both verify crypto, not only SQL shape.
    with pytest.raises(MpcBindingError):
        account.save()
    with pytest.raises(MpcBindingError):
        verified_account(account)


def test_migration_quarantines_unsigned_issued_evidence_without_rewriting_history(root):
    from django.db.migrations.executor import MigrationExecutor

    from custody.mpc_issuance import verified_account
    from custody.mpc_provisioning import reserve_derivation_path

    executor = MigrationExecutor(connection)
    final = executor.loader.graph.leaf_nodes()
    try:
        executor.migrate([("custody", "0031_original_custody_child_authorization")])
        old = (
            MigrationExecutor(connection)
            .loader.project_state([("custody", "0031_original_custody_child_authorization")])
            .apps
        )
        client = PublicFixtureClient(root)
        evidence = client.attest_hd(str(root.keyset.keyset_id), client.original["request"])
        for report in evidence["participant_agreement"]:
            del report["signer_signature"]
        old.get_model("custody", "MpcHdRootEvidence").objects.create(
            root_id=root.pk, evidence=evidence
        )
        reservation = reserve_derivation_path(
            keyset_id=root.keyset.keyset_id,
            ownership_scope=root.ownership_scope,
            customer_ref="old-owner",
            idempotency_key="old-request",
        )
        request = child_request(reservation, evidence["root"])
        child_evidence = client.approve_child(str(root.keyset.keyset_id), request)
        for report in child_evidence["participant_agreement"]:
            del report["signer_signature"]
        account = old.get_model("custody", "MpcCustodyAccount").objects.create(
            reservation_id=reservation.pk,
            chain_id=root.chain_id,
            ownership_scope=root.ownership_scope,
            customer_ref="old-owner",
        )
        account.status = "ISSUED"
        account.public_key = child_evidence["child"]["public_key"]
        account.address = child_evidence["child"]["address"]
        account.evidence = child_evidence
        account.save()
        wallet = old.get_model("custody", "UserWallet").objects.create(
            custody_account_id=account.pk,
            user_id="old-owner",
            chain_id="ETH",
            asset_key="ETH",
            deposit_address=account.address,
            derivation_path=reservation.derivation_path,
            derivation_version="mpc_child_v1",
            mpc_keyset_id=root.pk,
            address_index=0,
        )
        before = old.get_model("custody", "MpcCustodyAccount").objects.values().get(pk=account.pk)
        before_wallet = old.get_model("custody", "UserWallet").objects.values().get(pk=wallet.pk)
        MigrationExecutor(connection).migrate(final)
        assert MpcHdRootEvidence.objects.get(root=root).evidence == evidence
        assert MpcCustodyAccount.objects.values().get(pk=account.pk) == before
        assert UserWallet.objects.values().get(pk=wallet.pk) == before_wallet
        persisted = MpcCustodyAccount.objects.get(pk=account.pk)
        from io import StringIO

        from django.core.management import call_command
        from django.core.management.base import CommandError

        audit_output = StringIO()
        with patch("custody.mpc_issuance._network"), pytest.raises(CommandError):
            call_command("audit_mpc_hd_evidence", stdout=audit_output)
        assert str(account.pk) in audit_output.getvalue()
        assert account.address not in audit_output.getvalue()
        assert MpcCustodyAccount.objects.values().get(pk=account.pk) == before
        with patch("custody.mpc_issuance._network"), pytest.raises(MpcBindingError):
            verified_account(persisted)
        with patch("custody.mpc_issuance._network"), pytest.raises(MpcBindingError):
            attach_account_asset(
                account_id=account.pk,
                customer_ref="old-owner",
                ownership_scope=root.ownership_scope,
                asset_key="ETH",
            )
    finally:
        MigrationExecutor(connection).migrate(final)
