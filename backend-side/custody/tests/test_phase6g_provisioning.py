"""PostgreSQL allocation evidence, not cryptographic HD/spendability evidence."""

import copy
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from uuid import uuid4

import pytest
from django.db import DatabaseError, close_old_connections, connection, transaction
from django.db.migrations.executor import MigrationExecutor

from custody.models import MpcDerivationReservation, MpcKeyset, MpcProvisioningRoot, UserWallet
from custody.mpc_provisioning import (
    CAPACITY,
    ProvisioningError,
    register_provisioning_root,
    reserve_derivation_path,
)
from custody.tests.test_phase6_signing import metadata_for


def fixture_keyset():
    return MpcKeyset.objects.create(
        keyset_id=uuid4(),
        algorithm="CGGMP24_ECDSA",
        curve="secp256k1",
        scope="EVM",
        derivation_version="cggmp_hd_v1",
        status="ACTIVE",
        public_key="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        dkg_execution_id=uuid4(),
        dkg_result_fingerprint="ab" * 32,
        participant_identities=["signer-a", "signer-b", "signer-c"],
    )


def fixture_freeze(keyset, spec):
    binding = {
        "scope": keyset.scope,
        "algorithm": keyset.algorithm,
        "public_key": keyset.public_key,
        "dkg_execution_id": str(keyset.dkg_execution_id),
        "dkg_fingerprint": keyset.dkg_result_fingerprint,
        "network": {"evm_chain_id": 31337, "genesis_hash": "0x" + "11" * 32},
    }
    MpcKeyset.objects.filter(pk=keyset.pk).update(network_bindings={spec.chain_id: binding})


@pytest.fixture
def root():
    assert connection.vendor == "postgresql"
    keyset = fixture_keyset()
    with (
        patch(
            "custody.signer_adapter.SelfHostedMpcAdapter.get_keyset",
            return_value=metadata_for(keyset),
        ),
        patch("custody.mpc_provisioning._freeze_root_network", side_effect=fixture_freeze),
    ):
        return register_provisioning_root(
            keyset_id=keyset.keyset_id, chain_id="ETH", ownership_scope="deployment:isolated"
        )


def allocate(root, retry="request-1", customer="customer-1", owner="deployment:isolated"):
    return reserve_derivation_path(
        keyset_id=root.keyset.keyset_id,
        ownership_scope=owner,
        customer_ref=customer,
        idempotency_key=retry,
    )


@pytest.mark.django_db(transaction=True)
def test_concurrent_unique_assignment_and_duplicate_retry(root):
    before = UserWallet.objects.count()

    def worker(index):
        close_old_connections()
        try:
            item = allocate(root, f"request-{index % 32}", f"customer-{index % 32}")
            return str(item.pk), item.child_index, item.derivation_path
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=8) as workers:
        results = list(workers.map(worker, range(64)))
    assert len(set(results)) == 32
    assert sorted({r[1] for r in results}) == list(range(32))
    assert {r[2] for r in results} == {f"m/0/{i}" for i in range(32)}
    root.refresh_from_db()
    assert root.next_index == 32
    assert UserWallet.objects.count() == before
    assert set(MpcDerivationReservation.objects.values_list("status", flat=True)) == {"RESERVED"}


@pytest.mark.django_db(transaction=True)
def test_conflicting_retry_has_one_owner_under_concurrency(root):
    def worker(customer):
        close_old_connections()
        try:
            return allocate(root, customer=customer).customer_ref
        except ProvisioningError:
            return "conflict"
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(worker, ["alice", "bob"]))
    assert results.count("conflict") == 1
    assert MpcDerivationReservation.objects.count() == 1
    root.refresh_from_db()
    assert root.next_index == 1


@pytest.mark.django_db(transaction=True)
def test_rollback_restart_and_retirement_preserve_original_assignment(root):
    with pytest.raises(RuntimeError), transaction.atomic():
        allocate(root)
        raise RuntimeError("coordinator interrupted before commit")
    root.refresh_from_db()
    assert root.next_index == 0 and MpcDerivationReservation.objects.count() == 0
    original = allocate(root)
    connection.close()
    assert allocate(root).pk == original.pk
    MpcKeyset.objects.filter(pk=root.pk).update(status="RETIRED", active_for_new_wallets=False)
    assert allocate(root).pk == original.pk
    with pytest.raises(ProvisioningError, match="retired"):
        allocate(root, retry="new")
    root.refresh_from_db()
    assert root.next_index == 1


@pytest.mark.django_db
@pytest.mark.parametrize(
    "owner,customer,retry",
    [
        ("other-deployment", "customer-1", "request-1"),
        ("deployment:isolated", "", "request-1"),
        ("deployment:isolated", " customer-1", "request-1"),
        ("deployment:isolated", "customer-1", ""),
    ],
)
def test_invalid_ownership_inputs_fail_without_allocation(root, owner, customer, retry):
    with pytest.raises(ProvisioningError):
        allocate(root, retry=retry, customer=customer, owner=owner)
    assert MpcDerivationReservation.objects.count() == 0


@pytest.mark.django_db
def test_authentication_and_original_scope_required(root):
    metadata = metadata_for(root.keyset)
    with (
        patch("custody.signer_adapter.SelfHostedMpcAdapter.get_keyset", return_value=metadata),
        patch("custody.mpc_provisioning._freeze_root_network"),
    ):
        assert (
            register_provisioning_root(
                keyset_id=root.keyset.keyset_id,
                chain_id="ETH",
                ownership_scope=root.ownership_scope,
            ).pk
            == root.pk
        )
        with pytest.raises(ProvisioningError, match="cannot be replaced"):
            register_provisioning_root(
                keyset_id=root.keyset.keyset_id, chain_id="ETH", ownership_scope="another"
            )
        metadata["auxiliary"]["internally_signable"] = False
        with pytest.raises(ValueError, match="readiness"):
            register_provisioning_root(
                keyset_id=root.keyset.keyset_id,
                chain_id="ETH",
                ownership_scope=root.ownership_scope,
            )
    for chain in ("SOL", "TON"):
        with pytest.raises(ProvisioningError, match="secp256k1"):
            register_provisioning_root(
                keyset_id=root.keyset.keyset_id,
                chain_id=chain,
                ownership_scope=root.ownership_scope,
            )


@pytest.mark.django_db
def test_numeric_network_id_without_genesis_cannot_register_namespace():
    keyset = fixture_keyset()
    binding = {
        "scope": keyset.scope,
        "algorithm": keyset.algorithm,
        "public_key": keyset.public_key,
        "dkg_execution_id": str(keyset.dkg_execution_id),
        "dkg_fingerprint": keyset.dkg_result_fingerprint,
        "network": {"evm_chain_id": 11155111},
    }
    # Historical public-testnet root signing can have a numeric-only binding.
    # It must not establish a new namespace's mandatory genesis identity.
    keyset.network_bindings = {"ETH": binding}
    keyset.save()
    with (
        patch(
            "custody.signer_adapter.SelfHostedMpcAdapter.get_keyset",
            return_value=metadata_for(keyset),
        ),
        patch("custody.mpc_provisioning._freeze_root_network"),
    ):
        with pytest.raises(ProvisioningError, match="genesis"):
            register_provisioning_root(
                keyset_id=keyset.keyset_id, chain_id="ETH", ownership_scope="isolated"
            )
    identity = {"keyset_id": str(keyset.keyset_id), "chain_id": "ETH", **binding}
    with pytest.raises(DatabaseError), transaction.atomic():
        MpcProvisioningRoot.objects.create(
            keyset=keyset,
            ownership_scope="isolated",
            chain_id="ETH",
            root_identity=identity,
            dkg_public_evidence=metadata_for(keyset),
        )
    assert MpcProvisioningRoot.objects.count() == 0


@pytest.mark.django_db
def test_database_identity_and_security_class_guards(root):
    reservation = allocate(root)
    for change in (
        {"customer_ref": "someone-else"},
        {"root_id": 999},
        {"status": "ISSUED"},
        {"child_index": 1},
        {"derivation_path": "m/0/1'"},
    ):
        with pytest.raises(DatabaseError), transaction.atomic():
            MpcDerivationReservation.objects.filter(pk=reservation.pk).update(**change)
    for change in (
        {"ownership_scope": "other"},
        {"wallet_class": "COLD"},
        {"wallet_class": "WARM"},
        {"purpose": "WITHDRAWAL"},
        {"next_index": 0},
        {"next_index": 10},
        {"chain_id": "BASE"},
        {"root_identity": {}},
        {"dkg_public_evidence": {}},
    ):
        with pytest.raises(DatabaseError), transaction.atomic():
            MpcProvisioningRoot.objects.filter(pk=root.pk).update(**change)
    for model, pk in ((MpcDerivationReservation, reservation.pk), (MpcProvisioningRoot, root.pk)):
        with pytest.raises(DatabaseError), transaction.atomic(), connection.cursor() as cursor:
            field = model._meta.pk.column
            cursor.execute(f'DELETE FROM "{model._meta.db_table}" WHERE "{field}" = %s', [pk])
    root.keyset.refresh_from_db()
    pins = copy.deepcopy(root.keyset.network_bindings)
    pins["BASE"] = pins["ETH"]
    with pytest.raises(DatabaseError, match="another network"), transaction.atomic():
        MpcKeyset.objects.filter(pk=root.pk).update(network_bindings=pins)


@pytest.mark.django_db
def test_noncanonical_or_hardened_paths_cannot_enter_database(root):
    for index, path in ((0, "m/0/0'"), (0, "m/0/00"), (1, "m/0/1"), (CAPACITY, f"m/0/{CAPACITY}")):
        with pytest.raises(DatabaseError), transaction.atomic():
            MpcDerivationReservation.objects.create(
                root=root,
                customer_ref="customer",
                idempotency_key="invalid",
                child_index=index,
                derivation_path=path,
            )
    root.refresh_from_db()
    assert root.next_index == 0


@pytest.mark.django_db(transaction=True)
def test_index_exhaustion_never_wraps(root):
    # Simulate a historical full namespace without billions of inserts. The
    # trigger is disabled only in this test transaction and reenabled immediately.
    with transaction.atomic(), connection.cursor() as cursor:
        cursor.execute(
            "ALTER TABLE custody_mpcprovisioningroot DISABLE TRIGGER "
            "custody_provisioning_root_identity"
        )
        cursor.execute(
            "UPDATE custody_mpcprovisioningroot SET next_index = %s WHERE keyset_id = %s",
            [CAPACITY - 1, root.pk],
        )
        cursor.execute(
            "ALTER TABLE custody_mpcprovisioningroot ENABLE TRIGGER "
            "custody_provisioning_root_identity"
        )
    last = allocate(root)
    assert last.child_index == CAPACITY - 1
    with pytest.raises(ProvisioningError, match="exhausted"):
        allocate(root, retry="overflow")
    assert allocate(root).pk == last.pk
    root.refresh_from_db()
    assert root.next_index == CAPACITY


@pytest.mark.django_db(transaction=True)
def test_migration_preserves_legacy_wallets_and_refuses_evidence_downgrade():
    executor = MigrationExecutor(connection)
    original = executor.loader.graph.leaf_nodes()
    try:
        executor.migrate([("custody", "0026_evm_token_verified_scan_checkpoint")])
        historical = executor.loader.project_state(
            [("custody", "0026_evm_token_verified_scan_checkpoint")]
        ).apps
        wallet = historical.get_model("custody", "UserWallet").objects.create(
            user_id="legacy",
            chain_id="ETH",
            asset_key="ETH",
            derivation_path="historical",
            deposit_address="0x" + "12" * 20,
        )
        before = historical.get_model("custody", "UserWallet").objects.values().get(pk=wallet.pk)
        executor = MigrationExecutor(connection)
        executor.migrate(original)
        assert UserWallet.objects.values().get(pk=wallet.pk) == {
            **before,
            "custody_account_id": None,
        }
        assert MpcProvisioningRoot.objects.count() == 0
        assert MpcDerivationReservation.objects.count() == 0
        keyset = fixture_keyset()
        with (
            patch(
                "custody.signer_adapter.SelfHostedMpcAdapter.get_keyset",
                return_value=metadata_for(keyset),
            ),
            patch("custody.mpc_provisioning._freeze_root_network", side_effect=fixture_freeze),
        ):
            register_provisioning_root(
                keyset_id=keyset.keyset_id, chain_id="ETH", ownership_scope="isolated"
            )
        with pytest.raises(RuntimeError, match="cannot downgrade"):
            MigrationExecutor(connection).migrate([("custody", "0027_mpc_derivation_reservations")])
    finally:
        MigrationExecutor(connection).migrate(original)


@pytest.mark.django_db(transaction=True)
def test_large_population_reservation_benchmark(root, tmp_path):
    count = int(os.environ.get("PHASE6G_BENCHMARK_COUNT", "1000"))
    assert 1000 <= count <= 100000
    workers = 8
    started = time.perf_counter()

    def worker(worker_id):
        close_old_connections()
        try:
            return [
                allocate(root, f"benchmark-{i}", f"customer-{i}").child_index
                for i in range(worker_id, count, workers)
            ]
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=workers) as pool:
        assigned = [index for group in pool.map(worker, range(workers)) for index in group]
    elapsed = time.perf_counter() - started
    assert sorted(assigned) == list(range(count))
    assert MpcDerivationReservation.objects.count() == count
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_total_relation_size('custody_mpcderivationreservation')")
        stored_bytes = cursor.fetchone()[0]
        cursor.execute("SHOW server_version")
        postgres = cursor.fetchone()[0]
    evidence = {
        "kind": "durable-path-reservations-only",
        "count": count,
        "workers": workers,
        "seconds": elapsed,
        "reservations_per_second": count / elapsed,
        "table_and_index_bytes": stored_bytes,
        "bytes_per_reservation": stored_bytes / count,
        "postgres_version": postgres,
        "dkg_ceremonies_during_allocation": 0,
        "chain_transactions": 0,
        "issued_addresses": 0,
        "root": "synthetic-public-test-fixture",
    }
    (tmp_path / "reservation-benchmark.json").write_text(json.dumps(evidence, indent=2))
    print(json.dumps(evidence, sort_keys=True))
