"""Transactional allocation and immutable public ownership evidence on PostgreSQL."""

from django.db import migrations

FORWARD = """
CREATE FUNCTION custody_provisioning_root_guard() RETURNS trigger AS $$
DECLARE k custody_mpckeyset%ROWTYPE;
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'original provisioning root cannot be deleted';
  END IF;
  IF TG_OP = 'UPDATE' THEN
    IF (to_jsonb(NEW) - 'next_index') IS DISTINCT FROM (to_jsonb(OLD) - 'next_index')
       OR NEW.next_index < OLD.next_index OR NEW.next_index > OLD.next_index + 1 THEN
      RAISE EXCEPTION 'original provisioning root identity/counter is immutable';
    END IF;
    RETURN NEW;
  END IF;
  SELECT * INTO STRICT k FROM custody_mpckeyset WHERE id = NEW.keyset_id FOR UPDATE;
  IF k.status <> 'ACTIVE' OR k.algorithm <> 'CGGMP24_ECDSA' OR k.curve <> 'secp256k1'
     OR k.scope NOT IN ('EVM', 'TRON') OR k.derivation_version <> 'cggmp_hd_v1'
     OR k.threshold <> 2 OR k.party_count <> 3
     OR k.participant_identities <> '["signer-a", "signer-b", "signer-c"]'::jsonb
     OR k.dkg_execution_id IS NULL OR length(k.dkg_result_fingerprint) <> 64
     OR length(k.public_key) <> 66 OR NEW.next_index <> 0
     OR jsonb_typeof(k.network_bindings) <> 'object'
     OR (SELECT count(*) FROM jsonb_each(k.network_bindings)) <> 1
     OR NOT (k.network_bindings ? NEW.chain_id)
     OR NEW.root_identity IS DISTINCT FROM
       (jsonb_build_object('keyset_id', k.keyset_id::text, 'chain_id', NEW.chain_id)
        || (k.network_bindings -> NEW.chain_id))
     OR NOT (NEW.root_identity ? 'network')
     OR jsonb_typeof(NEW.root_identity -> 'network') IS DISTINCT FROM 'object'
     OR NEW.root_identity -> 'network' = '{}'::jsonb
     OR (k.scope = 'EVM' AND coalesce(
           NEW.root_identity -> 'network' ->> 'genesis_hash', '') = '')
     OR (k.scope = 'TRON' AND coalesce(
           NEW.root_identity -> 'network' ->> 'genesis_block_id', '') = '')
     OR NEW.dkg_public_evidence = '{}'::jsonb THEN
    RAISE EXCEPTION 'provisioning requires original active CGGMP root/network evidence';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER custody_provisioning_root_identity BEFORE INSERT OR UPDATE OR DELETE
ON custody_mpcprovisioningroot FOR EACH ROW EXECUTE FUNCTION custody_provisioning_root_guard();

CREATE FUNCTION custody_reservation_guard() RETURNS trigger AS $$
DECLARE r custody_mpcprovisioningroot%ROWTYPE;
DECLARE k custody_mpckeyset%ROWTYPE;
BEGIN
  IF TG_OP <> 'INSERT' THEN
    IF TG_OP = 'DELETE' OR NEW IS DISTINCT FROM OLD THEN
      RAISE EXCEPTION 'original derivation reservation is immutable';
    END IF;
    RETURN NEW;
  END IF;
  -- Same lock order as registration/allocation/lifecycle: keyset, then namespace.
  SELECT * INTO STRICT k FROM custody_mpckeyset WHERE id = NEW.root_id FOR UPDATE;
  SELECT * INTO STRICT r FROM custody_mpcprovisioningroot
    WHERE keyset_id = NEW.root_id FOR UPDATE;
  IF k.status <> 'ACTIVE' OR r.next_index >= 2147483648
     OR NEW.child_index <> r.next_index
     OR NEW.derivation_path <> 'm/0/' || r.next_index::text
     OR NEW.customer_ref = '' OR NEW.customer_ref <> btrim(NEW.customer_ref)
     OR NEW.idempotency_key = '' OR NEW.idempotency_key <> btrim(NEW.idempotency_key) THEN
    RAISE EXCEPTION 'invalid active root/non-hardened reservation assignment';
  END IF;
  UPDATE custody_mpcprovisioningroot SET next_index = next_index + 1
    WHERE keyset_id = NEW.root_id;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER custody_derivation_reservation_identity BEFORE INSERT OR UPDATE OR DELETE
ON custody_mpcderivationreservation FOR EACH ROW EXECUTE FUNCTION custody_reservation_guard();

CREATE FUNCTION custody_provisioning_network_guard() RETURNS trigger AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM custody_mpcprovisioningroot WHERE keyset_id = OLD.id)
     AND NEW.network_bindings IS DISTINCT FROM OLD.network_bindings THEN
    RAISE EXCEPTION 'dedicated provisioning root cannot adopt another network';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER custody_provisioning_network_identity BEFORE UPDATE ON custody_mpckeyset
FOR EACH ROW EXECUTE FUNCTION custody_provisioning_network_guard();
"""

REVERSE = """
DROP TRIGGER custody_provisioning_network_identity ON custody_mpckeyset;
DROP FUNCTION custody_provisioning_network_guard();
DROP TRIGGER custody_derivation_reservation_identity ON custody_mpcderivationreservation;
DROP FUNCTION custody_reservation_guard();
DROP TRIGGER custody_provisioning_root_identity ON custody_mpcprovisioningroot;
DROP FUNCTION custody_provisioning_root_guard();
"""


def install(apps, schema_editor):
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(FORWARD, params=None)


def uninstall(apps, schema_editor):
    if apps.get_model("custody", "MpcProvisioningRoot").objects.exists():
        raise RuntimeError("cannot downgrade allocated provisioning evidence; reconcile first")
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(REVERSE, params=None)


class Migration(migrations.Migration):
    dependencies = [("custody", "0027_mpc_derivation_reservations")]
    operations = [migrations.RunPython(install, uninstall)]
