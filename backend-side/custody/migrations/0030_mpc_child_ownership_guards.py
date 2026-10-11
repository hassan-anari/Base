"""Freeze original HD statements, canonical issuance and financial asset views.

No historical root wallet or journal is backfilled. PROVISIONING claims survive
partial external commits; only their original authenticated evidence can issue.
"""

from django.db import migrations

FORWARD = r"""
CREATE FUNCTION custody_hd_guard() RETURNS trigger AS $$
DECLARE r custody_mpcprovisioningroot%ROWTYPE;
DECLARE original jsonb;
DECLARE receipt jsonb;
DECLARE party text;
BEGIN
  IF TG_OP <> 'INSERT' THEN
    IF TG_OP = 'DELETE' OR NEW IS DISTINCT FROM OLD THEN
      RAISE EXCEPTION 'original HD evidence is immutable';
    END IF;
    RETURN NEW;
  END IF;
  SELECT * INTO STRICT r FROM custody_mpcprovisioningroot WHERE keyset_id = NEW.root_id FOR UPDATE;
  original := NEW.evidence -> 'root';
  IF original -> 'request' IS DISTINCT FROM jsonb_build_object(
      'auxiliary', r.dkg_public_evidence -> 'auxiliary' -> 'request',
      'scope', jsonb_build_object('ownership_scope', r.ownership_scope, 'chain_id', r.chain_id,
      'purpose', r.purpose, 'wallet_class', r.wallet_class, 'derivation_version',
    r.derivation_version,
      'root_identity', r.root_identity))
     OR coalesce(original ->> 'chain_code', '') !~ '^[0-9a-f]{64}$'
     OR coalesce(original ->> 'extended_identity', '') !~ '^[0-9a-f]{64}$'
     OR jsonb_array_length(NEW.evidence -> 'participant_agreement') IS DISTINCT FROM 3 THEN
    RAISE EXCEPTION 'HD evidence does not bind original namespace';
  END IF;
  FOR i IN 0..2 LOOP
    party := (ARRAY['signer-a', 'signer-b', 'signer-c'])[i+1];
    receipt := NEW.evidence -> 'participant_agreement' -> i;
    IF receipt IS DISTINCT FROM jsonb_build_object('root', original, 'party_id', party,
    'durable', true) THEN
      RAISE EXCEPTION 'HD evidence lacks original three-store agreement';
    END IF;
  END LOOP;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER custody_hd_identity BEFORE INSERT OR UPDATE OR DELETE ON custody_mpchdrootevidence
FOR EACH ROW EXECUTE FUNCTION custody_hd_guard();

CREATE FUNCTION custody_mpc_account_guard() RETURNS trigger AS $$
DECLARE reservation custody_mpcderivationreservation%ROWTYPE;
DECLARE r custody_mpcprovisioningroot%ROWTYPE;
DECLARE h custody_mpchdrootevidence%ROWTYPE;
DECLARE child jsonb;
BEGIN
  IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'canonical account cannot be deleted/recycled'; END IF;
  IF TG_OP = 'UPDATE' THEN
    IF OLD.status = 'ISSUED' AND NEW IS DISTINCT FROM OLD THEN
      RAISE EXCEPTION 'issued account identity is immutable';
    END IF;
    IF (to_jsonb(NEW) - ARRAY['status','public_key','address','evidence']) IS DISTINCT FROM
       (to_jsonb(OLD) - ARRAY['status','public_key','address','evidence']) THEN
      RAISE EXCEPTION 'original issuance claim/ownership is immutable';
    END IF;
  END IF;
  SELECT * INTO STRICT reservation FROM custody_mpcderivationreservation WHERE reservation_id =
    NEW.reservation_id;
  SELECT * INTO STRICT r FROM custody_mpcprovisioningroot WHERE keyset_id = reservation.root_id;
  IF NEW.customer_ref <> reservation.customer_ref OR NEW.chain_id <> r.chain_id OR
    NEW.ownership_scope <> r.ownership_scope THEN
    RAISE EXCEPTION 'canonical account must preserve reservation ownership/network';
  END IF;
  IF NEW.status = 'PROVISIONING' THEN RETURN NEW; END IF;
  IF TG_OP = 'INSERT' THEN RAISE EXCEPTION 'durable original claim must precede issuance'; END IF;
  SELECT * INTO STRICT h FROM custody_mpchdrootevidence WHERE root_id = r.keyset_id;
  child := NEW.evidence -> 'child';
  IF child -> 'request' IS DISTINCT FROM jsonb_build_object('root', h.evidence -> 'root',
       'reservation_id', reservation.reservation_id::text, 'customer_ref', reservation.customer_ref,
       'idempotency_key', reservation.idempotency_key, 'child_index', reservation.child_index,
       'derivation_path', reservation.derivation_path)
     OR child ->> 'public_key' IS DISTINCT FROM NEW.public_key
     OR child ->> 'address' IS DISTINCT FROM NEW.address
     OR NEW.public_key = r.root_identity ->> 'public_key'
     OR NEW.public_key !~ '^(02|03)[0-9a-f]{64}$'
     OR jsonb_array_length(NEW.evidence -> 'participant_agreement') IS DISTINCT FROM 3 THEN
    RAISE EXCEPTION 'issuance lacks original verified child binding';
  END IF;
  FOR i IN 0..2 LOOP
    IF NEW.evidence -> 'participant_agreement' -> i IS DISTINCT FROM jsonb_build_object(
         'child', child, 'party_id', (ARRAY['signer-a','signer-b','signer-c'])[i+1], 'durable',
    true) THEN
      RAISE EXCEPTION 'issuance requires three independent ready-share approvals';
    END IF;
  END LOOP;
  IF (r.root_identity ->> 'scope' = 'EVM' AND NEW.address !~ '^0x[0-9a-f]{40}$')
     OR (r.root_identity ->> 'scope' = 'TRON' AND NEW.address !~ '^T[1-9A-HJ-NP-Za-km-z]{33}$') THEN
    RAISE EXCEPTION 'noncanonical child address';
  END IF;
  IF EXISTS (SELECT 1 FROM custody_userwallet w WHERE w.chain_id = NEW.chain_id
      AND (CASE WHEN r.root_identity ->> 'scope' = 'EVM' THEN lower(w.deposit_address) ELSE
    w.deposit_address END) = NEW.address
      AND w.custody_account_id IS DISTINCT FROM NEW.account_id) THEN
    RAISE EXCEPTION 'issued address conflicts with historical financial owner';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER custody_mpc_account_identity BEFORE INSERT OR UPDATE OR DELETE ON
    custody_mpccustodyaccount
FOR EACH ROW EXECUTE FUNCTION custody_mpc_account_guard();

CREATE FUNCTION custody_child_wallet_guard() RETURNS trigger AS $$
DECLARE a custody_mpccustodyaccount%ROWTYPE;
DECLARE reservation custody_mpcderivationreservation%ROWTYPE;
DECLARE keyset custody_mpckeyset%ROWTYPE;
DECLARE norm text;
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.custody_account_id IS NOT NULL THEN RAISE EXCEPTION 'issued asset view cannot be
    deleted'; END IF;
    RETURN OLD;
  END IF;
  IF TG_OP = 'UPDATE' AND OLD.custody_account_id IS NOT NULL AND
    (NEW.custody_account_id, NEW.user_id, NEW.chain_id, NEW.asset_key, NEW.deposit_address,
     NEW.derivation_path, NEW.derivation_version, NEW.mpc_keyset_id, NEW.address_index,
    NEW.memo) IS DISTINCT FROM
    (OLD.custody_account_id, OLD.user_id, OLD.chain_id, OLD.asset_key, OLD.deposit_address,
     OLD.derivation_path, OLD.derivation_version, OLD.mpc_keyset_id, OLD.address_index,
    OLD.memo) THEN
    RAISE EXCEPTION 'issued financial asset view is immutable';
  END IF;
  IF NEW.custody_account_id IS NULL THEN
    IF NEW.derivation_version = 'mpc_child_v1' OR EXISTS (SELECT 1 FROM custody_mpccustodyaccount c
       JOIN custody_mpcderivationreservation d ON d.reservation_id = c.reservation_id
       JOIN custody_mpckeyset k ON k.id = d.root_id
       WHERE c.status = 'ISSUED' AND c.chain_id = NEW.chain_id AND c.address =
       CASE WHEN k.scope = 'EVM' THEN lower(NEW.deposit_address) ELSE NEW.deposit_address END) THEN
      RAISE EXCEPTION 'child asset view requires canonical account ownership';
    END IF;
    RETURN NEW;
  END IF;
  SELECT * INTO STRICT a FROM custody_mpccustodyaccount WHERE account_id =
    NEW.custody_account_id FOR UPDATE;
  SELECT * INTO STRICT reservation FROM custody_mpcderivationreservation WHERE reservation_id =
    a.reservation_id;
  SELECT * INTO STRICT keyset FROM custody_mpckeyset WHERE id = reservation.root_id;
  norm := CASE WHEN keyset.scope = 'EVM' THEN lower(NEW.deposit_address) ELSE
    NEW.deposit_address END;
  IF a.status <> 'ISSUED' OR NEW.user_id <> a.customer_ref OR NEW.chain_id <> a.chain_id
     OR norm <> a.address OR NEW.derivation_path <> reservation.derivation_path
     OR NEW.derivation_version <> 'mpc_child_v1' OR NEW.mpc_keyset_id IS DISTINCT FROM keyset.id
     OR NEW.address_index <> 0 OR NEW.memo IS NOT NULL
     OR NOT EXISTS (SELECT 1 FROM custody_asset WHERE asset_key = NEW.asset_key AND chain_id =
    a.chain_id) THEN
    RAISE EXCEPTION 'child asset view must preserve approved account/path/asset';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER custody_child_wallet_identity BEFORE INSERT OR UPDATE OR DELETE ON custody_userwallet
FOR EACH ROW EXECUTE FUNCTION custody_child_wallet_guard();
"""

REVERSE = """
DROP TRIGGER custody_child_wallet_identity ON custody_userwallet;
DROP FUNCTION custody_child_wallet_guard();
DROP TRIGGER custody_mpc_account_identity ON custody_mpccustodyaccount;
DROP FUNCTION custody_mpc_account_guard();
DROP TRIGGER custody_hd_identity ON custody_mpchdrootevidence;
DROP FUNCTION custody_hd_guard();
"""


def install(apps, schema_editor):
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(FORWARD, params=None)


def uninstall(apps, schema_editor):
    if (
        apps.get_model("custody", "MpcHdRootEvidence").objects.exists()
        or apps.get_model("custody", "MpcCustodyAccount").objects.exists()
    ):
        raise RuntimeError("cannot downgrade original HD/account evidence")
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(REVERSE, params=None)


class Migration(migrations.Migration):
    dependencies = [("custody", "0029_mpchdrootevidence_mpccustodyaccount_and_more")]
    operations = [migrations.RunPython(install, uninstall)]
