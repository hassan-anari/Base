"""Freeze existing financial identities without rewriting balances or journals.

Account insertion and registry mutation lock the same asset row. A stale ORM
instance, bulk update or concurrent admin request cannot bypass the boundary.
MPC execution already requires PostgreSQL; SQLite is not acceptance evidence.
"""

from django.db import migrations, models

FORWARD = """
UPDATE custody_asset SET financial_identity_locked = TRUE
WHERE asset_key IN (SELECT asset_key FROM custody_ledgeraccount);

CREATE FUNCTION custody_freeze_financial_identity() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF EXISTS (SELECT 1 FROM custody_ledgeraccount WHERE asset_key = NEW.asset_key) THEN
      RAISE EXCEPTION 'asset financial identity cannot adopt existing orphan accounts';
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.financial_identity_locked THEN
    IF TG_OP = 'DELETE' THEN
      RAISE EXCEPTION 'asset financial identity cannot be deleted';
    END IF;
    IF NOT NEW.financial_identity_locked OR
       ROW(NEW.asset_key, NEW.chain_id, NEW.is_native, NEW.contract_address,
           NEW.token_standard, NEW.decimals) IS DISTINCT FROM
       ROW(OLD.asset_key, OLD.chain_id, OLD.is_native, OLD.contract_address,
           OLD.token_standard, OLD.decimals) THEN
      RAISE EXCEPTION 'asset financial identity is immutable after account creation';
    END IF;
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER custody_asset_identity BEFORE INSERT OR UPDATE OR DELETE ON custody_asset
FOR EACH ROW EXECUTE FUNCTION custody_freeze_financial_identity();

CREATE FUNCTION custody_lock_account_asset() RETURNS trigger AS $$
BEGIN
  -- UPDATE acquires the row lock even if another account already froze it.
  UPDATE custody_asset SET financial_identity_locked = TRUE WHERE asset_key = NEW.asset_key;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ledger account requires a registered asset financial identity'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER custody_account_asset BEFORE INSERT ON custody_ledgeraccount
FOR EACH ROW EXECUTE FUNCTION custody_lock_account_asset();

CREATE FUNCTION custody_immutable_ton_binding() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' OR NEW IS DISTINCT FROM OLD THEN
    RAISE EXCEPTION 'TON original root network binding is immutable';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER custody_ton_binding_identity BEFORE UPDATE OR DELETE ON custody_tonwalletbinding
FOR EACH ROW EXECUTE FUNCTION custody_immutable_ton_binding();

CREATE FUNCTION custody_immutable_root_network() RETURNS trigger AS $$
DECLARE binding RECORD;
BEGIN
  IF OLD.network_bindings <> '{}'::jsonb THEN
    IF TG_OP = 'DELETE' THEN
      RAISE EXCEPTION 'original root network binding cannot be deleted';
    END IF;
    IF ROW(NEW.keyset_id, NEW.scope, NEW.algorithm, NEW.curve, NEW.public_key,
           NEW.dkg_execution_id, NEW.dkg_result_fingerprint, NEW.derivation_version,
           NEW.threshold, NEW.party_count, NEW.participant_identities, NEW.dkg_public_evidence)
       IS DISTINCT FROM
       ROW(OLD.keyset_id, OLD.scope, OLD.algorithm, OLD.curve, OLD.public_key,
           OLD.dkg_execution_id, OLD.dkg_result_fingerprint, OLD.derivation_version,
           OLD.threshold, OLD.party_count, OLD.participant_identities, OLD.dkg_public_evidence) THEN
      RAISE EXCEPTION 'original root network/DKG identity is immutable';
    END IF;
    FOR binding IN SELECT * FROM jsonb_each(OLD.network_bindings) LOOP
      IF NEW.network_bindings -> binding.key IS DISTINCT FROM binding.value THEN
        RAISE EXCEPTION 'original root network binding cannot be replaced';
      END IF;
    END LOOP;
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER custody_root_network_identity BEFORE UPDATE OR DELETE ON custody_mpckeyset
FOR EACH ROW EXECUTE FUNCTION custody_immutable_root_network();
"""

REVERSE = """
DROP TRIGGER custody_root_network_identity ON custody_mpckeyset;
DROP FUNCTION custody_immutable_root_network();
DROP TRIGGER custody_ton_binding_identity ON custody_tonwalletbinding;
DROP FUNCTION custody_immutable_ton_binding();
DROP TRIGGER custody_account_asset ON custody_ledgeraccount;
DROP FUNCTION custody_lock_account_asset();
DROP TRIGGER custody_asset_identity ON custody_asset;
DROP FUNCTION custody_freeze_financial_identity();
"""


def install(apps, schema_editor):
    if schema_editor.connection.vendor == "postgresql":
        keysets = apps.get_model("custody", "MpcKeyset")
        sessions = apps.get_model("custody", "MpcSigningSession")
        bindings = apps.get_model("custody", "TonWalletBinding")
        for keyset in keysets.objects.all():
            pins = {}

            def pin(chain, network):
                identity = {
                    "scope": keyset.scope,
                    "algorithm": keyset.algorithm,
                    "public_key": keyset.public_key,
                    "dkg_execution_id": str(keyset.dkg_execution_id),
                    "dkg_fingerprint": keyset.dkg_result_fingerprint,
                    "network": network,
                }
                if chain in pins and pins[chain] != identity:
                    raise ValueError("conflicting original root network evidence; reconcile first")
                pins[chain] = identity

            for session in sessions.objects.filter(keyset=keyset):
                identity = session.transaction_identity
                chain = identity.get("chain", session.attempt.chain_id)
                if keyset.scope == "EVM" and identity.get("evm_chain_id"):
                    network = identity.get("network") or {"evm_chain_id": identity["evm_chain_id"]}
                else:
                    network = identity.get("network") or identity.get("fees", {}).get("network")
                if network:
                    if (
                        identity.get("public_key", keyset.public_key) != keyset.public_key
                        or identity.get("dkg_fingerprint") != keyset.dkg_result_fingerprint
                    ):
                        raise ValueError("conflicting original DKG evidence; reconcile first")
                    pin(chain, network)
                else:
                    pins.setdefault(chain, {"legacy_unverified": True})
            for binding in bindings.objects.filter(keyset=keyset):
                pin(binding.chain_id, binding.network_identity)
            for model in ("HotWallet", "UserWallet"):
                for chain in (
                    apps.get_model("custody", model)
                    .objects.filter(mpc_keyset=keyset)
                    .values_list("chain_id", flat=True)
                ):
                    pins.setdefault(chain, {"legacy_unverified": True})
            keysets.objects.filter(pk=keyset.pk).update(network_bindings=pins)
        schema_editor.execute(FORWARD)


def uninstall(apps, schema_editor):
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(REVERSE)


class Migration(migrations.Migration):
    dependencies = [("custody", "0023_ton_funding_costs")]
    operations = [
        migrations.AddField(
            model_name="asset",
            name="financial_identity_locked",
            field=models.BooleanField(default=False, editable=False),
        ),
        migrations.AddField(
            model_name="mpckeyset",
            name="network_bindings",
            field=models.JSONField(default=dict, blank=True, editable=False),
        ),
        migrations.AddConstraint(
            model_name="tonwalletbinding",
            constraint=models.UniqueConstraint(
                fields=["keyset"], name="uq_ton_keyset_network_binding"
            ),
        ),
        migrations.RunPython(install, uninstall),
    ]
