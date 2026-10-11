from django.db import migrations, models

SQL = """
CREATE FUNCTION custody_original_request_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.custody_authorization <> '{}'::jsonb THEN
      RAISE EXCEPTION 'original custody signing authorization cannot be deleted';
    END IF;
    RETURN OLD;
  END IF;
  IF OLD.custody_authorization = '{}'::jsonb AND NEW.custody_authorization <> '{}'::jsonb AND
     (OLD.status <> 'CREATED' OR OLD.crypto_execution_id IS NOT NULL OR
      OLD.signature_consumed_at IS NOT NULL) THEN
    RAISE EXCEPTION 'cannot authorize an already-started execution retrospectively';
  END IF;
  IF OLD.custody_authorization <> '{}'::jsonb AND
     NEW.custody_authorization IS DISTINCT FROM OLD.custody_authorization THEN
    RAISE EXCEPTION 'original custody signing authorization is immutable';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER custody_original_request BEFORE UPDATE OR DELETE ON custody_mpcsigningsession
FOR EACH ROW EXECUTE FUNCTION custody_original_request_guard();

CREATE FUNCTION custody_dedicated_root_binding_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.mpc_keyset_id IS NULL THEN RETURN NEW; END IF;
  IF TG_TABLE_NAME = 'custody_userwallet' AND
     (to_jsonb(NEW) ->> 'custody_account_id') IS NOT NULL THEN RETURN NEW; END IF;
  IF TG_OP = 'UPDATE' AND OLD.mpc_keyset_id IS NOT DISTINCT FROM NEW.mpc_keyset_id THEN
    RETURN NEW;
  END IF;
  IF current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'root binding publication requires READ COMMITTED';
  END IF;
  PERFORM 1 FROM custody_mpckeyset WHERE id = NEW.mpc_keyset_id FOR UPDATE;
  IF EXISTS (SELECT 1 FROM custody_mpcprovisioningroot WHERE keyset_id = NEW.mpc_keyset_id) THEN
    RAISE EXCEPTION 'dedicated DEPOSIT namespace cannot bind a new root-only wallet';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER custody_dedicated_user_root BEFORE INSERT OR UPDATE ON custody_userwallet
FOR EACH ROW EXECUTE FUNCTION custody_dedicated_root_binding_guard();
CREATE TRIGGER custody_dedicated_hot_root BEFORE INSERT OR UPDATE ON custody_hotwallet
FOR EACH ROW EXECUTE FUNCTION custody_dedicated_root_binding_guard();
"""


def install(apps, schema_editor):
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(SQL, params=None)


def uninstall(apps, schema_editor):
    if (
        apps.get_model("custody", "MpcSigningSession")
        .objects.exclude(custody_authorization={})
        .exists()
    ):
        raise RuntimeError("cannot downgrade original custody authorization evidence")
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(
            "DROP TRIGGER custody_dedicated_user_root ON custody_userwallet; "
            "DROP TRIGGER custody_dedicated_hot_root ON custody_hotwallet; "
            "DROP FUNCTION custody_dedicated_root_binding_guard(); "
            "DROP TRIGGER custody_original_request ON custody_mpcsigningsession; "
            "DROP FUNCTION custody_original_request_guard();",
            params=None,
        )


class Migration(migrations.Migration):
    dependencies = [("custody", "0030_mpc_child_ownership_guards")]
    operations = [
        migrations.AddField(
            model_name="mpcsigningsession",
            name="custody_authorization",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.RunPython(install, uninstall),
    ]
