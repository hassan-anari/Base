from django.db import migrations


def reset_unverified_token_cursors(apps, schema_editor):
    # Old ERC-20 cursors represented head, not complete finalized history.
    # Reconcile from genesis without changing credited deposits or journals.
    db = schema_editor.connection.alias
    chains = apps.get_model("ops", "Chain").objects.using(db).filter(kind="evm")
    assets = apps.get_model("custody", "Asset").objects.using(db).filter(is_native=False)
    apps.get_model("custody", "UserWallet").objects.using(db).filter(
        chain_id__in=chains.values("chain_id"), asset_key__in=assets.values("asset_key")
    ).update(last_scanned_block=None, last_scanned_at=None, evm_scan_block_hash=None)


class Migration(migrations.Migration):
    dependencies = [("custody", "0025_evm_native_verified_scan_checkpoint")]

    operations = [
        migrations.RunPython(reset_unverified_token_cursors, migrations.RunPython.noop),
    ]
