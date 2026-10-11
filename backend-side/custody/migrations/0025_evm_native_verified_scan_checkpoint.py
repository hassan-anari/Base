from django.db import migrations, models


def reset_unverified_native_cursors(apps, schema_editor):
    # The former recent-window scanner reported head even after partial failure.
    # Rebuild native EVM history; retain deposits/journals for exactly-once replay.
    db = schema_editor.connection.alias
    chains = apps.get_model("ops", "Chain").objects.using(db).filter(kind="evm")
    assets = apps.get_model("custody", "Asset").objects.using(db).filter(is_native=True)
    apps.get_model("custody", "UserWallet").objects.using(db).filter(
        chain_id__in=chains.values("chain_id"), asset_key__in=assets.values("asset_key")
    ).update(last_scanned_block=None, last_scanned_at=None, evm_scan_block_hash=None)


class Migration(migrations.Migration):
    dependencies = [("custody", "0024_financial_identity_and_ton_binding")]

    operations = [
        migrations.AddField(
            model_name="userwallet",
            name="evm_scan_block_hash",
            field=models.CharField(blank=True, max_length=66, null=True),
        ),
        migrations.RunPython(reset_unverified_native_cursors, migrations.RunPython.noop),
    ]
