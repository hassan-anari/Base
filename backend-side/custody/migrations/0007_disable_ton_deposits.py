from django.db import migrations


def disable_ton_deposits(apps, schema_editor):
    Asset = apps.get_model("custody", "Asset")
    Asset.objects.filter(asset_key="TON", chain_id="TON", is_native=True).update(
        deposit_supported=False
    )


class Migration(migrations.Migration):
    dependencies = [("custody", "0006_ledgeraccount_ledger_account_valid_shape")]
    operations = [migrations.RunPython(disable_ton_deposits, migrations.RunPython.noop)]
