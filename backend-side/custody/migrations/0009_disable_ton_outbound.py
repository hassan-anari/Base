from django.db import migrations


def disable_builtin_ton(apps, schema_editor):
    Asset = apps.get_model("custody", "Asset")
    Asset.objects.filter(asset_key="TON", chain_id="TON", is_native=True).update(
        deposit_supported=False,
        withdrawal_supported=False,
        sweep_supported=False,
    )


class Migration(migrations.Migration):
    dependencies = [("custody", "0008_native_transaction_lifecycle")]
    operations = [migrations.RunPython(disable_builtin_ton, migrations.RunPython.noop)]
