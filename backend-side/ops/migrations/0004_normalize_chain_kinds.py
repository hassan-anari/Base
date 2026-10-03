from django.db import migrations, models


def normalize_kinds(apps, schema_editor):
    Chain = apps.get_model("ops", "Chain")
    mapping = {"EVM": "evm", "TRON": "tron", "SOLANA": "solana", "TON": "ton"}
    for old, new in mapping.items():
        Chain.objects.filter(kind=old).update(kind=new)


class Migration(migrations.Migration):
    dependencies = [
        ("ops", "0003_rename_ops_blockl_scope_b7c6db_idx_ops_blockli_scope_f8b99c_idx_and_more")
    ]
    operations = [
        migrations.RunPython(normalize_kinds, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="chain",
            name="kind",
            field=models.CharField(
                choices=[("evm", "EVM"), ("ton", "TON"), ("tron", "Tron"), ("solana", "Solana")],
                default="evm",
                max_length=16,
            ),
        ),
    ]
