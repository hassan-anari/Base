import ops.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("ops", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="Blocklist",
            fields=[
                ("id", models.CharField(default=ops.models._new_id, editable=False, max_length=24, primary_key=True, serialize=False)),
                ("scope", models.CharField(choices=[("DEPOSIT_ADDRESS", "Deposit Address"), ("WITHDRAW_ADDRESS", "Withdrawal Address"), ("CHAIN_ASSET", "Chain+Asset")], max_length=20)),
                ("value", models.CharField(default="-", max_length=64)),
                ("chain_id", models.CharField(blank=True, default="", max_length=16)),
                ("asset_key", models.CharField(blank=True, default="", max_length=32)),
                ("reason", models.CharField(choices=[("compliance", "Compliance"), ("sanctions", "Sanctions"), ("scam", "Scam/Phishing"), ("manual", "Manual"), ("dust", "Dust/Spam")], default="compliance", max_length=32)),
                ("note", models.TextField(blank=True, default="")),
                ("enabled", models.BooleanField(default=True)),
                ("created_by", models.CharField(blank=True, default="", max_length=64)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={
                "ordering": ["-created_at"],
                "indexes": [models.Index(fields=["scope", "value", "enabled"], name="ops_blockl_scope_b7c6db_idx"), models.Index(fields=["scope", "chain_id", "asset_key", "enabled"], name="ops_blockl_scope_b0b0b0_idx")],
            },
        ),
    ]