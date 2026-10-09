from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("custody", "0016_mpcsigningsession_selected_signers")]
    operations = [
        migrations.AddField(
            model_name="mpcsigningsession",
            name="transaction_identity",
            field=models.JSONField(default=dict, blank=True),
        ),
    ]
