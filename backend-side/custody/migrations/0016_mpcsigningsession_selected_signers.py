from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("custody", "0015_mpcsigningsession_signature_consumed_at")]

    operations = [
        migrations.AddField(
            model_name="mpcsigningsession",
            name="selected_signers",
            field=models.JSONField(blank=True, default=list),
        )
    ]
