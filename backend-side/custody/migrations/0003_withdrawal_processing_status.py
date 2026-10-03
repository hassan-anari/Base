from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("custody", "0002_indexer_scan_fields")]

    operations = [
        migrations.AlterField(
            model_name="withdrawalrequest",
            name="status",
            field=models.CharField(
                choices=[
                    ("PENDING_APPROVAL", "PENDING_APPROVAL"),
                    ("APPROVED", "APPROVED"),
                    ("PROCESSING", "PROCESSING"),
                    ("DENIED", "DENIED"),
                    ("BROADCASTED", "BROADCASTED"),
                    ("CONFIRMED", "CONFIRMED"),
                    ("FAILED", "FAILED"),
                ],
                default="PENDING_APPROVAL",
                max_length=16,
            ),
        ),
    ]
