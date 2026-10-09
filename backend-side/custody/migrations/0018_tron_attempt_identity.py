from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("custody", "0017_mpc_transaction_identity")]
    operations = [
        migrations.AddConstraint(
            model_name="onchaintransactionattempt",
            constraint=models.UniqueConstraint(
                fields=("chain_id", "network_tx_id"),
                condition=models.Q(chain_id="TRX", network_tx_id__isnull=False),
                name="uq_tron_attempt_txid",
            ),
        )
    ]
