from django.apps import AppConfig
from django.db.models.signals import post_migrate


class CustodyConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "custody"
    label = "custody"

    def ready(self):
        # Seed config-registry data (assets + hot wallets) once migrations
        # have created the tables. Idempotent (upsert by unique key).
        from . import config
        from .models import Asset, HotWallet

        def _seed(sender, **kwargs):
            for ak, a in config.get_assets().items():
                Asset.objects.update_or_create(
                    asset_key=ak,
                    defaults={
                        "chain_id": a.chain_id,
                        "symbol": a.symbol,
                        "is_native": a.is_native,
                        "contract_address": a.contract_address or "",
                        "decimals": a.decimals,
                        "deposit_threshold": config.effective_deposit_threshold(a),
                        "enabled": a.enabled,
                    },
                )
            for cid, c in config.get_chains().items():
                HotWallet.objects.update_or_create(
                    chain_id=cid,
                    defaults={"address": c.hot_wallet_address or ""},
                )

        post_migrate.connect(_seed, sender=self)
