from django.apps import AppConfig
from django.db.models.signals import post_migrate


class CustodyConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "custody"
    label = "custody"

    def ready(self):
        # Seed config-registry data (assets + hot wallets) once migrations
        # have created the tables. Idempotent (upsert by unique key).
        from . import (
            checks,  # noqa: F401 - register deployment safety checks
            config,
        )
        from .models import Asset, HotWallet

        def _seed(sender, **kwargs):
            for ak, a in config.DEFAULT_ASSETS.items():
                Asset.objects.get_or_create(
                    asset_key=ak,
                    defaults={
                        "chain_id": a.chain_id,
                        "symbol": a.symbol,
                        "is_native": a.is_native,
                        "contract_address": a.contract_address or "",
                        "decimals": a.decimals,
                        "deposit_threshold": (
                            a.deposit_threshold
                            if a.deposit_threshold is not None
                            else config.DEFAULT_CHAINS[a.chain_id].deposit_threshold
                        ),
                        "enabled": a.enabled,
                        "deposit_supported": a.deposit_supported,
                        "withdrawal_supported": a.withdrawal_supported,
                        "sweep_supported": a.sweep_supported,
                    },
                )
            for cid, c in config.DEFAULT_CHAINS.items():
                HotWallet.objects.get_or_create(
                    chain_id=cid,
                    defaults={"address": c.hot_wallet_address or ""},
                )

        post_migrate.connect(
            _seed, sender=self, weak=False, dispatch_uid="custody.seed_runtime_config"
        )
