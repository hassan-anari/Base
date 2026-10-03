from django.apps import AppConfig
from django.db.models.signals import post_migrate


class OpsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "ops"
    verbose_name = "Wallet Operations"

    def ready(self) -> None:
        # Seed the ops registry (chains/assets/nodes) ONLY after migrations
        # have created the tables. Doing it directly in `ready()` would query
        # non-existent tables during `migrate` and crash startup on a fresh DB.
        def _seed(sender, **kwargs):
            from . import services as S

            try:
                S.seed_defaults()
            except Exception:  # pragma: no cover - never crash startup on seed
                import logging

                logging.getLogger("ops").warning("ops seed_defaults skipped", exc_info=True)

        post_migrate.connect(
            _seed, sender=self, weak=False, dispatch_uid="ops.seed_bootstrap_registry"
        )
