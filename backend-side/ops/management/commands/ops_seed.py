"""Django management command: seed the ops chain/asset/node registry.

Idempotent: safe to run repeatedly (uses update_or_create).
Usage:
    python manage.py ops_seed
"""
from __future__ import annotations

from django.core.management.base import BaseCommand

from ops import services as ops_services


class Command(BaseCommand):
    help = "Seed built-in chains/assets/nodes into the ops registry."

    def handle(self, *args, **options):
        ops_services.seed_defaults()
        self.stdout.write(
            self.style.SUCCESS("ops registry seeded (chains/assets/nodes).")
        )