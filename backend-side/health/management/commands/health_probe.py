"""Management command: run system-health probes (unattended).

Use cases:
  * Cron / systemd timer:    python manage.py health_probe
  * External monitor gate:   python manage.py health_probe --fail-on-down
                             (exit code 1 when aggregate == DOWN)
  * CI smoke:                python manage.py health_probe --no-persist

Persists results to SystemHealthProbe and (on DOWN/DEGRADED) raises an ops
alert so the console surfaces it.
"""
from __future__ import annotations

import json
import sys

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Run system-health probes and persist results."

    def add_arguments(self, parser):
        parser.add_argument("--no-persist", action="store_true",
                            help="Run probes but do not write DB rows.")
        parser.add_argument("--fail-on-down", action="store_true",
                            help="Exit with code 1 if aggregate status is DOWN.")

    def handle(self, *args, **options):
        from health import services as H
        data = H.run_probes(persist=not options["no_persist"])
        self.stdout.write(json.dumps(data, indent=2, default=str))

        if options["fail_on_down"] and data["status"] == "DOWN":
            sys.exit(1)