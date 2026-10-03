"""
Management command to run the indexer service (background deposit scanner).

Usage:
    python manage.py run_indexer                    # scan all networks, 30s interval
    python manage.py run_indexer --interval 10      # 10s interval
    python manage.py run_indexer --networks ETH BSC # only specific networks
    python manage.py run_indexer --once             # single scan, then exit

In production, run this as a systemd service or Celery beat task:
    [Service]
    ExecStart=/path/to/venv/bin/python manage.py run_indexer
    Restart=always
"""
from django.core.management.base import BaseCommand

from custody.indexer_service import run_indexer_loop, scan_all_wallets


class Command(BaseCommand):
    help = "Run the indexer service (background deposit scanner)"

    def add_arguments(self, parser):
        parser.add_argument(
            "--interval", type=int, default=30,
            help="Scan interval in seconds (default: 30)",
        )
        parser.add_argument(
            "--networks", nargs="*", default=None,
            help="Only scan these networks (e.g. ETH BSC). Default: all",
        )
        parser.add_argument(
            "--once", action="store_true",
            help="Run a single scan and exit (useful for cron/testing)",
        )

    def handle(self, *args, **options):
        interval = options["interval"]
        networks = options["networks"]
        once = options["once"]

        if once:
            self.stdout.write(f"Running single indexer scan (networks={networks or 'all'})...")
            results = scan_all_wallets(networks)
            sweeps = [r for r in results if r["sweep_triggered"]]
            deposits = sum(r["new_deposits"] for r in results)
            self.stdout.write(self.style.SUCCESS(
                f"Scan complete: {len(results)} wallets, "
                f"{deposits} new deposits, {len(sweeps)} sweeps triggered"
            ))
            for r in results:
                if r["new_deposits"] or r["sweep_triggered"]:
                    self.stdout.write(
                        f"  wallet={r['wallet_id']} addr={r['address'][:16]}... "
                        f"balance={r['confirmed_balance']} "
                        f"deposits={r['new_deposits']} "
                        f"sweep={'YES job=' + str(r['sweep_job_id']) if r['sweep_triggered'] else 'no'} "
                        f"({r['reason']})"
                    )
        else:
            self.stdout.write(
                f"Starting indexer service (interval={interval}s, networks={networks or 'all'})"
            )
            self.stdout.write("Press Ctrl+C to stop.")
            try:
                run_indexer_loop(interval_seconds=interval, networks=networks)
            except KeyboardInterrupt:
                self.stdout.write(self.style.WARNING("\nIndexer service stopped."))