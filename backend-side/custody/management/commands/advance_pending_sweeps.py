from django.core.management.base import BaseCommand

from custody.sweeper import advance_pending_sweeps


class Command(BaseCommand):
    help = "Idempotently advance token sweeps waiting for gas or execution"

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=100)

    def handle(self, *args, **options):
        jobs = advance_pending_sweeps(limit=options["limit"])
        self.stdout.write(self.style.SUCCESS(f"advanced {len(jobs)} token sweep(s)"))
