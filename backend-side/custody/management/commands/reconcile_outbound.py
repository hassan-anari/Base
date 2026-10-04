from django.core.management.base import BaseCommand

from custody.reconciliation import reconcile_pending_attempts


class Command(BaseCommand):
    help = "Reconcile pending native outbound transaction attempts"

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=100)

    def handle(self, *args, **options):
        attempts = reconcile_pending_attempts(limit=options["limit"])
        self.stdout.write(self.style.SUCCESS(f"reconciled {len(attempts)} attempts"))
