from django.core.management.base import BaseCommand

from custody.models import MpcSigningSession
from custody.outbound import execute_attempt


class Command(BaseCommand):
    help = "Advance recoverable self-hosted MPC signing sessions"

    def add_arguments(self, parser):
        parser.add_argument("--attempt-id", type=int)

    def handle(self, *args, **options):
        query = MpcSigningSession.objects.filter(
            status__in=[
                "CREATED",
                "STARTING",
                "IN_PROGRESS",
                "COMPLETED",
                "RECONCILIATION_REQUIRED",
            ]
        )
        if options["attempt_id"]:
            query = query.filter(attempt_id=options["attempt_id"])
        for attempt_id in query.values_list("attempt_id", flat=True).iterator():
            try:
                execute_attempt(attempt_id, "system:mpc_advancement")
            except Exception as exc:
                self.stderr.write(f"attempt {attempt_id}: {type(exc).__name__}")
