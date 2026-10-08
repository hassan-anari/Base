from django.core.management.base import BaseCommand

from custody.models import MpcSigningSession
from custody.mpc_signing import advance_mpc_signing


class Command(BaseCommand):
    help = "Advance recoverable self-hosted MPC signing sessions"

    def add_arguments(self, parser):
        parser.add_argument("--attempt-id", type=int)

    def handle(self, *args, **options):
        query = MpcSigningSession.objects.filter(status__in=["CREATED", "STARTING", "IN_PROGRESS"])
        if options["attempt_id"]:
            query = query.filter(attempt_id=options["attempt_id"])
        for attempt_id in query.values_list("attempt_id", flat=True).iterator():
            try:
                advance_mpc_signing(attempt_id)
            except Exception as exc:
                self.stderr.write(f"attempt {attempt_id}: {type(exc).__name__}: {exc}")
