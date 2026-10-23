"""Read-only audit: unverifiable records stay immutable and operationally quarantined."""

import json

from django.core.management.base import BaseCommand, CommandError

from custody.models import MpcCustodyAccount, MpcHdRootEvidence
from custody.mpc_binding import MpcBindingError
from custody.mpc_hd import verify_hd_evidence
from custody.mpc_issuance import verified_account


class Command(BaseCommand):
    help = (
        "Audit independent signer evidence; never repair or expose unverifiable deposit addresses"
    )

    def handle(self, *args, **options):
        failed = []
        roots = 0
        accounts = 0
        for hd in MpcHdRootEvidence.objects.select_related("root__keyset").iterator():
            roots += 1
            try:
                verify_hd_evidence(hd.root, hd.evidence)
            except (MpcBindingError, ValueError, OSError) as error:
                failed.append({"kind": "root", "id": str(hd.root_id), "reason": str(error)})
        for account in MpcCustodyAccount.objects.filter(status="ISSUED").iterator():
            accounts += 1
            try:
                verified_account(account)
            except (MpcBindingError, ValueError, OSError) as error:
                failed.append({"kind": "account", "id": str(account.pk), "reason": str(error)})
        self.stdout.write(
            json.dumps(
                {"roots": roots, "issued_accounts": accounts, "quarantine_required": failed},
                sort_keys=True,
            )
        )
        if failed:
            raise CommandError(
                "Unverifiable custody evidence: freeze publication/funding; "
                "preserve records for independent reconciliation"
            )
