"""Operate public MPC keyset metadata. This command never handles or prints shares."""

import uuid

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from custody.models import MpcKeyset


class Command(BaseCommand):
    help = "Create, inspect, activate, or retire public MPC keyset metadata"

    def add_arguments(self, parser):
        parser.add_argument("action", choices=["create", "inspect", "activate", "retire"])
        parser.add_argument("--keyset-id")
        parser.add_argument("--algorithm", choices=["CGGMP24_ECDSA", "FROST_ED25519"])
        parser.add_argument("--scope", choices=["EVM", "TRON", "SOLANA"])
        parser.add_argument("--threshold", type=int, default=2)
        parser.add_argument("--parties", type=int, default=3)

    def handle(self, *args, **options):
        action = options["action"]
        if action == "create":
            if not options["algorithm"] or not options["scope"]:
                raise CommandError("--algorithm and --scope are required")
            keyset = MpcKeyset.objects.create(
                keyset_id=uuid.uuid4(),
                algorithm=options["algorithm"],
                scope=options["scope"],
                curve="secp256k1" if options["algorithm"] == "CGGMP24_ECDSA" else "ed25519",
                threshold=options["threshold"],
                party_count=options["parties"],
            )
            self.stdout.write(str(keyset.keyset_id))
            return
        if not options["keyset_id"]:
            raise CommandError("--keyset-id is required")
        keyset = MpcKeyset.objects.get(keyset_id=options["keyset_id"])
        if action == "inspect":
            self.stdout.write(
                f"{keyset.keyset_id} {keyset.algorithm} "
                f"{keyset.threshold}-of-{keyset.party_count} {keyset.status}"
            )
        elif action == "activate":
            if not all(
                [
                    keyset.public_key,
                    keyset.dkg_execution_id,
                    keyset.dkg_result_fingerprint,
                    len(keyset.participant_identities) == keyset.party_count,
                ]
            ):
                raise CommandError(
                    "activation requires an imported, verified coordinator DKG result"
                )
            with transaction.atomic():
                MpcKeyset.objects.select_for_update().filter(
                    algorithm=keyset.algorithm, active_for_new_wallets=True
                ).update(active_for_new_wallets=False)
                keyset.status = "ACTIVE"
                keyset.active_for_new_wallets = True
                keyset.full_clean()
                keyset.save()
        else:
            keyset.status = "RETIRED"
            keyset.active_for_new_wallets = False
            keyset.retired_at = timezone.now()
            keyset.save()
