from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from custody.models import HotWallet, MpcKeyset
from custody.mpc_identity import address_from_public_key


class Command(BaseCommand):
    help = "Bind a hot wallet to an MPC keyset after local address verification"

    def add_arguments(self, parser):
        parser.add_argument("--chain", required=True)
        parser.add_argument("--keyset-id", required=True)
        parser.add_argument("--derivation-reference", default="")

    def handle(self, *args, **options):
        with transaction.atomic():
            wallet = HotWallet.objects.select_for_update().get(chain_id=options["chain"])
            keyset = MpcKeyset.objects.get(keyset_id=options["keyset_id"], status="ACTIVE")
            if options["derivation_reference"]:
                raise CommandError(
                    "child public-key derivation evidence is required; root key cannot be rebound"
                )
            expected = address_from_public_key(wallet.chain_id, keyset.public_key)
            if expected.lower() != wallet.address.lower():
                raise CommandError("MPC public key does not control configured hot-wallet address")
            wallet.mpc_keyset = keyset
            wallet.signing_key_ref = f"keyset:{keyset.keyset_id}"
            wallet.save(update_fields=["mpc_keyset", "signing_key_ref"])
            self.stdout.write(f"bound {wallet.chain_id} to {keyset.keyset_id}")
