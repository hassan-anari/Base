from django.core.management.base import BaseCommand, CommandError

from custody.token_metadata import TokenVerificationError, verify_token_asset


class Command(BaseCommand):
    help = "Verify a disabled reviewed token asset against runtime RPC endpoints"

    def add_arguments(self, parser):
        parser.add_argument("asset_key")

    def handle(self, *args, **options):
        try:
            asset = verify_token_asset(options["asset_key"])
        except TokenVerificationError as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(
            self.style.SUCCESS(
                f"verified {asset.asset_key} {asset.token_standard} {asset.contract_address} "
                f"fingerprint={asset.metadata_fingerprint}; capabilities unchanged"
            )
        )
