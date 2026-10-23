"""Explicit internal HD attestation and customer account issuance, never activation."""

from django.core.management.base import BaseCommand

from custody.mpc_issuance import attach_account_asset, attest_original_hd, issue_customer_account


class Command(BaseCommand):
    help = "Attest original HD stores or issue an approved EVM/TRON customer account"

    def add_arguments(self, parser):
        parser.add_argument("action", choices=["attest", "issue"])
        parser.add_argument("--keyset-id", required=True)
        parser.add_argument("--ownership-scope", required=True)
        parser.add_argument("--customer-ref")
        parser.add_argument("--idempotency-key")
        parser.add_argument("--asset-key", action="append", default=[])

    def handle(self, *args, **options):
        if options["action"] == "attest":
            result = attest_original_hd(
                keyset_id=options["keyset_id"], ownership_scope=options["ownership_scope"]
            )
            self.stdout.write(result.evidence["root"]["extended_identity"])
            return
        account = issue_customer_account(
            keyset_id=options["keyset_id"],
            ownership_scope=options["ownership_scope"],
            customer_ref=options["customer_ref"],
            idempotency_key=options["idempotency_key"],
        )
        for asset in options["asset_key"]:
            attach_account_asset(
                account_id=account.pk,
                customer_ref=options["customer_ref"],
                ownership_scope=options["ownership_scope"],
                asset_key=asset,
            )
        self.stdout.write(f"{account.pk} {account.address}")
