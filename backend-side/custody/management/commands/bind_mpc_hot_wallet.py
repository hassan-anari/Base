from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from custody.chain_registry import ChainKind, get_chain_spec
from custody.models import HotWallet, MpcKeyset, UserWallet
from custody.mpc_identity import address_from_public_key


class Command(BaseCommand):
    help = "Bind a hot wallet to an MPC keyset after local address verification"

    def add_arguments(self, parser):
        parser.add_argument("--chain", required=True)
        parser.add_argument("--keyset-id", required=True)
        parser.add_argument("--derivation-reference", default="")
        parser.add_argument("--user-wallet-id", type=int)

    def handle(self, *args, **options):
        with transaction.atomic():
            wallet = (
                UserWallet.objects.select_for_update().get(
                    pk=options["user_wallet_id"], chain_id=options["chain"]
                )
                if options["user_wallet_id"]
                else HotWallet.objects.select_for_update().get(chain_id=options["chain"])
            )
            keyset = MpcKeyset.objects.get(keyset_id=options["keyset_id"], status="ACTIVE")
            kind = get_chain_spec(wallet.chain_id).kind
            expected_scope = {
                ChainKind.EVM: "EVM",
                ChainKind.TRON: "TRON",
                ChainKind.SOLANA: "SOLANA",
            }.get(kind)
            if expected_scope is None or keyset.scope != expected_scope:
                raise CommandError(
                    f"keyset scope {keyset.scope} cannot control "
                    f"{kind.value} chain {wallet.chain_id}"
                )
            if options["derivation_reference"]:
                raise CommandError(
                    "child public-key derivation evidence is required; root key cannot be rebound"
                )
            expected = address_from_public_key(wallet.chain_id, keyset.public_key)
            if kind is ChainKind.EVM:
                from eth_utils import is_same_address

                matches = is_same_address(
                    expected,
                    wallet.deposit_address if isinstance(wallet, UserWallet) else wallet.address,
                )
            else:
                # Base58 encodings used by TRON and Solana are case-sensitive.
                matches = expected == (
                    wallet.deposit_address if isinstance(wallet, UserWallet) else wallet.address
                )
            if not matches:
                raise CommandError("MPC public key does not control configured hot-wallet address")
            wallet.mpc_keyset = keyset
            if isinstance(wallet, UserWallet):
                wallet.derivation_path = f"keyset:{keyset.keyset_id}"
                wallet.derivation_version = "mpc_root_v1"
                wallet.save(update_fields=["mpc_keyset", "derivation_path", "derivation_version"])
            else:
                wallet.signing_key_ref = f"keyset:{keyset.keyset_id}"
                wallet.save(update_fields=["mpc_keyset", "signing_key_ref"])
            if kind is ChainKind.SOLANA:
                from custody.mpc_binding import _wallet_root_keyset, verify_coordinator_keyset
                from custody.signer_adapter import SelfHostedMpcAdapter

                _wallet_root_keyset(wallet, wallet.chain_id, expected)
                verify_coordinator_keyset(
                    keyset, SelfHostedMpcAdapter().get_keyset(str(keyset.keyset_id))
                )
            self.stdout.write(f"bound {wallet.chain_id} to {keyset.keyset_id}")
