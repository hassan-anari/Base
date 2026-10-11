"""Bind an original authenticated TON DKG public key to its verified V5R1 state."""

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from custody.models import MpcKeyset, TonWalletBinding
from custody.mpc_binding import verify_coordinator_keyset
from custody.mpc_ton_network import network_identity, proof_client
from custody.ton_wire import (
    WALLET_CODE_HASH,
    WALLET_VERSION,
    verify_wallet_state,
    wallet_address,
    wallet_id,
    wallet_init,
)


class Command(BaseCommand):
    help = "Verify and bind one TON V5R1 original root contract; never derives child keys"

    def add_arguments(self, parser):
        parser.add_argument("keyset_id")

    def handle(self, *args, **options):
        keyset = MpcKeyset.objects.get(keyset_id=options["keyset_id"])
        if keyset.scope != "TON" or keyset.status != "ACTIVE" or keyset.active_for_new_wallets:
            raise CommandError("explicit original active TON FROST root required")
        verify_coordinator_keyset(keyset, keyset.dkg_public_evidence)
        identity = network_identity("TON")
        public = bytes.fromhex(keyset.public_key)
        address = wallet_address(public, identity["global_id"])
        client = proof_client("TON")
        checkpoint, _ = client.checkpoint()
        state = client.account(address, checkpoint)
        verify_wallet_state(
            address,
            public,
            identity["global_id"],
            status=state["status"],
            code=state["code"],
            data=state["data"],
        )
        defaults = dict(
            keyset=keyset,
            network_identity=identity,
            wallet_version=WALLET_VERSION,
            code_hash=WALLET_CODE_HASH,
            wallet_id=wallet_id(identity["global_id"]),
            workchain=0,
            state_init=wallet_init(public, identity["global_id"]).to_boc().hex(),
        )
        with transaction.atomic():
            binding, created = TonWalletBinding.objects.get_or_create(
                keyset=keyset, defaults={"chain_id": "TON", "address": address, **defaults}
            )
            if not created and any(
                getattr(binding, k) != v
                for k, v in {"chain_id": "TON", "address": address, **defaults}.items()
            ):
                raise CommandError("TON original binding cannot be replaced")
        self.stdout.write(address)
