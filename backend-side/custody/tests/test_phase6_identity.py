import uuid

import pytest
from django.core.management import CommandError, call_command
from eth_keys import keys

from custody.models import HotWallet, MpcKeyset
from custody.mpc_identity import address_from_public_key


@pytest.mark.django_db
def test_bind_hot_wallet_requires_exact_locally_derived_address():
    public_key = keys.PrivateKey(bytes.fromhex("01".rjust(64, "0"))).public_key
    address = public_key.to_checksum_address()
    keyset = MpcKeyset.objects.create(
        keyset_id=uuid.uuid4(),
        algorithm="CGGMP24_ECDSA",
        curve="secp256k1",
        scope="EVM",
        threshold=2,
        party_count=3,
        derivation_version="cggmp_hd_v1",
        status="ACTIVE",
        public_key=public_key.to_compressed_bytes().hex(),
    )
    wallet, _ = HotWallet.objects.update_or_create(chain_id="ETH", defaults={"address": address})
    call_command("bind_mpc_hot_wallet", chain="ETH", keyset_id=str(keyset.keyset_id))
    wallet.refresh_from_db()
    assert wallet.mpc_keyset == keyset
    assert address_from_public_key("ETH", keyset.public_key) == address


@pytest.mark.django_db
def test_bind_hot_wallet_mismatch_has_no_mutation():
    public_key = keys.PrivateKey(bytes.fromhex("02".rjust(64, "0"))).public_key
    keyset = MpcKeyset.objects.create(
        keyset_id=uuid.uuid4(),
        algorithm="CGGMP24_ECDSA",
        curve="secp256k1",
        scope="EVM",
        threshold=2,
        party_count=3,
        derivation_version="cggmp_hd_v1",
        status="ACTIVE",
        public_key=public_key.to_compressed_bytes().hex(),
    )
    wallet, _ = HotWallet.objects.update_or_create(
        chain_id="ETH", defaults={"address": "0x" + "11" * 20}
    )
    with pytest.raises(CommandError, match="does not control"):
        call_command("bind_mpc_hot_wallet", chain="ETH", keyset_id=str(keyset.keyset_id))
    wallet.refresh_from_db()
    assert wallet.mpc_keyset is None
