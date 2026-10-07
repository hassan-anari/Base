import uuid
from unittest.mock import patch

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


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("chain", "scope", "algorithm", "curve", "derivation"),
    [
        ("ETH", "TRON", "CGGMP24_ECDSA", "secp256k1", "cggmp_hd_v1"),
        ("TRX", "EVM", "CGGMP24_ECDSA", "secp256k1", "cggmp_hd_v1"),
        ("ETH", "SOLANA", "FROST_ED25519", "ed25519", "frost_keyset_v1"),
    ],
)
def test_bind_hot_wallet_rejects_cross_scope(chain, scope, algorithm, curve, derivation):
    keyset = MpcKeyset.objects.create(
        keyset_id=uuid.uuid4(),
        algorithm=algorithm,
        curve=curve,
        scope=scope,
        threshold=2,
        party_count=3,
        derivation_version=derivation,
        status="ACTIVE",
        public_key="02" + "11" * 32 if curve == "secp256k1" else "11" * 32,
    )
    wallet, _ = HotWallet.objects.update_or_create(
        chain_id=chain, defaults={"address": "different"}
    )
    with pytest.raises(CommandError, match="cannot control"):
        call_command("bind_mpc_hot_wallet", chain=chain, keyset_id=str(keyset.keyset_id))
    wallet.refresh_from_db()
    assert wallet.mpc_keyset is None


@pytest.mark.django_db
@pytest.mark.parametrize(("chain", "scope"), [("TRX", "TRON"), ("SOL", "SOLANA")])
def test_base58_address_binding_is_case_sensitive(chain, scope):
    keyset = MpcKeyset.objects.create(
        keyset_id=uuid.uuid4(),
        algorithm="CGGMP24_ECDSA" if scope == "TRON" else "FROST_ED25519",
        curve="secp256k1" if scope == "TRON" else "ed25519",
        scope=scope,
        threshold=2,
        party_count=3,
        derivation_version="cggmp_hd_v1" if scope == "TRON" else "frost_keyset_v1",
        status="ACTIVE",
        public_key="02" + "11" * 32 if scope == "TRON" else "11" * 32,
    )
    wallet, _ = HotWallet.objects.update_or_create(chain_id=chain, defaults={"address": "AbC123"})
    with (
        patch(
            "custody.management.commands.bind_mpc_hot_wallet.address_from_public_key",
            return_value="aBc123",
        ),
        pytest.raises(CommandError, match="does not control"),
    ):
        call_command("bind_mpc_hot_wallet", chain=chain, keyset_id=str(keyset.keyset_id))
    wallet.refresh_from_db()
    assert wallet.mpc_keyset is None
