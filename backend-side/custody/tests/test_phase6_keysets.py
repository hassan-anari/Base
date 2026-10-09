import uuid
from unittest.mock import patch

import pytest
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.db import IntegrityError, transaction

from custody.models import MpcKeyset

from .test_phase6_signing import metadata_for


def keyset(scope, algorithm, curve, derivation):
    return MpcKeyset(
        keyset_id=uuid.uuid4(),
        scope=scope,
        algorithm=algorithm,
        curve=curve,
        derivation_version=derivation,
        threshold=2,
        party_count=3,
    )


@pytest.mark.django_db
def test_keyset_scope_algorithm_and_derivation_shape():
    valid = [
        keyset("EVM", "CGGMP24_ECDSA", "secp256k1", "cggmp_hd_v1"),
        keyset("TRON", "CGGMP24_ECDSA", "secp256k1", "cggmp_hd_v1"),
        keyset("SOLANA", "FROST_ED25519", "ed25519", "frost_keyset_v1"),
    ]
    for item in valid:
        item.full_clean()
    invalid = [
        keyset("EVM", "FROST_ED25519", "ed25519", "frost_keyset_v1"),
        keyset("TRON", "CGGMP24_ECDSA", "secp256k1", "frost_keyset_v1"),
        keyset("SOLANA", "CGGMP24_ECDSA", "secp256k1", "cggmp_hd_v1"),
    ]
    for item in invalid:
        with pytest.raises(ValidationError):
            item.full_clean()


@pytest.mark.django_db
def test_active_keyset_unique_per_scope():
    first = keyset("EVM", "CGGMP24_ECDSA", "secp256k1", "cggmp_hd_v1")
    first.active_for_new_wallets = True
    first.save()
    second = keyset("EVM", "CGGMP24_ECDSA", "secp256k1", "cggmp_hd_v1")
    second.active_for_new_wallets = True
    with pytest.raises((ValidationError, IntegrityError)), transaction.atomic():
        second.save()


@pytest.mark.django_db
def test_activation_is_scoped_and_preserves_other_cggmp_scope():
    evm = keyset("EVM", "CGGMP24_ECDSA", "secp256k1", "cggmp_hd_v1")
    evm.status = "ACTIVE"
    evm.active_for_new_wallets = True
    evm.save()
    tron = keyset("TRON", "CGGMP24_ECDSA", "secp256k1", "cggmp_hd_v1")
    tron.public_key = "02" + "11" * 32
    tron.dkg_execution_id = uuid.uuid4()
    tron.dkg_result_fingerprint = "22" * 32
    tron.participant_identities = ["signer-a", "signer-b", "signer-c"]
    tron.save()

    with patch(
        "custody.signer_adapter.SelfHostedMpcAdapter.get_keyset", return_value=metadata_for(tron)
    ):
        call_command("mpc_keyset", "activate", keyset_id=str(tron.keyset_id))

    evm.refresh_from_db()
    tron.refresh_from_db()
    assert evm.active_for_new_wallets is True
    assert tron.status == "ACTIVE"
    assert tron.active_for_new_wallets is False  # Root binding only; provisioning remains 6G.
