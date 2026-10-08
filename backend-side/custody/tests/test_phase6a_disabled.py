import tempfile
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

import pytest
from django.test import override_settings

from custody.checks import custody_signer_configuration
from custody.models import OnchainTransactionAttempt, WithdrawalRequest
from custody.outbound import execute_attempt
from custody.signer_adapter import LocalVault, get_adapter
from custody.withdrawals import process_withdrawal


def _credential_files(directory):
    paths = []
    for name in ("client.crt", "client.key", "ca.crt"):
        path = Path(directory) / name
        path.write_text("valid-looking test fixture")
        paths.append(str(path))
    return paths


@pytest.mark.django_db
def test_valid_looking_https_and_certificates_cannot_enable_phase6a():
    with tempfile.TemporaryDirectory() as directory:
        cert, key, ca = _credential_files(directory)
        with override_settings(
            MPC_SIGNER_BACKEND="self_hosted_mpc",
            CUSTODY_DEMO_MODE=False,
            CUSTODY_TX_MODE="live",
            MPC_COORDINATOR_URL="https://mpc.internal.example",
            MPC_CLIENT_CERT=cert,
            MPC_CLIENT_KEY=key,
            MPC_CA_CERT=ca,
            MPC_REQUEST_TIMEOUT_SECONDS=10,
        ):
            errors = custody_signer_configuration(None)
            assert "custody.E011" in {error.id for error in errors}
            with (
                patch("custody.signer_adapter._ADAPTER", None),
                pytest.raises(RuntimeError, match="Phase 6A foundation only"),
            ):
                get_adapter()


@pytest.mark.django_db
@override_settings(
    MPC_SIGNER_BACKEND="self_hosted_mpc",
    CUSTODY_DEMO_MODE=False,
    CUSTODY_TX_MODE="live",
)
def test_runtime_guards_prevent_attempt_and_withdrawal_side_effects():
    request = WithdrawalRequest.objects.create(
        user_id="phase6a",
        chain_id="ETH",
        asset_key="ETH",
        to_address="0x" + "22" * 20,
        amount=Decimal("1"),
        status="APPROVED",
    )
    with pytest.raises(RuntimeError, match="Phase 6A foundation only"):
        process_withdrawal("admin", request.pk)
    request.refresh_from_db()
    assert request.status == "APPROVED"
    assert not OnchainTransactionAttempt.objects.filter(
        operation_type="WITHDRAWAL", operation_id=request.pk
    ).exists()

    with pytest.raises(RuntimeError, match="Phase 6A foundation only"):
        execute_attempt(999_999, "admin")


@override_settings(
    MPC_SIGNER_BACKEND="local_key",
    CUSTODY_DEMO_MODE=True,
    CUSTODY_TX_MODE="stub",
    LOCAL_KEY_ENCRYPTION_PASSPHRASE="phase6a-demo-test",
)
def test_demo_local_key_remains_available_without_production_fallback():
    with patch("custody.signer_adapter._ADAPTER", None):
        assert isinstance(get_adapter(), LocalVault)


@override_settings(
    MPC_SIGNER_BACKEND="local_key",
    CUSTODY_DEMO_MODE=False,
    CUSTODY_TX_MODE="live",
    LOCAL_KEY_ENCRYPTION_PASSPHRASE="not-enough-to-enable-production",
)
def test_production_local_key_cannot_be_used_as_fallback():
    assert "custody.E003" in {error.id for error in custody_signer_configuration(None)}
    with (
        patch("custody.signer_adapter._ADAPTER", None),
        pytest.raises(RuntimeError, match="restricted to demo mode"),
    ):
        get_adapter()
