"""Django system checks for fail-closed custody configuration."""

from django.conf import settings
from django.core.checks import Error, register


@register()
def custody_signer_configuration(app_configs, **kwargs):
    del app_configs, kwargs
    errors = []
    backend = settings.MPC_SIGNER_BACKEND
    demo = settings.CUSTODY_DEMO_MODE
    tx_mode = settings.CUSTODY_TX_MODE
    if tx_mode not in {"stub", "live"}:
        errors.append(Error("CUSTODY_TX_MODE must be stub or live", id="custody.E005"))
    if tx_mode == "stub" and not demo:
        errors.append(Error("stub transaction transport requires demo mode", id="custody.E006"))
    if backend not in {"local_key", "self_hosted_mpc"}:
        errors.append(Error("Unknown MPC_SIGNER_BACKEND", id="custody.E001"))
    if backend == "mpc_vendor":
        errors.append(
            Error("SaaS MPC backends were removed; use self_hosted_mpc", id="custody.E002")
        )
    if backend == "self_hosted_mpc":
        missing = [
            name
            for name in ("MPC_CLIENT_CERT", "MPC_CLIENT_KEY", "MPC_CA_CERT")
            if not getattr(settings, name, "")
        ]
        if missing:
            errors.append(Error("self_hosted_mpc requires mTLS credentials", id="custody.E002"))
    if backend == "local_key" and not demo:
        errors.append(
            Error(
                "local_key is permitted only with CUSTODY_DEMO_MODE=true",
                id="custody.E003",
            )
        )
    if backend == "local_key" and not settings.LOCAL_KEY_ENCRYPTION_PASSPHRASE.strip():
        errors.append(
            Error(
                "LOCAL_KEY_ENCRYPTION_PASSPHRASE must be non-empty for local_key",
                id="custody.E004",
            )
        )
    return errors
