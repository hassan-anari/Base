"""Django system checks for fail-closed custody configuration."""

from django.conf import settings
from django.core.checks import Error, register


@register()
def custody_signer_configuration(app_configs, **kwargs):
    del app_configs, kwargs
    errors = []
    backend = settings.MPC_SIGNER_BACKEND
    demo = settings.CUSTODY_DEMO_MODE
    if backend not in {"local_key", "mpc_vendor"}:
        errors.append(Error("Unknown MPC_SIGNER_BACKEND", id="custody.E001"))
    if backend == "mpc_vendor":
        errors.append(
            Error(
                "mpc_vendor is not implemented; configure a real adapter before use",
                id="custody.E002",
            )
        )
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
