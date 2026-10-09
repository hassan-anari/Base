"""Django system checks for fail-closed custody configuration."""

import os
from urllib.parse import urlparse

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
        from .signer_adapter import assert_mpc_backend_runtime_safe

        try:
            assert_mpc_backend_runtime_safe()
        except (RuntimeError, ValueError, OSError) as exc:
            errors.append(Error(str(exc), id="custody.E011"))
        if demo:
            errors.append(Error("self_hosted_mpc requires demo mode disabled", id="custody.E007"))
        parsed = urlparse(settings.MPC_COORDINATOR_URL)
        if parsed.scheme != "https" or not parsed.hostname:
            errors.append(Error("MPC coordinator URL must be HTTPS", id="custody.E008"))
        missing = [
            name
            for name in ("MPC_CLIENT_CERT", "MPC_CLIENT_KEY", "MPC_CA_CERT")
            if not getattr(settings, name, "")
        ]
        if missing:
            errors.append(Error("self_hosted_mpc requires mTLS credentials", id="custody.E002"))
        else:
            unreadable = [
                name
                for name in ("MPC_CLIENT_CERT", "MPC_CLIENT_KEY", "MPC_CA_CERT")
                if not os.path.isfile(getattr(settings, name))
                or not os.access(getattr(settings, name), os.R_OK)
            ]
            if unreadable:
                errors.append(Error("MPC mTLS files must exist and be readable", id="custody.E009"))
        if not 1 <= settings.MPC_REQUEST_TIMEOUT_SECONDS <= 120:
            errors.append(Error("MPC timeout must be between 1 and 120 seconds", id="custody.E010"))
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
