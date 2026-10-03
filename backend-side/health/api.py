"""
System health API.

  GET /health/live                -> liveness (no auth; for k8s/lb)
  GET /health/ready               -> readiness (no auth; for k8s/lb)
  GET /ops/system/health          -> full probe rollup (operator/auditor)
  GET /ops/system/health/history  -> recent persisted probe rows

The two /health/* endpoints intentionally require NO authentication so that
orchestrators / load balancers / uptime monitors can call them freely.
The /ops/system/health endpoint is protected (operator/auditor) because it
exposes internal topology (node counts) useful to an attacker.
"""
from __future__ import annotations

import logging
from typing import Optional

from django.http import JsonResponse
from ninja import Router, Header

from . import services as H
from .schemas import (
    ComponentHealthDTO, SystemHealthDTO, LivenessDTO, ReadinessDTO,
)
from custody.auth import decode_token
from custody.api import require_auditor

logger = logging.getLogger("health.api")
api = Router()


# ---------------------------------------------------------------------------
# Unauthenticated liveness / readiness (k8s, LB, UptimeRobot)
# ---------------------------------------------------------------------------
@api.get("/health/live", response=LivenessDTO, auth=None)
def live(request):
    return LivenessDTO(**H.liveness())


@api.get("/health/ready", response=ReadinessDTO, auth=None)
def ready(request):
    return ReadinessDTO(**H.readiness())


# ---------------------------------------------------------------------------
# Authenticated full system health (operator console)
# ---------------------------------------------------------------------------
def _require_operator(authorization: Optional[str],
                      x_user_id: Optional[str], x_role: Optional[str]):
    if authorization and authorization.lower().startswith("bearer "):
        decoded = decode_token(authorization.split(" ", 1)[1].strip())
        if decoded:
            return decoded
        from ninja.errors import HttpError
        raise HttpError(401, "invalid or expired token")
    from django.conf import settings
    if getattr(settings, "ALLOW_DEV_STUB_AUTH", False) and x_user_id:
        return (x_user_id, x_role or "operator")
    from ninja.errors import HttpError
    raise HttpError(401, "authentication required")


@api.get("/ops/system/health", response=SystemHealthDTO)
def system_health(request,
                   authorization: Optional[str] = Header(None),
                   x_user_id: Optional[str] = Header(None),
                   x_role: Optional[str] = Header(None)):
    actor_id, role = _require_operator(authorization, x_user_id, x_role)
    require_auditor(role)
    data = H.run_probes(persist=True)
    return SystemHealthDTO(
        status=data["status"],
        components=[ComponentHealthDTO(**c) for c in data["components"]],
        generated_at=data["generated_at"],
        uptime_seconds=data["uptime_seconds"],
        pending_sweeps=data["pending_sweeps"],
        pending_withdrawals=data["pending_withdrawals"],
    )


@api.get("/ops/system/health/history", response=list[ComponentHealthDTO])
def health_history(request,
                   component: Optional[str] = None,
                   authorization: Optional[str] = Header(None),
                   x_user_id: Optional[str] = Header(None),
                   x_role: Optional[str] = Header(None)):
    _require_operator(authorization, x_user_id, x_role)
    from .models import SystemHealthProbe
    qs = SystemHealthProbe.objects.all().order_by("-checked_at")
    if component:
        qs = qs.filter(component=component)
    out = []
    for p in qs[:200]:
        out.append(ComponentHealthDTO(
            component=p.component, status=p.status, detail=p.detail,
            metric=p.metric, checked_at=str(p.checked_at)))
    return out