"""
System health monitoring service.

Provides live "probes" for every critical dependency of the custody platform
and an aggregate health rollup consumed by:
  * the `/ops/system/health` API (operator console)
  * the `health_probe` management command (cron / Prometheus / external monitor)
  * Kubernetes / load-balancer liveness + readiness endpoints

Probes (each returns OK / DEGRADED / DOWN / NA):
  * database   : PostgreSQL connectivity + query latency
  * redis      : Celery broker reachability (used for locks + worker queue)
  * disk       : free space on the data volume (alert < 10%)
  * signer     : MPC signing backend configuration / reachability
  * indexer    : per-chain node health (from ops.NodeEndpoint registry)
  * pending    : stuck custody jobs (in-flight sweeps / unapproved withdrawals)

The aggregate status is the worst component status (DOWN > DEGRADED > OK > NA),
with NA never degrading the aggregate (it means "not applicable / disabled").
"""
from __future__ import annotations

import logging
import os
import shutil
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from django.conf import settings
from django.db import connection
from django.utils import timezone as dj_timezone

logger = logging.getLogger("health.services")

# Process start time (for uptime reporting). Module-level = once per process.
_PROCESS_STARTED_AT = time.time()


def _status_rank(s: str) -> int:
    return {"OK": 0, "NA": 1, "DEGRADED": 2, "DOWN": 3}.get(s, 2)


def _worst(statuses: List[str]) -> str:
    """Aggregate; NA is ignored unless everything is NA."""
    real = [s for s in statuses if s != "NA"]
    if not real:
        return "NA"
    return max(real, key=_status_rank)


# ---------------------------------------------------------------------------
# Individual probes
# ---------------------------------------------------------------------------
def probe_database() -> Dict[str, Any]:
    t0 = time.time()
    try:
        with connection.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
        latency_ms = int((time.time() - t0) * 1000)
        return {"status": "OK",
                "detail": f"postgres reachable ({latency_ms}ms)",
                "metric": {"latency_ms": latency_ms}}
    except Exception as e:  # noqa: BLE001 - health must never 500
        return {"status": "DOWN", "detail": f"db error: {e}", "metric": {}}


def probe_redis() -> Dict[str, Any]:
    broker = getattr(settings, "CELERY_BROKER_URL", "") or "redis://127.0.0.1:6379/0"
    try:
        import redis  # imported lazily so tests without redis still import
        client = redis.from_url(broker, socket_connect_timeout=2,
                                socket_timeout=2)
        t0 = time.time()
        pong = client.ping()
        latency_ms = int((time.time() - t0) * 1000)
        if not pong:
            return {"status": "DOWN", "detail": "redis ping failed",
                    "metric": {}}
        return {"status": "OK",
                "detail": f"redis reachable ({latency_ms}ms)",
                "metric": {"latency_ms": latency_ms}}
    except Exception as e:  # noqa: BLE001
        # Redis is optional in local dev; report DEGRADED not DOWN so the
        # platform (which runs fine synchronously) is not marked fully DOWN.
        return {"status": "DEGRADED",
                "detail": f"redis unavailable ({e}); background workers disabled",
                "metric": {}}


def probe_disk() -> Dict[str, Any]:
    try:
        base = str(getattr(settings, "BASE_DIR", os.getcwd()))
        usage = shutil.disk_usage(base)
        free_pct = usage.free / usage.total * 100
        status = "OK" if free_pct > 10 else ("DEGRADED" if free_pct > 3 else "DOWN")
        return {"status": status,
                "detail": f"{free_pct:.1f}% free on {base}",
                "metric": {"free_pct": round(free_pct, 2)}}
    except Exception as e:  # noqa: BLE001
        return {"status": "NA", "detail": f"disk check error: {e}", "metric": {}}


def probe_signer() -> Dict[str, Any]:
    backend = getattr(settings, "MPC_SIGNER_BACKEND", "")
    try:
        from custody.mpc_signer import get_signer
        signer = get_signer()
        ok = bool(getattr(signer, "is_configured", lambda: True)())
        if not ok:
            return {"status": "DEGRADED",
                    "detail": "MPC signer not fully configured",
                    "metric": {"backend": backend}}
        return {"status": "OK",
                "detail": f"signer backend '{backend}' configured",
                "metric": {"backend": backend}}
    except Exception as e:  # noqa: BLE001
        return {"status": "DEGRADED",
                "detail": f"signer probe failed: {e}",
                "metric": {"backend": backend}}


def probe_indexer_nodes() -> Dict[str, Any]:
    try:
        from ops.models import NodeEndpoint
        nodes = list(NodeEndpoint.objects.filter(enabled=True))
        total = len(nodes)
        healthy = sum(1 for n in nodes if n.healthy is True)
        unhealthy = sum(1 for n in nodes if n.healthy is False)
        if total == 0:
            return {"status": "NA", "detail": "no nodes registered",
                    "metric": {"total": 0}}
        if unhealthy == 0:
            return {"status": "OK",
                    "detail": f"{healthy}/{total} nodes healthy",
                    "metric": {"healthy": healthy, "total": total}}
        if unhealthy < total:
            return {"status": "DEGRADED",
                    "detail": f"{unhealthy}/{total} nodes unhealthy",
                    "metric": {"healthy": healthy, "total": total,
                               "unhealthy": unhealthy}}
        return {"status": "DOWN",
                "detail": f"all {total} nodes unhealthy",
                "metric": {"total": total, "unhealthy": unhealthy}}
    except Exception as e:  # noqa: BLE001
        return {"status": "NA", "detail": f"node probe error: {e}",
                "metric": {}}


def probe_pending_jobs() -> Dict[str, Any]:
    """Detect stuck custody flows that need operator attention."""
    try:
        from datetime import timedelta
        from custody.models import GasTopupIntent, SweepJob, WithdrawalRequest
        # In-flight sweeps older than 30 min => likely stuck.
        stuck_cutoff = dj_timezone.now() - timedelta(minutes=30)
        stuck_sweeps = SweepJob.objects.filter(
            status__in=("CREATED", "GAS_TOPUP_REQUIRED", "GAS_TOPUP_BROADCASTED",
                        "SWEEP_BROADCASTED", "RECONCILIATION_REQUIRED")).filter(
            created_at__lt=stuck_cutoff).count()
        # Withdrawals pending approval (not a fault, but operator load).
        pending_wd = WithdrawalRequest.objects.filter(
            status="PENDING_APPROVAL").count()
        # Withdrawals approved but never broadcast (older than 30 min).
        stuck_wd = WithdrawalRequest.objects.filter(
            status__in=("APPROVED", "PROCESSING", "RECONCILIATION_REQUIRED"),
            updated_at__lt=stuck_cutoff).count()
        uncertain_gas = GasTopupIntent.objects.filter(
            status="RECONCILIATION_REQUIRED").count()

        status = "OK"
        detail = "no stuck jobs"
        if stuck_sweeps or stuck_wd or uncertain_gas:
            status = "DEGRADED"
            detail = (f"{stuck_sweeps} stuck sweep(s), "
                      f"{stuck_wd} stuck withdrawal(s), "
                      f"{uncertain_gas} gas top-up(s) requiring reconciliation")
        return {"status": status, "detail": detail,
                "metric": {"stuck_sweeps": stuck_sweeps,
                           "pending_withdrawals": pending_wd,
                           "stuck_withdrawals": stuck_wd,
                           "uncertain_gas_topups": uncertain_gas}}
    except Exception as e:  # noqa: BLE001
        return {"status": "NA", "detail": f"job probe error: {e}", "metric": {}}


# ---------------------------------------------------------------------------
# Aggregate rollup
# ---------------------------------------------------------------------------
_PROBES = [
    ("database", probe_database),
    ("redis", probe_redis),
    ("disk", probe_disk),
    ("signer", probe_signer),
    ("indexer", probe_indexer_nodes),
    ("pending_jobs", probe_pending_jobs),
]


def run_probes(persist: bool = True) -> Dict[str, Any]:
    """Run every probe, compute aggregate status, optionally persist.

    Returns a serialisable dict consumed by the API + management command.
    """
    components: List[Dict[str, Any]] = []
    for name, fn in _PROBES:
        try:
            res = fn()
        except Exception as e:  # noqa: BLE001
            res = {"status": "DEGRADED", "detail": f"{name} probe crashed: {e}",
                   "metric": {}}
        res["component"] = name
        res["checked_at"] = datetime.now(timezone.utc).isoformat()
        components.append(res)
        if persist:
            try:
                from .models import SystemHealthProbe
                SystemHealthProbe.objects.create(
                    component=name, status=res["status"],
                    detail=res.get("detail", ""),
                    metric=res.get("metric", {}) or {})
            except Exception:  # noqa: BLE001 - never block health on write
                logger.exception("failed to persist probe %s", name)

    aggregate = _worst([c["status"] for c in components])
    pending = next((c["metric"] for c in components if c["component"] == "pending_jobs"), {})

    # Surface critical DOWN as an ops alert (integration with ops platform).
    if aggregate in ("DOWN", "DEGRADED") and persist:
        try:
            from ops.services import maybe_alert
            maybe_alert("", "system", aggregate.lower(),
                        f"System health {aggregate}",
                        f"components={components}")
        except Exception:  # noqa: BLE001
            logger.exception("failed to raise system alert")

    return {
        "status": aggregate,
        "components": components,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "uptime_seconds": int(time.time() - _PROCESS_STARTED_AT),
        "pending_sweeps": int(pending.get("stuck_sweeps", 0)),
        "pending_withdrawals": int(pending.get("pending_withdrawals", 0)),
    }


def liveness() -> Dict[str, Any]:
    """Cheap liveness check for k8s/lb — process is up + Django imports OK."""
    return {
        "status": "ok",
        "uptime_seconds": int(time.time() - _PROCESS_STARTED_AT),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def readiness() -> Dict[str, Any]:
    """Readiness — can this process serve traffic? Needs DB (and Redis)."""
    db = probe_database()
    rds = probe_redis()
    ready = db["status"] != "DOWN" and rds["status"] != "DOWN"
    return {
        "status": "ready" if ready else "not_ready",
        "database": db["status"],
        "redis": rds["status"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
