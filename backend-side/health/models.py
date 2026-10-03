"""
System health persistence models.

We persist point-in-time probe results so the ops dashboard can show a
history/availability timeline and so external monitors (Prometheus, Grafana,
UptimeRobot, etc.) can scrape `/ops/system/health` without hammering live
dependencies on every poll.

A probe row is written by:
  * the live API (`/ops/system/health`) on each request (most recent row wins)
  * a Celery-beat / cron command `python manage.py health_probe` for
    unattended monitoring when no operator is viewing the dashboard.
"""
from __future__ import annotations

import uuid

from django.db import models


def _new_id() -> str:
    return uuid.uuid4().hex[:24]


class SystemHealthProbe(models.Model):
    """One component probe result (DB, Redis, disk, signing, indexer, ...)."""

    STATUS = [
        ("OK", "OK"),
        ("DEGRADED", "DEGRADED"),
        ("DOWN", "DOWN"),
        ("NA", "NA"),  # component intentionally disabled / not configured
    ]

    id = models.CharField(primary_key=True, max_length=24, default=_new_id,
                          editable=False)
    component = models.CharField(max_length=32, db_index=True)
    status = models.CharField(max_length=16, choices=STATUS, default="OK")
    detail = models.TextField(blank=True, default="")
    metric = models.JSONField(default=dict, blank=True)  # latency_ms, pct, etc.
    checked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-checked_at"]
        indexes = [models.Index(fields=["component", "-checked_at"])]

    def __str__(self) -> str:
        return f"Probe({self.component}:{self.status})"