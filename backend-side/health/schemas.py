"""Pydantic/Ninja DTOs for system health endpoints."""
from __future__ import annotations

from typing import List, Optional

from ninja import Schema


class ComponentHealthDTO(Schema):
    component: str
    status: str
    detail: str
    metric: dict
    checked_at: str


class SystemHealthDTO(Schema):
    status: str                      # OK | DEGRADED | DOWN | NA
    components: List[ComponentHealthDTO]
    generated_at: str
    uptime_seconds: int
    pending_sweeps: int
    pending_withdrawals: int


class LivenessDTO(Schema):
    status: str
    uptime_seconds: int
    generated_at: str


class ReadinessDTO(Schema):
    status: str
    database: str
    redis: str
    generated_at: str