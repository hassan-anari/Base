"""Health monitoring app: system liveness/readiness + component probes."""
from django.apps import AppConfig


class HealthConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "health"
    label = "health"
    verbose_name = "System Health"