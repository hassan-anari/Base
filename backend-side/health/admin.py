"""Django admin registration for the system-health probe models."""
from django.contrib import admin

from .models import SystemHealthProbe


@admin.register(SystemHealthProbe)
class SystemHealthProbeAdmin(admin.ModelAdmin):
    list_display = ("component", "status", "detail", "checked_at")
    list_filter = ("component", "status")
    search_fields = ("component",)
    readonly_fields = ("checked_at", "metric")