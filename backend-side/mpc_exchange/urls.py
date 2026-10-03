"""Root URL configuration."""
from django.contrib import admin
from django.urls import path, re_path

from mpc_exchange.ninja_router import api
from mpc_exchange.views import spa, simulator_spa

urlpatterns = [
    path("api/", api.urls),
    # Django admin (staff/ops console for ledger + ops tables).
    path("admin/", admin.site.urls),
    # Standalone API Simulator SPA (built into simulator_dist).
    re_path(r"^simulator/(?P<path>.*)$", simulator_spa),
    # Catch-all: serve the main SPA + built assets for any non-API/static route.
    # Exclude `api/` (API), `simulator/` (simulator SPA), `static/` (assets),
    # and `admin/` so the admin UI keeps its CSS/JS. The named group
    # (?P<path>.*) is REQUIRED so the view can serve real files under
    # /assets/*; without it every request gets index.html (white screen).
    re_path(r"^(?!api/|simulator/|static/|admin/)(?P<path>.*)$", spa),
]
