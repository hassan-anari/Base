"""SPA hosting: serve the built Vue frontends from Django at `/` and `/simulator/`.

This lets the entire product run from a single origin/port.
  * The main exchange app is built by Vite into ``frontend_dist`` (served at `/`).
  * The standalone API Simulator is built by Vite into ``simulator_dist``
    (served at `/simulator/`).

All non-API, non-static requests fall back to the relevant index.html so
client-side routing works.
"""
import os

from django.conf import settings
from django.http import FileResponse, HttpResponse
from django.utils._os import safe_join


FRONTEND_DIST = os.path.join(settings.BASE_DIR, "frontend_dist")
SIMULATOR_DIST = os.path.join(settings.BASE_DIR, "simulator_dist")


def _serve_from(request, dist_dir, filename):
    """Serve a real file from ``dist_dir`` if it exists, else None.

    Uses safe_join to reject path-traversal attempts.
    """
    try:
        full = safe_join(dist_dir, filename)
    except ValueError:
        return HttpResponse("Not found", status=404)
    if os.path.isfile(full):
        return FileResponse(open(full, "rb"))
    return None


def _serve_index(dist_dir, missing_msg):
    index = os.path.join(dist_dir, "index.html")
    if not os.path.exists(index):
        return HttpResponse(missing_msg, status=503, content_type="text/plain")
    return FileResponse(open(index, "rb"))


def spa(request, path=""):
    """Serve the main exchange SPA for any non-API/static/admin route."""
    if path:
        served = _serve_from(request, FRONTEND_DIST, path)
        if served is not None:
            return served
    return _serve_index(
        FRONTEND_DIST,
        "Frontend not built. Run: npm --prefix ../frontend run build",
    )


def simulator_spa(request, path=""):
    """Serve the standalone API Simulator SPA from ``/simulator/``."""
    if path:
        served = _serve_from(request, SIMULATOR_DIST, path)
        if served is not None:
            return served
    return _serve_index(
        SIMULATOR_DIST,
        "Simulator not built. Run: npm --prefix ../frontend run build:sim",
    )