"""
Central Ninja API instance + router registration.

All API routers live under a versioned prefix ``/api`` (mounted in urls.py).
We attach the router modules from the ``custody`` app here.

API docs (Swagger UI) are served at ``/api/docs`` and the OpenAPI schema at
``/api/openapi.json``. These are enabled by default for developer convenience
and can be turned off in production by setting ``NINJA_DOCS_ENABLED=false``.
"""
from decouple import config
from ninja import NinjaAPI

# Docs are handy in dev/demo; disable in production via env if desired.
_DOCS_ENABLED = config("NINJA_DOCS_ENABLED", default=True, cast=bool)

api = NinjaAPI(
    title="MPC Custodial Exchange API",
    version="1.0.0",
    # Swagger UI at /api/docs, schema at /api/openapi.json (when enabled).
    docs_url="/docs" if _DOCS_ENABLED else None,
    openapi_url="/openapi.json" if _DOCS_ENABLED else None,
    # auth=JWTBearer(),  # <-- enable in production (see custody/api.py)
)


def register_routers() -> None:
    """Import the custody and ops API routers and attach them to the instance.

    Custody and ops routers declare their full paths under their own prefixes,
    so we mount them at the root with no additional prefix here.

    Imported lazily to avoid import cycles at Django startup.
    """
    from custody.api import api as custody_api
    from ops.api import api as ops_api
    from health.api import api as health_api
    api.add_router("", custody_api)
    api.add_router("", ops_api)
    api.add_router("", health_api)


register_routers()
