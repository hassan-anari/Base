"""
ASGI config for mpc_exchange project.
Exposes the ASGI callable as a module-level variable named ``application``.
"""
import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mpc_exchange.settings")

application = get_asgi_application()