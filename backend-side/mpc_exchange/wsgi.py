"""
WSGI config for mpc_exchange project.
Exposes the WSGI callable as a module-level variable named ``application``.
"""
import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mpc_exchange.settings")

application = get_wsgi_application()