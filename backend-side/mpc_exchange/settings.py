"""
Django settings for mpc_exchange (production-oriented skeleton).
Loads all configuration from environment variables (see .env.example).
No secrets are hard-coded.
"""

import json
from pathlib import Path

from decouple import Csv, config
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent

# Load .env (backend/.env) into os.environ BEFORE any module reads config.
# python-dotenv is required so non-decouple readers (custody.config via
# os.environ) also see these values. Silently no-op if the file is absent.
_env_path = BASE_DIR / ".env"
if _env_path.exists():
    load_dotenv(_env_path)

SECRET_KEY = config("DJANGO_SECRET_KEY", default="dev-only-change-me-in-prod")
DEBUG = config("DEBUG", default=False, cast=bool)
ALLOWED_HOSTS = config("ALLOWED_HOSTS", default="127.0.0.1,localhost", cast=Csv())

# ----------------------------------------------------------------------------
# Applications
# ----------------------------------------------------------------------------
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "ninja",
    "corsheaders",
    "custody",
    "ops",
    "health",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "mpc_exchange.urls"
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ]
        },
    },
]

WSGI_APPLICATION = "mpc_exchange.wsgi.application"

# ----------------------------------------------------------------------------
# Database (PostgreSQL in production; sqlite fallback for local dev)
# ----------------------------------------------------------------------------
_db_url = config("DATABASE_URL", default="sqlite:///db.sqlite3")
if _db_url.startswith("postgres://") or _db_url.startswith("postgresql://"):
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": config("POSTGRES_DB", default="mpc_exchange"),
            "USER": config("POSTGRES_USER", default="mpc"),
            "PASSWORD": config("POSTGRES_PASSWORD", default=""),
            "HOST": config("POSTGRES_HOST", default="127.0.0.1"),
            "PORT": config("POSTGRES_PORT", default="5432"),
        }
    }
else:
    DATABASES = {
        "default": {"ENGINE": "django.db.backends.sqlite3", "NAME": BASE_DIR / "db.sqlite3"}
    }

# ----------------------------------------------------------------------------
# Security
# ----------------------------------------------------------------------------
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 10},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]
SESSION_COOKIE_SECURE = config("SESSION_COOKIE_SECURE", default=not DEBUG, cast=bool)
CSRF_COOKIE_SECURE = config("CSRF_COOKIE_SECURE", default=not DEBUG, cast=bool)
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = "DENY"

# ----------------------------------------------------------------------------
# CORS (frontend origin)
# ----------------------------------------------------------------------------
CORS_ALLOWED_ORIGINS = [
    o for o in config("CORS_ALLOWED_ORIGINS", default="http://localhost:5173", cast=Csv())
]
CORS_ALLOW_CREDENTIALS = True

# ----------------------------------------------------------------------------
# JWT
# ----------------------------------------------------------------------------
JWT_SECRET = config("JWT_SECRET", default=SECRET_KEY)
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TTL_SECONDS = config("JWT_ACCESS_TTL_SECONDS", default=900, cast=int)
JWT_REFRESH_TTL_SECONDS = config("JWT_REFRESH_TTL_SECONDS", default=86400 * 7, cast=int)
JWT_EXP_SECONDS = config("JWT_EXP_SECONDS", default=JWT_ACCESS_TTL_SECONDS, cast=int)

# Dev convenience: accept x-user-id / x-role stub headers for local curl testing.
# MUST be False in production — real Bearer JWT is always required otherwise.
ALLOW_DEV_STUB_AUTH = config("ALLOW_DEV_STUB_AUTH", default=False, cast=bool)

# ----------------------------------------------------------------------------
# MPC signer backend selection
#   local_key  -> real local signing for ETH/BSC/TRX/SOL (demo/dev)
#   self_hosted_mpc -> authenticated coordinator, explicitly restricted Phase 6E integration
# ----------------------------------------------------------------------------
MPC_SIGNER_BACKEND = config("MPC_SIGNER_BACKEND", default="local_key")
CUSTODY_DEMO_MODE = config("CUSTODY_DEMO_MODE", default=False, cast=bool)
CUSTODY_TX_MODE = config("CUSTODY_TX_MODE", default="live").strip().lower()
MPC_COORDINATOR_URL = config("MPC_COORDINATOR_URL", default="https://mpc-coordinator:8443")
MPC_CLIENT_CERT = config("MPC_CLIENT_CERT", default="")
MPC_CLIENT_KEY = config("MPC_CLIENT_KEY", default="")
MPC_CA_CERT = config("MPC_CA_CERT", default="")
MPC_REQUEST_TIMEOUT_SECONDS = config("MPC_REQUEST_TIMEOUT_SECONDS", default=30, cast=int)
MPC_EVM_INTEGRATION_ENABLED = config("MPC_EVM_INTEGRATION_ENABLED", default=False, cast=bool)
MPC_TRON_INTEGRATION_ENABLED = config("MPC_TRON_INTEGRATION_ENABLED", default=False, cast=bool)
MPC_TRON_NETWORK = config("MPC_TRON_NETWORK", default="{}", cast=json.loads)
MPC_INTEGRATION_ENVIRONMENT = config("MPC_INTEGRATION_ENVIRONMENT", default="disabled")
MPC_EVM_DEVELOPMENT_CHAINS = config("MPC_EVM_DEVELOPMENT_CHAINS", default="{}", cast=json.loads)
# Local-key encryption passphrase for at-rest encrypted hot-wallet keys
LOCAL_KEY_ENCRYPTION_PASSPHRASE = config("LOCAL_KEY_ENCRYPTION_PASSPHRASE", default="")

# ----------------------------------------------------------------------------
# Rate limiting (Django-level; additionally enforced in code via rate_limit.py)
# ----------------------------------------------------------------------------
RATE_LIMIT_PER_MINUTE = config("RATE_LIMIT_PER_MINUTE", default=60, cast=int)
RATE_LIMIT_SIGN_PER_MINUTE = config("RATE_LIMIT_SIGN_PER_MINUTE", default=20, cast=int)

# ----------------------------------------------------------------------------
# Observability (optional Sentry)
# ----------------------------------------------------------------------------
SENTRY_DSN = config("SENTRY_DSN", default="")
if SENTRY_DSN:
    import sentry_sdk

    sentry_sdk.init(dsn=SENTRY_DSN, traces_sample_rate=0.1)

# ----------------------------------------------------------------------------
# Static / default
# ----------------------------------------------------------------------------
STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "static_collected"
# Built Vue frontend (output of `npm --prefix ../frontend run build`) and the
# standalone API Simulator (output of `npm --prefix ../frontend run build:sim`)
# are copied into the dirs below before collectstatic serves them at /static/.
# The main app index is served at "/" by index_spa; the simulator at "/simulator/".
STATICFILES_DIRS = [
    path for path in (BASE_DIR / "frontend_dist", BASE_DIR / "simulator_dist") if path.exists()
]
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
LOGIN_URL = "/api/auth/login"
