"""
Minimal, dependency-free JWT auth for the custody API (skeleton).

SECURITY NOTE
-------------
This is a DEV/SKELETON implementation:
  * Tokens are HMAC-SHA256 signed with settings.JWT_SECRET (no external lib).
  * Demo users live in an in-memory dict. In production, replace
    DEMO_USERS / _verify_credentials with Django's User model (or your IdP /
    OIDC), and verify passwords via PBKDF2/argon2 (django.contrib.auth).
  * Plug point: swap `create_token`/`decode_token` for PyJWT or a real IdP
    introspection endpoint without changing the API surface.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Optional, Tuple

from django.conf import settings

# ---------------------------------------------------------------------------
# Role model (RBAC). Four roles for the internal ops platform:
#   admin      -> full control (approve withdrawals, manage nodes/assets)
#   operator   -> day-to-day ops (refresh wallets, manage nodes, view all)
#   auditor    -> read + export audit logs only
#   read_only  -> read-only dashboards
# Demo identity store (REPLACE with DB/IdP in production)
# ---------------------------------------------------------------------------
ROLES = ("admin", "operator", "auditor", "read_only")

# password is plaintext only for local dev demonstration; never ship this.
# The operator console (frontend) logs in as `ops` (operator) and acts on
# behalf of subject customers. Only `admin` can approve withdrawals.
DEMO_USERS = {
    # Operator console accounts (initiate custody actions on behalf of users)
    # Approver / full admin (RBAC: withdrawal approval is admin-only)
    "admin": {"role": "admin", "password": "admin"},
    # Ops platform operators/auditors (username == password for demo)
    "ops": {"role": "operator", "password": "ops"},
    "audit": {"role": "auditor", "password": "audit"},
    "viewer": {"role": "read_only", "password": "viewer"},
}

# Role hierarchy (higher = more privilege). Used by require_min_role.
_ROLE_RANK = {"read_only": 1, "auditor": 2, "operator": 3, "admin": 4,
              "user": 0}


def role_rank(role: str) -> int:
    return _ROLE_RANK.get(role, 0)


def require_min_role(role: str, required: str) -> None:
    """Raise 403 if `role` has insufficient privilege vs `required`."""
    from ninja.errors import HttpError
    if role_rank(role) < role_rank(required):
        raise HttpError(403, f"role '{required}' or higher required")


def _verify_credentials(username: str, password: str) -> Optional[str]:
    """Return role if credentials are valid, else None."""
    u = DEMO_USERS.get(username)
    if not u:
        return None
    # Constant-time-ish compare (skeleton only).
    if hmac.compare_digest(u["password"], password):
        return u["role"]
    return None


# ---------------------------------------------------------------------------
# JWT (HMAC-SHA256, stdlib only)
# ---------------------------------------------------------------------------
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _sign(header_b64: str, payload_b64: str) -> str:
    secret = settings.JWT_SECRET.encode("utf-8")
    msg = f"{header_b64}.{payload_b64}".encode("utf-8")
    sig = hmac.new(secret, msg, hashlib.sha256).digest()
    return _b64url(sig)


def create_token(user_id: str, role: str, exp_seconds: Optional[int] = None) -> str:
    exp = int(time.time()) + (exp_seconds or settings.JWT_EXP_SECONDS)
    header = {"alg": settings.JWT_ALGORITHM, "typ": "JWT"}
    payload = {"sub": user_id, "role": role, "exp": exp, "iat": int(time.time())}
    h = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    s = _sign(h, p)
    return f"{h}.{p}.{s}"


def decode_token(token: str) -> Optional[Tuple[str, str]]:
    """Return (user_id, role) if valid+unexpired, else None."""
    try:
        h, p, s = token.split(".")
    except ValueError:
        return None
    expected = _sign(h, p)
    if not hmac.compare_digest(expected, s):
        return None
    try:
        payload = json.loads(_b64url_decode(p))
    except Exception:
        return None
    if payload.get("exp", 0) < int(time.time()):
        return None
    return (payload.get("sub"), payload.get("role"))


def authenticate(username: str, password: str) -> Optional[str]:
    """Validate credentials and return a signed JWT, or None."""
    role = _verify_credentials(username, password)
    if not role:
        return None
    return create_token(username, role)