"""
Compliance screening integration point.

Wraps the `ops.Blocklist` registry (single source of truth for hotlists).
Called from deposit provisioning + withdrawal creation. Lazy-imports
`ops.models` to avoid a hard custody<->ops import cycle at module load.

Scopes:
  DEPOSIT_ADDRESS  -> a generated deposit EOA that must not be used
  WITHDRAW_ADDRESS -> an outgoing withdrawal destination that is blocked
  CHAIN_ASSET      -> a (chain, asset) pair disabled by compliance

This is the pluggable AML/KYC boundary: a real deployment would additionally
fan out to an external screening provider (Chainalysis/Elliptic) via the hook
registered in `custody.audit.register_aml_kyc_hook`.
"""
from __future__ import annotations

from typing import Optional

from ninja.errors import HttpError


def _is_blocked(scope: str, value: str, chain_id: str, asset_key: str) -> bool:
    """Return True if a matching enabled Blocklist row exists.

    CHAIN_ASSET matches on (chain_id, asset_key). Other scopes match on the
    exact (scope, value) pair; a row with blank chain_id/asset_key applies to
    all chains/assets.
    """
    from ops.models import Blocklist

    qs = Blocklist.objects.filter(scope=scope, enabled=True)
    if scope == "CHAIN_ASSET":
        return qs.filter(chain_id=chain_id, asset_key=asset_key).exists()
    qs = qs.filter(value=value)
    return qs.filter(chain_id__in=["", chain_id]).filter(
        asset_key__in=["", asset_key]).exists()


def check_withdrawal_target(to_address: str, chain_id: str, asset_key: str) -> None:
    """Raise 403 if the outgoing destination is blocked by compliance."""
    if _is_blocked("WITHDRAW_ADDRESS", to_address, chain_id, asset_key):
        raise HttpError(403, "destination address is blocked by compliance")
    if _is_blocked("CHAIN_ASSET", "", chain_id, asset_key):
        raise HttpError(403, "asset/chain disabled by compliance policy")


def check_deposit_asset(chain_id: str, asset_key: str) -> None:
    """Raise 403 if the deposit (chain, asset) pair is disabled by compliance."""
    if _is_blocked("CHAIN_ASSET", "", chain_id, asset_key):
        raise HttpError(403, "asset/chain disabled by compliance policy")