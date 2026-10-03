"""
HD-style deterministic deposit address derivation.

Design goals
------------
- Each user deterministically gets a UNIQUE deposit EOA address per network.
- The derivation path scheme (BIP-44 style semantics):

      m / purpose' / exchange' / userIndex / addressIndex

  where:
    - purpose'      : fixed per network (e.g. 44' for ETH/BSC/TRX, 501' for SOL,
                      396' for TON) -- hardened
    - exchange'     : fixed hardened index identifying THIS exchange
    - userIndex     : per-user sequential id (hardened)
    - addressIndex  : rotateable per-user index (0,1,2,...) for rotation

- For EVM (ETH/BSC) and TRX we derive an *externally-owned account* (EOA)
  public address. For SOL we derive an Ed25519 system-account pubkey (EOA
  equivalent). For TON we derive a raw workchain-0 wallet (EOA equivalent).
- CRITICAL: the address returned to the user is ALWAYS an EOA, never a
  smart-contract address. The "smart contract" concept (e.g. ERC-4337) is
  explicitly avoided for user deposit addresses.

- Rotation strategy:
    * Start with addressIndex = 0.
    * If an address is exhausted/compromised/"retired", bump to
      addressIndex + 1 deterministically and mark the old record as
      status = RETIRED. The new address is still an EOA.

NOTE: This skeleton shows the *semantics*. A production system delegates the
actual key generation/material to the MPC signer (vault). Django never holds
raw private keys. Here we compute the *public* address from a published
extended public key (xpub / on-chain verified) or ask the MPC vault for the
derived EOA address via an adapter call. We stub the adapter call.
"""

import hashlib
from dataclasses import dataclass
from enum import StrEnum

from .chain_adapters import get_adapter

EXCHANGE_HARDENED_INDEX = 0  # identifies this exchange

# Per-network purpose' value (hardened). Mirrors SLIP-44-ish assignment.
HARDENED = 0x80000000  # BIP-32 hardened offset


class AddressStatus(StrEnum):
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"


@dataclass(frozen=True)
class DerivedAddress:
    chain_id: str
    deposit_address: str  # the EOA address shown to the user
    derivation_path: str  # e.g. "m/44'/0'/12'/0"
    address_index: int


def build_derivation_path(
    chain_id: str, user_index: int, address_index: int, asset_key: str | None = None
) -> str:
    """Return the BIP-32 style path string (display + storage).

    Includes an asset-specific hardened salt so each (chain, asset) gets a
    distinct deterministic EOA while remaining reproducible.
    """
    purpose = get_adapter(chain_id).derivation_purpose
    asset_salt = _asset_salt(asset_key or chain_id)
    # hardened indices are denoted with a trailing '
    return f"m/{purpose}'/{EXCHANGE_HARDENED_INDEX}'/{user_index}'/{address_index}'/{asset_salt}'"


def _asset_salt(asset_key: str) -> int:
    """Fold an asset key into a stable integer salt for path derivation."""
    return (int.from_bytes(hashlib.sha256(asset_key.encode()).digest()[:4], "big") % 100000) + 1


def derive_deposit_address(
    chain_id: str,
    user_index: int,
    address_index: int = 0,
    *,
    asset_key: str | None = None,
    mpc_adapter=None,
) -> DerivedAddress:
    """Derive a deposit EOA address for (user, network, asset, index).

    The actual EOA address is produced by the MPC vault adapter which owns the
    master key. Django passes the path; the adapter returns the EOA address.
    We stub the adapter call below; in production, replace ``_stub_eoa`` with
    ``mpc_adapter.get_derived_address(network, derivation_path)``.

    SECURITY:
      - Never returns a contract address. Adapters MUST return EOAs.
      - Validate the returned address format per network before persisting.
    """
    path = build_derivation_path(chain_id, user_index, address_index, asset_key)
    eoa = _resolve_eoa(chain_id, path, mpc_adapter)
    get_adapter(chain_id).validate_address(eoa, custody_derived=True)
    return DerivedAddress(
        chain_id=chain_id,
        deposit_address=eoa,
        derivation_path=path,
        address_index=address_index,
    )


def stable_user_index(user_id: str) -> int:
    """Deterministic, cross-process-stable mapping user_id -> uint31.

    Uses SHA-256 (NOT Python's hash(), which is salted per process) so the
    same user always maps to the same HD userIndex across restarts/workers.
    """
    digest = hashlib.sha256(user_id.encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big") % (2**31)


def _resolve_eoa(chain_id: str, path: str, mpc_adapter=None) -> str:
    """Ask the MPC vault for the EOA address at ``path``.

    In production this calls the vendor adapter (Fireblocks/Turnkey/Lit/...)
    which holds the root key and returns a *standard* single-signer EOA for
    that path. We never handle raw key material here.

    If no adapter is injected we lazily load the configured one
    (LocalVault in dev / VendorSignerAdapter in prod). TON derivation is
    vendor-side and raises NotImplementedError until a vendor is wired.
    """
    if mpc_adapter is None:
        from .signer_adapter import get_adapter

        mpc_adapter = get_adapter()
    return mpc_adapter.get_derived_address(chain_id, path)
