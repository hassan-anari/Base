"""
Gas Station: top-up a user's deposit EOA with native gas so it can broadcast
the sweep transaction (some UTXO/account models require the sending EOA to pay
gas). For account-based chains (ETH/BSC/TRX) the deposit EOA must hold gas to
emit the sweep; for SOL/TON the custody hot wallet can pay fees instead.

This is triggered by the sweeper when a gas check fails.

Flow:
  1. Check deposit EOA native balance via indexer.
  2. If below gas floor -> build GAS_TOPUP UnsignedTx from hot wallet EOA ->
     user deposit EOA.
  3. sign_and_broadcast(policy=GAS_TOPUP, idempotency_key=...).
  4. Record audit (GAS_TOPUP).

Operator manual top-up (admin):
  - POST /api/gas-station/topup  ->  admin-triggered top-up for a station.
  - Validates amount > 0, destination is a known hot wallet / deposit EOA.
  - Rate-limited + audited like every other signing request.

SECURITY: amount is a tiny fixed gas grant (auto) or admin-bounded amount;
never logs secrets; every signing request is authorized + validated + audited.
"""

from __future__ import annotations

import logging

from .audit import AuditAction, write_audit_log
from .config import Network, get_chain, is_memo_required, native_asset_key
from .models import HotWallet, UserWallet
from .mpc_signer import SignPolicy, UnsignedTx, get_signer

logger = logging.getLogger("custody.gas")


def ensure_gas(user_wallet: UserWallet) -> bool:
    """Top up gas for user_wallet deposit EOA if needed. Returns True if topped."""
    net = Network(user_wallet.chain_id)
    cfg = get_chain(user_wallet.chain_id)
    hot = HotWallet.objects.get(chain_id=user_wallet.chain_id)
    # Bounded grant from chain config (tiny, fixed) — prevents abuse.
    grant = cfg.gas_topup_amount or 0.0

    idem = f"gas_topup:{user_wallet.id}:{user_wallet.chain_id}"
    tx = UnsignedTx(
        network=net,
        chain_id=user_wallet.chain_id,
        asset_key=native_asset_key(user_wallet.chain_id),
        from_address=hot.address,
        to_address=user_wallet.deposit_address,
        amount=grant,
        derivation_path="<hot-wallet-path>",  # vault resolves hot wallet path
        memo=user_wallet.memo if is_memo_required(net) else None,
    )
    signer = get_signer()
    try:
        res = signer.sign_and_broadcast(
            actor_id="system:gas_station",
            tx=tx,
            policy=SignPolicy.GAS_TOPUP,
            idempotency_key=idem,
        )
        write_audit_log(
            "system:gas_station",
            AuditAction.GAS_TOPUP,
            "UserWallet",
            str(user_wallet.id),
            {"tx": res.tx_hash},
        )
        logger.info(
            "gas topup broadcast %s -> %s (%s)",
            hot.address,
            user_wallet.deposit_address,
            res.tx_hash,
        )
        return True
    except Exception:
        logger.exception("gas topup failed for %s", user_wallet.id)
        return False


def admin_topup(
    actor_id: str, chain_id: str, to_address: str, amount: float, memo: str | None = None
) -> dict:
    """Operator/admin manual top-up of a gas-station address.

    SECURITY / GUARD POINTS (enforced before signing):
      - amount must be > 0 and bounded by chain gas_topup_max (anti-abuse).
      - destination must be a known hot wallet or an active user deposit EOA
        for the chain (prevents sending funds to an arbitrary address).
      - caller is authorized + rate-limited inside the signer (GAS_TOPUP policy).
      - fully audited (SIGN_REQUEST + BROADCAST).

    Returns {"tx_hash": ..., "to": ..., "amount": ...}.
    """
    cfg = get_chain(chain_id)
    net = Network(chain_id)

    # ---- Validation: amount > 0 + bounded ceiling ----
    if amount <= 0:
        raise ValueError("amount must be > 0")
    max_grant = getattr(cfg, "gas_topup_max", None) or (cfg.gas_topup_amount or 0) * 10
    if amount > max_grant:
        raise ValueError(f"amount exceeds gas station ceiling {max_grant}")

    # ---- Validation: destination must be a known custody address ----
    # Accept either the chain's hot wallet or an active user deposit EOA.
    known_hot = HotWallet.objects.filter(chain_id=chain_id, address=to_address).exists()
    known_deposit = UserWallet.objects.filter(
        chain_id=chain_id,
        deposit_address=to_address,
        status="ACTIVE",
    ).exists()
    if not (known_hot or known_deposit):
        raise ValueError(
            "destination must be a known hot wallet or active deposit EOA for this chain"
        )

    hot = HotWallet.objects.filter(chain_id=chain_id).first()
    if not hot:
        raise ValueError(f"no hot wallet configured for {chain_id}")

    idem = f"gas_topup:admin:{chain_id}:{to_address}:{amount}"
    tx = UnsignedTx(
        network=net,
        chain_id=chain_id,
        asset_key=native_asset_key(chain_id),
        from_address=hot.address,
        to_address=to_address,
        amount=amount,
        derivation_path="<hot-wallet-path>",  # vault resolves hot wallet path
        memo=memo if is_memo_required(net) else None,
    )
    signer = get_signer()
    res = signer.sign_and_broadcast(
        actor_id=actor_id,
        tx=tx,
        policy=SignPolicy.GAS_TOPUP,
        idempotency_key=idem,
    )
    logger.info("admin gas topup broadcast %s -> %s (%s)", hot.address, to_address, res.tx_hash)
    return {"tx_hash": res.tx_hash, "to": to_address, "amount": amount}
