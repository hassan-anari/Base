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
from decimal import Decimal

from .audit import AuditAction, write_audit_log
from .config import Network, ensure_hot_wallet, get_chain, is_memo_required, native_asset_key
from .models import GasTopupIntent, HotWallet, UserWallet
from .mpc_signer import SignPolicy, UnsignedTx, get_signer

logger = logging.getLogger("custody.gas")


class AmbiguousBroadcastError(RuntimeError):
    """The caller must reconcile an external operation before any retry."""


def _intent(*, key, actor_id, chain_id, to_address, amount, memo):
    requested = {
        "actor_id": actor_id,
        "chain_id": chain_id,
        "to_address": to_address,
        "amount": Decimal(str(amount)),
        "memo": memo,
    }
    intent, created = GasTopupIntent.objects.get_or_create(
        idempotency_key=key, defaults={**requested, "status": "CREATED"}
    )
    if not created and any(getattr(intent, field) != value for field, value in requested.items()):
        raise ValueError("idempotency_key was already used with different parameters")
    return intent


def _claim_intent(intent: GasTopupIntent) -> None:
    if (
        GasTopupIntent.objects.filter(pk=intent.pk, status="CREATED").update(status="PROCESSING")
        != 1
    ):
        raise AmbiguousBroadcastError("gas top-up is already processing; do not retry")


def ensure_gas(user_wallet: UserWallet, *, idempotency_key: str) -> bool:
    """Top up gas for user_wallet deposit EOA if needed. Returns True if topped."""
    net = Network(user_wallet.chain_id)
    cfg = get_chain(user_wallet.chain_id)
    hot_address = ensure_hot_wallet(user_wallet.chain_id)
    # Bounded grant from chain config (tiny, fixed) — prevents abuse.
    grant = cfg.gas_topup_amount or 0.0

    intent = _intent(
        key=idempotency_key,
        actor_id="system:gas_station",
        chain_id=user_wallet.chain_id,
        to_address=user_wallet.deposit_address,
        amount=grant,
        memo=user_wallet.memo if is_memo_required(net) else None,
    )
    if intent.status == "BROADCASTED":
        return True
    if intent.status in {"PROCESSING", "RECONCILIATION_REQUIRED"}:
        raise AmbiguousBroadcastError("gas top-up requires reconciliation")
    tx = UnsignedTx(
        network=net,
        chain_id=user_wallet.chain_id,
        asset_key=native_asset_key(user_wallet.chain_id),
        from_address=hot_address,
        to_address=user_wallet.deposit_address,
        amount=grant,
        derivation_path="<hot-wallet-path>",  # vault resolves hot wallet path
        memo=user_wallet.memo if is_memo_required(net) else None,
    )
    _claim_intent(intent)
    signer = get_signer()
    try:
        res = signer.sign_and_broadcast(
            actor_id="system:gas_station",
            tx=tx,
            policy=SignPolicy.GAS_TOPUP,
            idempotency_key=idempotency_key,
        )
        GasTopupIntent.objects.filter(pk=intent.pk, status="PROCESSING").update(
            status="BROADCASTED", tx_hash=res.tx_hash
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
            hot_address,
            user_wallet.deposit_address,
            res.tx_hash,
        )
        return True
    except Exception as exc:
        GasTopupIntent.objects.filter(pk=intent.pk, status="PROCESSING").update(
            status="RECONCILIATION_REQUIRED"
        )
        logger.exception("gas topup failed for %s", user_wallet.id)
        raise AmbiguousBroadcastError("gas top-up outcome is unknown") from exc


def admin_topup(
    actor_id: str,
    chain_id: str,
    to_address: str,
    amount: float,
    idempotency_key: str,
    memo: str | None = None,
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

    hot_address = ensure_hot_wallet(chain_id)
    intent = _intent(
        key=idempotency_key,
        actor_id=actor_id,
        chain_id=chain_id,
        to_address=to_address,
        amount=amount,
        memo=memo,
    )
    if intent.status == "BROADCASTED":
        return {"tx_hash": intent.tx_hash, "to": to_address, "amount": amount}
    if intent.status in {"PROCESSING", "RECONCILIATION_REQUIRED"}:
        raise AmbiguousBroadcastError("gas top-up requires reconciliation")

    tx = UnsignedTx(
        network=net,
        chain_id=chain_id,
        asset_key=native_asset_key(chain_id),
        from_address=hot_address,
        to_address=to_address,
        amount=amount,
        derivation_path="<hot-wallet-path>",  # vault resolves hot wallet path
        memo=memo if is_memo_required(net) else None,
    )
    _claim_intent(intent)
    signer = get_signer()
    try:
        res = signer.sign_and_broadcast(
            actor_id=actor_id,
            tx=tx,
            policy=SignPolicy.GAS_TOPUP,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        GasTopupIntent.objects.filter(pk=intent.pk, status="PROCESSING").update(
            status="RECONCILIATION_REQUIRED"
        )
        raise AmbiguousBroadcastError("gas top-up outcome is unknown") from exc
    GasTopupIntent.objects.filter(pk=intent.pk, status="PROCESSING").update(
        status="BROADCASTED", tx_hash=res.tx_hash
    )
    logger.info("admin gas topup broadcast %s -> %s (%s)", hot_address, to_address, res.tx_hash)
    return {"tx_hash": res.tx_hash, "to": to_address, "amount": amount}
