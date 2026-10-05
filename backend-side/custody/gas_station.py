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

from django.conf import settings

from .audit import AuditAction, write_audit_log
from .config import ensure_hot_wallet, get_chain, is_memo_required, native_asset_key
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


def _execute_live(intent, actor_id, source, asset_key):
    from .native_tx import AmbiguousBroadcast, SafePreBroadcastRejection
    from .outbound import create_attempt, execute_attempt

    attempt = create_attempt(
        operation_type="GAS_TOPUP",
        operation_id=intent.pk,
        chain_id=intent.chain_id,
        asset_key=asset_key,
        source=source,
        destination=intent.to_address,
        amount=intent.amount,
    )
    try:
        attempt = execute_attempt(attempt.pk, actor_id)
    except AmbiguousBroadcast as exc:
        GasTopupIntent.objects.filter(pk=intent.pk).update(status="RECONCILIATION_REQUIRED")
        raise AmbiguousBroadcastError(str(exc)) from exc
    except SafePreBroadcastRejection:
        GasTopupIntent.objects.filter(pk=intent.pk).update(status="CREATED", tx_hash=None)
        raise
    except Exception:
        attempt.refresh_from_db()
        GasTopupIntent.objects.filter(pk=intent.pk).update(
            status="FAILED" if attempt.status == "FAILED" else "RECONCILIATION_REQUIRED"
        )
        raise
    GasTopupIntent.objects.filter(pk=intent.pk).update(
        status="BROADCASTED", tx_hash=attempt.network_tx_id
    )
    return attempt


def ensure_gas(user_wallet: UserWallet, *, idempotency_key: str) -> bool:
    """Top up gas for user_wallet deposit EOA if needed. Returns True if topped."""
    intent = get_or_create_gas_intent(user_wallet, idempotency_key=idempotency_key)
    return execute_gas_intent(intent.pk)


def get_or_create_gas_intent(user_wallet: UserWallet, *, idempotency_key: str) -> GasTopupIntent:
    """Persist a reviewed gas grant without signing or broadcasting it."""
    cfg = get_chain(user_wallet.chain_id)
    grant = cfg.gas_topup_amount
    if grant <= 0:
        raise ValueError("positive reviewed gas top-up amount is required")
    return _intent(
        key=idempotency_key,
        actor_id="system:gas_station",
        chain_id=user_wallet.chain_id,
        to_address=user_wallet.deposit_address,
        amount=grant,
        memo=user_wallet.memo if is_memo_required(user_wallet.chain_id) else None,
    )


def execute_gas_intent(intent_id: int) -> bool:
    """Claim and execute an already-durable gas intent, outside caller transactions."""
    intent = GasTopupIntent.objects.get(pk=intent_id)
    if intent.status == "CONFIRMED":
        return True
    if intent.status == "BROADCASTED":
        return False
    if intent.status in {"PROCESSING", "RECONCILIATION_REQUIRED"}:
        raise AmbiguousBroadcastError("gas top-up requires reconciliation")
    if intent.status == "FAILED":
        raise ValueError("failed gas top-up requires a new idempotency key")
    hot_address = ensure_hot_wallet(intent.chain_id)
    tx = UnsignedTx(
        chain_id=intent.chain_id,
        asset_key=native_asset_key(intent.chain_id),
        from_address=hot_address,
        to_address=intent.to_address,
        amount=intent.amount,
        derivation_path=_hot_signing_ref(intent.chain_id),
        memo=intent.memo if is_memo_required(intent.chain_id) else None,
    )
    _claim_intent(intent)
    if settings.CUSTODY_TX_MODE == "live":
        _execute_live(intent, "system:gas_station", hot_address, native_asset_key(intent.chain_id))
        return False
    signer = get_signer()
    try:
        res = signer.sign_and_broadcast(
            actor_id="system:gas_station",
            tx=tx,
            policy=SignPolicy.GAS_TOPUP,
            idempotency_key=intent.idempotency_key,
        )
        GasTopupIntent.objects.filter(pk=intent.pk, status="PROCESSING").update(
            status="BROADCASTED", tx_hash=res.tx_hash
        )
        write_audit_log(
            "system:gas_station",
            AuditAction.GAS_TOPUP,
            "UserWallet",
            str(intent.id),
            {"tx": res.tx_hash},
        )
        logger.info(
            "gas topup broadcast %s -> %s (%s)",
            hot_address,
            intent.to_address,
            res.tx_hash,
        )
        return False
    except Exception as exc:
        GasTopupIntent.objects.filter(pk=intent.pk, status="PROCESSING").update(
            status="RECONCILIATION_REQUIRED"
        )
        logger.exception("gas topup failed for intent %s", intent.id)
        raise AmbiguousBroadcastError("gas top-up outcome is unknown") from exc


def admin_topup(
    actor_id: str,
    chain_id: str,
    to_address: str,
    amount: Decimal,
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
    amount = Decimal(str(amount))

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
    if intent.status in {"BROADCASTED", "CONFIRMED"}:
        return {"tx_hash": intent.tx_hash, "to": to_address, "amount": amount}
    if intent.status in {"PROCESSING", "RECONCILIATION_REQUIRED"}:
        raise AmbiguousBroadcastError("gas top-up requires reconciliation")
    if intent.status == "FAILED":
        raise ValueError("failed gas top-up requires a new idempotency key")

    tx = UnsignedTx(
        chain_id=chain_id,
        asset_key=native_asset_key(chain_id),
        from_address=hot_address,
        to_address=to_address,
        amount=amount,
        derivation_path=_hot_signing_ref(chain_id),
        memo=memo if is_memo_required(chain_id) else None,
    )
    _claim_intent(intent)
    if settings.CUSTODY_TX_MODE == "live":
        attempt = _execute_live(intent, actor_id, hot_address, native_asset_key(chain_id))
        return {"tx_hash": attempt.network_tx_id, "to": to_address, "amount": amount}
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


def _hot_signing_ref(chain_id: str) -> str:
    key_ref = HotWallet.objects.get(chain_id=chain_id).signing_key_ref
    if not key_ref:
        raise ValueError("hot wallet signing_key_ref is not configured")
    return key_ref
