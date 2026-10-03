"""
Indexer Service — background deposit scanner.

This is the actual indexer service that runs continuously (as a management
command or Celery beat task) to monitor all active user deposit addresses
for incoming deposits.

FLOW:
  1. Scan all ACTIVE UserWallets (grouped by network)
  2. For each wallet, query the indexer client for current balance + deposit events
  3. Persist new deposit events to the Deposit ledger (idempotent via unique constraint)
  4. If confirmed balance > deposit_threshold:
     a. Trigger gas station top-up (if EOA needs gas)
     b. Trigger sweeper (EOA -> hot wallet)
  5. Update wallet.last_scanned_at / last_scanned_block

This service is IDEMPOTENT:
  - Deposit records use unique (user_wallet, tx_hash) constraint
  - SweepJob uses unique (user_wallet, sweep_round) constraint
  - In-flight sweep detection prevents double-sweep

REORG HANDLING:
  - Deposits below confirmation threshold are marked PENDING
  - Once confirmations >= threshold, marked CONFIRMED
  - If a deposit disappears (reorg), it can be marked REVERTED (future)
"""

from __future__ import annotations

import logging
import time
from decimal import Decimal

from django.db import transaction
from django.utils import timezone

from .audit import AuditAction, write_audit_log
from .config import Network, effective_deposit_threshold, get_asset, get_chain, is_memo_required
from .deposits import ingest_event
from .indexer.factory import get_indexer
from .models import UserWallet
from .sweeper import trigger_sweep

logger = logging.getLogger("custody.indexer_service")

# Actor ID for system-initiated actions
SYSTEM_ACTOR = "indexer-service"


def scan_wallet(user_wallet: UserWallet) -> dict:
    """Scan a single wallet for deposits. Returns scan result dict.

    This is the core indexer logic for one wallet:
      1. Query indexer for balance + deposit events
      2. Persist new deposits (idempotent)
      3. Update confirmation status
      4. If balance > threshold, trigger gas + sweep
    """
    net = Network(user_wallet.chain_id)
    cfg = get_chain(user_wallet.chain_id)
    asset = get_asset(user_wallet.asset_key)
    threshold = effective_deposit_threshold(asset, cfg)

    result = {
        "wallet_id": user_wallet.id,
        "address": user_wallet.deposit_address,
        "network": user_wallet.chain_id,
        "new_deposits": 0,
        "confirmed_balance": 0.0,
        "sweep_triggered": False,
        "sweep_job_id": None,
        "reason": "",
    }

    try:
        indexer = get_indexer(net)
        bal = indexer.get_balance(
            user_wallet.deposit_address,
            memo=user_wallet.memo if is_memo_required(net) else None,
        )
    except Exception as e:
        logger.warning(
            "indexer query failed for %s (%s): %s",
            user_wallet.deposit_address,
            user_wallet.chain_id,
            e,
        )
        result["reason"] = f"indexer error: {e}"
        return result

    confirmed = Decimal(str(bal.confirmed_balance))
    result["confirmed_balance"] = float(confirmed)

    # Concrete events, rather than aggregate address balance, back credits.
    for ev in bal.deposit_events:
        deposit, created = ingest_event(user_wallet, ev)
        if created:
            result["new_deposits"] += 1
            logger.info(
                "new deposit: wallet=%s tx=%s amount=%s conf=%s",
                user_wallet.id,
                ev.tx_hash,
                ev.amount,
                ev.confirmations,
            )
            write_audit_log(
                SYSTEM_ACTOR,
                AuditAction.DEPOSIT_DETECTED,
                "Deposit",
                str(deposit.id),
                {
                    "wallet": user_wallet.deposit_address,
                    "tx_hash": ev.tx_hash,
                    "amount": float(ev.amount),
                },
            )
    with transaction.atomic():
        user_wallet.last_scanned_at = timezone.now()
        if bal.last_scanned_block:
            user_wallet.last_scanned_block = bal.last_scanned_block
        user_wallet.save(update_fields=["last_scanned_at", "last_scanned_block"])

    # Check threshold and trigger sweep pipeline
    if confirmed > threshold:
        logger.info(
            "threshold met for wallet=%s balance=%s > %s, triggering sweep",
            user_wallet.id,
            confirmed,
            threshold,
        )

        # Gas station top-up is handled inside trigger_sweep -> _run_sweep
        triggered, job_id, reason = trigger_sweep(
            user_wallet, actor_id=SYSTEM_ACTOR, balance_result=bal
        )
        result["sweep_triggered"] = triggered
        result["sweep_job_id"] = job_id
        result["reason"] = reason
    else:
        result["reason"] = "balance below threshold"

    return result


def scan_all_wallets(networks: list[str] | None = None) -> list[dict]:
    """Scan all active wallets, optionally filtered by network.

    Returns list of scan results.
    """
    qs = UserWallet.objects.filter(status="ACTIVE")
    if networks:
        qs = qs.filter(chain_id__in=networks)

    results = []
    for wallet in qs.iterator(chunk_size=100):
        result = scan_wallet(wallet)
        results.append(result)

    return results


def run_indexer_loop(interval_seconds: int = 30, networks: list[str] | None = None):
    """Main indexer loop. Runs continuously, scanning all wallets each interval.

    In production, this would be a Celery beat task or a dedicated worker.
    For now, it's a simple loop that can be run as a management command.
    """
    logger.info(
        "indexer service starting (interval=%ss, networks=%s)", interval_seconds, networks or "all"
    )

    while True:
        start = time.time()
        try:
            results = scan_all_wallets(networks)
            sweeps = [r for r in results if r["sweep_triggered"]]
            deposits = sum(r["new_deposits"] for r in results)
            logger.info(
                "indexer scan complete: %d wallets, %d new deposits, %d sweeps triggered",
                len(results),
                deposits,
                len(sweeps),
            )
        except Exception as e:
            logger.error("indexer scan error: %s", e, exc_info=True)

        # Sleep for remaining interval
        elapsed = time.time() - start
        sleep_time = max(0, interval_seconds - elapsed)
        if sleep_time > 0:
            time.sleep(sleep_time)
