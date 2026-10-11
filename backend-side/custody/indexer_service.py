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
from .chain_registry import ChainKind, get_chain_spec
from .config import (
    effective_deposit_threshold,
    get_chain,
    is_memo_required,
    validate_chain_asset,
)
from .deposits import ingest_event
from .indexer.factory import get_indexer
from .models import UserWallet
from .sweeper import trigger_sweep

logger = logging.getLogger("custody.indexer_service")

# Actor ID for system-initiated actions
SYSTEM_ACTOR = "indexer-service"


def scan_wallet(user_wallet: UserWallet, *, actor_id=SYSTEM_ACTOR) -> dict:
    """Scan a single wallet for deposits. Returns scan result dict.

    This is the core indexer logic for one wallet:
      1. Query indexer for balance + deposit events
      2. Persist new deposits (idempotent)
      3. Update confirmation status
      4. If balance > threshold, trigger gas + sweep
    """
    result = {
        "wallet_id": user_wallet.id,
        "address": user_wallet.deposit_address,
        "network": user_wallet.chain_id,
        "new_deposits": 0,
        "confirmed_balance": Decimal("0"),
        "sweep_triggered": False,
        "sweep_job_id": None,
        "reason": "",
        "outcome": "pending",
    }

    try:
        asset = validate_chain_asset(user_wallet.chain_id, user_wallet.asset_key, "deposit")
        if asset.token_standard == "SPL":
            from .spl import derive_ata

            expected_ata = derive_ata(user_wallet.deposit_address, asset.contract_address)
            if user_wallet.asset_account_address != expected_ata:
                raise ValueError("stored SPL asset account is not the canonical ATA")
        if user_wallet.chain_id == "TON" and user_wallet.mpc_keyset_id:
            from .ton_indexer import scan_ton_wallet

            return scan_ton_wallet(user_wallet)
        cfg = get_chain(user_wallet.chain_id)
        threshold = effective_deposit_threshold(asset, cfg)
    except ValueError as exc:
        result["outcome"] = "unsupported"
        result["reason"] = f"deposit scanning unsupported: {exc}"
        return result

    try:
        indexer = get_indexer(user_wallet.chain_id)
        scan_options = {}
        if get_chain_spec(user_wallet.chain_id).kind == ChainKind.EVM:
            scan_options["after_block_hash"] = user_wallet.evm_scan_block_hash
        try:
            bal = indexer.get_balance(
                user_wallet.deposit_address,
                asset_key=user_wallet.asset_key,
                after_block=user_wallet.last_scanned_block,
                memo=user_wallet.memo if is_memo_required(user_wallet.chain_id) else None,
                **scan_options,
            )
        except TypeError as exc:
            # Temporary compatibility for externally supplied Phase 4 clients.
            if (
                "unexpected keyword argument" not in str(exc)
                or not asset.is_native
                or user_wallet.mpc_keyset_id
            ):
                raise
            bal = indexer.get_balance(
                user_wallet.deposit_address,
                memo=user_wallet.memo if is_memo_required(user_wallet.chain_id) else None,
            )
    except Exception as e:
        logger.warning(
            "indexer query failed for %s (%s): %s",
            user_wallet.deposit_address,
            user_wallet.chain_id,
            e,
        )
        result["reason"] = f"indexer error: {e}"
        result["outcome"] = "indexer_unavailable"
        return result

    confirmed = Decimal(str(bal.confirmed_balance))
    result["confirmed_balance"] = confirmed

    # Commit event journals and cursor together; a crash cannot skip uncredited history.
    with transaction.atomic():
        locked = UserWallet.objects.select_for_update().get(pk=user_wallet.pk)
        if (
            locked.solana_scan_cursor != user_wallet.solana_scan_cursor
            or locked.last_scanned_block != user_wallet.last_scanned_block
            or locked.evm_scan_block_hash != user_wallet.evm_scan_block_hash
        ):
            result["reason"] = "another scanner advanced this wallet; retry from durable cursor"
            return result
        if hasattr(bal, "minimum_confirmations"):
            from ops.models import Chain

            chain = Chain.objects.select_for_update().get(chain_id=user_wallet.chain_id)
            if chain.min_confirmations != bal.minimum_confirmations:
                result["reason"] = "confirmation policy changed during EVM history scan; retry"
                result["outcome"] = "indexer_unavailable"
                return result
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
                    actor_id,
                    AuditAction.DEPOSIT_DETECTED,
                    "Deposit",
                    str(deposit.id),
                    {
                        "wallet": user_wallet.deposit_address,
                        "tx_hash": ev.tx_hash,
                        "amount": str(ev.amount),
                    },
                )
        user_wallet.last_scanned_at = timezone.now()
        if bal.last_scanned_block is not None:
            user_wallet.last_scanned_block = bal.last_scanned_block
        if hasattr(bal, "evm_scan_block_hash"):
            user_wallet.evm_scan_block_hash = bal.evm_scan_block_hash
        if hasattr(bal, "scan_cursor"):
            user_wallet.solana_scan_cursor = bal.scan_cursor
        user_wallet.save(
            update_fields=[
                "last_scanned_at",
                "last_scanned_block",
                "evm_scan_block_hash",
                "solana_scan_cursor",
            ]
        )

    if not getattr(bal, "scan_complete", True):
        result["reason"] = "bounded historical backfill continues from durable cursor"
        result["outcome"] = "backfill"
        return result

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
            user_wallet, actor_id=actor_id, balance_result=bal
        )
        result["sweep_triggered"] = triggered
        result["sweep_job_id"] = job_id
        result["reason"] = reason
        result["outcome"] = "sweep"
    else:
        result["reason"] = "balance below threshold"
        result["outcome"] = "scanned"

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
        try:
            result = scan_wallet(wallet)
        except Exception as exc:  # isolate a malformed wallet from the batch
            logger.exception("wallet scan failed wallet=%s", wallet.id)
            result = {
                "wallet_id": wallet.id,
                "address": wallet.deposit_address,
                "network": wallet.chain_id,
                "new_deposits": 0,
                "confirmed_balance": Decimal("0"),
                "sweep_triggered": False,
                "sweep_job_id": None,
                "reason": f"wallet scan error: {exc}",
                "outcome": "error",
            }
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
