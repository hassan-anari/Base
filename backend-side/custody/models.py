"""
Custody data models (PostgreSQL-backed ledger/state).

Models
------
- UserWallet      : user_id -> network -> derivation_path -> deposit EOA address
- Deposit         : parsed on-chain deposit events (indexer-driven)
- WithdrawalRequest : user-initiated withdrawal, gated by admin approval
- HotWallet       : pre-determined custody hot wallet address per network
- SweepJob        : EOA -> hot wallet sweep state machine
- AdminActionLog  : immutable audit trail

Status enums are defined inline. Unique constraints enforce idempotency for
sweeps/withdrawals (see Meta). Indexes support fast lookups by address/user.
"""
from __future__ import annotations

from django.db import models


class Asset(models.Model):
    """Catalog of supported assets (native coins + tokens like USDT).

    This is the single place to "add a token on a chain". Populated from
    ``config.DEFAULT_ASSETS`` at startup; admins can also add rows.
    """
    asset_key = models.CharField(max_length=32, unique=True)   # "USDT-BSC"
    chain_id = models.CharField(max_length=16, db_index=True)  # "BSC"
    symbol = models.CharField(max_length=16)
    decimals = models.PositiveIntegerField(default=18)
    is_native = models.BooleanField(default=False)
    contract_address = models.CharField(max_length=128, null=True, blank=True)
    deposit_threshold = models.DecimalField(max_digits=40, decimal_places=18,
                                            null=True, blank=True)
    enabled = models.BooleanField(default=True)

    def __str__(self) -> str:
        return f"Asset({self.asset_key},{self.symbol})"


class UserWallet(models.Model):
    """A user's deposit EOA address for a given (chain, asset).

    deposit_address is ALWAYS an EOA (never a contract). The derivation_path
    is stored so we can rotate (addressIndex+1) deterministically.
    """
    STATUS = [("ACTIVE", "ACTIVE"), ("RETIRED", "RETIRED")]

    user_id = models.CharField(max_length=64, db_index=True)
    chain_id = models.CharField(max_length=16, db_index=True)   # "ETH"/"BASE"
    asset_key = models.CharField(max_length=32, db_index=True)  # "ETH"/"USDT-BSC"
    # Unique within a user+chain+asset; guard against collisions across assets.
    derivation_path = models.CharField(max_length=64, db_index=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["user_id", "chain_id", "asset_key", "derivation_path"],
                name="uq_user_chain_asset_derivation_path",
            ),
            models.UniqueConstraint(
                fields=["user_id", "chain_id", "asset_key", "address_index"],
                name="uq_user_chain_asset_addrindex",
            ),
            models.UniqueConstraint(
                fields=["deposit_address", "chain_id", "asset_key"],
                name="uq_deposit_address_chain_asset",
            ),
        ]
        indexes = [
            models.Index(fields=["user_id", "chain_id", "status"]),
        ]
    deposit_address = models.CharField(max_length=128, db_index=True)
    # TON memo attribution (optional). For TON this binds the user on-chain.
    memo = models.CharField(max_length=128, null=True, blank=True)
    address_index = models.PositiveIntegerField(default=0)
    status = models.CharField(max_length=16, choices=STATUS, default="ACTIVE")
    created_at = models.DateTimeField(auto_now_add=True)
    # Indexer scan metadata
    last_scanned_at = models.DateTimeField(null=True, blank=True)
    last_scanned_block = models.BigIntegerField(null=True, blank=True)

    def __str__(self) -> str:
        return f"UserWallet({self.user_id},{self.chain_id},{self.asset_key})"


class Deposit(models.Model):
    """A confirmed (or pending) on-chain deposit parsed by the indexer."""
    user_wallet = models.ForeignKey(UserWallet, on_delete=models.PROTECT,
                                     related_name="deposits")
    asset_key = models.CharField(max_length=32, db_index=True)
    tx_hash = models.CharField(max_length=128, db_index=True)
    amount = models.DecimalField(max_digits=40, decimal_places=18)
    block = models.BigIntegerField(null=True, blank=True)
    confirmations = models.PositiveIntegerField(default=0)
    parsed_at = models.DateTimeField(auto_now_add=True)
    # TON memo (echoed for attribution / reorg backfill).
    memo = models.CharField(max_length=128, null=True, blank=True)
    # Deposit status: PENDING (below confirmation threshold) -> CONFIRMED -> REVERTED (reorg)
    DEPOSIT_STATUS = [
        ("PENDING", "PENDING"),
        ("CONFIRMED", "CONFIRMED"),
        ("REVERTED", "REVERTED"),
    ]
    status = models.CharField(max_length=16, choices=DEPOSIT_STATUS, default="PENDING")

    class Meta:
        constraints = [
            # Idempotency: do not double-count the same deposit tx for a wallet.
            models.UniqueConstraint(
                fields=["user_wallet", "tx_hash", "asset_key"],
                name="uq_deposit_wallet_tx_asset",
            ),
        ]


class WithdrawalRequest(models.Model):
    """User withdrawal request. No broadcast until admin APPROVES."""
    STATUS = [
        ("PENDING_APPROVAL", "PENDING_APPROVAL"),
        ("APPROVED", "APPROVED"),
        ("DENIED", "DENIED"),
        ("BROADCASTED", "BROADCASTED"),
        ("CONFIRMED", "CONFIRMED"),
        ("FAILED", "FAILED"),
    ]

    user_id = models.CharField(max_length=64, db_index=True)
    chain_id = models.CharField(max_length=16, db_index=True)
    asset_key = models.CharField(max_length=32, db_index=True)
    to_address = models.CharField(max_length=128)
    amount = models.DecimalField(max_digits=40, decimal_places=18)
    status = models.CharField(max_length=16, choices=STATUS, default="PENDING_APPROVAL")
    admin_notes = models.TextField(null=True, blank=True)
    tx_hash = models.CharField(max_length=128, null=True, blank=True, db_index=True)
    # Idempotency key so retries of the same user request don't create dupes.
    idempotency_key = models.CharField(max_length=64, unique=True, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["user_id", "status"]),
            models.Index(fields=["status"]),
        ]


class HotWallet(models.Model):
    """Pre-determined custody hot wallet address per chain (MPC-controlled)."""
    chain_id = models.CharField(max_length=16, unique=True)
    address = models.CharField(max_length=128)

    def __str__(self) -> str:
        return f"HotWallet({self.chain_id},{self.address})"


class SweepJob(models.Model):
    """EOA -> hot wallet sweep job (state machine).

    State machine:
      CREATED -> GAS_TOPUP_REQUIRED? -> SWEEP_BROADCASTED -> CONFIRMED / FAILED

    Idempotency strategy:
      - unique (user_wallet_id, sweep_round) prevents duplicate sweeps for the
        same balance-check round.
      - repeated "Check Balance" calls recompute but must not create a new
        SWEEP_BROADCASTED job if one already exists for this round.
    """
    STATUS = [
        ("CREATED", "CREATED"),
        ("GAS_TOPUP_REQUIRED", "GAS_TOPUP_REQUIRED"),
        ("GAS_TOPUP_BROADCASTED", "GAS_TOPUP_BROADCASTED"),
        ("SWEEP_BROADCASTED", "SWEEP_BROADCASTED"),
        ("CONFIRMED", "CONFIRMED"),
        ("FAILED", "FAILED"),
    ]

    user_wallet = models.ForeignKey(UserWallet, on_delete=models.PROTECT,
                                    related_name="sweeps")
    asset_key = models.CharField(max_length=32, db_index=True)
    sweep_round = models.PositiveIntegerField(default=1)
    balance_snapshot = models.DecimalField(max_digits=40, decimal_places=18,
                                           null=True, blank=True)
    deposit = models.ForeignKey(Deposit, null=True, blank=True, on_delete=models.SET_NULL)
    status = models.CharField(max_length=24, choices=STATUS, default="CREATED")
    tx_hash = models.CharField(max_length=128, null=True, blank=True, db_index=True)
    idempotency_key = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["user_wallet", "asset_key", "sweep_round"],
                name="uq_sweep_wallet_asset_round",
            ),
        ]


class AdminActionLog(models.Model):
    """Append-style audit trail for all sensitive actions."""
    actor_id = models.CharField(max_length=64, db_index=True)
    action_type = models.CharField(max_length=32, db_index=True)
    entity_type = models.CharField(max_length=32)
    entity_id = models.CharField(max_length=128, db_index=True)
    metadata = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["actor_id", "created_at"]),
            models.Index(fields=["action_type", "created_at"]),
        ]
