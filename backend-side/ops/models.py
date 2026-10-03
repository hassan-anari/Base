"""
Ops persistence models for the internal wallet operations platform.

These tables hold operational metadata (chains, assets, nodes), point-in-time
observations (balances, node health), and operational alerting. They are kept
deliberately separate from the custody ledger (`custody` app) to enforce a
clean separation between chain integration/operations and the signing ledger.

All monetary values are stored as Decimal to avoid float drift.
"""
from __future__ import annotations

import uuid
from decimal import Decimal

from django.db import models


def _new_id() -> str:
    return uuid.uuid4().hex[:24]


# ---------------------------------------------------------------------------
# Chain metadata (network onboarding — config-driven, no code change)
# ---------------------------------------------------------------------------
class Chain(models.Model):
    """A supported blockchain network (L1 or EVM-compatible)."""

    chain_id = models.CharField(max_length=16, unique=True)  # ETH, BSC, TON, ...
    display_name = models.CharField(max_length=64)
    kind = models.CharField(
        max_length=16,
        choices=[("evm", "EVM"), ("ton", "TON"), ("tron", "Tron"),
                 ("solana", "Solana"), ("other", "Other")],
        default="evm",
    )
    evm_chain_id = models.IntegerField(null=True, blank=True)  # EVM numeric id
    native_asset_key = models.CharField(max_length=32)         # e.g. BNB for BSC
    is_testnet = models.BooleanField(default=True)
    # Confirmation / finality policy
    min_confirmations = models.IntegerField(default=12)
    sweep_threshold = models.DecimalField(
        max_digits=40, decimal_places=18, default=Decimal("0.01"))
    memo_required = models.BooleanField(default=False)  # TON
    explorer_tx_url = models.URLField(blank=True, default="")
    explorer_address_url = models.URLField(blank=True, default="")
    gas_settings = models.JSONField(default=dict, blank=True)  # EIP-1559 / base fee
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["chain_id"]

    def __str__(self) -> str:
        return f"Chain({self.chain_id})"


# ---------------------------------------------------------------------------
# Asset / token registry (token onboarding — config-driven)
# ---------------------------------------------------------------------------
class Asset(models.Model):
    """A token or native asset on a chain. New tokens added via admin config."""

    asset_key = models.CharField(max_length=32, unique=True)  # ETH, BNB, USDT_BSC
    chain_id = models.CharField(max_length=16)
    symbol = models.CharField(max_length=16)
    name = models.CharField(max_length=64, blank=True, default="")
    contract_address = models.CharField(max_length=64, blank=True, default="")
    decimals = models.IntegerField(default=18)
    is_native = models.BooleanField(default=False)
    deposit_threshold = models.DecimalField(
        max_digits=40, decimal_places=18, default=Decimal("0.0"))
    withdraw_enabled = models.BooleanField(default=True)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["chain_id", "symbol"]
        unique_together = [("chain_id", "contract_address", "symbol")]

    def __str__(self) -> str:
        return f"Asset({self.asset_key})"


# ---------------------------------------------------------------------------
# Node / RPC endpoint registry + health
# ---------------------------------------------------------------------------
class NodeEndpoint(models.Model):
    """An RPC endpoint for a chain. Supports primary/fallback + health metrics."""

    id = models.CharField(primary_key=True, max_length=24, default=_new_id,
                          editable=False)
    chain_id = models.CharField(max_length=16)
    name = models.CharField(max_length=64)
    url = models.URLField()
    kind = models.CharField(
        max_length=16,
        choices=[("rpc", "RPC"), ("indexer", "Indexer"), ("explorer", "Explorer")],
        default="rpc",
    )
    priority = models.IntegerField(default=10)  # lower = preferred
    is_primary = models.BooleanField(default=False)
    enabled = models.BooleanField(default=True)
    # Last observed health
    healthy = models.BooleanField(null=True, blank=True)
    latency_ms = models.IntegerField(null=True, blank=True)
    block_height = models.BigIntegerField(null=True, blank=True)
    sync_status = models.CharField(max_length=32, blank=True, default="")  # synced/stale
    last_error = models.TextField(blank=True, default="")
    last_checked = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["chain_id", "priority", "name"]

    def __str__(self) -> str:
        return f"Node({self.chain_id}:{self.name})"


# ---------------------------------------------------------------------------
# Balance snapshots (current + historical)
# ---------------------------------------------------------------------------
class AddressBalance(models.Model):
    """Point-in-time balance of an address for a given asset."""

    id = models.CharField(primary_key=True, max_length=24, default=_new_id,
                          editable=False)
    chain_id = models.CharField(max_length=16)
    asset_key = models.CharField(max_length=32)
    address = models.CharField(max_length=64)
    owner_type = models.CharField(
        max_length=16,
        choices=[("user_deposit", "User Deposit"), ("hot_wallet", "Hot Wallet"),
                 ("cold_wallet", "Cold Wallet")],
        default="user_deposit",
    )
    owner_ref = models.CharField(max_length=64, blank=True, default="")  # user_id
    confirmed_balance = models.DecimalField(max_digits=40, decimal_places=18,
                                            default=Decimal("0"))
    pending_balance = models.DecimalField(max_digits=40, decimal_places=18,
                                          null=True, blank=True)
    snapshot_at = models.DateTimeField(auto_now_add=True)
    source = models.CharField(max_length=16, default="indexer")  # node/indexer

    class Meta:
        indexes = [models.Index(fields=["address", "asset_key", "-snapshot_at"]),
                   models.Index(fields=["chain_id", "owner_type"])]
        ordering = ["-snapshot_at"]

    def __str__(self) -> str:
        return f"Bal({self.address}:{self.asset_key}={self.confirmed_balance})"


# ---------------------------------------------------------------------------
# Transaction ledger (deposits, sweeps, withdrawals, gas top-ups)
# ---------------------------------------------------------------------------
class TransactionLog(models.Model):
    tx_type = models.CharField(
        max_length=16,
        choices=[("deposit", "Deposit"), ("sweep", "Sweep"),
                 ("withdrawal", "Withdrawal"), ("gas_topup", "Gas Top-up"),
                 ("transfer", "Transfer")],
    )
    chain_id = models.CharField(max_length=16)
    asset_key = models.CharField(max_length=32)
    tx_hash = models.CharField(max_length=96, blank=True, default="")
    from_address = models.CharField(max_length=64, blank=True, default="")
    to_address = models.CharField(max_length=64, blank=True, default="")
    amount = models.DecimalField(max_digits=40, decimal_places=18,
                                 default=Decimal("0"))
    memo = models.CharField(max_length=128, blank=True, default="")
    block = models.BigIntegerField(null=True, blank=True)
    confirmations = models.IntegerField(default=0)
    status = models.CharField(
        max_length=16,
        choices=[("pending", "Pending"), ("broadcasted", "Broadcasted"),
                 ("confirmed", "Confirmed"), ("failed", "Failed"),
                 ("reverted", "Reverted")],
        default="pending",
    )
    ref_type = models.CharField(max_length=24, blank=True, default="")  # SweepJob/WithdrawalRequest
    ref_id = models.CharField(max_length=24, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [models.Index(fields=["tx_type", "-created_at"]),
                   models.Index(fields=["chain_id", "status"]),
                   models.Index(fields=["tx_hash"])]
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"Tx({self.tx_type}:{self.tx_hash or 'pending'})"


# ---------------------------------------------------------------------------
# Operator sessions & activity (operator activity tracking)
# ---------------------------------------------------------------------------
class OperatorSession(models.Model):
    id = models.CharField(primary_key=True, max_length=24, default=_new_id,
                          editable=False)
    user_id = models.CharField(max_length=64)
    role = models.CharField(max_length=16)
    ip = models.CharField(max_length=64, blank=True, default="")
    user_agent = models.CharField(max_length=256, blank=True, default="")
    login_at = models.DateTimeField(auto_now_add=True)
    last_active = models.DateTimeField(auto_now=True)
    revoked = models.BooleanField(default=False)

    class Meta:
        ordering = ["-login_at"]


class OperatorActivity(models.Model):
    """Lightweight operator activity stream (distinct from the audit trail)."""

    id = models.CharField(primary_key=True, max_length=24, default=_new_id,
                          editable=False)
    actor_id = models.CharField(max_length=64)
    role = models.CharField(max_length=16)
    action = models.CharField(max_length=64)
    target = models.CharField(max_length=128, blank=True, default="")
    meta = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]


# ---------------------------------------------------------------------------
# Operational alerts
# ---------------------------------------------------------------------------
class Alert(models.Model):
    severity = models.CharField(
        max_length=16,
        choices=[("info", "Info"), ("warning", "Warning"),
                 ("critical", "Critical")],
        default="warning",
    )
    category = models.CharField(
        max_length=32,
        choices=[("node_health", "Node Health"), ("balance", "Balance"),
                 ("security", "Security"), ("withdrawal", "Withdrawal"),
                 ("reorg", "Reorg"), ("system", "System")],
        default="system",
    )
    chain_id = models.CharField(max_length=16, blank=True, default="")
    title = models.CharField(max_length=128)
    detail = models.TextField(blank=True, default="")
    resolved = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=["resolved", "-created_at"]),
                   models.Index(fields=["category", "severity"])]
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"Alert[{self.severity}]({self.category}:{self.title})"


# ---------------------------------------------------------------------------
# Blocklist (deposit / withdrawal address screening)
# ---------------------------------------------------------------------------
class Blocklist(models.Model):
    """Denied addresses / (chain,asset) pairs for deposit & withdrawal screening.

    SCOPE tells *where* the value is checked:
      * DEPOSIT_ADDRESS  -> a user deposit EOA that must NOT be serviced
      * WITHDRAW_ADDRESS -> a destination address that must NOT receive funds
      * CHAIN_ASSET      -> a whole (chain_id, asset_key) disabled for transfers
    For CHAIN_ASSET scope, ``value`` is "-" and chain_id/asset_key are used.
    Enforcement points: custody balance-check (deposit) and withdrawal
    create/broadcast (withdrawal). See custody.api / custody.withdrawals.
    """

    SCOPE_CHOICES = [
        ("DEPOSIT_ADDRESS", "Deposit Address"),
        ("WITHDRAW_ADDRESS", "Withdrawal Address"),
        ("CHAIN_ASSET", "Chain+Asset"),
    ]

    id = models.CharField(primary_key=True, max_length=24, default=_new_id,
                          editable=False)
    scope = models.CharField(max_length=20, choices=SCOPE_CHOICES)
    value = models.CharField(max_length=64, default="-")   # address or "-"
    chain_id = models.CharField(max_length=16, blank=True, default="")
    asset_key = models.CharField(max_length=32, blank=True, default="")
    reason = models.CharField(max_length=32, default="compliance",
                              choices=[("compliance", "Compliance"),
                                       ("sanctions", "Sanctions"),
                                       ("scam", "Scam/Phishing"),
                                       ("manual", "Manual"),
                                       ("dust", "Dust/Spam")])
    note = models.TextField(blank=True, default="")
    enabled = models.BooleanField(default=True)
    created_by = models.CharField(max_length=64, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["scope", "value", "enabled"]),
                   models.Index(fields=["scope", "chain_id", "asset_key", "enabled"])]

    def __str__(self) -> str:
        if self.scope == "CHAIN_ASSET":
            return f"Block[{self.scope}]({self.chain_id}:{self.asset_key})"
        return f"Block[{self.scope}]({self.value})"