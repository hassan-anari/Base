"""Django admin registration for the ops/operations models."""
from django.contrib import admin

from .models import (
    Chain,
    Asset,
    NodeEndpoint,
    AddressBalance,
    TransactionLog,
    OperatorSession,
    OperatorActivity,
    Alert,
    Blocklist,
)


@admin.register(Chain)
class ChainAdmin(admin.ModelAdmin):
    list_display = ("chain_id", "display_name", "kind", "is_testnet",
                    "min_confirmations", "memo_required", "enabled")
    list_filter = ("kind", "is_testnet", "memo_required", "enabled")
    search_fields = ("chain_id", "display_name")


@admin.register(Asset)
class OpsAssetAdmin(admin.ModelAdmin):
    list_display = ("asset_key", "chain_id", "symbol", "is_native",
                    "withdraw_enabled", "enabled")
    list_filter = ("chain_id", "is_native", "withdraw_enabled", "enabled")
    search_fields = ("asset_key", "symbol", "contract_address")


@admin.register(NodeEndpoint)
class NodeEndpointAdmin(admin.ModelAdmin):
    list_display = ("chain_id", "name", "url", "kind", "priority",
                    "is_primary", "healthy", "latency_ms", "last_checked")
    list_filter = ("chain_id", "kind", "is_primary", "enabled", "healthy")
    search_fields = ("chain_id", "name", "url")


@admin.register(AddressBalance)
class AddressBalanceAdmin(admin.ModelAdmin):
    list_display = ("address", "chain_id", "asset_key", "owner_type",
                    "confirmed_balance", "snapshot_at")
    list_filter = ("chain_id", "asset_key", "owner_type")
    search_fields = ("address", "owner_ref")


@admin.register(TransactionLog)
class TransactionLogAdmin(admin.ModelAdmin):
    list_display = ("id", "tx_type", "chain_id", "asset_key", "tx_hash",
                    "amount", "status", "created_at")
    list_filter = ("tx_type", "chain_id", "status")
    search_fields = ("tx_hash", "from_address", "to_address", "ref_id")


@admin.register(OperatorSession)
class OperatorSessionAdmin(admin.ModelAdmin):
    list_display = ("user_id", "role", "ip", "login_at", "last_active", "revoked")
    list_filter = ("role", "revoked")
    search_fields = ("user_id", "ip")


@admin.register(OperatorActivity)
class OperatorActivityAdmin(admin.ModelAdmin):
    list_display = ("actor_id", "role", "action", "target", "created_at")
    list_filter = ("role", "action")
    search_fields = ("actor_id", "action", "target")


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ("severity", "category", "chain_id", "title",
                    "resolved", "created_at")
    list_filter = ("severity", "category", "resolved")
    search_fields = ("title", "chain_id")


@admin.register(Blocklist)
class BlocklistAdmin(admin.ModelAdmin):
    list_display = ("scope", "value", "chain_id", "asset_key",
                    "reason", "enabled", "created_at")
    list_filter = ("scope", "reason", "enabled")
    search_fields = ("value", "chain_id", "asset_key")