"""Django admin registration for custody state and ledger models.

These are the authoritative tables behind the on-chain custody engine:
deposit EOAs, deposits, withdrawal requests, hot wallets, sweep jobs and the
append-only audit trail. Registered read-mostly; sensitive state changes
(approvals, signing) are performed via the API, not the admin form.
"""

from django.contrib import admin

from .models import (
    AdminActionLog,
    Asset,
    Deposit,
    GasTopupIntent,
    HotWallet,
    LedgerAccount,
    LedgerPosting,
    LedgerTransaction,
    SweepJob,
    UserWallet,
    WithdrawalRequest,
)


@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = ("asset_key", "chain_id", "symbol", "decimals", "is_native", "enabled")
    list_filter = ("chain_id", "is_native", "enabled")
    search_fields = ("asset_key", "symbol", "contract_address")


@admin.register(UserWallet)
class UserWalletAdmin(admin.ModelAdmin):
    list_display = (
        "user_id",
        "chain_id",
        "asset_key",
        "deposit_address",
        "address_index",
        "status",
        "created_at",
    )
    list_filter = ("chain_id", "asset_key", "status")
    search_fields = ("user_id", "deposit_address", "derivation_path", "memo")
    readonly_fields = ("derivation_path", "created_at")


@admin.register(Deposit)
class DepositAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user_wallet",
        "asset_key",
        "tx_hash",
        "amount",
        "block",
        "confirmations",
        "parsed_at",
    )
    list_filter = ("asset_key",)
    search_fields = ("tx_hash", "memo")
    readonly_fields = ("parsed_at",)


@admin.register(WithdrawalRequest)
class WithdrawalRequestAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user_id",
        "chain_id",
        "asset_key",
        "to_address",
        "amount",
        "status",
        "created_at",
        "updated_at",
    )
    list_filter = ("chain_id", "asset_key", "status")
    search_fields = ("user_id", "to_address", "tx_hash", "idempotency_key")
    readonly_fields = ("created_at", "updated_at", "idempotency_key")


@admin.register(HotWallet)
class HotWalletAdmin(admin.ModelAdmin):
    list_display = ("chain_id", "address")
    search_fields = ("chain_id", "address")


@admin.register(SweepJob)
class SweepJobAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user_wallet",
        "asset_key",
        "sweep_round",
        "status",
        "tx_hash",
        "created_at",
        "completed_at",
    )
    list_filter = ("asset_key", "status")
    search_fields = ("tx_hash", "idempotency_key")
    readonly_fields = ("created_at", "completed_at", "idempotency_key")


@admin.register(GasTopupIntent)
class GasTopupIntentAdmin(admin.ModelAdmin):
    list_display = ("id", "chain_id", "to_address", "amount", "status", "updated_at")
    list_filter = ("chain_id", "status")
    search_fields = ("to_address", "tx_hash", "idempotency_key")
    readonly_fields = ("idempotency_key", "created_at", "updated_at")


@admin.register(AdminActionLog)
class AdminActionLogAdmin(admin.ModelAdmin):
    list_display = ("id", "actor_id", "action_type", "entity_type", "entity_id", "created_at")
    list_filter = ("action_type", "entity_type")
    search_fields = ("actor_id", "entity_id")
    readonly_fields = ("created_at", "metadata")

    def has_add_permission(self, request):
        return False  # append-only audit trail

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


class ImmutableLedgerAdmin(admin.ModelAdmin):
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(LedgerAccount)
class LedgerAccountAdmin(ImmutableLedgerAdmin):
    list_display = ("owner_type", "owner_id", "asset_key", "bucket", "created_at")
    list_filter = ("owner_type", "asset_key", "bucket")


@admin.register(LedgerTransaction)
class LedgerTransactionAdmin(ImmutableLedgerAdmin):
    list_display = ("event_key", "event_type", "asset_key", "ref_type", "ref_id", "created_at")
    list_filter = ("event_type", "asset_key")


@admin.register(LedgerPosting)
class LedgerPostingAdmin(ImmutableLedgerAdmin):
    list_display = ("transaction", "account", "amount", "created_at")
    list_filter = ("account__asset_key",)
