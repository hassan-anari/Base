"""Custody state and authoritative financial-ledger models.

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

from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q


class Asset(models.Model):
    """Authoritative custody capability record for a reviewed asset.

    Token metadata alone does not provide custody support. Token capability
    flags remain disabled until a reviewed Phase 5 implementation exists.
    """

    asset_key = models.CharField(max_length=32, unique=True)  # "USDT-BSC"
    chain_id = models.CharField(max_length=16, db_index=True)  # "BSC"
    symbol = models.CharField(max_length=16)
    decimals = models.PositiveIntegerField(default=18)
    is_native = models.BooleanField(default=False)
    contract_address = models.CharField(max_length=128, null=True, blank=True)
    TOKEN_STANDARDS = [(value, value) for value in ("ERC20", "TRC20", "SPL")]
    token_standard = models.CharField(max_length=8, choices=TOKEN_STANDARDS, null=True, blank=True)
    metadata_verified_at = models.DateTimeField(null=True, blank=True)
    metadata_fingerprint = models.CharField(max_length=64, blank=True, default="")
    deposit_threshold = models.DecimalField(max_digits=40, decimal_places=18, null=True, blank=True)
    enabled = models.BooleanField(default=True)
    deposit_supported = models.BooleanField(default=True)
    withdrawal_supported = models.BooleanField(default=True)
    sweep_supported = models.BooleanField(default=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=(
                    Q(is_native=True, token_standard__isnull=True)
                    | Q(is_native=False, token_standard__isnull=False)
                    | Q(
                        is_native=False,
                        token_standard__isnull=True,
                        deposit_supported=False,
                        withdrawal_supported=False,
                        sweep_supported=False,
                    )
                ),
                name="asset_native_token_standard_shape",
            ),
            models.CheckConstraint(
                condition=Q(is_native=False) | Q(contract_address__isnull=True),
                name="asset_native_has_no_contract",
            ),
            models.UniqueConstraint(
                fields=["chain_id", "contract_address", "token_standard"],
                condition=Q(is_native=False, enabled=True),
                name="uq_active_token_identity",
            ),
        ]

    def clean(self):
        super().clean()
        if self.is_native:
            if self.token_standard or self.contract_address:
                raise ValidationError("native assets cannot have token metadata")
        elif not self.token_standard or not self.contract_address:
            raise ValidationError("tokens require a standard and contract/mint")

    def save(self, *args, **kwargs):
        if self.pk:
            old = (
                type(self)
                .objects.filter(pk=self.pk)
                .values("chain_id", "contract_address", "decimals", "token_standard")
                .first()
            )
            identity = (self.chain_id, self.contract_address, self.decimals, self.token_standard)
            if old and identity != tuple(old[key] for key in old):
                self.metadata_verified_at = None
                self.metadata_fingerprint = ""
                if kwargs.get("update_fields") is not None:
                    kwargs["update_fields"] = set(kwargs["update_fields"]) | {
                        "metadata_verified_at",
                        "metadata_fingerprint",
                    }
        return super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"Asset({self.asset_key},{self.symbol})"


class MpcKeyset(models.Model):
    """Public MPC metadata; signer shares must never be stored here."""

    ALGORITHMS = [("CGGMP24_ECDSA", "CGGMP24_ECDSA"), ("FROST_ED25519", "FROST_ED25519")]
    STATUSES = [("CREATING", "CREATING"), ("ACTIVE", "ACTIVE"), ("RETIRED", "RETIRED")]
    SCOPES = [(value, value) for value in ("EVM", "TRON", "SOLANA")]
    keyset_id = models.UUIDField(unique=True)
    algorithm = models.CharField(max_length=32, choices=ALGORITHMS)
    curve = models.CharField(max_length=16)
    scope = models.CharField(max_length=16, choices=SCOPES)
    threshold = models.PositiveSmallIntegerField(default=2)
    party_count = models.PositiveSmallIntegerField(default=3)
    public_key = models.TextField(blank=True)
    derivation_version = models.CharField(max_length=32, default="cggmp_hd_v1")
    dkg_execution_id = models.UUIDField(null=True, blank=True, unique=True)
    dkg_result_fingerprint = models.CharField(max_length=64, blank=True, default="")
    participant_identities = models.JSONField(default=list, blank=True)
    status = models.CharField(max_length=16, choices=STATUSES, default="CREATING")
    active_for_new_wallets = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    retired_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=models.Q(threshold__gte=2)
                & models.Q(party_count__gte=models.F("threshold")),
                name="mpc_keyset_valid_threshold",
            ),
            models.UniqueConstraint(
                fields=["scope"],
                condition=models.Q(active_for_new_wallets=True),
                name="uq_active_mpc_keyset_per_scope",
            ),
        ]


class UserWallet(models.Model):
    """A user's deposit EOA address for a given (chain, asset).

    deposit_address is ALWAYS an EOA (never a contract). The derivation_path
    is stored so we can rotate (addressIndex+1) deterministically.
    """

    STATUS = [("ACTIVE", "ACTIVE"), ("RETIRED", "RETIRED")]

    user_id = models.CharField(max_length=64, db_index=True)
    chain_id = models.CharField(max_length=16, db_index=True)  # "ETH"/"BASE"
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
    # SPL ATA. The signing authority remains deposit_address.
    asset_account_address = models.CharField(max_length=128, null=True, blank=True)
    mpc_keyset = models.ForeignKey(
        MpcKeyset, null=True, blank=True, on_delete=models.PROTECT, related_name="user_wallets"
    )
    derivation_version = models.CharField(max_length=32, default="legacy_local_v1")

    def __str__(self) -> str:
        return f"UserWallet({self.user_id},{self.chain_id},{self.asset_key})"


class Deposit(models.Model):
    """A confirmed (or pending) on-chain deposit parsed by the indexer."""

    user_wallet = models.ForeignKey(UserWallet, on_delete=models.PROTECT, related_name="deposits")
    asset_key = models.CharField(max_length=32, db_index=True)
    tx_hash = models.CharField(max_length=128, db_index=True)
    amount = models.DecimalField(max_digits=40, decimal_places=18)
    block = models.BigIntegerField(null=True, blank=True)
    confirmations = models.PositiveIntegerField(default=0)
    event_index = models.CharField(max_length=64, default="native:0")
    block_hash = models.CharField(max_length=128, null=True, blank=True)
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
                fields=["user_wallet", "tx_hash", "asset_key", "event_index"],
                name="uq_deposit_wallet_tx_asset_event",
            ),
        ]


class WithdrawalRequest(models.Model):
    """User withdrawal request. No broadcast until admin APPROVES."""

    STATUS = [
        ("PENDING_APPROVAL", "PENDING_APPROVAL"),
        ("APPROVED", "APPROVED"),
        ("PROCESSING", "PROCESSING"),
        ("RECONCILIATION_REQUIRED", "RECONCILIATION_REQUIRED"),
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
    status = models.CharField(max_length=32, choices=STATUS, default="PENDING_APPROVAL")
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
    # Opaque signer-owned identity.  Deliberately nullable for non-destructive
    # migration: legacy wallets must be repaired by an operator and fail closed.
    signing_key_ref = models.CharField(max_length=255, null=True, blank=True)
    mpc_keyset = models.ForeignKey(
        MpcKeyset, null=True, blank=True, on_delete=models.PROTECT, related_name="hot_wallets"
    )

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
        ("GAS_TOPUP_CONFIRMED", "GAS_TOPUP_CONFIRMED"),
        ("SWEEP_PROCESSING", "SWEEP_PROCESSING"),
        ("SWEEP_BROADCASTED", "SWEEP_BROADCASTED"),
        ("RECONCILIATION_REQUIRED", "RECONCILIATION_REQUIRED"),
        ("CONFIRMED", "CONFIRMED"),
        ("FAILED", "FAILED"),
    ]

    user_wallet = models.ForeignKey(UserWallet, on_delete=models.PROTECT, related_name="sweeps")
    asset_key = models.CharField(max_length=32, db_index=True)
    sweep_round = models.PositiveIntegerField(default=1)
    balance_snapshot = models.DecimalField(max_digits=40, decimal_places=18, null=True, blank=True)
    deposit = models.ForeignKey(Deposit, null=True, blank=True, on_delete=models.SET_NULL)
    status = models.CharField(max_length=24, choices=STATUS, default="CREATED")
    tx_hash = models.CharField(max_length=128, null=True, blank=True, db_index=True)
    idempotency_key = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    gas_topup_intent = models.OneToOneField(
        "GasTopupIntent", null=True, blank=True, on_delete=models.PROTECT, related_name="sweep_job"
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["user_wallet", "asset_key", "sweep_round"],
                name="uq_sweep_wallet_asset_round",
            ),
        ]


class GasTopupIntent(models.Model):
    """Persisted idempotency and reconciliation state for gas transfers."""

    STATUS = [
        ("CREATED", "CREATED"),
        ("PROCESSING", "PROCESSING"),
        ("BROADCASTED", "BROADCASTED"),
        ("RECONCILIATION_REQUIRED", "RECONCILIATION_REQUIRED"),
        ("FAILED", "FAILED"),
        ("CONFIRMED", "CONFIRMED"),
    ]
    idempotency_key = models.CharField(max_length=64, unique=True)
    actor_id = models.CharField(max_length=64)
    chain_id = models.CharField(max_length=16)
    to_address = models.CharField(max_length=128)
    amount = models.DecimalField(max_digits=40, decimal_places=18)
    memo = models.CharField(max_length=128, null=True, blank=True)
    status = models.CharField(max_length=32, choices=STATUS, default="CREATED")
    tx_hash = models.CharField(max_length=128, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class SourceAccountSequence(models.Model):
    """Durable allocator for account-chain sequence numbers (not a cache)."""

    chain_id = models.CharField(max_length=16)
    address = models.CharField(max_length=128)
    next_sequence = models.PositiveBigIntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["chain_id", "address"], name="uq_source_account_sequence"
            )
        ]


class OnchainTransactionAttempt(models.Model):
    """One immutable-identity execution attempt for a logical custody operation."""

    OPERATION_TYPES = [
        ("WITHDRAWAL", "WITHDRAWAL"),
        ("SWEEP", "SWEEP"),
        ("GAS_TOPUP", "GAS_TOPUP"),
    ]
    STATUSES = [
        (value, value)
        for value in (
            "PREPARING",
            "PREPARED",
            "SIGNING",
            "SIGNED",
            "BROADCASTING",
            "BROADCASTED",
            "CONFIRMED",
            "FAILED",
            "RECONCILIATION_REQUIRED",
        )
    ]
    operation_type = models.CharField(max_length=16, choices=OPERATION_TYPES)
    operation_id = models.PositiveBigIntegerField()
    attempt_number = models.PositiveIntegerField(default=1)
    chain_id = models.CharField(max_length=16, db_index=True)
    asset_key = models.CharField(max_length=32)
    from_address = models.CharField(max_length=128)
    to_address = models.CharField(max_length=128)
    amount = models.DecimalField(max_digits=40, decimal_places=18)
    base_unit_amount = models.DecimalField(max_digits=78, decimal_places=0)
    status = models.CharField(max_length=32, choices=STATUSES, default="PREPARING")
    network_tx_id = models.CharField(max_length=128, null=True, blank=True, db_index=True)
    sequence = models.PositiveBigIntegerField(null=True, blank=True)
    prepared_metadata = models.JSONField(default=dict, blank=True)
    fee_metadata = models.JSONField(default=dict, blank=True)
    # Required to replay the *same* authorized bytes after an uncertain RPC.
    # Sensitive: never serialize this field through the public API or logs.
    signed_payload = models.TextField(blank=True, default="")
    expires_at = models.DateTimeField(null=True, blank=True)
    last_valid_block = models.PositiveBigIntegerField(null=True, blank=True)
    broadcast_started_at = models.DateTimeField(null=True, blank=True)
    broadcast_at = models.DateTimeField(null=True, blank=True)
    confirmation_metadata = models.JSONField(default=dict, blank=True)
    error_code = models.CharField(max_length=64, blank=True, default="")
    error_message = models.CharField(max_length=512, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["operation_type", "operation_id", "attempt_number"],
                name="uq_onchain_attempt_number",
            ),
            models.UniqueConstraint(
                fields=["chain_id", "from_address", "sequence"],
                condition=models.Q(sequence__isnull=False),
                name="uq_onchain_source_sequence",
            ),
            models.CheckConstraint(
                condition=models.Q(amount__gt=0) & models.Q(base_unit_amount__gt=0),
                name="onchain_attempt_positive_amount",
            ),
        ]
        indexes = [models.Index(fields=["status", "chain_id"])]


class MpcSigningSession(models.Model):
    """Durable, idempotent link between a prepared attempt and one MPC execution."""

    STATUSES = [
        (value, value)
        for value in (
            "CREATED",
            "STARTING",
            "IN_PROGRESS",
            "COMPLETED",
            "DEFINITIVE_NO_SIGNATURE_FAILURE",
            "RECONCILIATION_REQUIRED",
        )
    ]
    attempt = models.ForeignKey(
        OnchainTransactionAttempt, on_delete=models.PROTECT, related_name="mpc_sessions"
    )
    session_id = models.UUIDField(unique=True)
    session_number = models.PositiveIntegerField(default=1)
    keyset = models.ForeignKey(MpcKeyset, on_delete=models.PROTECT, related_name="signing_sessions")
    algorithm = models.CharField(max_length=32)
    message_fingerprint = models.CharField(max_length=64)
    payload_type = models.CharField(max_length=32)
    signing_payload = models.BinaryField()
    crypto_execution_id = models.UUIDField(null=True, blank=True, unique=True)
    signature_result = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=32, choices=STATUSES, default="CREATED")
    coordinator_request_id = models.CharField(max_length=128, blank=True, default="")
    error_code = models.CharField(max_length=64, blank=True, default="")
    error_message = models.CharField(max_length=512, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["attempt", "session_number"], name="uq_mpc_attempt_session_number"
            ),
            models.UniqueConstraint(
                fields=["attempt"],
                condition=models.Q(status__in=["CREATED", "STARTING", "IN_PROGRESS"]),
                name="uq_active_mpc_session_per_attempt",
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


class ImmutableAccountQuerySet(models.QuerySet):
    """Allow account creation and locking, but never bulk mutation/deletion."""

    def update(self, **kwargs):
        raise ValueError("ledger account identity is immutable")

    def delete(self):
        raise ValueError("ledger accounts cannot be deleted")


class AppendOnlyQuerySet(models.QuerySet):
    """Block journal mutation through normal Django ORM queryset APIs."""

    def update(self, **kwargs):
        raise ValueError("ledger journal rows are append-only")

    def delete(self):
        raise ValueError("ledger journal rows are append-only")


class LedgerAccount(models.Model):
    """Stable account identity; balances are derived only from postings."""

    OWNER_TYPES = [("USER", "USER"), ("SYSTEM", "SYSTEM")]
    BUCKETS = [
        ("AVAILABLE", "AVAILABLE"),
        ("RESERVED", "RESERVED"),
        ("CUSTODY_CLEARING", "CUSTODY_CLEARING"),
    ]
    owner_type = models.CharField(max_length=16, choices=OWNER_TYPES)
    owner_id = models.CharField(max_length=64)
    asset_key = models.CharField(max_length=32, db_index=True)
    bucket = models.CharField(max_length=24, choices=BUCKETS)
    created_at = models.DateTimeField(auto_now_add=True)
    objects = ImmutableAccountQuerySet.as_manager()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["owner_type", "owner_id", "asset_key", "bucket"],
                name="uq_ledger_account_identity",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(owner_type="USER", bucket__in=["AVAILABLE", "RESERVED"])
                    | models.Q(
                        owner_type="SYSTEM",
                        owner_id="custody",
                        bucket="CUSTODY_CLEARING",
                    )
                ),
                name="ledger_account_valid_shape",
            ),
        ]

    def save(self, *args, **kwargs):
        if self.pk:
            original = type(self).objects.get(pk=self.pk)
            identity = (self.owner_type, self.owner_id, self.asset_key, self.bucket)
            original_identity = (
                original.owner_type,
                original.owner_id,
                original.asset_key,
                original.bucket,
            )
            if identity != original_identity:
                raise ValueError("ledger account identity is immutable")
        valid_user = self.owner_type == "USER" and self.bucket in {"AVAILABLE", "RESERVED"}
        valid_system = (
            self.owner_type == "SYSTEM"
            and self.owner_id == "custody"
            and self.bucket == "CUSTODY_CLEARING"
        )
        if not (valid_user or valid_system):
            raise ValidationError("invalid ledger account identity shape")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("ledger accounts cannot be deleted")


class LedgerTransaction(models.Model):
    """Immutable journal header. Corrections are compensating transactions."""

    TYPES = [
        ("DEPOSIT_CREDIT", "DEPOSIT_CREDIT"),
        ("DEPOSIT_REVERSAL", "DEPOSIT_REVERSAL"),
        ("WITHDRAWAL_RESERVE", "WITHDRAWAL_RESERVE"),
        ("WITHDRAWAL_RELEASE", "WITHDRAWAL_RELEASE"),
        ("WITHDRAWAL_SETTLE", "WITHDRAWAL_SETTLE"),
    ]
    event_key = models.CharField(max_length=160, unique=True)
    event_type = models.CharField(max_length=32, choices=TYPES)
    asset_key = models.CharField(max_length=32, db_index=True)
    ref_type = models.CharField(max_length=32)
    ref_id = models.CharField(max_length=128)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    objects = AppendOnlyQuerySet.as_manager()

    def save(self, *args, **kwargs):
        if self.pk:
            raise ValueError("ledger transactions are append-only")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("ledger transactions are append-only")


class LedgerPosting(models.Model):
    """Signed journal line: positive adds to an account, negative removes."""

    transaction = models.ForeignKey(
        LedgerTransaction, on_delete=models.PROTECT, related_name="postings"
    )
    account = models.ForeignKey(LedgerAccount, on_delete=models.PROTECT, related_name="postings")
    amount = models.DecimalField(max_digits=40, decimal_places=18)
    created_at = models.DateTimeField(auto_now_add=True)
    objects = AppendOnlyQuerySet.as_manager()

    class Meta:
        constraints = [
            models.CheckConstraint(condition=~models.Q(amount=0), name="ledger_posting_nonzero")
        ]

    def save(self, *args, **kwargs):
        if self.pk:
            raise ValueError("ledger postings are append-only")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("ledger postings are append-only")
