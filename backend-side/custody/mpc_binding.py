"""Phase 6E root ownership and approved custody intent checks. Public metadata only."""

from __future__ import annotations

import hashlib
import json

from .chain_registry import ChainKind, get_chain_spec
from .models import (
    AdminActionLog,
    Asset,
    GasTopupIntent,
    HotWallet,
    LedgerTransaction,
    SweepJob,
    UserWallet,
    WithdrawalRequest,
)
from .mpc_identity import address_from_public_key
from .native_tx import _cap, to_base_units

PARTICIPANTS = ["signer-a", "signer-b", "signer-c"]


class MpcBindingError(ValueError):
    """Missing or inconsistent public ownership/intent evidence."""


class UnsupportedMpcDerivation(MpcBindingError):
    """The requested address requires unavailable child derivation."""


def source_wallet(attempt):
    if attempt.operation_type == "SWEEP":
        return (
            SweepJob.objects.select_related("user_wallet__mpc_keyset")
            .get(pk=attempt.operation_id)
            .user_wallet
        )
    return HotWallet.objects.select_related("mpc_keyset").get(chain_id=attempt.chain_id)


def local_root_keyset(attempt):
    return _wallet_root_keyset(source_wallet(attempt), attempt.chain_id, attempt.from_address)


def _wallet_root_keyset(wallet, chain_id, source_address):
    spec = get_chain_spec(chain_id)
    if spec.kind not in {ChainKind.EVM, ChainKind.TRON, ChainKind.SOLANA}:
        raise MpcBindingError("unsupported root signing family")
    keyset = wallet.mpc_keyset
    if keyset is None:
        raise MpcBindingError("source wallet has no explicit MPC keyset binding")
    reference = wallet.derivation_path if isinstance(wallet, UserWallet) else wallet.signing_key_ref
    if reference != f"keyset:{keyset.keyset_id}":
        raise UnsupportedMpcDerivation(
            "unsupported child derivation; explicit root binding required"
        )
    if isinstance(wallet, UserWallet) and wallet.derivation_version != "mpc_root_v1":
        raise UnsupportedMpcDerivation("deposit wallet must explicitly select mpc_root_v1")
    solana = spec.kind is ChainKind.SOLANA
    if (
        keyset.status != "ACTIVE"
        or keyset.algorithm != ("FROST_ED25519" if solana else "CGGMP24_ECDSA")
        or keyset.curve != ("ed25519" if solana else "secp256k1")
        or keyset.scope
        != ("SOLANA" if solana else "TRON" if spec.kind is ChainKind.TRON else "EVM")
        or (keyset.threshold, keyset.party_count) != (2, 3)
        or keyset.participant_identities != PARTICIPANTS
        or keyset.derivation_version != ("frost_keyset_v1" if solana else "cggmp_hd_v1")
        or not keyset.dkg_execution_id
        or len(keyset.dkg_result_fingerprint) != 64
        or len(keyset.public_key) != (64 if solana else 66)
        or (solana and (keyset.active_for_new_wallets or not keyset.dkg_public_evidence))
    ):
        raise MpcBindingError("keyset is not a reviewed active 2-of-3 root keyset")
    if solana:
        verify_coordinator_keyset(keyset, keyset.dkg_public_evidence)
    address = wallet.deposit_address if isinstance(wallet, UserWallet) else wallet.address
    expected = address_from_public_key(chain_id, keyset.public_key)
    normalize = str.lower if spec.kind is ChainKind.EVM else str
    if normalize(expected) != normalize(address) or normalize(expected) != normalize(
        source_address
    ):
        raise MpcBindingError("DKG public key does not control the bound transaction source")
    return keyset


def verify_coordinator_keyset(keyset, metadata):
    """The authenticated coordinator validates real protocol evidence; cross-check its receipts."""
    expected = {
        "keyset_id": str(keyset.keyset_id),
        "execution_id": str(keyset.dkg_execution_id),
        "algorithm": keyset.algorithm,
        "curve": keyset.curve,
        "scope": keyset.scope,
        "derivation_version": keyset.derivation_version,
        "threshold": 2,
        "party_count": 3,
        "participants": PARTICIPANTS,
    }
    if any(metadata.get(k) != v for k, v in expected.items()):
        raise MpcBindingError("coordinator DKG identity mismatch")
    frost = keyset.algorithm == "FROST_ED25519"
    if (
        metadata.get("status") != ("COMPLETED" if frost else "KEYGEN_COMPLETED")
        or metadata.get("group_public_key") != keyset.public_key
        or metadata.get("result_fingerprint") != keyset.dkg_result_fingerprint
    ):
        raise MpcBindingError("coordinator DKG result mismatch")
    dkg = {k: metadata[k] for k in ("session_id", *expected)}
    reports = metadata.get("participant_agreement", [])
    if len(reports) != 3:
        raise MpcBindingError("incomplete DKG participant agreement")
    for party, report in zip(PARTICIPANTS, reports, strict=True):
        if (
            report.get("request") != dkg
            or report.get("party_id") != party
            or report.get("status") != ("COMPLETED" if frost else "KEYGEN_COMPLETED")
            or report.get("durable") is not True
            or report.get("group_public_key") != keyset.public_key
            or report.get("share_format_version") != 1
            or report.get("public_key_package") != reports[0].get("public_key_package")
        ):
            raise MpcBindingError("DKG participant receipt mismatch")
    if frost:
        if (keyset.threshold, keyset.party_count) != (2, 3):
            raise MpcBindingError("FROST root threshold must be exactly 2-of-3")
        if (keyset.scope, keyset.curve, keyset.derivation_version) != (
            "SOLANA",
            "ed25519",
            "frost_keyset_v1",
        ):
            raise MpcBindingError("invalid FROST root shape")
        try:
            if (
                len(bytes.fromhex(keyset.public_key)) != 32
                or bytes.fromhex(keyset.public_key).hex() != keyset.public_key
            ):
                raise ValueError
            package = reports[0]["public_key_package"]
            if (
                not isinstance(package, list)
                or not package
                or any(type(b) is not int or not 0 <= b <= 255 for b in package)
            ):
                raise ValueError
            for report in reports:
                share = report["verification_share"]
                if (
                    not isinstance(share, list)
                    or len(share) != 32
                    or any(type(b) is not int or not 0 <= b <= 255 for b in share)
                ):
                    raise ValueError
            import uuid

            if (
                uuid.UUID(metadata["session_id"]).int == 0
                or uuid.UUID(str(keyset.dkg_execution_id)).int == 0
            ):
                raise ValueError
            if (
                len(bytes.fromhex(keyset.dkg_result_fingerprint)) != 32
                or bytes.fromhex(keyset.dkg_result_fingerprint).hex()
                != keyset.dkg_result_fingerprint
            ):
                raise ValueError
        except (KeyError, TypeError, ValueError):
            raise MpcBindingError("incomplete canonical FROST DKG public evidence") from None
        if keyset.dkg_public_evidence and metadata != keyset.dkg_public_evidence:
            raise MpcBindingError("FROST DKG differs from imported authenticated evidence")
        # Rust validates the serialized PublicKeyPackage and all public shares.
        # No auxiliary ceremony is part of FROST. CGGMP checks below are unchanged.
        return
    auxiliary = metadata.get("auxiliary") or {}
    request = auxiliary.get("request") or {}
    if (
        auxiliary.get("status") != "AUXILIARY_COMPLETED"
        or auxiliary.get("internally_signable") is not True
        or request.get("dkg") != dkg
        or request.get("group_public_key") != keyset.public_key
        or request.get("public_key_package") != reports[0].get("public_key_package")
        or not request.get("execution_id")
        or request.get("execution_id") == str(keyset.dkg_execution_id)
    ):
        raise MpcBindingError("authoritative auxiliary readiness is missing")
    receipts = auxiliary.get("participant_agreement", [])
    if len(receipts) != 3:
        raise MpcBindingError("incomplete auxiliary participant agreement")
    for party, report in zip(PARTICIPANTS, receipts, strict=True):
        if (
            report.get("request") != request
            or report.get("party_id") != party
            or report.get("status") != "AUXILIARY_COMPLETED"
            or report.get("durable") is not True
            or not report.get("public_parameters_fingerprint")
            or report.get("public_parameters_fingerprint")
            != receipts[0].get("public_parameters_fingerprint")
            or report.get("artifact_format_version") != 1
        ):
            raise MpcBindingError("auxiliary participant receipt mismatch")


def validate_custody_intent(attempt):
    """Revalidate durable business authorization at every advancement, including consumption."""
    from .config import effective_deposit_threshold, validate_chain_asset
    from .ledger import _require_withdrawal_reservation, lock_user_accounts

    spec = get_chain_spec(attempt.chain_id)
    normalize = str.lower if spec.kind is ChainKind.EVM else str
    validate_chain_asset(attempt.chain_id, attempt.asset_key)
    asset = Asset.objects.get(asset_key=attempt.asset_key, chain_id=attempt.chain_id, enabled=True)
    if to_base_units(attempt.amount, asset.decimals) != int(attempt.base_unit_amount):
        raise MpcBindingError("attempt amount/base-unit mismatch")
    hot = HotWallet.objects.get(chain_id=attempt.chain_id)
    reconciling = bool(attempt.signed_payload) and attempt.status in {
        "BROADCASTED",
        "RECONCILIATION_REQUIRED",
    }
    if attempt.operation_type == "WITHDRAWAL":
        operation = WithdrawalRequest.objects.get(pk=attempt.operation_id)
        if operation.status not in {"APPROVED", "PROCESSING", "RECONCILIATION_REQUIRED"} | (
            {"BROADCASTED"} if reconciling else set()
        ):
            raise MpcBindingError("withdrawal is not approved for signing")
        if (operation.chain_id, operation.asset_key, operation.to_address, operation.amount) != (
            attempt.chain_id,
            attempt.asset_key,
            attempt.to_address,
            attempt.amount,
        ) or normalize(hot.address) != normalize(attempt.from_address):
            raise MpcBindingError("withdrawal intent mismatch")
        approval = (
            AdminActionLog.objects.filter(
                action_type="WITHDRAWAL_APPROVE",
                entity_type="WithdrawalRequest",
                entity_id=str(operation.pk),
            )
            .order_by("-id")
            .first()
        )
        if not approval or approval.metadata != {
            "to": operation.to_address,
            "amount": str(operation.amount),
        }:
            raise MpcBindingError("withdrawal approval evidence mismatch")
        _require_withdrawal_reservation(
            operation, lock_user_accounts(operation.user_id, operation.asset_key)
        )
        if LedgerTransaction.objects.filter(
            event_key__in=[
                f"withdrawal:{operation.pk}:release",
                f"withdrawal:{operation.pk}:settle",
            ]
        ).exists():
            raise MpcBindingError("withdrawal reservation is no longer spendable")
    elif attempt.operation_type == "SWEEP":
        operation = SweepJob.objects.select_related("user_wallet").get(pk=attempt.operation_id)
        wallet = operation.user_wallet
        if (
            wallet.status != "ACTIVE"
            or wallet.chain_id != attempt.chain_id
            or wallet.asset_key != attempt.asset_key
            or operation.asset_key != attempt.asset_key
            or normalize(wallet.deposit_address) != normalize(attempt.from_address)
            or normalize(hot.address) != normalize(attempt.to_address)
            or operation.status
            not in (
                {"CREATED", "SWEEP_PROCESSING", "GAS_TOPUP_CONFIRMED", "RECONCILIATION_REQUIRED"}
                | ({"SWEEP_BROADCASTED"} if reconciling else set())
            )
            or operation.balance_snapshot is None
            or operation.balance_snapshot <= effective_deposit_threshold(asset, spec)
            or attempt.amount > operation.balance_snapshot
            or (not asset.is_native and attempt.amount != operation.balance_snapshot)
        ):
            raise MpcBindingError("sweep eligibility or intent mismatch")
        if operation.gas_topup_intent_id and operation.gas_topup_intent.status != "CONFIRMED":
            raise MpcBindingError("sweep gas grant is not confirmed")
    elif attempt.operation_type == "GAS_TOPUP":
        operation = GasTopupIntent.objects.get(pk=attempt.operation_id)
        known = UserWallet.objects.filter(
            chain_id=attempt.chain_id,
            **(
                {"deposit_address__iexact": attempt.to_address}
                if spec.kind is ChainKind.EVM
                else {"deposit_address": attempt.to_address}
            ),
            status="ACTIVE",
        ).exists() or normalize(hot.address) == normalize(attempt.to_address)
        maximum_grant = spec.gas_topup_amount * 10
        if spec.kind is ChainKind.TRON:
            maximum_grant = spec.gas_topup_amount
            recipients = UserWallet.objects.select_related("mpc_keyset").filter(
                chain_id=attempt.chain_id, deposit_address=attempt.to_address, status="ACTIVE"
            )
            if normalize(hot.address) == normalize(attempt.to_address):
                _wallet_root_keyset(hot, attempt.chain_id, attempt.to_address)
            elif not recipients.exists():
                raise MpcBindingError("TRON resource grant destination is not a bound wallet")
            else:
                for recipient in recipients:
                    _wallet_root_keyset(recipient, attempt.chain_id, attempt.to_address)
        elif spec.kind is ChainKind.SOLANA:
            recipients = list(
                UserWallet.objects.select_related("mpc_keyset").filter(
                    chain_id=attempt.chain_id,
                    deposit_address=attempt.to_address,
                    status="ACTIVE",
                )
            )
            is_hot = hot.address == attempt.to_address
            if not recipients and not is_hot:
                raise MpcBindingError("Solana gas grant destination is not a bound wallet")
            owner_keysets = set()
            if is_hot:
                owner_keysets.add(_wallet_root_keyset(hot, attempt.chain_id, attempt.to_address).pk)
            # Every active record must agree, including records at the hot address.
            # Base58 addresses are case-sensitive; registration alone is not ownership.
            for recipient in recipients:
                owner_keysets.add(
                    _wallet_root_keyset(recipient, attempt.chain_id, attempt.to_address).pk
                )
            if len(owner_keysets) != 1:
                raise MpcBindingError("Solana gas grant destination has conflicting root bindings")
        if (
            operation.status
            not in (
                {"PROCESSING", "RECONCILIATION_REQUIRED"}
                | ({"BROADCASTED"} if reconciling else set())
            )
            or (operation.chain_id, operation.to_address, operation.amount)
            != (attempt.chain_id, attempt.to_address, attempt.amount)
            or not asset.is_native
            or asset.asset_key != spec.native_asset_key
            or not known
            or normalize(hot.address) != normalize(attempt.from_address)
            or attempt.amount > maximum_grant
        ):
            raise MpcBindingError("gas top-up policy or intent mismatch")
    else:
        raise MpcBindingError("unsupported custody operation")


def transaction_identity(attempt, keyset):
    """Validate and snapshot the complete persisted unsigned transaction, after nonce ownership."""
    from .token_metadata import assert_verified_token

    spec = get_chain_spec(attempt.chain_id)
    if spec.kind is ChainKind.SOLANA:
        from .solana_policy import solana_transaction_identity

        return solana_transaction_identity(attempt, keyset)
    if spec.kind is ChainKind.TRON:
        from .tron_policy import tron_transaction_identity

        return tron_transaction_identity(attempt, keyset)
    raw = attempt.prepared_metadata
    asset = Asset.objects.get(asset_key=attempt.asset_key)
    if (raw.get("chainId"), raw.get("nonce")) != (spec.evm_chain_id, attempt.sequence):
        raise MpcBindingError("persisted chain ID or allocated nonce mismatch")
    if raw.get("from", "").lower() != attempt.from_address.lower():
        raise MpcBindingError("persisted unsigned source mismatch")
    if asset.is_native:
        expected_to, value, data = attempt.to_address, int(attempt.base_unit_amount), "0x"
    else:
        asset = assert_verified_token(attempt.asset_key)
        expected_to, value = asset.contract_address, 0
        data = (
            "0xa9059cbb"
            + attempt.to_address.lower()[2:].rjust(64, "0")
            + int(attempt.base_unit_amount).to_bytes(32, "big").hex()
        )
    if (
        raw.get("to", "").lower() != expected_to.lower()
        or raw.get("value") != value
        or raw.get("data", "0x").lower() != data
    ):
        raise MpcBindingError("unsigned transaction differs from approved transfer")
    gas = raw.get("gas", 0)
    if not isinstance(gas, int) or not 0 < gas <= _cap(spec.gas_settings, "max_gas_limit"):
        raise MpcBindingError("unsigned transaction gas limit violates reviewed policy")
    if "maxFeePerGas" in raw:
        price = raw["maxFeePerGas"]
        if not 0 <= raw.get("maxPriorityFeePerGas", -1) <= min(
            price, _cap(spec.gas_settings, "max_priority_fee_per_gas")
        ) or not 0 < price <= _cap(spec.gas_settings, "max_fee_per_gas"):
            raise MpcBindingError("unsigned EIP-1559 fees violate reviewed policy")
    else:
        price = raw.get("gasPrice", 0)
        if not 0 < price <= _cap(spec.gas_settings, "max_legacy_gas_price"):
            raise MpcBindingError("unsigned legacy fee violates reviewed policy")
    if "max_total_fee_base_units" in spec.gas_settings and gas * price > _cap(
        spec.gas_settings, "max_total_fee_base_units"
    ):
        raise MpcBindingError("unsigned transaction exceeds reviewed total fee limit")
    return {
        "attempt_id": attempt.pk,
        "operation_type": attempt.operation_type,
        "operation_id": attempt.operation_id,
        "chain": attempt.chain_id,
        "evm_chain_id": spec.evm_chain_id,
        "asset": attempt.asset_key,
        "token_contract": None if asset.is_native else asset.contract_address,
        "source": attempt.from_address,
        "destination": attempt.to_address,
        "base_unit_amount": str(int(attempt.base_unit_amount)),
        "nonce": attempt.sequence,
        "unsigned_transaction": dict(raw),
        "transaction_type": "eip1559" if "maxFeePerGas" in raw else "legacy",
        "fees": dict(attempt.fee_metadata),
        "keyset_id": str(keyset.keyset_id),
        "public_key": keyset.public_key,
        "dkg_fingerprint": keyset.dkg_result_fingerprint,
    }


def identity_fingerprint(identity):
    return hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
