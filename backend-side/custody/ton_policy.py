"""Public TON root binding and durable ownership within the existing lifecycle."""

from django.db import connection, transaction

from .models import OnchainTransactionAttempt, SourceAccountSequence, TonWalletBinding
from .mpc_ton_network import network_identity
from .ton_wire import (
    WALLET_CODE_HASH,
    WALLET_VERSION,
    normalize_address,
    validate_authorization,
    wallet_address,
    wallet_id,
    wallet_init,
)


class TonSequenceBusy(ValueError):
    pass


def verified_binding(chain_id, address, keyset):
    identity = network_identity(chain_id)
    expected = wallet_address(bytes.fromhex(keyset.public_key), identity["global_id"])
    binding = TonWalletBinding.objects.get(chain_id=chain_id, address=expected, keyset=keyset)
    if (
        normalize_address(address).raw != expected
        or binding.network_identity != identity
        or binding.wallet_version != WALLET_VERSION
        or binding.code_hash != WALLET_CODE_HASH
        or binding.workchain != 0
        or binding.wallet_id != wallet_id(identity["global_id"])
        or binding.state_init
        != wallet_init(bytes.fromhex(keyset.public_key), identity["global_id"]).to_boc().hex()
    ):
        raise ValueError("TON root StateInit/network binding mismatch")
    return binding


def own_sequence(attempt_id, observed_seqno):
    """All assets/operations at one contract share one unresolved sequence owner.

    Commit this alongside prepared bytes. RPC acceptance/expiry never releases it.
    A settled attempt still needs a separately verified contract observation.
    """
    if connection.vendor != "postgresql":
        raise ValueError("TON execution ownership requires PostgreSQL")
    if type(observed_seqno) is not int or not 0 <= observed_seqno < 2**32:
        raise ValueError("invalid verified TON seqno")
    with transaction.atomic():
        attempt = OnchainTransactionAttempt.objects.select_for_update().get(pk=attempt_id)
        if (
            attempt.chain_id != "TON"
            or normalize_address(attempt.from_address).raw != attempt.from_address
        ):
            raise ValueError("canonical TON source identity required")
        # The source advisory lock also serializes the first row creation.
        import hashlib

        lock_key = int.from_bytes(
            hashlib.sha256(("TON:" + attempt.from_address).encode()).digest()[:8],
            "big",
            signed=True,
        )
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_xact_lock(%s)", [lock_key])
        state, _ = SourceAccountSequence.objects.get_or_create(
            chain_id=attempt.chain_id, address=attempt.from_address
        )
        state = SourceAccountSequence.objects.select_for_update().get(pk=state.pk)
        if state.owner_attempt_id == attempt.pk:
            if attempt.sequence != state.next_sequence or observed_seqno != state.next_sequence:
                raise TonSequenceBusy("original TON execution requires reconciliation")
            return state.next_sequence
        if state.owner_attempt_id:
            previous = OnchainTransactionAttempt.objects.get(pk=state.owner_attempt_id)
            if (
                previous.status not in {"CONFIRMED", "FAILED"}
                or not previous.confirmation_metadata.get("ton_terminal_delivery")
                or observed_seqno != state.next_sequence + 1
            ):
                raise TonSequenceBusy("unresolved TON sequence owner cannot be replaced")
        if observed_seqno < state.next_sequence:
            raise TonSequenceBusy("TON seqno observation regressed")
        state.owner_attempt = attempt
        state.next_sequence = observed_seqno
        state.save(update_fields=["owner_attempt", "next_sequence", "updated_at"])
        attempt.sequence = observed_seqno
        attempt.save(update_fields=["sequence", "updated_at"])
        return observed_seqno


def ton_transaction_identity(attempt, keyset):
    from .models import Asset
    from .token_metadata import assert_verified_token

    asset = Asset.objects.get(asset_key=attempt.asset_key, chain_id=attempt.chain_id)
    if not asset.is_native:
        assert_verified_token(asset.asset_key)
    binding = verified_binding(attempt.chain_id, attempt.from_address, keyset)
    raw = attempt.prepared_metadata
    a = raw["ton_authorization"]
    from .native_tx import to_base_units

    if (
        raw["ton_asset_decimals"] != asset.decimals
        or raw["ton_token_metadata_fingerprint"]
        != (None if asset.is_native else asset.metadata_fingerprint)
        or to_base_units(attempt.amount, asset.decimals, maximum=2**120 - 1)
        != int(attempt.base_unit_amount)
    ):
        raise ValueError("TON original asset decimals/metadata/financial amount changed")
    if (
        raw["public_key"] != keyset.public_key
        or a["network_global_id"] != binding.network_identity["global_id"]
        or a["seqno"] != attempt.sequence
        or a["destination"] != normalize_address(attempt.to_address).raw
        or a["amount"] != str(int(attempt.base_unit_amount))
    ):
        raise ValueError("TON message differs from durable approved operation")
    if a["jetton_master"] != (None if asset.is_native else asset.contract_address):
        raise ValueError("TON authorization does not bind approved asset master")
    if attempt.fee_metadata != {
        "max_fee_nanoton": "10000000",
        "storage_reserve_nanoton": "20000000",
        "attached_nanoton": a["attached_nanoton"],
    }:
        raise ValueError("TON immutable fee policy mismatch")
    digest = validate_authorization(a, bytes.fromhex(keyset.public_key))
    owner = SourceAccountSequence.objects.get(
        chain_id=attempt.chain_id, address=attempt.from_address
    )
    if owner.owner_attempt_id != attempt.pk or owner.next_sequence != attempt.sequence:
        raise ValueError("TON operation does not own wallet sequence")
    return {
        "attempt_id": attempt.pk,
        "operation_type": attempt.operation_type,
        "operation_id": attempt.operation_id,
        "chain": attempt.chain_id,
        "asset": attempt.asset_key,
        "asset_decimals": asset.decimals,
        "token_metadata_fingerprint": None if asset.is_native else asset.metadata_fingerprint,
        "source": attempt.from_address,
        "destination": attempt.to_address,
        "amount": str(int(attempt.base_unit_amount)),
        "keyset_id": str(keyset.keyset_id),
        "dkg_fingerprint": keyset.dkg_result_fingerprint,
        "network": binding.network_identity,
        "signing_cell_hash": digest.hex(),
        "authorization": a,
        "fees": attempt.fee_metadata,
    }


def prepare_authorization(
    *,
    public_key,
    global_id,
    source,
    destination,
    amount_units,
    seqno,
    valid_until,
    chain_time,
    balance_nanoton,
    deployed,
    comment=b"",
    destination_active=False,
    jetton_master=None,
    query_id=None,
    jetton_balance=None,
    fee_cap=10_000_000,
    storage_reserve=20_000_000,
):
    """Freeze one reviewed transfer after independently verified observations.

    This public serializer is used by MPC/TVM acceptance. Live code must first
    establish finality and contract ownership; it cannot call this as RPC proof.
    """
    from .ton_wire import (
        JETTON_WALLET_CODE_HASH,
        SEND_MODE,
        coins,
        jetton_wallet_address,
        signing_cell,
        uint,
    )

    source = normalize_address(source).raw
    target = normalize_address(destination, require_test=True)
    if (
        source != wallet_address(public_key, global_id)
        or target.workchain != 0
        or target.raw == source
    ):
        raise ValueError("TON source/destination contract identity mismatch")
    for value in (balance_nanoton, chain_time, fee_cap, storage_reserve):
        uint(value, 64)
    if fee_cap != 10_000_000 or storage_reserve != 20_000_000:
        raise ValueError("unreviewed TON fee/storage reserve policy")
    uint(valid_until, 32)
    if not chain_time + 30 <= valid_until <= chain_time + 300:
        raise ValueError("TON expiry lacks bounded validity margin")
    uint(seqno, 32)
    if (
        type(deployed) is not bool
        or type(destination_active) is not bool
        or (not deployed and seqno != 0)
    ):
        raise ValueError("TON deployment/seqno state mismatch")
    amount = coins(str(amount_units))
    if amount == 0 or type(amount_units) is not int or not isinstance(comment, bytes):
        raise ValueError("positive integer amount and exact comment bytes required")
    attached = amount if jetton_master is None else 100_000_000
    if balance_nanoton < attached + fee_cap + storage_reserve:
        raise ValueError("insufficient TON fee/storage reserve budget")
    # Friendly bounceability is an explicit recipient instruction. Raw addresses
    # use the independently observed state: inactive native recipients are nobounce.
    bounce = target.bounceable if target.bounceable is not None else destination_active
    if bounce and not destination_active and jetton_master is None:
        raise ValueError("uninitialized native recipient cannot be bounced safely")
    if jetton_master is not None:
        master = normalize_address(jetton_master).raw
        if master != jetton_master or type(jetton_balance) is not int or jetton_balance < amount:
            raise ValueError("verified Jetton master/source balance required")
        uint(query_id, 64)
        bounce = True  # Transfer goes to the already verified sender Jetton wallet.
    a = {
        "wallet_version": WALLET_VERSION,
        "code_hash": WALLET_CODE_HASH,
        "workchain": 0,
        "network_global_id": global_id,
        "wallet_id": wallet_id(global_id),
        "seqno": seqno,
        "valid_until": valid_until,
        "deploy": not deployed,
        "destination": target.raw,
        "amount": str(amount),
        "attached_nanoton": str(attached),
        "bounce": bounce,
        "send_mode": SEND_MODE,
        "comment_hex": comment.hex(),
        "jetton_master": jetton_master,
        "query_id": query_id,
        "jetton_source": jetton_wallet_address(source, jetton_master) if jetton_master else None,
        "jetton_destination": jetton_wallet_address(target.raw, jetton_master)
        if jetton_master
        else None,
        "jetton_wallet_code_hash": JETTON_WALLET_CODE_HASH if jetton_master else None,
        "state_init_boc_hex": wallet_init(public_key, global_id).to_boc().hex()
        if not deployed
        else None,
    }
    a["signed_cell_boc_hex"] = signing_cell(a, public_key).to_boc().hex()
    validate_authorization(a, public_key)
    return {"public_key": public_key.hex(), "ton_authorization": a}


def require_owned_contract(chain_id, address, keyset):
    from .mpc_ton_network import proof_client
    from .ton_wire import verify_wallet_state

    verified_binding(chain_id, address, keyset)
    client = proof_client(chain_id)
    checkpoint, _ = client.checkpoint()
    state = client.account(address, checkpoint)
    return verify_wallet_state(
        address,
        bytes.fromhex(keyset.public_key),
        client.identity["global_id"],
        status=state["status"],
        code=state["code"],
        data=state["data"],
    )


def require_fresh_authorization(attempt):
    from .mpc_ton_network import proof_client
    from .ton_wire import verify_wallet_state

    client = proof_client(attempt.chain_id)
    checkpoint, block = client.checkpoint()
    client.verify_fee_config(checkpoint)
    a = attempt.prepared_metadata["ton_authorization"]
    if not block.info.gen_utime + 30 <= a["valid_until"] <= block.info.gen_utime + 300:
        raise ValueError("original TON authorization expired or lacks validity margin")
    state = client.account(attempt.from_address, checkpoint)
    seqno = verify_wallet_state(
        attempt.from_address,
        bytes.fromhex(attempt.prepared_metadata["public_key"]),
        client.identity["global_id"],
        status=state["status"],
        code=state["code"],
        data=state["data"],
    )
    if seqno != a["seqno"]:
        raise ValueError("TON original wallet sequence requires reconciliation")
    if state["balance"] < int(a["attached_nanoton"]) + 30_000_000:
        raise ValueError("TON original fee/storage budget is no longer funded")
    if a["jetton_master"]:
        from .models import Asset
        from .ton_assets import verified_asset_wallet

        asset = Asset.objects.get(chain_id=attempt.chain_id, asset_key=attempt.asset_key)
        _, balance = verified_asset_wallet(asset, attempt.from_address, client, checkpoint)
        verified_asset_wallet(asset, a["destination"], client, checkpoint, allow_uninit=True)
        if balance < int(a["amount"]):
            raise ValueError("TON original Jetton amount is no longer funded")
