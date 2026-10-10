"""Proof-bound per-account TON history scanner; journals/cursors commit together.

No balance delta or unauthenticated notification is a deposit. Backfill follows
hash-linked shard blocks to genesis; bounded pages keep progress durable. Internal
custody messages and funding are excluded. Unique root contracts are required;
shared-address customer invoices are intentionally not enabled.
"""

from decimal import Decimal

from django.db import transaction
from django.utils import timezone
from pytoniq_core import Address

from .chain_registry import get_chain_spec
from .deposits import ingest_event
from .indexer.base import DepositEvent
from .ledger import financial_precision
from .models import Asset, HotWallet, TonWalletBinding, UserWallet
from .mpc_ton_network import proof_client
from .ton_effects import INTERNAL_TRANSFER, attribute_native_deposit, parse_jetton_body
from .ton_policy import verified_binding
from .ton_wire import jetton_wallet_address, verify_wallet_state


@financial_precision()
def scan_ton_wallet(wallet):
    client = proof_client(wallet.chain_id)
    from .mpc_binding import _wallet_root_keyset

    _wallet_root_keyset(wallet, wallet.chain_id, wallet.deposit_address)
    verified_binding(wallet.chain_id, wallet.deposit_address, wallet.mpc_keyset)
    asset = Asset.objects.get(asset_key=wallet.asset_key, chain_id=wallet.chain_id)
    checkpoint, block = client.checkpoint()
    state = client.account(wallet.deposit_address, checkpoint)
    verify_wallet_state(
        wallet.deposit_address,
        bytes.fromhex(wallet.mpc_keyset.public_key),
        client.identity["global_id"],
        status=state["status"],
        code=state["code"],
        data=state["data"],
    )
    old = wallet.ton_scan_cursor
    floor = int(old.get("complete_through", 0))
    if old.get("backfill"):
        checkpoint, block = client.verify_checkpoint(old["anchor"])
        head = old["target_head"]
        history, parent, complete = client.history_from(
            old["backfill"], after_seqno=floor, max_blocks=128
        )
    else:
        identity = client.shard_head(block)
        head = identity["seqno"]
        history, parent, complete = client.history_from(identity, after_seqno=floor, max_blocks=128)
    known = set(
        TonWalletBinding.objects.filter(chain_id=wallet.chain_id).values_list("address", flat=True)
    )
    known.update(
        HotWallet.objects.filter(chain_id=wallet.chain_id).values_list("address", flat=True)
    )
    events = []
    quarantined = []
    token_account = None
    if not asset.is_native:
        from .ton_assets import verified_asset_wallet

        token_account, _ = verified_asset_wallet(asset, wallet.deposit_address, client, checkpoint)
    fees = []
    for identity, e in client.transactions(history):
        if e.account in {wallet.deposit_address, token_account}:
            fees.append(
                (
                    e.account,
                    e.tx_hash,
                    e.fee_nanoton
                    + sum(
                        m.info.fwd_fee + m.info.ihr_fee
                        for _, m in e.outgoing
                        if hasattr(m.info, "fwd_fee")
                    ),
                )
            )
        if asset.is_native:
            if e.account != wallet.deposit_address:
                continue
            try:
                deposit = attribute_native_deposit(e, wallet, known_internal_sources=known)
            except ValueError as exc:
                quarantined.append(
                    dict(
                        account=e.account,
                        transaction_hash=e.tx_hash,
                        inbound_message_hash=e.inbound_hash,
                        shard_block=identity,
                        reason=str(exc)[:160],
                    )
                )
                continue
            if deposit is None:
                if getattr(e.inbound.info, "src", None) not in {Address(x) for x in known}:
                    quarantined.append(
                        dict(
                            account=e.account,
                            transaction_hash=e.tx_hash,
                            inbound_message_hash=e.inbound_hash,
                            shard_block=identity,
                            reason="UNATTRIBUTED_OR_UNSUPPORTED_NATIVE_MESSAGE",
                        )
                    )
                continue
            units = deposit["amount_nanoton"]
            memo = bytes.fromhex(deposit["comment_hex"]).decode("utf8", errors="strict") or None
        else:
            if e.account != token_account or not e.successful or e.inbound.info.bounced:
                continue
            body = parse_jetton_body(e.inbound.body)
            if body["opcode"] != INTERNAL_TRANSFER:
                continue
            sender = body["owner"]
            if sender in known:
                continue
            if e.inbound.info.src != Address(jetton_wallet_address(sender, asset.contract_address)):
                raise ValueError("spoofed Jetton deposit source")
            from .ton_assets import verified_asset_wallet

            verified_asset_wallet(asset, sender, client, checkpoint)
            if not wallet.memo or body["comment"] != wallet.memo.encode():
                continue
            units = body["amount"]
            memo = body["comment"].decode("utf8", errors="strict") or None
        if not units:
            continue
        owners = set(
            UserWallet.objects.filter(
                chain_id=wallet.chain_id, deposit_address=wallet.deposit_address, status="ACTIVE"
            ).values_list("user_id", flat=True)
        )
        if owners != {wallet.user_id}:
            raise ValueError("TON attribution conflicts")
        event = DepositEvent(
            tx_hash=e.tx_hash,
            amount=Decimal(units) / Decimal(10**asset.decimals),
            block=identity["seqno"],
            confirmations=get_chain_spec(wallet.chain_id).confirmations,
            memo=memo,
            asset_key=asset.asset_key,
            event_index=e.inbound_hash,
            block_hash=identity["root_hash"],
            contract_address=asset.contract_address,
        )
        event.ton_finality_evidence = {
            "masterchain": checkpoint,
            "shard_block": identity,
            "account": e.account,
            "lt": str(e.lt),
            "transaction_hash": e.tx_hash,
            "inbound_message_hash": e.inbound_hash,
        }
        events.append(event)
    created = 0
    with transaction.atomic():
        locked = UserWallet.objects.select_for_update().get(pk=wallet.pk)
        if locked.ton_scan_cursor != old:
            return dict(
                outcome="pending", new_deposits=0, reason="TON cursor advanced concurrently"
            )
        from .ton_costs import post_verified_transaction_fee

        for account, tx_hash, units in fees:
            post_verified_transaction_fee(account, tx_hash, units)
        for e in events:
            _, new = ingest_event(locked, e)
            created += int(new)
        from .models import AdminActionLog

        for item in quarantined:
            # This required audit record and scan progress share the credit
            # transaction; an audit failure cannot silently discard the message.
            AdminActionLog.objects.create(
                actor_id="ton-indexer",
                action_type="INDEXER_SCAN",
                entity_type="UserWallet",
                entity_id=str(locked.pk),
                metadata={"quarantined": True, "masterchain": checkpoint, **item},
            )
        locked.ton_scan_cursor = (
            dict(complete_through=head, masterchain=checkpoint)
            if complete
            else dict(complete_through=floor, anchor=checkpoint, target_head=head, backfill=parent)
        )
        locked.last_scanned_at = timezone.now()
        locked.last_scanned_block = checkpoint["seqno"]
        locked.save(update_fields=["ton_scan_cursor", "last_scanned_at", "last_scanned_block"])
    return dict(
        outcome="confirmed" if complete else "backfill",
        new_deposits=created,
        confirmed_balance=Decimal(state["balance"]) / Decimal(10**9),
        sweep_triggered=False,
        reason="TON finalized account history",
    )
