"""Proof-bound V5R1 execution in the existing custody attempt lifecycle."""

import tempfile
from decimal import Decimal
from pathlib import Path

from .mpc_ton_network import proof_client
from .native_tx import (
    AmbiguousBroadcast,
    PreparedNativeTransaction,
    ReconciliationResult,
    ReconciliationState,
    RequestsTransport,
    to_base_units,
)
from .ton_effects import terminal_transfer_effect
from .ton_policy import prepare_authorization, verified_binding
from .ton_wire import Cell, normalize_address, validate_authorization, verify_wallet_state


class TonNativeExecutor:
    def __init__(self, transport=None):
        self.transport = transport or RequestsTransport()

    def prepare(self, chain_id, asset_key, source, destination, amount, *, sweep=False):
        from .models import Asset, TonWalletBinding

        client = proof_client(chain_id)
        binding = TonWalletBinding.objects.select_related("keyset").get(
            chain_id=chain_id, address=normalize_address(source).raw
        )
        verified_binding(chain_id, source, binding.keyset)
        public = bytes.fromhex(binding.keyset.public_key)
        checkpoint, block = client.checkpoint()
        client.verify_fee_config(checkpoint)
        state = client.account(source, checkpoint)
        seq = verify_wallet_state(
            source,
            public,
            client.identity["global_id"],
            status=state["status"],
            code=state["code"],
            data=state["data"],
        )
        asset = Asset.objects.get(chain_id=chain_id, asset_key=asset_key)
        units = to_base_units(amount, asset.decimals, maximum=2**120 - 1)
        kwargs = {}
        if not asset.is_native:
            from .ton_assets import verified_asset_wallet

            _, balance = verified_asset_wallet(asset, source, client, checkpoint)
            verified_asset_wallet(asset, destination, client, checkpoint, allow_uninit=True)
            # Query ID is a deterministic commitment to contract + original seqno.
            # All operations share sequence ownership; no competing query namespace.
            kwargs = dict(
                jetton_master=asset.contract_address, jetton_balance=balance, query_id=seq
            )
        if sweep and asset.is_native:
            units = min(units, state["balance"] - 30_000_000)
            amount = Decimal(units) / Decimal(10**9)
        target = normalize_address(destination, require_test=True)
        dest_state = client.account(target.raw, checkpoint)
        raw = prepare_authorization(
            public_key=public,
            global_id=client.identity["global_id"],
            source=source,
            destination=destination,
            amount_units=units,
            seqno=seq,
            valid_until=block.info.gen_utime + 120,
            chain_time=block.info.gen_utime,
            balance_nanoton=state["balance"],
            deployed=state["status"] == "active",
            destination_active=dest_state["status"] == "active",
            **kwargs,
        )
        raw["ton_checkpoint"] = checkpoint
        raw["ton_asset_decimals"] = asset.decimals
        raw["ton_token_metadata_fingerprint"] = (
            None if asset.is_native else asset.metadata_fingerprint
        )
        raw["ton_history_after_seqno"] = block.extra.custom.shard_hashes[0].list[0].seq_no
        return PreparedNativeTransaction(
            chain_id,
            asset_key,
            source,
            destination,
            amount,
            units,
            validate_authorization(raw["ton_authorization"], public),
            raw,
            {
                "max_fee_nanoton": "10000000",
                "storage_reserve_nanoton": "20000000",
                "attached_nanoton": raw["ton_authorization"]["attached_nanoton"],
            },
            sequence=seq,
            expires_at_ms=raw["ton_authorization"]["valid_until"] * 1000,
        )

    def prepare_sweep(self, *args):
        return self.prepare(*args, sweep=True)

    def broadcast(self, chain_id, signed, expected):
        client = proof_client(chain_id)
        raw = signed if isinstance(signed, bytes) else bytes.fromhex(signed)
        if Cell.one_from_boc(raw).hash.hex() != expected:
            raise ValueError("TON persisted external BOC identity mismatch")
        try:
            with tempfile.TemporaryDirectory(prefix="ton-send-") as root:
                path = Path(root) / "message.boc"
                path.write_bytes(raw)
                out = client.command("sendfile " + str(path), submission=True)
            if "external message status is 1" not in out:
                raise AmbiguousBroadcast("TON external acceptance unknown")
        except Exception as exc:
            # RPC failure/expiry is never authoritative proof of non-execution.
            raise AmbiguousBroadcast(
                "TON broadcast requires original-message reconciliation"
            ) from exc
        return expected

    def reconcile(self, prepared, tx_id):
        progress = prepared.unsigned_payload.get("_ton_reconciliation_progress", {})
        try:
            client = proof_client(prepared.chain_id)
            checkpoint, block = client.checkpoint()
            a = prepared.unsigned_payload["ton_authorization"]
            floor = progress.get(
                "complete_through", prepared.unsigned_payload["ton_history_after_seqno"]
            )
            if progress.get("parent"):
                checkpoint, block = client.verify_checkpoint(progress["anchor"])
                head = progress["target_head"]
                identity = progress["parent"]
            else:
                identity = client.shard_head(block)
                head = identity["seqno"]
            history, parent, complete = client.history_from(identity, after_seqno=floor)
            relevant = {
                prepared.from_address,
                a["destination"],
                a["jetton_source"],
                a["jetton_destination"],
            }
            retained = dict(progress.get("transactions", {}))
            inclusions = dict(progress.get("inclusions", {}))
            for shard, execution in client.transactions(history):
                if execution.account in relevant:
                    retained[execution.tx_hash] = execution.transaction.cell.to_boc().hex()
                    inclusions[execution.tx_hash] = dict(
                        masterchain=checkpoint,
                        shard_block=shard,
                        account=execution.account,
                        lt=str(execution.lt),
                    )
            if len(retained) > 128:
                raise ValueError(
                    "TON operation evidence exceeds reviewed bound; manual reconciliation required"
                )
            progress = dict(
                complete_through=head if complete else floor,
                transactions=retained,
                inclusions=inclusions,
            )
            if not complete:
                progress.update(anchor=checkpoint, target_head=head, parent=parent)
            if not complete:
                raise ValueError("TON verified history backfill continues durably")
            from .ton_effects import execution_from_boc

            executions = [execution_from_boc(raw) for raw in retained.values()]
            state = client.account(prepared.from_address, checkpoint)
            seq = verify_wallet_state(
                prepared.from_address,
                bytes.fromhex(prepared.unsigned_payload["public_key"]),
                client.identity["global_id"],
                status=state["status"],
                code=state["code"],
                data=state["data"],
            )
            if seq != a["seqno"] + 1:
                raise ValueError("TON original wallet execution/state requires reconciliation")
            if a["jetton_master"]:
                from .models import Asset
                from .ton_assets import verified_asset_wallet

                asset = Asset.objects.get(asset_key=prepared.asset_key, chain_id=prepared.chain_id)
                verified_asset_wallet(asset, prepared.from_address, client, checkpoint)
                verified_asset_wallet(asset, a["destination"], client, checkpoint)
            from .models import TonWalletBinding
            from .ton_wire import jetton_wallet_address

            owned = set(
                TonWalletBinding.objects.filter(chain_id=prepared.chain_id).values_list(
                    "address", flat=True
                )
            )
            if a["jetton_master"]:
                owned |= {jetton_wallet_address(owner, a["jetton_master"]) for owner in owned}
            effect = terminal_transfer_effect(
                a, prepared.from_address, tx_id, executions, custody_addresses=owned
            )
            if not effect["terminal"]:
                raise ValueError(effect["reason"])
            return ReconciliationResult(
                ReconciliationState.CONFIRMED,
                {
                    **effect,
                    "network_finality": True,
                    "ton_terminal_delivery": True,
                    "masterchain": checkpoint,
                    "transaction_inclusions": inclusions,
                },
            )
        except Exception as exc:
            return ReconciliationResult(
                ReconciliationState.RECONCILIATION_REQUIRED,
                {
                    "error": "TON_TERMINAL_DELIVERY_UNPROVEN",
                    "detail": str(exc)[:256],
                    "ton_progress": progress,
                },
            )


class JettonExecutor(TonNativeExecutor):
    """TEP-74 shares the owner V5 wallet sequence and reconciliation lifecycle."""
