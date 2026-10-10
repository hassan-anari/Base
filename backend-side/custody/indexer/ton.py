"""TON balances from verified state; deposit history uses the atomic TON scanner.

The former recent-30-transaction/memo balance-delta path is deliberately removed.
A TON custody identity is a pinned smart contract StateInit, never an EOA.
"""

from decimal import Decimal

from ..ledger import financial_precision
from .base import BalanceResult, IndexerClient, IndexerUnavailable


class TonIndexer(IndexerClient):
    def __init__(self, chain_id="TON"):
        super().__init__(chain_id)

    @financial_precision()
    def get_balance(self, address, *, asset_key=None, after_block=None, memo=None):
        del after_block, memo
        from ..models import Asset, TonWalletBinding
        from ..mpc_ton_network import proof_client
        from ..ton_policy import verified_binding
        from ..ton_wire import normalize_address, verify_wallet_state

        try:
            address = normalize_address(address).raw
            client = proof_client(self.chain_id)
            binding = TonWalletBinding.objects.select_related("keyset").get(
                chain_id=self.chain_id, address=address
            )
            verified_binding(self.chain_id, address, binding.keyset)
            checkpoint, _ = client.checkpoint()
            state = client.account(address, checkpoint)
            verify_wallet_state(
                address,
                bytes.fromhex(binding.keyset.public_key),
                client.identity["global_id"],
                status=state["status"],
                code=state["code"],
                data=state["data"],
            )
            asset = Asset.objects.get(asset_key=asset_key or "TON", chain_id=self.chain_id)
            units = state["balance"]
            if not asset.is_native:
                from ..ton_assets import verified_asset_wallet

                _, units = verified_asset_wallet(asset, address, client, checkpoint)
            return BalanceResult(
                confirmed_balance=Decimal(units) / Decimal(10**asset.decimals),
                last_scanned_block=checkpoint["seqno"],
            )
        except Exception as exc:
            raise IndexerUnavailable("TON proof-bound balance unavailable") from exc

    def get_txs(self, address, after_block=None, memo=None):
        raise IndexerUnavailable("TON deposits require the durable per-account scanner")
