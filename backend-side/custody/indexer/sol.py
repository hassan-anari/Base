"""SOL indexer: isolated root-bound MPC evidence or legacy demo indexing.

LIVE mode (default): real Solana JSON-RPC via the editable node registry
(ops dashboard -> Nodes). Balance = getBalance (lamports -> SOL, 1e9).
Deposit events = getSignaturesForAddress + getTransaction (best-effort).
STUB mode (CUSTODY_INDEXER_MODE=stub): offline simulated balance.
"""

from __future__ import annotations

import logging
from decimal import Decimal
from typing import List

import requests

from .base import BalanceResult, DepositEvent, IndexerClient, IndexerUnavailable
from .rpc_nodes import rpc_urls

logger = logging.getLogger("custody.indexer.sol")

RPC_TIMEOUT = 8.0


def _rpc(url: str, method: str, params: list):
    r = requests.post(
        url,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        timeout=RPC_TIMEOUT,
    )
    r.raise_for_status()
    data = r.json()
    if "error" in data:
        raise RuntimeError(f"{method}: {data['error']}")
    return data["result"]


def _mint_for_account(tx, account):
    """Resolve a token account mint from authoritative pre/post token balances."""
    keys = tx.get("transaction", {}).get("message", {}).get("accountKeys", [])
    for index, key in enumerate(keys):
        pubkey = key.get("pubkey") if isinstance(key, dict) else key
        if pubkey != account:
            continue
        for balance in (tx.get("meta", {}).get("preTokenBalances") or []) + (
            tx.get("meta", {}).get("postTokenBalances") or []
        ):
            if int(balance.get("accountIndex", -1)) == index:
                return balance.get("mint")
    return None


class SolIndexer(IndexerClient):
    def __init__(self, chain_id: str = "SOL"):
        super().__init__(chain_id)

    def get_balance(
        self, address: str, *, asset_key=None, after_block=None, memo=None
    ) -> BalanceResult:
        from django.conf import settings

        if settings.MPC_SIGNER_BACKEND == "self_hosted_mpc":
            from ..models import UserWallet
            from ..signer_adapter import assert_mpc_backend_runtime_safe
            from ..solana_deposits import scan_root_wallet

            assert_mpc_backend_runtime_safe(self.chain_id)
            if (
                asset_key == "SOL"
                and not UserWallet.objects.filter(
                    chain_id="SOL", deposit_address=address, asset_key="SOL"
                ).exists()
            ):
                from ..solana_deposits import root_native_balance

                return root_native_balance(address)
            return scan_root_wallet(self.chain_id, address, asset_key, after_block)
        if self._stub_enabled():
            return self._stub_balance(asset_key=asset_key)
        from ..models import Asset

        asset = Asset.objects.filter(
            asset_key=asset_key, chain_id=self.chain_id, enabled=True
        ).first()
        if asset and not asset.is_native:
            return self._token_balance(asset, address, after_block)
        urls = rpc_urls(self.chain_id)
        if not urls:
            raise IndexerUnavailable("no RPC node configured for SOL")
        last_err: Exception | None = None
        for u in urls:
            try:
                slot = int(_rpc(u, "getSlot", []))
                lamports = int(
                    _rpc(u, "getBalance", [address, {"commitment": "confirmed"}])["value"]
                )
                from ..chain_registry import get_chain_spec

                divisor = Decimal(10 ** get_chain_spec(self.chain_id).native_decimals)
                confirmed = Decimal(lamports) / divisor

                events: List[DepositEvent] = []
                try:
                    sigs = _rpc(u, "getSignaturesForAddress", [address, {"limit": 25}]) or []
                    for s in sigs:
                        if s.get("err"):
                            continue
                        try:
                            tx = _rpc(
                                u,
                                "getTransaction",
                                [
                                    s["signature"],
                                    {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0},
                                ],
                            )
                        except Exception:  # noqa: BLE001
                            continue
                        if not tx:
                            continue
                        meta = tx.get("meta") or {}
                        msg = tx.get("transaction", {}).get("message", {}) or {}
                        accs = msg.get("accountKeys", [])
                        # Find this address's index in the account list.
                        idx = None
                        for i, ak in enumerate(accs):
                            pk = ak.get("pubkey") if isinstance(ak, dict) else ak
                            if pk == address:
                                idx = i
                                break
                        if idx is None:
                            continue
                        pre = (meta.get("preBalances") or [0] * (idx + 1))[idx]
                        post = (meta.get("postBalances") or [0] * (idx + 1))[idx]
                        delta = post - pre
                        if delta > 0:
                            events.append(
                                DepositEvent(
                                    tx_hash=s["signature"],
                                    amount=Decimal(delta) / divisor,
                                    block=int(tx.get("slot", 0)),
                                    confirmations=max(0, slot - int(tx.get("slot", slot))),
                                )
                            )
                except Exception as e:  # noqa: BLE001
                    logger.warning("SOL tx scan failed for %s: %s", address, e)

                return BalanceResult(
                    confirmed_balance=confirmed,
                    pending_balance=Decimal("0"),
                    last_scanned_block=slot,
                    deposit_events=events,
                )
            except Exception as e:  # noqa: BLE001 - failover to next node
                last_err = e
                logger.warning("sol rpc fail url=%s err=%s", u, e)
        logger.error("SOL live balance failed for %s: %s", address, last_err)
        raise IndexerUnavailable("SOL balance unavailable") from last_err

    def _token_balance(self, asset, owner, after_block):
        from ..chain_registry import get_chain_spec
        from ..spl import derive_ata
        from ..token_metadata import CLASSIC_TOKEN_PROGRAM, assert_verified_token

        assert_verified_token(asset.asset_key)
        ata = derive_ata(owner, asset.contract_address)
        last_error = None
        for url in rpc_urls(self.chain_id):
            try:
                account = _rpc(
                    url,
                    "getAccountInfo",
                    [ata, {"encoding": "jsonParsed", "commitment": "finalized"}],
                )["value"]
                units = 0
                if account is not None:
                    if account.get("owner") != CLASSIC_TOKEN_PROGRAM:
                        raise IndexerUnavailable("SPL ATA is not owned by classic Token Program")
                    info = account["data"]["parsed"]["info"]
                    token_amount = info["tokenAmount"]
                    if info.get("mint") != asset.contract_address or info.get("owner") != owner:
                        raise IndexerUnavailable("SPL ATA mint/owner mismatch")
                    if int(token_amount["decimals"]) != asset.decimals:
                        raise IndexerUnavailable("SPL ATA decimals mismatch")
                    units = int(token_amount["amount"])
                slot = int(_rpc(url, "getSlot", [{"commitment": "finalized"}]))
                settings = get_chain_spec(self.chain_id).gas_settings
                boundary = (
                    int(after_block)
                    if after_block is not None
                    else max(0, slot - int(settings.get("token_initial_lookback_slots", 10_000)))
                )
                max_pages = int(settings.get("token_signature_max_pages", 100))
                signatures = []
                before = None
                complete = False
                for _page in range(max_pages):
                    options = {"commitment": "finalized", "limit": 100}
                    if before:
                        options["before"] = before
                    page = _rpc(url, "getSignaturesForAddress", [ata, options]) or []
                    signatures.extend(page)
                    if not page or len(page) < 100 or int(page[-1].get("slot", 0)) < boundary:
                        complete = True
                        break
                    before = page[-1]["signature"]
                if not complete:
                    raise IndexerUnavailable("SPL signature scan exceeded reviewed page limit")
                events = []
                for summary in signatures:
                    if summary.get("err") is not None or (int(summary.get("slot", 0)) < boundary):
                        continue
                    tx = _rpc(
                        url,
                        "getTransaction",
                        [
                            summary["signature"],
                            {
                                "encoding": "jsonParsed",
                                "commitment": "finalized",
                                "maxSupportedTransactionVersion": 0,
                            },
                        ],
                    )
                    if not tx:
                        raise IndexerUnavailable(
                            "required finalized Solana transaction is unavailable"
                        )
                    if (tx.get("meta") or {}).get("err") is not None:
                        continue
                    message = tx["transaction"]["message"]
                    outer = message.get("instructions", [])
                    groups = [(f"ix:{i}", ix) for i, ix in enumerate(outer)]
                    for inner_group in tx.get("meta", {}).get("innerInstructions") or []:
                        oi = int(inner_group["index"])
                        groups.extend(
                            (f"inner:{oi}:{j}", ix)
                            for j, ix in enumerate(inner_group.get("instructions", []))
                        )
                    for event_index, instruction in groups:
                        parsed = (
                            instruction.get("parsed") if isinstance(instruction, dict) else None
                        )
                        if (
                            instruction.get("programId") != CLASSIC_TOKEN_PROGRAM
                            or not parsed
                            or parsed.get("type") not in {"transfer", "transferChecked"}
                        ):
                            continue
                        details = parsed.get("info", {})
                        if details.get("destination") != ata:
                            continue
                        amount_data = details.get("tokenAmount") or {}
                        amount = int(amount_data.get("amount", details.get("amount", 0)))
                        mint = details.get("mint")
                        if mint is None:
                            mint = _mint_for_account(tx, details.get("source"))
                        if mint != asset.contract_address or amount <= 0:
                            continue
                        events.append(
                            DepositEvent(
                                tx_hash=summary["signature"],
                                amount=Decimal(amount) / (Decimal(10) ** asset.decimals),
                                block=int(tx.get("slot", 0)),
                                confirmations=max(0, slot - int(tx.get("slot", slot)) + 1),
                                asset_key=asset.asset_key,
                                event_index=event_index,
                                contract_address=asset.contract_address,
                            )
                        )
                return BalanceResult(
                    Decimal(units) / (Decimal(10) ** asset.decimals),
                    last_scanned_block=slot,
                    deposit_events=events,
                )
            except Exception as exc:
                last_error = exc
        raise IndexerUnavailable("SPL token scan unavailable") from last_error

    def get_txs(self, address: str, after_block=None, memo=None):
        return []
