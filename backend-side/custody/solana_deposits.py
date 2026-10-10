"""Root-bound finalized deposit scanning with durable bounded history pagination."""

from decimal import Decimal

import base58
from django.conf import settings

from .chain_registry import get_chain_spec, rpc_urls
from .indexer.base import BalanceResult, DepositEvent, IndexerUnavailable
from .models import Asset, HotWallet, OnchainTransactionAttempt, UserWallet
from .mpc_binding import _wallet_root_keyset
from .mpc_solana_network import guarded_solana_rpc
from .native_tx import RequestsTransport
from .solana_policy import account_data, validate_mint, validate_token_account
from .solana_settlement import finalized_transaction, token_balances
from .solana_wire import SYSTEM_PROGRAM, uint
from .spl import derive_ata
from .token_metadata import CLASSIC_TOKEN_PROGRAM, assert_verified_token


def transfer_events(tx, meta, slot, signature, wallet, asset):
    """Attribute explicit successful program transfers, keeping each instruction identity."""
    if meta["err"] is not None:
        return []
    keys = [str(k) for k in tx.message.account_keys]
    signed = tx.message.header.num_required_signatures
    groups = [
        (f"ix:{i}", keys[ix.program_id_index], list(ix.accounts), bytes(ix.data))
        for i, ix in enumerate(tx.message.instructions)
    ]
    inner_seen = set()
    for group in meta.get("innerInstructions") or []:
        outer = group["index"]
        if (
            type(outer) is not int
            or not 0 <= outer < len(tx.message.instructions)
            or outer in inner_seen
        ):
            raise ValueError("invalid finalized inner instruction index")
        inner_seen.add(outer)
        for i, ix in enumerate(group["instructions"]):
            program = ix["programIdIndex"]
            accounts = ix["accounts"]
            if (
                type(program) is not int
                or not 0 <= program < len(keys)
                or any(type(a) is not int or not 0 <= a < len(keys) for a in accounts)
            ):
                raise ValueError("invalid finalized inner account index")
            groups.append(
                (f"inner:{outer}:{i}", keys[program], accounts, base58.b58decode(ix["data"]))
            )
    internal = set(
        HotWallet.objects.filter(chain_id="SOL").values_list("address", flat=True)
    ) | set(UserWallet.objects.filter(chain_id="SOL").values_list("deposit_address", flat=True))
    if OnchainTransactionAttempt.objects.filter(chain_id="SOL", network_tx_id=signature).exists():
        return []  # Durable internal transfer identity, including grants/withdrawals/sweeps.
    before = after = None
    if not asset.is_native:
        before = token_balances(
            meta, "preTokenBalances", keys, asset.contract_address, asset.decimals
        )
        after = token_balances(
            meta, "postTokenBalances", keys, asset.contract_address, asset.decimals
        )
    events = []
    incoming = 0
    for identity, program, accounts, data in groups:
        if asset.is_native:
            if (
                program != SYSTEM_PROGRAM
                or len(data) != 12
                or data[:4] != b"\x02\x00\x00\x00"
                or len(accounts) != 2
            ):
                continue
            source, destination = (keys[a] for a in accounts)
            units = int.from_bytes(data[4:], "little")
            if destination != wallet.deposit_address or source == destination or units == 0:
                continue
            # Only independent system-account signer transfers are in this deposit scope.
            # CPI PDA transfers/rent refunds remain unsupported instead of inferred credits.
            if accounts[0] >= signed:
                raise ValueError("native deposit transfer has unsupported PDA source")
            if source in internal:
                continue
            if meta["postBalances"][accounts[1]] - meta["preBalances"][accounts[1]] < units:
                raise ValueError("native explicit deposit effect lacks balance corroboration")
        else:
            if program != CLASSIC_TOKEN_PROGRAM or not data:
                continue
            if data[0] == 12 and len(data) == 10 and len(accounts) == 4:
                source_index, mint_index, destination_index, authority = accounts
                if keys[mint_index] != asset.contract_address or data[9] != asset.decimals:
                    continue
                units = int.from_bytes(data[1:9], "little")
            elif data[0] == 3 and len(data) == 9 and len(accounts) == 3:
                source_index, destination_index, authority = accounts
                units = int.from_bytes(data[1:], "little")
            else:
                continue
            if keys[destination_index] != wallet.asset_account_address:
                continue
            if keys[source_index] == keys[destination_index] or units == 0:
                continue
            source_balance = before.get(source_index)
            destination_balance = after.get(destination_index)
            if (
                not source_balance
                or not destination_balance
                or destination_balance[1] != wallet.deposit_address
            ):
                raise ValueError("SPL deposit mint/owner balance evidence incomplete")
            source_owner = source_balance[1]
            if (
                keys[source_index] != derive_ata(source_owner, asset.contract_address)
                or keys[authority] != source_owner
                or authority >= signed
            ):
                raise ValueError("SPL deposit source ATA/authority/delegate is unsupported")
            if source_owner in internal:
                continue
            if source_index not in after or source_balance[0] - after[source_index][0] < units:
                raise ValueError("SPL deposit source transfer effect mismatch")
            destination_pre = before.get(destination_index, (0, wallet.deposit_address))
            if (
                destination_pre[1] != wallet.deposit_address
                or destination_balance[0] - destination_pre[0] < units
            ):
                raise ValueError("SPL deposit destination effect mismatch")
        incoming += units
        events.append(
            DepositEvent(
                signature,
                Decimal(units) / (10**asset.decimals),
                slot,
                get_chain_spec("SOL").confirmations,
                asset_key=asset.asset_key,
                event_index=identity,
                contract_address=None if asset.is_native else asset.contract_address,
            )
        )
    # Multiple transfers must be corroborated in aggregate, not each against the same delta.
    if events:
        index = keys.index(
            wallet.deposit_address if asset.is_native else wallet.asset_account_address
        )
        if asset.is_native:
            delta = meta["postBalances"][index] - meta["preBalances"][index]
        else:
            delta = after[index][0] - before.get(index, (0, wallet.deposit_address))[0]
        if delta < incoming:
            raise ValueError("aggregate deposit instruction effects conflict with metadata")
    return events


def scan_root_wallet(chain_id, address, asset_key, after_block, *, transport=None):
    import os
    from decimal import Decimal

    if (
        settings.CUSTODY_INDEXER_MODE != "live"
        or os.environ.get("CUSTODY_INDEXER_MODE", "live") != "live"
    ):
        raise IndexerUnavailable("Solana MPC rejects simulated/stub deposit indexing")
    wallet = UserWallet.objects.select_related("mpc_keyset").get(
        chain_id=chain_id, deposit_address=address, asset_key=asset_key, status="ACTIVE"
    )
    _wallet_root_keyset(wallet, chain_id, address)
    asset = Asset.objects.get(asset_key=asset_key, chain_id=chain_id, enabled=True)
    transport = transport or RequestsTransport()
    if not asset.is_native:
        asset = assert_verified_token(asset_key)
        if wallet.asset_account_address != derive_ata(address, asset.contract_address):
            raise IndexerUnavailable("SPL deposit wallet is not bound to canonical ATA")
    cursor = wallet.solana_scan_cursor
    errors = []
    for url in rpc_urls(chain_id):
        try:

            def rpc(method, params):
                return guarded_solana_rpc(chain_id, url, transport, method, params)

            boundary = cursor.get("boundary", int(after_block or 0))
            if uint(rpc("getFirstAvailableBlock", [])) > max(1, boundary):
                raise IndexerUnavailable("Solana required deposit history is pruned")
            head = cursor.get("head_slot") or uint(rpc("getSlot", [{"commitment": "finalized"}]))
            history_address = address if asset.is_native else wallet.asset_account_address
            account = rpc(
                "getAccountInfo",
                [history_address, {"encoding": "base64", "commitment": "finalized"}],
            )["value"]
            if asset.is_native:
                if account is None:
                    units = 0
                else:
                    account_data(account, SYSTEM_PROGRAM, 0)
                    units = uint(account["lamports"])
            elif account is None:
                units = 0
            else:
                mint = rpc(
                    "getAccountInfo",
                    [asset.contract_address, {"encoding": "base64", "commitment": "finalized"}],
                )["value"]
                validate_mint(mint, asset.decimals)
                units = validate_token_account(
                    account, address, asset.contract_address, asset.decimals
                )
            before_signature = cursor.get("before")
            previous_slot = cursor.get("before_slot")
            events = []
            complete = False
            seen = set()
            # Fixed bounded work per invocation; persistence commits cursor with credits.
            for _ in range(4):
                options = {"commitment": "finalized", "limit": 100}
                if before_signature:
                    options["before"] = before_signature
                page = rpc("getSignaturesForAddress", [history_address, options])
                if not isinstance(page, list) or len(page) > 100:
                    raise IndexerUnavailable("invalid Solana signature pagination")
                for summary in page:
                    signature = summary["signature"]
                    slot = uint(summary["slot"], positive=True)
                    if previous_slot is not None and slot > previous_slot:
                        raise IndexerUnavailable("Solana signature pagination is not ordered")
                    previous_slot = slot
                    if signature in seen or signature == before_signature:
                        raise IndexerUnavailable("Solana signature pagination made no progress")
                    seen.add(signature)
                    if slot < boundary:
                        complete = True
                        continue
                    if slot > head:
                        continue
                    status = rpc(
                        "getSignatureStatuses", [[signature], {"searchTransactionHistory": True}]
                    )["value"][0]
                    response = rpc(
                        "getTransaction",
                        [signature, {"encoding": "base64", "commitment": "finalized"}],
                    )
                    tx, meta, actual_slot = finalized_transaction(response, signature, status)
                    if slot != actual_slot or summary.get("err") != meta["err"]:
                        raise IndexerUnavailable("conflicting finalized signature scan evidence")
                    events.extend(transfer_events(tx, meta, slot, signature, wallet, asset))
                if not page or len(page) < 100 or complete:
                    complete = True
                    break
                before_signature = page[-1]["signature"]
            result = BalanceResult(
                Decimal(units) / (10**asset.decimals),
                deposit_events=events,
                last_scanned_block=head if complete else None,
            )
            result.scan_complete = complete
            result.scan_cursor = (
                {}
                if complete
                else {
                    "boundary": boundary,
                    "head_slot": head,
                    "before": before_signature,
                    "before_slot": previous_slot,
                }
            )
            return result
        except (ValueError, KeyError, TypeError, IndexError) as exc:
            raise IndexerUnavailable("conflicting/malformed finalized deposit evidence") from exc
        except Exception as exc:
            errors.append(exc)
    raise IndexerUnavailable(
        "Solana finalized deposit history unavailable; cursor remains unchanged"
    ) from errors[-1]


def root_native_balance(address):
    """Fee funding observation for a bound token wallet; no deposit attribution."""
    wallets = list(
        UserWallet.objects.select_related("mpc_keyset").filter(
            chain_id="SOL", deposit_address=address, status="ACTIVE"
        )
    )
    if not wallets:
        raise IndexerUnavailable("native funding observation needs explicit root ownership")
    for wallet in wallets:
        _wallet_root_keyset(wallet, "SOL", address)
    transport = RequestsTransport()
    for url in rpc_urls("SOL"):
        info = guarded_solana_rpc(
            "SOL",
            url,
            transport,
            "getAccountInfo",
            [address, {"encoding": "base64", "commitment": "finalized"}],
        )["value"]
        if info is None:
            return BalanceResult(Decimal(0))
        account_data(info, SYSTEM_PROGRAM, 0)
        return BalanceResult(Decimal(uint(info["lamports"])) / (10**9))
    raise IndexerUnavailable("root native funding observation unavailable")
