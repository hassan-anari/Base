"""Verify actual TVM transaction/message effects, separate from network finality.

These functions never credit/settle a live operation. Full masterchain and shard
inclusion is an additional mandatory boundary enforced by the live proof client.
"""

from dataclasses import dataclass

from pytoniq_core import Address, Cell, MessageAny, Transaction

from .ton_wire import (
    EXCESSES,
    INTERNAL_TRANSFER,
    NOTIFICATION,
    TRANSFER,
    coins,
    normalize_address,
)


@dataclass(frozen=True)
class Execution:
    account: str
    lt: int
    tx_hash: str
    transaction: object
    inbound: object
    inbound_hash: str
    outgoing: tuple
    fee_nanoton: int

    @property
    def successful(self):
        d = self.transaction.description
        compute = getattr(d, "compute_ph", None)
        action = getattr(d, "action", None)
        return (
            not getattr(d, "aborted", True)
            and getattr(compute, "success", False)
            and getattr(compute, "exit_code", None) in (0, 1)
            and (action is None or (action.success and action.result_code == 0))
        )


def execution_from_boc(boc_hex):
    raw = bytes.fromhex(boc_hex)
    cell = Cell.one_from_boc(raw)
    t = Transaction.deserialize(cell.begin_parse())
    # Preserve exact message cells as encoded in the transaction. Re-serializing
    # a relaxed/inline message can change its representation hash.
    messages = cell.refs[0].begin_parse()
    inbound = messages.load_maybe_ref()
    outgoing = messages.load_dict(15, value_deserializer=lambda s: s.load_ref()) or {}
    if inbound is None:
        raise ValueError("unsupported TON transaction without inbound message")
    return Execution(
        "0:" + t.account_addr.hex(),
        t.lt,
        cell.hash.hex(),
        t,
        MessageAny.deserialize(inbound.begin_parse()),
        inbound.hash.hex(),
        tuple(
            (c.hash.hex(), MessageAny.deserialize(c.begin_parse()))
            for _, c in sorted(outgoing.items())
        ),
        t.total_fees.grams,
    )


def comment_bytes(body):
    s = body.begin_parse()
    if not s.remaining_bits:
        return b""
    if s.remaining_bits < 32 or s.load_uint(32) != 0 or s.remaining_refs or s.remaining_bits % 8:
        raise ValueError("unsupported/malformed TON comment")
    raw = s.load_bytes(s.remaining_bits // 8)
    if len(raw) > 96:
        raise ValueError("unsupported TON comment length")
    return raw


def parse_jetton_body(body):
    s = body.begin_parse()
    opcode, query = s.load_uint(32), s.load_uint(64)
    result = {"opcode": opcode, "query_id": query}
    if opcode == EXCESSES:
        if s.remaining_bits or s.remaining_refs:
            raise ValueError("malformed Jetton excesses")
        return result
    if opcode not in (TRANSFER, INTERNAL_TRANSFER, NOTIFICATION):
        raise ValueError("unsupported Jetton opcode")
    result["amount"] = s.load_coins()
    first = s.load_address()
    if first is None or first.anycast:
        raise ValueError("missing Jetton message owner")
    result["owner"] = first.to_str(False)
    if opcode in (TRANSFER, INTERNAL_TRANSFER):
        response = s.load_address()
        if response is None or response.anycast:
            raise ValueError("invalid Jetton response destination")
        result["response"] = response.to_str(False)
        if opcode == TRANSFER and s.load_uint(1) != 0:
            raise ValueError("Jetton custom payload forbidden")
        result["forward_nanoton"] = s.load_coins()
    referenced = s.load_uint(1)
    payload = s.load_ref() if referenced else s.to_cell()
    if not referenced:
        s.load_bits(s.remaining_bits)
        while s.remaining_refs:
            s.load_ref()
    result["comment"] = comment_bytes(payload)
    if s.remaining_bits or s.remaining_refs:
        raise ValueError("unexpected Jetton body trailing data")
    return result


def terminal_transfer_effect(
    authorization, source, external_hash, executions, *, custody_addresses=()
):
    """Require each intended internal message to execute successfully at recipient.

    Increased wallet seqno, outgoing emission and notifications alone never prove
    token credit. Partial, bounced, expired, missing histories remain unresolved.
    """
    by_in = {}
    for e in executions:
        if e.inbound_hash in by_in:
            raise ValueError("duplicate inbound TON execution identity")
        by_in[e.inbound_hash] = e
    wallet = by_in.get(external_hash)
    if wallet is None or wallet.account != source or not wallet.successful:
        return {"terminal": False, "reason": "WALLET_EXECUTION_UNPROVEN"}
    a = authorization
    jetton = a["jetton_master"] is not None
    expected_to = a["jetton_source"] if jetton else a["destination"]
    candidates = [
        (h, m)
        for h, m in wallet.outgoing
        if isinstance(m.info.dest, Address) and m.info.dest.to_str(False) == expected_to
    ]
    if len(candidates) != 1:
        return {"terminal": False, "reason": "INTENDED_MESSAGE_UNPROVEN"}
    message_hash, message = candidates[0]
    if (
        message.info.bounced
        or message.info.value.grams != coins(a["attached_nanoton"])
        or message.info.bounce != a["bounce"]
    ):
        raise ValueError("actual outgoing TON message differs from authorization")
    delivered = by_in.get(message_hash)
    uninit_credit = False
    if delivered is not None and not jetton and not a["bounce"]:
        d = delivered.transaction.description
        compute = getattr(d, "compute_ph", None)
        credit = getattr(d, "credit_ph", None)
        # A nobounce transfer to an uninitialized account has skipped compute
        # and aborted=True, but TON retains its proven credit phase. Require
        # exact internal message value, no bounce/action/outgoing, and no-state.
        uninit_credit = (
            getattr(compute, "type_", None) == "skipped"
            and getattr(getattr(compute, "reason", None), "type_", None) == "no_state"
            and credit is not None
            and credit.credit.grams == coins(a["amount"])
            and not credit.credit.other.dict
            and getattr(d, "bounce", None) is None
            and getattr(d, "action", None) is None
            and not delivered.outgoing
            and not message.info.bounced
        )
    if (
        delivered is None
        or delivered.account != expected_to
        or not (delivered.successful or uninit_credit)
    ):
        return {"terminal": False, "reason": "RECIPIENT_EXECUTION_UNPROVEN"}
    chain = [wallet, delivered]
    if not jetton:
        if comment_bytes(message.body) != bytes.fromhex(a["comment_hex"]):
            raise ValueError("native TON comment mismatch")
    else:
        transfer = parse_jetton_body(message.body)
        if transfer != {
            "opcode": TRANSFER,
            "query_id": a["query_id"],
            "amount": coins(a["amount"]),
            "owner": a["destination"],
            "response": source,
            "forward_nanoton": 1,
            "comment": bytes.fromhex(a["comment_hex"]),
        }:
            raise ValueError("sender Jetton transfer request mismatch")
        internal = [
            (h, m)
            for h, m in delivered.outgoing
            if isinstance(m.info.dest, Address)
            and m.info.dest.to_str(False) == a["jetton_destination"]
        ]
        if len(internal) != 1:
            return {"terminal": False, "reason": "JETTON_INTERNAL_TRANSFER_UNPROVEN"}
        h, m = internal[0]
        body = parse_jetton_body(m.body)
        if (
            body
            != {
                "opcode": INTERNAL_TRANSFER,
                "query_id": a["query_id"],
                "amount": coins(a["amount"]),
                "owner": source,
                "response": source,
                "forward_nanoton": 1,
                "comment": bytes.fromhex(a["comment_hex"]),
            }
            or m.info.src != Address(a["jetton_source"])
            or m.info.bounced
        ):
            raise ValueError("Jetton internal owner/message identity mismatch")
        m_internal_value = m.info.value.grams
        recipient = by_in.get(h)
        if (
            recipient is None
            or recipient.account != a["jetton_destination"]
            or not recipient.successful
        ):
            return {"terminal": False, "reason": "JETTON_RECIPIENT_EFFECT_UNPROVEN"}
        # Reviewed wallet code commits balance increment only on successful compute
        # and action phases; caller must separately verify its actual code/owner state.
        chain.append(recipient)
    owned_chain = [wallet]
    returned_nanoton = 0
    if jetton:
        owned_chain.extend(chain[1:])
        excesses = []
        for h, m in chain[-1].outgoing:
            body = parse_jetton_body(m.body)
            if body["query_id"] != a["query_id"]:
                raise ValueError("Jetton asynchronous query mismatch")
            if body["opcode"] == EXCESSES:
                if (
                    m.info.src != Address(a["jetton_destination"])
                    or m.info.dest != Address(source)
                    or m.info.bounced
                ):
                    raise ValueError("Jetton excesses response identity mismatch")
                reply = by_in.get(h)
                if reply is None or reply.account != source or not reply.successful:
                    return {"terminal": False, "reason": "JETTON_EXCESSES_UNPROVEN"}
                returned_nanoton += m.info.value.grams
                owned_chain.append(reply)
                excesses.append(h)
            elif (
                body["opcode"] != NOTIFICATION
                or body["owner"] != source
                or body["amount"] != coins(a["amount"])
                or m.info.dest != Address(a["destination"])
            ):
                raise ValueError("unapproved Jetton asynchronous outgoing message")
        if len(excesses) != 1:
            return {"terminal": False, "reason": "JETTON_RETURNED_FUNDS_UNPROVEN"}
    owned = set(custody_addresses) | {source}
    if jetton:
        owned.add(a["jetton_source"])
    if delivered.account in owned and delivered not in owned_chain:
        owned_chain.append(delivered)
    # Only custody contract costs are paid by the aggregate TON treasury. Gas
    # sent to an external Jetton recipient, less proven excesses, is distinct.
    owned_chain = {e.tx_hash: e for e in owned_chain if e.account in owned}.values()
    fee_transactions = [
        {
            "account": e.account,
            "hash": e.tx_hash,
            "fee_nanoton": e.fee_nanoton
            + sum(
                m.info.fwd_fee + m.info.ihr_fee for _, m in e.outgoing if hasattr(m.info, "fwd_fee")
            ),
        }
        for e in owned_chain
    ]
    funding_expense = 0
    if jetton and a["jetton_destination"] not in owned:
        funding_expense = m_internal_value - returned_nanoton
        if funding_expense < 0:
            raise ValueError("Jetton returned value exceeds original funding")
    return {
        "terminal": True,
        "network_finality": False,
        "transactions": [{"account": e.account, "lt": str(e.lt), "hash": e.tx_hash} for e in chain],
        "fee_nanoton": sum(e["fee_nanoton"] for e in fee_transactions),
        "fee_transactions": fee_transactions,
        "funding_expense_nanoton": funding_expense,
        "returned_nanoton": returned_nanoton,
        "recipient_fee_nanoton": chain[-1].fee_nanoton,
    }


def attribute_native_deposit(execution, wallet, *, known_internal_sources=()):
    msg = execution.inbound
    description = execution.transaction.description
    compute = getattr(description, "compute_ph", None)
    credit = getattr(description, "credit_ph", None)
    uninit_credit = (
        hasattr(msg.info, "value")
        and not msg.info.bounce
        and not msg.info.bounced
        and getattr(compute, "type_", None) == "skipped"
        and getattr(getattr(compute, "reason", None), "type_", None) == "no_state"
        and credit is not None
        and credit.credit.grams == msg.info.value.grams
        and getattr(description, "bounce", None) is None
        and not execution.outgoing
    )
    if (
        not (execution.successful or uninit_credit)
        or not hasattr(msg.info, "value")
        or msg.info.bounced
        or execution.account != normalize_address(wallet.deposit_address).raw
        or msg.info.dest != Address(wallet.deposit_address)
    ):
        raise ValueError("unverified/bounced/misdirected native TON deposit")
    if msg.info.src is None or msg.info.src.to_str(False) in known_internal_sources:
        return None
    from .models import UserWallet

    owners = UserWallet.objects.filter(
        chain_id=wallet.chain_id, deposit_address=wallet.deposit_address, status="ACTIVE"
    )
    if set(owners.values_list("user_id", flat=True)) != {wallet.user_id}:
        raise ValueError("TON deposit address has conflicting customer ownership")
    memo = comment_bytes(msg.body)
    if not wallet.memo or memo != wallet.memo.encode():
        return None  # missing/unknown invoice is unattributed, never credit all.
    return {
        "amount_nanoton": msg.info.value.grams,
        "message_hash": execution.inbound_hash,
        "transaction_hash": execution.tx_hash,
        "lt": str(execution.lt),
        "comment_hex": memo.hex(),
        "network_finality": False,
    }
