"""PostgreSQL safety regressions around the TON authorization/lifecycle boundary."""

from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal

import pytest
from django.db import close_old_connections

from custody.models import OnchainTransactionAttempt, SourceAccountSequence
from custody.ton_policy import TonSequenceBusy, own_sequence, prepare_authorization
from custody.ton_wire import (
    Cell,
    normalize_address,
    validate_authorization,
    verify_wallet_state,
    wallet_address,
    wallet_init,
)

PUBLIC = bytes.fromhex("11" * 32)
SOURCE = wallet_address(PUBLIC, -777)


def authorization():
    return prepare_authorization(
        public_key=PUBLIC,
        global_id=-777,
        source=SOURCE,
        destination="0:" + "22" * 32,
        amount_units=100000000,
        seqno=0,
        valid_until=1900000120,
        chain_time=1900000000,
        balance_nanoton=2000000000,
        deployed=False,
    )["ton_authorization"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("send_mode", 1),
        ("seqno", 1),
        ("wallet_id", 0),
        ("wallet_version", "V4R2"),
        ("valid_until", 0),
        ("code_hash", "00" * 32),
        ("destination", "0:" + "33" * 32),
        ("amount", "100000001"),
        ("comment_hex", "ff"),
    ],
)
def test_immutable_ton_authorization(field, value):
    a = authorization()
    a[field] = value
    with pytest.raises(ValueError):
        validate_authorization(a, PUBLIC)


def test_ton_original_stateinit_and_extension_rejection():
    init = wallet_init(PUBLIC, -777)
    assert SOURCE == "0:" + init.hash.hex()
    assert verify_wallet_state(SOURCE, PUBLIC, -777, status="uninit") == 0
    with pytest.raises(ValueError):
        verify_wallet_state("0:" + PUBLIC.hex(), PUBLIC, -777, status="uninit")
    with pytest.raises(ValueError):
        verify_wallet_state(
            SOURCE, PUBLIC, -777, status="active", code=init.refs[0], data=Cell.empty()
        )


def attempt(operation):
    return OnchainTransactionAttempt.objects.create(
        operation_type="WITHDRAWAL",
        operation_id=operation,
        chain_id="TON",
        asset_key="TON",
        from_address=SOURCE,
        to_address="0:" + "22" * 32,
        amount=Decimal("0.1"),
        base_unit_amount=100000000,
    )


@pytest.mark.django_db(transaction=True)
def test_same_contract_concurrent_sequences_and_unknown_expiry():
    a, b = attempt(1), attempt(2)

    def claim(pk):
        close_old_connections()
        try:
            return own_sequence(pk, 0)
        except TonSequenceBusy:
            return "busy"
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(claim, [a.pk, b.pk]))
    assert sorted(map(str, results)) == ["0", "busy"]
    owner = SourceAccountSequence.objects.get(chain_id="TON", address=SOURCE).owner_attempt
    other = b if owner.pk == a.pk else a
    owner.status = "RECONCILIATION_REQUIRED"
    owner.save(update_fields=["status"])
    with pytest.raises(TonSequenceBusy):
        own_sequence(other.pk, 1)
    owner.status = "CONFIRMED"
    owner.confirmation_metadata = {"ton_terminal_delivery": True}
    owner.save(update_fields=["status", "confirmation_metadata"])
    assert own_sequence(other.pk, 1) == 1


@pytest.mark.parametrize("global_id", [-239, -3, 0, 1])
def test_public_network_identity_rejected(global_id):
    with pytest.raises(ValueError):
        wallet_init(PUBLIC, global_id)


def test_ton_friendly_checksum_network_and_bounce():
    from pytoniq_core import Address

    for bounce in (False, True):
        friendly = Address(SOURCE).to_str(
            is_user_friendly=True, is_bounceable=bounce, is_test_only=True
        )
        assert normalize_address(friendly, require_test=True).bounceable == bounce
        assert normalize_address(friendly, require_test=True).raw == SOURCE
    with pytest.raises(ValueError):
        normalize_address(
            Address(SOURCE).to_str(is_user_friendly=True, is_test_only=False), require_test=True
        )


@pytest.mark.django_db(transaction=True)
def test_concurrent_ton_fee_journal_is_exactly_once():
    from custody.models import LedgerPosting, LedgerTransaction
    from custody.ton_costs import post_verified_transaction_fee

    def post(_):
        close_old_connections()
        try:
            post_verified_transaction_fee(SOURCE, "ab" * 32, 123456)
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(post, range(3)))
    assert LedgerTransaction.objects.count() == 1
    assert LedgerPosting.objects.count() == 2
    with pytest.raises(ValueError):
        post_verified_transaction_fee(SOURCE, "ab" * 32, 123457)


@pytest.mark.parametrize("fault", ["owner", "master", "code", "getter", "balance"])
def test_fake_jetton_wallet_identity_rejected(fault):
    from custody.ton_wire import Builder, approved_code, jetton_wallet_address, verify_jetton_wallet

    master = "0:" + "55" * 32
    code = approved_code("jetton-wallet")
    address = jetton_wallet_address(SOURCE, master)
    data = (
        Builder()
        .store_coins(10)
        .store_address("0:" + "66" * 32 if fault == "owner" else SOURCE)
        .store_address("0:" + "77" * 32 if fault == "master" else master)
        .store_ref(Cell.empty() if fault == "balance" else code)
        .end_cell()
    )
    with pytest.raises(ValueError):
        verify_jetton_wallet(
            address,
            SOURCE,
            master,
            Cell.empty() if fault == "code" else code,
            data,
            SOURCE if fault == "getter" else address,
        )


@pytest.mark.django_db
@pytest.mark.parametrize("memo", [None, "unknown-invoice", "invoice-1"])
def test_native_memo_attribution_and_shared_address_conflict(memo):
    from types import SimpleNamespace as N

    from pytoniq_core import Address

    from custody.models import UserWallet
    from custody.ton_effects import attribute_native_deposit
    from custody.ton_wire import Builder

    wallet = UserWallet.objects.create(
        user_id="alice",
        chain_id="TON",
        asset_key="TON",
        deposit_address=SOURCE,
        memo="invoice-1",
        derivation_path="keyset:root",
    )
    body = Builder().store_uint(0, 32).store_bytes((memo or "").encode()).end_cell()
    execution = N(
        successful=True,
        account=SOURCE,
        outgoing=(),
        tx_hash="01" * 32,
        inbound_hash="02" * 32,
        lt=1,
        transaction=N(description=N()),
        inbound=N(
            body=body,
            info=N(
                src=Address("0:" + "33" * 32),
                dest=Address(SOURCE),
                bounce=False,
                bounced=False,
                value=N(grams=100000000),
            ),
        ),
    )
    result = attribute_native_deposit(execution, wallet)
    assert bool(result) == (memo == "invoice-1")
    UserWallet.objects.create(
        user_id="bob",
        chain_id="TON",
        asset_key="OTHER-JETTON",
        deposit_address=SOURCE,
        memo="invoice-2",
        derivation_path="keyset:other-root",
    )
    with pytest.raises(ValueError, match="conflicting"):
        attribute_native_deposit(execution, wallet)
    assert (
        attribute_native_deposit(execution, wallet, known_internal_sources={"0:" + "33" * 32})
        is None
    )


def test_outbound_history_resume_and_pruned_history_preserve_identity(monkeypatch):
    from types import SimpleNamespace as N
    from unittest.mock import Mock

    from custody.native_tx import PreparedNativeTransaction, ReconciliationState
    from custody.ton_tx import TonNativeExecutor

    head = dict(workchain=0, seqno=300, root_hash="01" * 32, file_hash="02" * 32)
    parent = dict(workchain=0, seqno=172, root_hash="03" * 32, file_hash="04" * 32)
    cp = dict(workchain=-1, seqno=400, root_hash="05" * 32, file_hash="06" * 32)
    client = Mock()
    client.identity = {"global_id": -777}
    client.checkpoint.return_value = (cp, N())
    client.verify_checkpoint.return_value = (cp, N())
    client.shard_head.return_value = head
    client.history_from.side_effect = [([], parent, False), ([], dict(seqno=5), True)]
    client.transactions.return_value = []
    client.account.return_value = dict(status="uninit", code=None, data=None)
    monkeypatch.setattr("custody.ton_tx.proof_client", lambda _: client)
    original = dict(
        public_key=PUBLIC.hex(), ton_authorization=authorization(), ton_history_after_seqno=5
    )
    prepared = PreparedNativeTransaction(
        "TON", "TON", SOURCE, "0:" + "22" * 32, Decimal("0.1"), 100000000, b"", original, {}
    )
    executor = TonNativeExecutor()
    first = executor.reconcile(prepared, "07" * 32)
    assert first.state is ReconciliationState.RECONCILIATION_REQUIRED
    progress = first.evidence["ton_progress"]
    assert progress["parent"] == parent and progress["complete_through"] == 5
    resumed = PreparedNativeTransaction(
        "TON",
        "TON",
        SOURCE,
        prepared.to_address,
        prepared.amount,
        prepared.base_unit_amount,
        b"",
        {**original, "_ton_reconciliation_progress": progress},
        {},
    )
    second = executor.reconcile(resumed, "07" * 32)
    assert second.state is ReconciliationState.RECONCILIATION_REQUIRED
    assert second.evidence["ton_progress"]["complete_through"] == 300
    client.verify_checkpoint.assert_called_once_with(cp)
    assert client.history_from.call_args_list[1].args[0] == parent
    client.history_from.side_effect = ValueError("pruned history")
    pruned = executor.reconcile(resumed, "07" * 32)
    assert pruned.state is ReconciliationState.RECONCILIATION_REQUIRED
    assert pruned.evidence["ton_progress"] == progress
    assert original["ton_authorization"]["seqno"] == 0
    assert original["ton_authorization"]["valid_until"] == 1900000120


def test_untrusted_block_bytes_fail_before_inclusion():
    from custody.ton_proofs import TonProofError, checked_block

    with pytest.raises(TonProofError, match="file hash"):
        checked_block(b"invented block", {"file_hash": "00" * 32}, -777)


@pytest.mark.django_db(transaction=True)
def test_jetton_full_precision_double_entry_survives_default_decimal_context():
    from decimal import localcontext
    from types import SimpleNamespace as N

    from django.db import transaction

    from custody.ledger import (
        credit_deposit,
        financial_precision,
        reserve_withdrawal,
        settle_withdrawal,
        user_balances,
    )
    from custody.models import Asset, LedgerPosting

    Asset.objects.create(
        asset_key="TON-JETTON",
        chain_id="TON",
        symbol="REFERENCE",
        decimals=18,
        token_standard="TEP74",
        contract_address="0:" + "44" * 32,
    )

    amount = Decimal("123456789012345.123456789012345678")
    deposit = N(
        pk=99, user_wallet=N(user_id="jetton-precision"), asset_key="TON-JETTON", amount=amount
    )
    with localcontext() as context:
        context.prec = 28
        with transaction.atomic():
            credit_deposit(deposit)
        assert user_balances("jetton-precision", "TON-JETTON")["available"] == amount
        req = N(pk=88, user_id="jetton-precision", asset_key="TON-JETTON", amount=amount)
        with transaction.atomic():
            reserve_withdrawal(req)
        assert user_balances(req.user_id, req.asset_key)["reserved"] == amount
        with transaction.atomic():
            settle_withdrawal(req)
        assert user_balances(req.user_id, req.asset_key)["reserved"] == 0
    with financial_precision():
        assert set(LedgerPosting.objects.values_list("amount", flat=True)) == {-amount, amount}
        assert sum(LedgerPosting.objects.values_list("amount", flat=True), Decimal(0)) == 0


@pytest.mark.django_db(transaction=True)
def test_original_ton_asset_precision_cannot_change_after_preparation(monkeypatch):
    from types import SimpleNamespace as N
    from uuid import uuid4

    from custody.ton_policy import ton_transaction_identity

    a = attempt(55)
    a.prepared_metadata = dict(
        public_key=PUBLIC.hex(),
        ton_authorization=authorization(),
        ton_asset_decimals=9,
        ton_token_metadata_fingerprint=None,
    )
    a.fee_metadata = dict(
        max_fee_nanoton="10000000", storage_reserve_nanoton="20000000", attached_nanoton="100000000"
    )
    a.save(update_fields=["prepared_metadata", "fee_metadata"])
    own_sequence(a.pk, 0)
    a.refresh_from_db()
    asset = N(is_native=True, decimals=9)
    keyset = N(public_key=PUBLIC.hex(), keyset_id=uuid4(), dkg_result_fingerprint="88" * 32)
    monkeypatch.setattr("custody.models.Asset.objects.get", lambda **_: asset)
    monkeypatch.setattr(
        "custody.ton_policy.verified_binding", lambda *args: N(network_identity={"global_id": -777})
    )
    original = ton_transaction_identity(a, keyset)
    assert original["asset_decimals"] == 9
    asset.decimals = 10
    with pytest.raises(ValueError, match="original asset"):
        ton_transaction_identity(a, keyset)
