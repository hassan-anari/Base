from unittest.mock import patch

from custody.chain_registry import ChainKind
from custody.mpc_payload import evm_signing_digest, exact_signing_payload

LEGACY = {
    "nonce": 0,
    "gasPrice": 20_000_000_000,
    "gas": 21_000,
    "to": "0x3535353535353535353535353535353535353535",
    "value": 10**18,
    "data": b"",
    "chainId": 1,
}
EIP1559 = {
    "type": 2,
    "chainId": 1,
    "nonce": 0,
    "maxPriorityFeePerGas": 1_000_000_000,
    "maxFeePerGas": 2_000_000_000,
    "gas": 21_000,
    "to": "0x3535353535353535353535353535353535353535",
    "value": 1,
    "data": b"",
    "accessList": [],
}


def test_known_eip155_legacy_digest():
    kind, digest = evm_signing_digest(LEGACY)
    assert kind == "EVM_LEGACY_DIGEST"
    assert digest.hex() == "7dbc5644b83abd32d014d170ba9bdc855c126328c0cb41af0ed6422bef0bb32e"


def test_known_eip1559_digest():
    kind, digest = evm_signing_digest(EIP1559)
    assert kind == "EVM_EIP1559_DIGEST"
    assert digest.hex() == "3d9bb8901315a692b04cf92bd92b74e13d998a9cbf022be5ff12481e902cf0b0"


def test_custom_evm_uses_runtime_chain_kind_not_symbol_allowlist():
    spec = type("Spec", (), {"kind": ChainKind.EVM})()
    with patch("custody.mpc_payload.get_chain_spec", return_value=spec):
        assert exact_signing_payload("CUSTOM-ROLLUP", LEGACY, b"") == evm_signing_digest(LEGACY)


def test_local_legacy_and_eip1559_assembly_from_normalized_components():
    from eth_account import Account
    from eth_keys import keys

    from custody.mpc_payload import assemble_evm_signature

    private_key = keys.PrivateKey(bytes.fromhex("01".rjust(64, "0")))
    expected = Account.from_key(private_key.to_bytes()).address
    for transaction in (LEGACY, EIP1559):
        _, digest = evm_signing_digest(transaction)
        signature = private_key.sign_msg_hash(digest)
        raw, tx_hash = assemble_evm_signature(
            transaction,
            {"r": hex(signature.r), "s": hex(signature.s), "recovery_id": signature.v},
            expected,
        )
        assert raw
        assert len(tx_hash) == 66
        assert Account.recover_transaction(bytes.fromhex(raw)) == expected
