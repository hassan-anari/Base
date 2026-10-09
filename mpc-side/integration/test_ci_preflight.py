"""Cheap real fixture startup checks before fresh-prime cryptographic executions.

No acceptance claim: the only transaction here uses the disposable validator
faucet. Original MPC acceptance still runs with independently generated roots.
"""

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import CryptoRun, crypto_suite
from custody.tron_wire import address_bytes
from environment import ROLES, Processes
from evm_acceptance import isolated_chains
from test_network import assert_quorum
from tron.validator import Validator
from tronpy import Tron
from tronpy.contract import Contract
from tronpy.providers import HTTPProvider


@pytest.mark.parametrize(
    "called,skipped,success",
    [
        (set(), set(), False),
        ({"required"}, {"required"}, False),
        ({"required"}, set(), True),
        ({"other"}, set(), False),
    ],
)
def test_selected_crypto_scenarios_must_execute_without_skips(called, skipped, success):
    config = SimpleNamespace(
        option=SimpleNamespace(collectonly=False),
        pluginmanager=SimpleNamespace(get_plugin=lambda _: None),
        getoption=lambda _: None,
    )
    guard = CryptoRun(config)
    guard.selected, guard.called, guard.skipped = {"required"}, called, skipped
    session = SimpleNamespace(exitstatus=pytest.ExitCode.OK)
    guard.pytest_sessionfinish(session, pytest.ExitCode.OK)
    assert (session.exitstatus == pytest.ExitCode.OK) is success


def test_new_auxiliary_scenario_requires_explicit_fixture_assignment():
    item = SimpleNamespace(
        path=Path("test_cggmp_aux.py"),
        fixturenames=[],
        originalname="test_unassigned",
        nodeid="test_cggmp_aux.py::test_unassigned",
    )
    with pytest.raises(pytest.UsageError, match="Unassigned auxiliary scenario"):
        crypto_suite(item)


def test_independent_tls_process_fixture_starts(tmp_path):
    services = Processes(tmp_path / "services")
    try:
        for role in ROLES[:4]:
            services.start(role)
        assert_quorum(services)
    finally:
        services.close()


def test_isolated_evm_validator_fixture_starts():
    with isolated_chains() as chains:
        assert [int(chain.rpc("eth_chainId", []), 16) for chain in chains] == [31337, 31338]
        assert all(chain.rpc("eth_getBlockByNumber", ["latest", False]) for chain in chains)


def test_pinned_tron_validator_and_tvm_fixture_execute(tmp_path):
    validator = Validator(tmp_path / "validator", [])
    try:
        output = tmp_path / "token.json"
        compiler = Path(__file__).parent / "tron" / "compile.cjs"
        subprocess.run(["node", str(compiler), str(output)], check=True)
        token = json.loads(output.read_text())
        contract = Contract(name="AcceptanceToken", bytecode=token["bytecode"], abi=token["abi"])
        contract.bytecode = bytes.fromhex(
            token["bytecode"] + address_bytes(validator.faucet_address)[1:].hex().rjust(64, "0")
        )
        provider = HTTPProvider(validator.url)
        provider.sess.trust_env = False
        transaction = (
            Tron(provider=provider)
            .trx.deploy_contract(validator.faucet_address, contract)
            .fee_limit(100000000)
            .build()
            .sign(validator.faucet)
        )
        assert transaction.broadcast()["result"] is True
        info = validator.wait_info(transaction.txid)
        assert info["id"] == transaction.txid
        assert info["receipt"]["result"] == "SUCCESS"
        assert info["contract_address"]
    finally:
        validator.close()
