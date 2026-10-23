"""CI suite partitioning only; unselected pytest runs retain their original behavior."""

import hashlib
import json
import os
from pathlib import Path

import pytest

SUITES = ("evm", "tron", "solana", "ton", "aux-persistence", "network", "integrated")
NETWORK_MODULES = {"test_cggmp.py", "test_network.py", "test_dkg.py", "test_signing.py"}


def crypto_suite(item):
    if item.path.name == "test_integrated.py":
        return "integrated"
    if item.path.name in {"test_ton.py", "test_ton_network.py", "test_ton_django.py"}:
        return "ton"
    if item.path.name == "test_solana.py":
        return "solana"
    if item.path.name in NETWORK_MODULES:
        return "network"
    if item.path.name != "test_cggmp_aux.py":
        raise pytest.UsageError(f"Unassigned crypto module: {item.nodeid}")
    if "tron_auxiliary_network" in item.fixturenames:
        return "tron"
    if {"auxiliary_network", "root_lifecycle_network"} & set(item.fixturenames):
        return "evm"
    if item.originalname == "test_partial_auxiliary_persistence_cannot_claim_readiness":
        return "aux-persistence"
    raise pytest.UsageError(f"Unassigned auxiliary scenario: {item.nodeid}")


def pytest_addoption(parser):
    parser.addoption("--crypto-suite", choices=("all", *SUITES), default=None)
    parser.addoption("--crypto-manifest", type=Path, default=None)


class CryptoRun:
    def __init__(self, config):
        self.config = config
        self.groups = {suite: [] for suite in SUITES}
        self.selected = set()
        self.called = set()
        self.skipped = set()
        self.durations = {}

    def pytest_collection_modifyitems(self, config, items):
        requested = config.getoption("crypto_suite")
        for item in items:
            self.groups[crypto_suite(item)].append(item.nodeid)
        inventory = [node for group in self.groups.values() for node in group]
        if len(inventory) != len(set(inventory)):
            raise pytest.UsageError("Duplicate crypto scenario in inventory")
        if any(not ids for ids in self.groups.values()):
            raise pytest.UsageError("Collect the complete crypto crypto inventory")
        selected, deselected = [], []
        for item in items:
            (
                selected if requested == "all" or crypto_suite(item) == requested else deselected
            ).append(item)
        self.selected = {item.nodeid for item in selected}
        if deselected:
            config.hook.pytest_deselected(items=deselected)
            items[:] = selected

    def pytest_runtest_logreport(self, report):
        self.durations.setdefault(report.nodeid, {})[report.when] = report.duration
        if report.when == "call":
            self.called.add(report.nodeid)
        if report.skipped:
            self.skipped.add(report.nodeid)

    def pytest_sessionfinish(self, session, exitstatus):
        if not self.config.option.collectonly and (self.skipped or self.called != self.selected):
            session.exitstatus = pytest.ExitCode.TESTS_FAILED
            terminal = self.config.pluginmanager.get_plugin("terminalreporter")
            if terminal:
                terminal.write_line(
                    "Crypto gate requires every selected scenario to execute; no skips"
                )
        destination = self.config.getoption("crypto_manifest")
        if destination:
            inventory = sorted(node for group in self.groups.values() for node in group)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(
                json.dumps(
                    {
                        "reviewed_head_sha": os.environ.get("REVIEWED_HEAD_SHA"),
                        "suite": self.config.getoption("crypto_suite"),
                        "inventory_sha256": hashlib.sha256(
                            "\n".join(inventory).encode()
                        ).hexdigest(),
                        "groups": self.groups,
                        "selected": sorted(self.selected),
                        "called": sorted(self.called),
                        "skipped": sorted(self.skipped),
                        "phase_seconds": self.durations,
                    },
                    indent=2,
                )
            )


def pytest_configure(config):
    if config.getoption("crypto_suite"):
        config.pluginmanager.register(CryptoRun(config), "crypto-run-guard")
