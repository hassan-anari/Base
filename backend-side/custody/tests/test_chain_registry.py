from decimal import Decimal

from django.test import TestCase, override_settings
from ops.models import Chain, NodeEndpoint

from custody.api import _balance_exceeds_threshold
from custody.chain_adapters import EvmAdapter, from_base_units, get_adapter
from custody.chain_registry import (
    ChainDisabled,
    ChainKind,
    ChainUnavailable,
    UnknownChain,
    UnsupportedChainKind,
    get_chain_spec,
    rpc_urls,
)
from custody.config import (
    effective_deposit_threshold,
    get_asset,
    is_memo_required,
    native_asset_key,
)
from custody.hd_wallet import build_derivation_path, derive_deposit_address
from custody.indexer.evm import EvmIndexer
from custody.indexer.factory import get_indexer
from custody.models import Asset
from custody.signer_adapter import LocalVault


class RuntimeChainRegistryTests(TestCase):
    def test_builtins_resolve_from_db_through_family_adapters(self):
        expected = {
            "ETH": (ChainKind.EVM, "ETH", 12, False, EvmAdapter),
            "BSC": (ChainKind.EVM, "BNB", 15, False, EvmAdapter),
            "TRX": (ChainKind.TRON, "TRX", 19, False, object),
            "SOL": (ChainKind.SOLANA, "SOL", 32, False, object),
            "TON": (ChainKind.TON, "TON", 5, True, object),
        }
        for chain_id, values in expected.items():
            kind, native, confirmations, memo, adapter_type = values
            spec = get_chain_spec(chain_id)
            self.assertEqual(
                (spec.kind, spec.native_asset_key, spec.confirmations, spec.memo_required),
                (kind, native, confirmations, memo),
            )
            self.assertTrue(rpc_urls(chain_id)[0])
            if adapter_type is not object:
                self.assertIsInstance(get_adapter(chain_id), adapter_type)
        self.assertIs(type(get_adapter("ETH")), type(get_adapter("BSC")))

    @override_settings(LOCAL_KEY_ENCRYPTION_PASSPHRASE="registry-demo")
    def test_custom_evm_needs_no_enum_or_factory_branch(self):
        Chain.objects.create(
            chain_id="CUSTOM_EVM",
            display_name="Custom EVM",
            kind="evm",
            evm_chain_id=424242,
            native_asset_key="CETH",
            is_testnet=True,
            min_confirmations=7,
            sweep_threshold=Decimal("0.000000000000000123"),
        )
        Asset.objects.create(
            asset_key="CETH",
            chain_id="CUSTOM_EVM",
            symbol="CETH",
            decimals=18,
            is_native=True,
            deposit_threshold=Decimal("0.000000000000000123"),
        )
        node = NodeEndpoint.objects.create(
            chain_id="CUSTOM_EVM",
            name="custom primary",
            url="https://rpc.custom.invalid",
            kind="rpc",
            priority=1,
            is_primary=True,
        )
        self.assertEqual(get_chain_spec("CUSTOM_EVM").evm_chain_id, 424242)
        self.assertIsInstance(get_adapter("CUSTOM_EVM"), EvmAdapter)
        self.assertIsInstance(get_indexer("CUSTOM_EVM"), EvmIndexer)
        self.assertEqual(rpc_urls("CUSTOM_EVM"), [node.url])
        get_adapter("CUSTOM_EVM").validate_address("0x" + "1" * 40)
        self.assertTrue(build_derivation_path("CUSTOM_EVM", 1, 0).startswith("m/44'"))
        derived = derive_deposit_address(
            "CUSTOM_EVM", 1, mpc_adapter=LocalVault(), asset_key="CETH"
        )
        self.assertTrue(derived.deposit_address.startswith("0x"))
        Chain.objects.filter(chain_id="CUSTOM_EVM").update(enabled=False)
        with self.assertRaises(ChainDisabled):
            get_chain_spec("CUSTOM_EVM")

    def test_runtime_edits_are_immediate_and_fail_closed(self):
        first = rpc_urls("ETH")[0]
        node = NodeEndpoint.objects.filter(chain_id="ETH", kind="rpc", enabled=True).first()
        node.url = "https://replacement.invalid"
        node.save(update_fields=["url"])
        self.assertNotEqual(first, rpc_urls("ETH")[0])
        self.assertEqual(rpc_urls("ETH")[0], "https://replacement.invalid")

        NodeEndpoint.objects.filter(chain_id="ETH", kind="rpc").update(enabled=False)
        with self.assertRaises(ChainUnavailable):
            rpc_urls("ETH")
        Chain.objects.filter(chain_id="ETH").update(enabled=False)
        with self.assertRaises(ChainDisabled):
            get_indexer("ETH")
        with self.assertRaises(UnknownChain):
            get_chain_spec("DOES_NOT_EXIST")

    def test_unknown_kind_is_not_reinterpreted(self):
        Chain.objects.filter(chain_id="ETH").update(kind="mystery")
        with self.assertRaises(UnsupportedChainKind):
            get_chain_spec("ETH")
        with self.assertRaises(UnsupportedChainKind):
            is_memo_required("ETH")

    def test_compatibility_helpers_propagate_registry_failures(self):
        asset = get_asset("ETH")
        Chain.objects.filter(chain_id="ETH").update(enabled=False)
        with self.assertRaises(ChainDisabled):
            is_memo_required("ETH")
        with self.assertRaises(ChainDisabled):
            native_asset_key("ETH")
        with self.assertRaises(ChainDisabled):
            effective_deposit_threshold(asset)
        with self.assertRaises(UnknownChain):
            native_asset_key("UNKNOWN")

    def test_malformed_native_asset_configuration_fails_closed(self):
        Chain.objects.filter(chain_id="ETH").update(native_asset_key="MISSING")
        with self.assertRaises(ChainUnavailable):
            native_asset_key("ETH")


class DecimalConversionTests(TestCase):
    def test_base_units_never_round_trip_through_float(self):
        value = 10**18 + 1
        self.assertEqual(from_base_units(value, 18), Decimal("1.000000000000000001"))
        self.assertIsInstance(from_base_units(1, 9), Decimal)

    def test_sweep_threshold_decision_does_not_collapse_to_float(self):
        threshold = Decimal("1.000000000000000000")
        confirmed = Decimal("1.000000000000000001")
        self.assertEqual(float(threshold), float(confirmed))
        self.assertTrue(_balance_exceeds_threshold(confirmed, threshold))
