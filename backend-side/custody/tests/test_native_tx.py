from decimal import Decimal

from django.test import SimpleTestCase, TestCase

from custody.models import HotWallet
from custody.native_tx import to_base_units
from custody.outbound import _signing_ref


class ExactBaseUnitTests(SimpleTestCase):
    def test_exact_wei(self):
        self.assertEqual(
            to_base_units(Decimal("1.000000000000000001"), 18),
            1_000_000_000_000_000_001,
        )

    def test_excess_precision_is_rejected(self):
        with self.assertRaisesMessage(ValueError, "exceeds asset precision"):
            to_base_units(Decimal("0.0000001"), 6)

    def test_non_positive_and_overflow_are_rejected(self):
        with self.assertRaises(ValueError):
            to_base_units(Decimal("0"), 18)
        with self.assertRaises(OverflowError):
            to_base_units(Decimal("256"), 0, maximum=255)


class HotWalletIdentityTests(TestCase):
    def test_missing_legacy_reference_fails_closed(self):
        HotWallet.objects.update_or_create(
            chain_id="ETH", defaults={"address": "0x" + "1" * 40, "signing_key_ref": None}
        )
        with self.assertRaisesMessage(ValueError, "signing_key_ref"):
            _signing_ref("WITHDRAWAL", 1, "ETH")
