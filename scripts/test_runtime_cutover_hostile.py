#!/usr/bin/env python3
"""Hostile tests for the Swift responsibility naming gate."""

import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check_runtime_cutover.py")
SPEC = importlib.util.spec_from_file_location("check_runtime_cutover", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ResponsibilityCutoverHostileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.retired = MODULE.load_authority()

    def assertRejected(self, value: bytes):
        self.assertTrue(MODULE.findings(value, self.retired), value)

    def test_exact_authority_token_is_rejected(self):
        self.assertRejected(self.retired[0])

    def test_raw_path_and_text_fixture_generations_are_rejected(self):
        lower_v = b"v"
        one = b"1"
        self.assertRejected(b"test-vectors/golden-" + lower_v + one + b".json")
        self.assertRejected(b'"scrypt_password_' + lower_v + one + b'": {}')
        self.assertRejected(b'"licensed_entry_' + lower_v + one + b'": {}')

    def test_owned_kdna_profile_and_api_generations_are_rejected(self):
        lower_v = b"v"
        upper_v = b"V"
        three = b"3"
        self.assertRejected(b"kdna-example-profile-" + lower_v + three)
        self.assertRejected(b"Runtime " + lower_v + three)
        self.assertRejected(b"buildRuntimeCapsule" + upper_v + three)

    def test_generic_public_generation_label_is_rejected(self):
        value = b"Values: " + b"V" + b"1"
        self.assertTrue(MODULE.owned_generation_labels("README.md", value), value)

    def test_removed_swift_public_trace_surface_is_rejected(self):
        for token in MODULE.RETIRED_SWIFT_PUBLIC:
            self.assertRejected(token)

    def test_current_coordinates_and_third_party_enumerations_are_accepted(self):
        lower_v = b"v"
        thirteen = b"13"
        for value in (
            b"kdna.runtime-capsule",
            b"kdna.encryption.password",
            b"contract_version=0.1.0",
            b"version: ." + lower_v + thirteen,
            b".macOS(." + lower_v + thirteen + b")",
        ):
            self.assertEqual(MODULE.findings(value, self.retired), [], value)

        self.assertEqual(
            MODULE.owned_generation_labels(
                "Sources/KDNACore/KDNAProtectedCrypto.swift",
                b"version: ." + lower_v + thirteen,
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
