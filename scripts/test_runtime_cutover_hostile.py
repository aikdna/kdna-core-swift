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
        self.assertRejected(b"test-vectors/golden-" + b"v1.json")
        self.assertRejected(b'"scrypt_password_' + b'v1": {}')
        self.assertRejected(b'"licensed_entry_' + b'v1": {}')

    def test_owned_kdna_profile_and_api_generations_are_rejected(self):
        self.assertRejected(b"kdna-example-profile-" + b"v3")
        self.assertRejected(b"Runtime " + b"v3")
        self.assertRejected(b"buildRuntimeCapsule" + b"V3")

    def test_removed_swift_public_trace_surface_is_rejected(self):
        for token in MODULE.RETIRED_SWIFT_PUBLIC:
            self.assertRejected(token)

    def test_current_coordinates_and_third_party_enumerations_are_accepted(self):
        for value in (
            b"kdna.runtime-capsule",
            b"kdna.encryption.password",
            b"contract_version=0.1.0",
            b"version: .v13",
            b".macOS(.v13)",
        ):
            self.assertEqual(MODULE.findings(value, self.retired), [], value)


if __name__ == "__main__":
    unittest.main()
