#!/usr/bin/env python3
"""Hostile tests for the Swift responsibility naming gate."""

import importlib.util
import sys
import unittest
from pathlib import Path


sys.dont_write_bytecode = True

SCRIPT = Path(__file__).with_name("check_runtime_cutover.py")
SPEC = importlib.util.spec_from_file_location("check_runtime_cutover", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ResponsibilityCutoverHostileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.retired = MODULE.load_authority()
        root = SCRIPT.parents[1]
        cls.package = (root / "Package.swift").read_bytes()
        cls.resolved = (root / "Package.resolved").read_bytes()
        cls.gitignore = (root / ".gitignore").read_bytes()
        cls.loader_test = (
            root / "Tests/KDNACoreTests/LoaderCompatibilityTests.swift"
        ).read_bytes()

    def assertRejected(self, value: bytes):
        self.assertTrue(MODULE.findings(value, self.retired), value)

    def replaceOnce(self, value: bytes, old: bytes, new: bytes) -> bytes:
        self.assertEqual(value.count(old), 1, old)
        return value.replace(old, new)

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

    def test_candidate_dependency_authority_is_accepted(self):
        self.assertEqual(
            MODULE.dependency_authority_failures(
                self.package,
                self.resolved,
                self.gitignore,
            ),
            [],
        )

    def test_dependency_authority_rejects_requirement_lock_and_ignore_drift(self):
        extra_dependency = self.replaceOnce(
            self.package,
            b"    dependencies: [\n",
            b'    dependencies: [\n        .package(path: "../forged"),\n',
        )
        lock_revision = self.replaceOnce(
            self.resolved,
            MODULE.ARGON2KIT_LOCK["state"]["revision"].encode("ascii"),
            b"0" * 40,
        )
        cases = (
            (
                self.replaceOnce(self.package, b'from: "0.1.1"', b'from: "0.1.2"'),
                self.resolved,
                self.gitignore,
            ),
            (extra_dependency, self.resolved, self.gitignore),
            (self.package, lock_revision, self.gitignore),
            (self.package, self.resolved, self.gitignore + b"Package.resolved\n"),
        )
        for package, resolved, gitignore in cases:
            self.assertTrue(
                MODULE.dependency_authority_failures(
                    package,
                    resolved,
                    gitignore,
                    require_exact_bytes=False,
                )
            )

    def test_controlled_node_contract_is_accepted(self):
        self.assertEqual(MODULE.controlled_node_test_failures(self.loader_test), [])

    def test_controlled_node_contract_rejects_fallback_and_injection_mutations(self):
        cases = (
            self.replaceOnce(
                self.loader_test,
                b'(nodePath as NSString).isAbsolutePath',
                b"!nodePath.isEmpty",
            ),
            self.replaceOnce(
                self.loader_test,
                b'process.executableURL = nodeExecutableURL',
                b'process.executableURL = URL(fileURLWithPath: "/usr/bin/env")',
            ),
            self.replaceOnce(
                self.loader_test,
                b'process.environment = [:]',
                b'process.environment = environment',
            ),
            self.replaceOnce(
                self.loader_test,
                b"6bc0a34ebcada8181bde391eae3e60a39751dda7e6aca423babad0e9846aac9d",
                b"0" * 64,
            ),
        )
        for source in cases:
            self.assertTrue(
                MODULE.controlled_node_test_failures(
                    source,
                    require_exact_bytes=False,
                )
            )

    def test_ci_contract_is_accepted(self):
        self.assertEqual(MODULE.ci_workflow_failures(MODULE.EXPECTED_CI_WORKFLOW), [])

    def test_ci_contract_rejects_bypasses_and_missing_release_flags(self):
        mutable_action = b"actions/setup-node@" + b"v" + b"4"
        mutations = (
            self.replaceOnce(
                MODULE.EXPECTED_CI_WORKFLOW,
                b"  test:\n",
                b"  test:\n    if: false\n",
            ),
            self.replaceOnce(
                MODULE.EXPECTED_CI_WORKFLOW,
                b"      - name: Test\n",
                b"      - name: Test\n        if: false\n",
            ),
            self.replaceOnce(
                MODULE.EXPECTED_CI_WORKFLOW,
                b"  contents: read\n",
                b"  contents: write\n",
            ),
            self.replaceOnce(
                MODULE.EXPECTED_CI_WORKFLOW,
                b"  pull_request:\n    branches: [main]\n",
                b"  pull_request:\n    branches: [main]\n    paths-ignore: ['Tests/**']\n",
            ),
            self.replaceOnce(
                MODULE.EXPECTED_CI_WORKFLOW,
                b"  test:\n",
                b"  test:\n    permissions:\n      contents: write\n",
            ),
            self.replaceOnce(
                MODULE.EXPECTED_CI_WORKFLOW,
                b"    timeout-minutes: 30\n",
                b"    timeout-minutes: 30\n    strategy:\n      matrix:\n        include: []\n        exclude: []\n",
            ),
            self.replaceOnce(
                MODULE.EXPECTED_CI_WORKFLOW,
                b"          node-version: '22.23.1'\n",
                b"          node-version: '22.23.0'\n",
            ),
            self.replaceOnce(
                MODULE.EXPECTED_CI_WORKFLOW,
                b"actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38",
                mutable_action,
            ),
            self.replaceOnce(
                MODULE.EXPECTED_CI_WORKFLOW,
                b"jobs:\n",
                b"jobs:\n  bypass:\n    runs-on: macos-14\n    steps: []\n",
            ),
            self.replaceOnce(
                MODULE.EXPECTED_CI_WORKFLOW,
                b"    timeout-minutes: 30\n",
                b"",
            ),
            self.replaceOnce(
                MODULE.EXPECTED_CI_WORKFLOW,
                b"      - name: Test\n",
                b"      - name: Test\n        continue-on-error: true\n",
            ),
            self.replaceOnce(
                MODULE.EXPECTED_CI_WORKFLOW,
                b"      - name: Test\n",
                b"      - name: Test\n        shell: bash\n",
            ),
            MODULE.EXPECTED_CI_WORKFLOW.replace(
                b"            --force-resolved-versions \\\n",
                b"",
            ),
            self.replaceOnce(
                MODULE.EXPECTED_CI_WORKFLOW,
                b"            -onlyUsePackageVersionsFromResolvedFile \\\n",
                b"",
            ),
            self.replaceOnce(
                MODULE.EXPECTED_CI_WORKFLOW,
                b"          printf 'NODE=%s\\n' \"$node_path\" >> \"$GITHUB_ENV\"\n",
                b"",
            ),
        )
        for workflow in mutations:
            self.assertTrue(MODULE.ci_workflow_failures(workflow))


if __name__ == "__main__":
    unittest.main()
