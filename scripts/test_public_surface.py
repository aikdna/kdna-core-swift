#!/usr/bin/env python3
"""Mutations must fail through the same gate that CI executes."""
import json
import unittest
from check_public_surface import collect, surface_errors

FILES = collect()


class PublicSurfaceTests(unittest.TestCase):
    def test_clean_graph(self):
        self.assertEqual(surface_errors(FILES), [])

    def reject(self, edit, expected):
        files = dict(FILES)
        edit(files)
        self.assertTrue(any(expected in item for item in surface_errors(files)), expected)

    def test_private_coordination_file(self):
        self.reject(lambda f: f.update({'AGENTS.md': b'Internal coordination'}), 'private coordination file')

    def test_internal_path(self):
        self.reject(lambda f: f.update({'Tests/PublicCoreTests/Fixtures/' + 'p' + 'd999-sample.kdna': b'fixture'}), 'internal identifier in path')

    def test_internal_content(self):
        self.reject(lambda f: f.update({'README.md': f['README.md'] + b'\n' + b'P' + b'D999 note\n'}), 'internal identifier in text')

    def test_machine_path(self):
        self.reject(lambda f: f.update({'README.md': f['README.md'] + b'\n/' + b'Users/fixture-user/private/\n'}), 'private machine or coordination path')

    def test_placeholder_identity(self):
        self.reject(lambda f: f.update({'README.md': f['README.md'] + b'\nAuthor <example@' + b'example.invalid>\n'}), 'placeholder identity')

    def test_owned_generation_label(self):
        self.reject(lambda f: f.update({'Sources/KDNACore/Example.swift': b'let name = "KDNA-' + b'v' + b'9"\n'}), 'owned generation label')

    def test_third_party_platform_versions_are_not_an_exemption(self):
        self.reject(lambda f: f.update({'Package.swift': f['Package.swift'] + b'\nlet KDNA' + b'Version = "' + b'v' + b'9"\n'}), 'owned generation label')

    def test_changed_implementation(self):
        key = 'Sources/KDNACore/PublicCore.swift'
        self.reject(lambda f: f.update({key: f[key] + b'\n// changed\n'}), 'frozen input bytes differ')

    def test_missing_fixture(self):
        key = next(p for p in FILES if p.startswith('Tests/PublicCoreTests/Fixtures/') and p.endswith('.kdna'))
        self.reject(lambda f: f.pop(key), 'frozen source and fixture inventory differs')

    def test_changed_fixture(self):
        key = next(p for p in FILES if p.startswith('Tests/PublicCoreTests/Fixtures/') and p.endswith('.kdna'))
        self.reject(lambda f: f.update({key: f[key] + b'x'}), 'frozen input bytes differ')

    def test_changed_generated_resource(self):
        key = 'Sources/KDNACore/Resources/Schemas/generated-contract.json'
        self.reject(lambda f: f.update({key: f[key] + b' '}), 'generated resources must match their exact binding')

    def test_missing_history(self):
        self.reject(lambda f: f.pop('retired/README.md'), 'historical bytes not preserved')

    def test_missing_suite(self):
        key = '.github/workflows/ci.yml'
        self.reject(lambda f: f.update({key: f[key].replace(b'python3 scripts/verify_native.py', b'echo skipped')}), 'CI must run python3 scripts/verify_native.py')

    def test_missing_ios_leg(self):
        key = '.github/workflows/ci.yml'
        self.reject(lambda f: f.update({key: f[key].replace(b' --ios', b'')}), 'CI must retain the generic iOS compilation leg')

    def test_renamed_required_context(self):
        key = '.github/workflows/ci.yml'
        self.reject(lambda f: f.update({key: f[key].replace(b'  test:', b'  replacement:')}), 'required test job must keep its context name')

    def test_codeql_autobuild(self):
        key = '.github/workflows/codeql-swift.yml'
        self.reject(lambda f: f.update({key: f[key].replace(b'swift build', b'autobuild')}), 'CodeQL must build the current package explicitly')

    def test_native_test_command_removed(self):
        key = 'scripts/verify_native.py'
        self.reject(lambda f: f.update({key: f[key].replace(b"['swift', 'test'", b"['echo', 'test'")}), 'native verification must execute swift test')

    def test_native_partial_suite(self):
        key = 'scripts/verify_native.py'
        self.reject(lambda f: f.update({key: f[key].replace(b"['swift', 'test'", b"['swift', 'test', '--filter', 'CoreTests'")}), 'native verification must run the full test suite')

    def test_consumer_authority_check_removed(self):
        key = 'scripts/verify_native.py'
        self.reject(lambda f: f.update({key: f[key].replace(b'precondition(denied["envelope"] == nil)', b'print("skipped")')}), 'clean consumer must check the public authority boundary')

    def test_retired_dependency(self):
        self.reject(lambda f: f.update({'Package.resolved': b'{}'}), 'dependency-free graph must not carry the retired lockfile')


if __name__ == '__main__':
    unittest.main(verbosity=2)
