#!/usr/bin/env python3
"""Mutations must fail through the same gate that CI executes."""
import ast
import hashlib
import json
import unittest
from unittest.mock import patch
import check_public_surface as gate
from check_public_surface import collect, surface_errors

FILES = collect()


class PublicSurfaceTests(unittest.TestCase):
    def test_clean_graph(self):
        self.assertEqual(surface_errors(FILES), [])

    def reject(self, edit, expected):
        files = dict(FILES)
        edit(files)
        self.assertTrue(any(expected in item for item in surface_errors(files)), expected)

    def test_original_private_name_hashes_are_retained(self):
        original = ast.parse(FILES['retired/scripts/check_public_surface.py'].decode('utf8'))
        values = [ast.literal_eval(node.value) for node in original.body
                  if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'FORBIDDEN_HASHES' for target in node.targets)]
        self.assertEqual(len(values), 1)
        self.assertTrue(values[0].issubset(gate.FORBIDDEN_HASHES))
        self.assertEqual(len(values[0]), 13)

    def test_original_token_and_local_path_patterns_are_retained(self):
        original = ast.parse(FILES[gate.LEGACY_PATH_CHECKER].decode('utf8'))
        for name in ['TOKEN_PATTERN', 'LOCAL_PATH_PATTERN']:
            calls = [node.value for node in original.body if isinstance(node, ast.Assign)
                     and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
            self.assertEqual(len(calls), 1)
            self.assertEqual(ast.literal_eval(calls[0].args[0]), getattr(gate, name).pattern)
            self.assertTrue(getattr(gate, name).flags & gate.re.IGNORECASE)

    def test_private_names_cannot_hide_in_text_or_paths(self):
        token = 'synthetic' + 'private' + 'probe'
        digest = hashlib.sha256(token.encode('utf8')).hexdigest()
        with patch.object(gate, 'FORBIDDEN_HASHES', gate.FORBIDDEN_HASHES | {digest}):
            self.assertEqual(surface_errors(FILES), [])
            for key, data, rule in [
                ('README.md', FILES['README.md'] + ('\n' + token.upper()).encode(), 'private name in text'),
                ('extensionless', token.encode(), 'private name in text'),
                ('large.data', b' ' * 1_000_001 + token.encode(), 'private name in text'),
                ('invalid-utf8.data', b'\xff' + token.encode(), 'private name in text'),
                ('docs/' + token + '/example.txt', b'public example', 'private name in path'),
            ]:
                with self.subTest(key=key):
                    self.reject(lambda files, key=key, data=data: files.update({key: data}), rule)

    def test_private_coordination_file(self):
        self.reject(lambda f: f.update({'AGENTS.md': b'Internal coordination'}), 'private coordination file')

    def test_internal_path(self):
        self.reject(lambda f: f.update({'Tests/PublicCoreTests/Fixtures/' + 'p' + 'd999-sample.kdna': b'fixture'}), 'internal identifier in path')

    def test_internal_content(self):
        self.reject(lambda f: f.update({'README.md': f['README.md'] + b'\n' + b'P' + b'D999 note\n'}), 'internal identifier in text')

    def test_machine_path(self):
        self.reject(lambda f: f.update({'README.md': f['README.md'] + b'\n/' + b'Users/fixture-user/private/\n'}), 'private machine or coordination path')

    def test_original_local_paths_cannot_hide_in_text_or_paths(self):
        values = [
            '/' + 'private/tmp/' + 'kdna',
            '/' + 'PRIVATE/TMP/' + 'KDNA-case',
            '/' + 'Users/' + '\u68c0\u67e5\u8005' + '/private/',
            '/' + 'users/' + 'Ren\u00e9' + '/private/',
            '/' + 'Users/' + '\U0001f9ea' + '/private/',
        ]
        for value in values:
            for key, data in [
                ('README.md', FILES['README.md'] + ('\n' + value).encode('utf8')),
                ('extensionless', value.encode('utf8')),
                ('large.data', b' ' * 1_000_001 + value.encode('utf8')),
                ('invalid-utf8.data', b'\xff' + value.encode('utf8')),
                ('docs/' + value.lstrip('/') + 'note', b'public example'),
            ]:
                with self.subTest(value=value, path=key):
                    self.reject(lambda files, key=key, data=data: files.update({key: data}), 'private machine or coordination path')

    def test_newer_machine_path_rules_cover_all_text(self):
        for value in ['/' + 'home/runner/work/project/private', 'C:' + '\\' + 'Users' + '\\' + 'fixture-user' + '\\' + 'private', 'commander-' + 'work/private']:
            with self.subTest(value=value):
                self.reject(lambda f: f.update({'extensionless': value.encode('utf8')}), 'private machine or coordination path')

    def test_known_text_still_rejects_invalid_utf8(self):
        self.reject(lambda f: f.update({'README.md': f['README.md'] + b'\xff'}), 'invalid UTF-8 public text')

    def test_historical_regex_is_only_a_locked_literal(self):
        key = gate.LEGACY_PATH_CHECKER
        data = FILES[key]
        spans = gate.legacy_path_pattern_spans(key, data, data.decode('utf8'))
        self.assertEqual(len(spans), 1)
        literal = data.decode('utf8')[slice(*spans[0])]
        self.assertEqual(ast.literal_eval(literal), gate.LOCAL_PATH_PATTERN.pattern)
        self.assertEqual(gate.legacy_path_pattern_spans('copied-checker.py', data, data.decode('utf8')), [])
        self.reject(lambda f: f.update({'copied-checker.py': data}), 'private machine or coordination path')
        extra = ('\n# /' + 'private/tmp/' + 'kdna-extra\n').encode('utf8')
        changed = data + extra
        self.assertEqual(gate.legacy_path_pattern_spans(key, changed, changed.decode('utf8')), [])
        self.reject(lambda f: f.update({key: changed}), 'private machine or coordination path')

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
