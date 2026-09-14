#!/usr/bin/env python3
"""Check the public source graph, frozen inputs, history and naming boundary."""
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
INTERNAL_ID = re.compile(r"\b[pP][dD]\d+\b")
GENERATION = re.compile(r"(?<![A-Za-z0-9])[vV]\d+(?!\d|\.\d)")
MACHINE_PATH = re.compile(r"/" + r"Users/[A-Za-z0-9._-]+/|/home/" + r"runner/work/[^\s]+|[A-Za-z]:\\Users\\[A-Za-z0-9._-]+\\")
LOCAL_PATH_PATTERN = re.compile(
    r"/" + r"Users/(?!<user>/|you/|username/)[^/\s]+/|/" + r"private/tmp/kdna",
    re.IGNORECASE,
)
LEGACY_PATH_CHECKER = 'retired/scripts/check_public_surface.py'
LEGACY_PATH_CHECKER_SHA256 = '8bc95afff9256f93b08cdc5e5fd76b0ab1c4bc52c14a1e0a6247f4f45d6c39f4'
PRIVATE_COORDINATION = re.compile(r"(?:" + "kdna-" + "machine-recovery|" + "kdna-" + "open-lead|" + "commander-" + "work" + r")[-/]")
PLACEHOLDER_IDENTITY = re.compile(r"[\w.+-]+@[\w.-]+\.invalid\b")
TEXT_SUFFIXES = {'.swift', '.py', '.json', '.jsonl', '.md', '.yml', '.yaml', '.sh', '.txt', '.resolved'}


FORBIDDEN_HASHES = {
    '068c8b48752eba18baf46af3324f3ffb9306457c54b6624fade5792109af536b',
    '0f89e837194f291beef89dcde345233adf1443f61763f05ee5cef5ad12d44c0a',
    '32a183bfe17c2d785b66d5a328402623bc5ab674c86bd8ad29905a05c1a6319c',
    '3ce236400925c24e9e5416bdc69abe5427b3183e2abe6f848b297334cfdeaa25',
    '4c94af7ca105abc9c4e2c9c7dce3b778b4bde7e6445c9e68101a0d9eb59f97bd',
    '5a02d80676cf1acf987c1787c1201a7648f8cc606b6014a29ecda4eed68e6315',
    '5de109ce9d5d074259ce2b3757d33b0a68afaaf88ca599ed77d78a46797cfdb0',
    '5f60fde8e355d8d81ffbb60095c2bb25a52f723940c4c01a77473badd3faa8cd',
    '61e79d887fa6b41acfebaeee47c2ba816bc76c892b1f72a3c2ba3f34900a22f8',
    '7206c17a81fdc22e097e4b78d33fee460804b0c5bf4c0e461adc7114d16d85ed',
    'a1f44465ac220babc075de0f4489642440192302357a2fe90265fb2ad2c376e5',
    'ad832a18658e09393a42c9966b94625c82effd30dfe8bc0a6d8c000fa8056222',
    'e2f6321a5972a38700c02f6b4344c8b9deb52b523fceb7ce25a255fb44f0917c',
}
TOKEN_PATTERN = re.compile(
    r"@[a-z][a-z0-9_-]*/[a-z][a-z0-9_-]*|"
    r"[a-z][a-z0-9_-]*/[a-z][a-z0-9_-]*|"
    r"[a-z][a-z0-9_-]*", re.IGNORECASE,
)


def private_name_present(text):
    return any(hashlib.sha256(token.lower().encode("utf-8")).hexdigest() in FORBIDDEN_HASHES
               for token in set(TOKEN_PATTERN.findall(text)))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def legacy_path_pattern_spans(path, data, text):
    """Recognize only the exact regex literal in the fixed historical checker."""
    if path != LEGACY_PATH_CHECKER or digest(data) != LEGACY_PATH_CHECKER_SHA256:
        return []
    lines = text.splitlines(keepends=True)
    for node in ast.parse(text).body:
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == 'LOCAL_PATH_PATTERN'):
            continue
        call = node.value
        if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name) and call.func.value.id == 're'
                and call.func.attr == 'compile' and call.args):
            continue
        literal = call.args[0]
        if isinstance(literal, ast.Constant) and literal.value == LOCAL_PATH_PATTERN.pattern:
            # AST columns count UTF-8 bytes. Convert them before comparing to
            # regex character offsets, even though the fixed source is ASCII.
            start = sum(map(len, lines[:literal.lineno - 1])) + len(lines[literal.lineno - 1].encode('utf8')[:literal.col_offset].decode('utf8'))
            end = sum(map(len, lines[:literal.end_lineno - 1])) + len(lines[literal.end_lineno - 1].encode('utf8')[:literal.end_col_offset].decode('utf8'))
            return [(start, end)]
    return []


def collect(root=ROOT):
    paths = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], cwd=root).split(b'\0')
    return {path.decode(): (root / path.decode()).read_bytes() for path in paths if path and (root / path.decode()).is_file()}


def third_party_spans(path, text):
    """Recognize numeric versions owned by SwiftPM and Argon2, by API syntax."""
    spans = []
    if Path(path).name == 'Package.swift' or path == 'scripts/verify_native.py':
        spans.extend(match.span() for match in re.finditer(r'\.(?:macOS|iOS)\(\.v\d+(?:_\d+)*\)', text))
    spans.extend(match.span() for match in re.finditer(r'Argon2\.hash\((?:(?!\n\}).)*?version:\s*\.v' + '13' + r'\s*\)', text, re.S))
    return spans


def surface_errors(files):
    errors = []
    def require(condition, message):
        if not condition:
            errors.append(message)
    def read(name):
        require(name in files, f'missing public input: {name}')
        return files.get(name, b'').decode('utf8', errors='replace')
    def read_json(name):
        try:
            return json.loads(read(name))
        except (ValueError, TypeError):
            errors.append(f'invalid JSON input: {name}')
            return {}

    for path, data in files.items():
        require(not private_name_present(path) and not any(private_name_present(part) for part in Path(path).parts), f'private name in path: {path}')
        require(not LOCAL_PATH_PATTERN.search(path) and not MACHINE_PATH.search(path)
                and not PRIVATE_COORDINATION.search(path), f'private machine or coordination path in filename: {path}')
        # Preserve the original all-text vocabulary and local-path boundary. File extensions
        # and text size do not exempt non-NUL content. As in the historical
        # checker, replacement decoding prevents a bad byte from hiding names
        # or paths elsewhere in the file; known text suffixes also fail below
        # when their UTF-8 is invalid.
        if b'\0' not in data:
            vocabulary_text = data.decode('utf8', errors='replace')
            require(not private_name_present(vocabulary_text), f'private name in text: {path}')
            spans = legacy_path_pattern_spans(path, data, vocabulary_text)
            for match in LOCAL_PATH_PATTERN.finditer(vocabulary_text):
                require(any(start <= match.start() and match.end() <= end for start, end in spans), f'private machine or coordination path: {path}')
            require(not MACHINE_PATH.search(vocabulary_text) and not PRIVATE_COORDINATION.search(vocabulary_text), f'private machine or coordination path: {path}')
        require(Path(path).name not in {"AGENTS.md", "WORKLOG.md"}, f"private coordination file: {path}")
        require(not INTERNAL_ID.search(path), f'internal identifier in path: {path}')
        require(not GENERATION.search(path), f'generation label in path: {path}')
        if Path(path).suffix not in TEXT_SUFFIXES:
            continue
        try:
            text = data.decode('utf8')
        except UnicodeError:
            errors.append(f'invalid UTF-8 public text: {path}')
            continue
        require(not INTERNAL_ID.search(text), f'internal identifier in text: {path}')
        require(not PLACEHOLDER_IDENTITY.search(text), f'placeholder identity: {path}')
        spans = third_party_spans(path, text)
        for match in GENERATION.finditer(text):
            require(any(start <= match.start() and match.end() <= end for start, end in spans), f'owned generation label: {path}:{text[:match.start()].count(chr(10)) + 1}')

    inputs = read_json('public-inputs.json')
    rows = inputs.get('files', [])
    expected_paths = [row.get('path') for row in rows]
    actual_paths = {p for p in files if p == 'Package.swift' or p == 'public-contract-binding.json' or p.startswith('Sources/') or p.startswith('Tests/PublicCoreTests/')}
    require(len(expected_paths) == len(set(expected_paths)), 'duplicate frozen input paths')
    require(set(expected_paths) == actual_paths, 'frozen source and fixture inventory differs')
    for row in rows:
        require(row.get('path') in files and digest(files[row['path']]) == row.get('sha256'), f'frozen input bytes differ: {row.get("path")}')

    binding = read_json('public-contract-binding.json')
    require(binding.get('implementation', {}).get('name') == 'KDNACore', 'binding must identify KDNACore')
    require(binding.get('implementation', {}).get('version') == '0.4.0-rc.component-semantics.1', 'binding must retain the current candidate coordinate')
    generated_path = 'Sources/KDNACore/Resources/Schemas/generated-contract.json'
    require(generated_path in files and digest(files[generated_path]) == binding.get('generated_contract_sha256'), 'generated resources must match their exact binding')
    package = read('Package.swift')
    require('dependencies: []' in package, 'current library must have no external package dependencies')
    require('path: "Tests/PublicCoreTests"' in package, 'package must select the complete current test target')
    require('retired' not in package, 'retired implementation must stay outside current targets')
    require('.copy("Resources/Schemas")' in package and '.copy("Fixtures")' in package, 'schema and fixture resources must remain bundled')
    require('Package.resolved' not in files, 'dependency-free graph must not carry the retired lockfile')

    history = read_json('surface-disposition.json')
    for row in history.get('original_files', []):
        path = row.get('original_bytes_preserved_at', row.get('current_path'))
        require(path in files and digest(files[path]) == row.get('entry_sha256'), f'historical bytes not preserved: {path}')
    require(bool(history.get('original_files')), 'history disposition must retain the original inventory')
    require('KDNA_CONFORMANCE_ROOT' not in read('CONTRIBUTING.md'), 'contribution instructions must not require the retired Node fixture graph')

    ci = read('.github/workflows/ci.yml')
    for command in ['python3 scripts/check_public_surface.py', 'python3 scripts/test_public_surface.py', 'python3 scripts/verify_native.py']:
        require(re.search(r'^\s+run:\s*' + re.escape(command) + r'(?:\s|$)', ci, re.M) is not None, f'CI must run {command}')
    require(re.search(r'^  test:\s*$', ci, re.M) is not None, 'required test job must keep its context name')
    require('--ios' in ci, 'CI must retain the generic iOS compilation leg')
    native = read('scripts/verify_native.py')
    try:
        tree = ast.parse(native)
        commands = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'run' and node.args and isinstance(node.args[0], ast.List):
                commands.append([item.value for item in node.args[0].elts if isinstance(item, ast.Constant) and isinstance(item.value, str)])
        for prefix in [['swift', 'build', '-c', 'release'], ['swift', 'test'], ['swift', 'run'], ['xcodebuild', '-scheme', 'kdna-core-swift']]:
            require(any(command[:len(prefix)] == prefix for command in commands), f'native verification must execute {" ".join(prefix)}')
        require(not any('--filter' in command or '--skip' in command for command in commands), 'native verification must run the full test suite')
        require('check=True' in native, 'native verification must propagate command failures')
        require('import KDNACore' in native and '@testable' not in native and 'precondition(denied["envelope"] == nil)' in native, 'clean consumer must check the public authority boundary')
    except SyntaxError:
        errors.append('native verification must be valid Python')
    codeql = read('.github/workflows/codeql-swift.yml')
    require('name: Analyze (swift)' in codeql and "language: ['swift']" in codeql, 'required CodeQL matrix context must remain unchanged')
    require('swift build' in codeql and 'autobuild' not in codeql, 'CodeQL must build the current package explicitly')
    require('retired/' not in codeql, 'CodeQL must not select the historical package')
    for path in files:
        if path.startswith('.github/workflows/'):
            for ref in re.findall(r'\buses:\s*[^@\s]+@([^\s#]+)', read(path)):
                require(re.fullmatch(r'[0-9a-f]{40}', ref), f'action ref must be immutable: {path}')
    return errors


def main():
    errors = surface_errors(collect())
    if errors:
        print('\n'.join(errors), file=sys.stderr)
        return 1
    print('Public source, exact contract inputs, current CI and preserved history verified.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
