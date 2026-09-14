#!/usr/bin/env python3
"""Build the current package and an independent public-API consumer."""
import argparse
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CONSUMER = r'''import Foundation
import KDNACore

@main
struct ConsumerCheck {
    static func main() async throws {
        let fixture = URL(fileURLWithPath: CommandLine.arguments[1])
        let bytes = try Data(contentsOf: fixture)
        let admitted = KDNACore.admitBytes(bytes)
        precondition(admitted.result["status"] == "accepted")
        precondition(KDNACore.admitFile(fixture).result["status"] == "accepted")
        guard let snapshot = admitted.snapshot else { fatalError("Snapshot missing") }
        precondition(snapshot.inspect()["ir"]["catalog"].list.count == 1)
        let tuple = try KDNACore.versionTuple()
        precondition(tuple["core"] == "kdna.core/0.3.0")
        precondition(tuple["read"] == "kdna.read/0.2.0")
        let capability = KDNACore.planCapability()
        precondition(capability["status"] == "unavailable")
        precondition(capability["action_authorized"] == false)
        precondition(capability["creation_accepted"] == false)
        let request: KDNAValue = ["request_id": "consumer-check", "tuple": tuple,
            "budget_bytes": 1000000, "mode": "whole_asset", "selection": nil, "handle": nil]
        let control = KDNATrustedReadControlProvider(observe: { ["admission_response_limit_bytes": 1000000] })
        let readAdmission = KDNARead.admitRequest(request, control: control)
        precondition(readAdmission.request != nil)
        precondition(KDNARead.project(readAdmission.request, snapshot: snapshot)["status"] == "projected")
        precondition(KDNARead.project(nil, snapshot: snapshot)["status"] == "rejected")
        let denied = await KDNARead.readSnapshot(snapshot, request: request, control: nil, host: nil)
        precondition(denied["channel"] == "transport_failure")
        precondition(denied["envelope"] == nil)
        precondition(KDNACore.admitBytes(Data()).snapshot == nil)
        print("Consumer verified: admission, bundled schemas, tuple, projection, no authority without providers.")
    }
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', required=True, type=Path, help='New directory outside the package for isolated build products')
    parser.add_argument('--ios', action='store_true', help='Also compile for a generic iOS device with Xcode')
    args = parser.parse_args()
    work = args.work_dir.resolve()
    if work == ROOT or ROOT in work.parents:
        parser.error('--work-dir must be outside the package')
    work.mkdir(parents=True, exist_ok=False)
    for name in ['cache', 'config', 'security', 'modules', 'tmp']:
        (work / name).mkdir()
    env = dict(os.environ, TMPDIR=str(work / 'tmp'))
    def run(argv, cwd=ROOT):
        print('+ ' + ' '.join(str(arg) for arg in argv), flush=True)
        subprocess.run([str(arg) for arg in argv], cwd=cwd, env=env, check=True)
    def swift_options(scratch):
        return ['--jobs', '1', '--scratch-path', work / scratch,
                '--cache-path', work / 'cache', '--config-path', work / 'config',
                '--security-path', work / 'security', '-Xcc', '-fmodules-cache-path=' + str(work / 'modules')]

    run(['swift', '--version'])
    run(['swift', 'build', '-c', 'release', *swift_options('release')])
    run(['swift', 'test', *swift_options('tests')])
    consumer = work / 'consumer'
    (consumer / 'Sources/ConsumerCheck').mkdir(parents=True)
    package = '''// swift-tools-version:5.9
import PackageDescription
let package = Package(name: "ConsumerCheck", platforms: [.macOS(.v13)],
    dependencies: [.package(name: "kdna-core-swift", path: REPO)],
    targets: [.executableTarget(name: "ConsumerCheck", dependencies: [.product(name: "KDNACore", package: "kdna-core-swift")])])
'''.replace('REPO', json.dumps(str(ROOT)))
    (consumer / 'Package.swift').write_text(package)
    (consumer / 'Sources/ConsumerCheck/ConsumerCheck.swift').write_text(CONSUMER)
    run(['swift', 'run', *swift_options('consumer-build'), 'ConsumerCheck', ROOT / 'Tests/PublicCoreTests/Fixtures/scale-1.kdna'], cwd=consumer)
    if args.ios:
        run(['xcodebuild', '-version'])
        run(['xcodebuild', '-scheme', 'kdna-core-swift', '-destination', 'generic/platform=iOS',
             '-derivedDataPath', work / 'ios', '-clonedSourcePackagesDirPath', work / 'packages',
             'CODE_SIGNING_ALLOWED=NO', 'CLANG_MODULE_CACHE_PATH=' + str(work / 'modules'), 'build'])
    print('Native verification passed' + (' including generic iOS compilation.' if args.ios else '; iOS compilation was not requested.'))


if __name__ == '__main__':
    main()
