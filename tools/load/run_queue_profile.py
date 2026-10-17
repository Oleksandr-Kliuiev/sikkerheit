"""Build and run the isolated PostgreSQL queue profile. No Azure/M365 credentials or production URLs are used."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, default=ROOT / '.dev/scaling/queue-profile.json')
    parser.add_argument('--no-build', action='store_true', help='Use the already built Release assembly')
    args = parser.parse_args()
    report = args.report.resolve()
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps({'status': 'running', 'profile': 'postgres_queue_synthetic_handlers'}) + '\n')
    dotnet = shutil.which('dotnet') or str(Path.home() / '.dotnet/dotnet')
    environment = dict(os.environ, SIKKERHEIT_QUEUE_PROFILE='1', SIKKERHEIT_QUEUE_PROFILE_REPORT=str(report))
    project = 'tests/Sikkerheit.IntegrationTests'
    commands = [] if args.no_build else [[dotnet, 'build', project, '--no-restore', '-c', 'Release', '-m:1', '--disable-build-servers']]
    commands.append([dotnet, 'test', '--project', project, '--no-build', '--no-restore', '-c', 'Release', '--',
                     '--filter-class', '*JobCapacityTests'])
    for command in commands:
        result = subprocess.run(command, cwd=ROOT, env=environment, check=False)
        if result.returncode:
            report.write_text(json.dumps({'status': 'failed', 'profile': 'postgres_queue_synthetic_handlers',
                                          'exitCode': result.returncode}) + '\n')
            return result.returncode
    result = json.loads(report.read_text())
    if result.get('status') != 'passed':
        print('FAIL: profile did not produce a completed report')
        return 1
    print(f'PASS: {report}')
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
