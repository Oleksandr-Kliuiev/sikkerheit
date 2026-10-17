"""Read normalized local Atera/Sikkerheit snapshots and write a private reconciliation report; no network calls."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from inventory_snapshots import InvalidSnapshot, read_snapshot, timestamp  # noqa: E402
from reconciliation import reconcile  # noqa: E402


def positive(value):
    hours = int(value)
    if not 1 <= hours <= 8760:
        raise argparse.ArgumentTypeError('hours must be between 1 and 8760')
    return hours


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--as-of', help='ISO timestamp; defaults to current UTC time')
    parser.add_argument('--minimum-agent-version')
    parser.add_argument('--stale-hours', type=positive, default=48)
    parser.add_argument('--snapshot-max-age-hours', type=positive, default=24)
    args = parser.parse_args()
    try:
        if args.input.resolve() == args.report.resolve() or (args.report.exists() and args.input.samefile(args.report)):
            raise InvalidSnapshot('input and report must be different files')
        with args.input.open('rb') as source:
            content = source.read(10 * 1024 * 1024 + 1)
        if len(content) > 10 * 1024 * 1024:
            raise InvalidSnapshot('input exceeds 10 MiB')
        snapshot = read_snapshot(json.loads(content))
        now = timestamp(args.as_of, 'as-of') if args.as_of else datetime.now(timezone.utc)
        report = reconcile(snapshot, now, args.minimum_agent_version, args.stale_hours, args.snapshot_max_age_hours)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0)
        with os.fdopen(os.open(args.report, flags, 0o600), 'w') as target:
            if os.name != 'nt':
                os.fchmod(target.fileno(), 0o600)
            json.dump(report, target, ensure_ascii=False, indent=2)
            target.write('\n')
        print(json.dumps({'report': str(args.report), 'comparisonComplete': report['comparisonComplete'], 'summary': report['summary']}))
        return 0 if report['comparisonComplete'] else 2
    except (InvalidSnapshot, OSError, UnicodeError, json.JSONDecodeError) as error:
        print(f'Invalid inventory snapshot: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
