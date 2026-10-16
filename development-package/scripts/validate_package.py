"""Validate the Development Package without writing any file.

Runs the bounded contract checks, document checks and, when jsonschema and openapi-spec-validator are
installed, the standard validators with format assertion. Only files inside the package root are read.
With --manifest every file must match manifest.json (a received package); without it a stale manifest is only
reported, because build_package.py rewrites it. Exit code is non-zero on any failure.
"""
import sys

sys.dont_write_bytecode = True
from pathlib import Path  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
import argparse  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import re  # noqa: E402

import validate_contracts as contracts  # noqa: E402
import validate_docs as documents  # noqa: E402
from contract_catalog import AGENT_ACTIONS, CATALOG_VERSION  # noqa: E402
from schema_check import read_json  # noqa: E402
from validate_invariants import check_invariants  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
STANDARD_SKIPPED = 'стандартная проверка не выполнена: jsonschema и openapi-spec-validator не установлены'
# Allowed package paths (relative, POSIX); build packages exactly the files that package_files returns.
ALLOWED_PATHS = [r'README\.md', r'VALIDATION\.md', r'REVIEW-BUNDLE\.md', r'manifest\.json',
                 r'(0[1-9]|10)-[a-z0-9-]+\.md', r'source/boss-chat\.md', r'specs/[a-z0-9-]+(\.schema)?\.json',
                 r'examples/[a-z0-9-]+\.json', r'scripts/[a-z_]+\.py']
VERSION = re.compile(r'\b[0-9]+\.[0-9]+\.[0-9]+\b')
MANIFEST_KEYS = ['date', 'files', 'packageVersion', 'timezone']
MANIFEST_ENTRY = ['bytes', 'path', 'sha256']


def package_files(root):
    """Files of the package: everything except hidden files or directories and __pycache__."""
    return sorted(p for p in root.rglob('*') if p.is_file() and '__pycache__' not in p.parts
                  and not any(part.startswith('.') for part in p.relative_to(root).parts))


def check_layout(report, root):
    for file in package_files(root):
        path = file.relative_to(root).as_posix()
        report.check(any(re.fullmatch(pattern, path) for pattern in ALLOWED_PATHS), 'contract',
                     f'Unexpected file in the package: {path}')
    build = (root / 'scripts' / 'build_package.py').read_text(encoding='utf-8')
    declared = re.findall(r"^VERSION = '([^']+)'$", build, re.M)
    report.check(declared == [CATALOG_VERSION], 'contract', 'build_package.py VERSION differs from CATALOG_VERSION')
    for name in ('README.md', '09-independent-review-prompt.md'):
        lines = (root / name).read_text(encoding='utf-8').splitlines() if (root / name).exists() else []
        found = VERSION.findall(lines[2]) if len(lines) > 2 else []
        report.check(bool(found) and set(found) == {CATALOG_VERSION}, 'docs',
                     f'{name}: line 3 must state version {CATALOG_VERSION}')


def _manifest_entries(report, root):
    """Entries of manifest.json by path, or None when the file is absent or malformed (structure is always checked)."""
    path = root / 'manifest.json'
    if not path.exists():
        return None
    try:
        manifest = read_json(path)
    except ValueError as error:
        report.fail('contract', f'manifest.json: {error}')
        return None
    if not isinstance(manifest, dict) or sorted(manifest) != MANIFEST_KEYS or not isinstance(manifest['files'], list):
        report.fail('contract', 'manifest.json: keys differ from packageVersion, date, timezone and files')
        return None
    entries = {}
    for entry in manifest['files']:
        valid = (isinstance(entry, dict) and sorted(entry) == MANIFEST_ENTRY and isinstance(entry['path'], str)
                 and entry['path'] != 'manifest.json' and entry['path'] not in entries
                 and any(re.fullmatch(pattern, entry['path']) for pattern in ALLOWED_PATHS)
                 and isinstance(entry['bytes'], int) and re.fullmatch(r'[0-9a-f]{64}', str(entry['sha256'])))
        if not valid:
            report.fail('contract', f'manifest.json: invalid entry {entry}')
            continue
        entries[entry['path']] = entry
    return manifest['packageVersion'], entries


def check_manifest(report, root, strict):
    """Compare manifest.json with the package files: size and SHA-256 of every file, no missing or extra file."""
    loaded = _manifest_entries(report, root)
    if loaded is None:
        report.check(not strict, 'contract', 'manifest.json missing or unreadable')
        report.summary['manifest'] = 'absent'
        return
    version, entries = loaded
    files = {p.relative_to(root).as_posix(): p for p in package_files(root)}
    files.pop('manifest.json', None)
    changed = sorted(set(entries) ^ set(files))
    for name in sorted(set(entries) & set(files)):
        data = files[name].read_bytes()
        if len(data) != entries[name]['bytes'] or hashlib.sha256(data).hexdigest() != entries[name]['sha256']:
            changed.append(name)
    current = not changed and version == CATALOG_VERSION
    report.summary['manifest'] = 'current' if current else 'stale'
    if strict:
        report.check(version == CATALOG_VERSION, 'contract', 'manifest.json: packageVersion differs from the package')
        for name in changed:
            report.fail('contract', f'manifest.json: {name} is missing, extra or changed')


class Report:
    def __init__(self):
        self.errors = []
        self.summary = {}

    def fail(self, category, message):
        self.errors.append((category, message))

    def check(self, condition, category, message):
        if not condition:
            self.fail(category, message)


def standard_validation(report, root):
    try:
        import jsonschema
        import openapi_spec_validator
        from referencing import Registry, Resource
    except ImportError:
        report.summary['standardValidation'] = False
        print(STANDARD_SKIPPED)
        return
    try:
        names = ['observation', 'scan-batch', 'graph-observation', 'graph-collection']
        loaded = {name: read_json(root / f'specs/{name}.schema.json') for name in names}
        registry = Registry().with_resources([(s['$id'], Resource.from_contents(s)) for s in loaded.values()])
        checker = jsonschema.Draft202012Validator.FORMAT_CHECKER
        validators = {'scan-batch': jsonschema.Draft202012Validator(loaded['scan-batch'], registry=registry,
                                                                    format_checker=checker),
                      'm365': jsonschema.Draft202012Validator(loaded['graph-collection'], registry=registry,
                                                              format_checker=checker)}
        for example in sorted((root / 'examples').glob('*.json')):
            validator = validators['m365' if example.name.startswith('m365') else 'scan-batch']
            for error in validator.iter_errors(read_json(example)):
                report.fail('contract', f'standard: examples/{example.name}: {error.message}')
        api = read_json(root / 'specs/openapi.json')
        check = getattr(openapi_spec_validator, 'validate', None) or openapi_spec_validator.validate_spec
        check(api)
        report.summary['standardValidation'] = True
    except Exception as error:  # noqa: BLE001 - any validator failure is a package failure
        report.fail('contract', f'standard validation failed: {error}')
        report.summary['standardValidation'] = True


def run(root=ROOT, manifest=False):
    report = Report()
    check_layout(report, root)
    check_manifest(report, root, manifest)
    contracts.check_json_files(report, root)
    try:
        ctx = contracts.load(root)
    except (OSError, ValueError, KeyError) as error:
        report.fail('contract', f'Contracts cannot be loaded: {error}')
        return report
    docs = documents.read_docs(root)
    for check in (contracts.check_catalog, contracts.check_schemas, contracts.check_examples,
                  contracts.check_negatives, contracts.check_openapi, contracts.check_responses):
        check(report, ctx)
    invariant_ids = check_invariants(report, ctx, docs)
    documents.check_catalog_rows(report, ctx, docs)
    documents.check_os_lifecycle(report, docs)
    documents.check_requirements(report, ctx, docs)
    documents.check_effort(report, docs)
    documents.check_calendar(report, docs)
    documents.check_acceptance_stages(report, ctx, docs)
    documents.check_runbooks(report, ctx, docs)
    documents.check_agent_states(report, docs)
    documents.check_data_api(report, ctx, docs)
    documents.check_purge_order(report, docs)
    documents.check_roles(report, ctx, docs)
    documents.check_references(report, docs, invariant_ids)
    documents.check_markdown(report, root, docs)
    documents.check_chat(report, root)
    report.summary['agentActions'] = len(AGENT_ACTIONS)
    standard_validation(report, root)
    return report


def main():
    parser = argparse.ArgumentParser(description='Validate the Development Package; writes no file.')
    parser.add_argument('--manifest', action='store_true',
                        help='fail unless every package file matches manifest.json (check a received package)')
    report = run(manifest=parser.parse_args().manifest)
    for category, message in report.errors:
        print(f'[{category}] {message}')
    counts = {category: sum(1 for c, _ in report.errors if c == category) for category in ('contract', 'docs')}
    print(json.dumps({'errors': counts, **report.summary}, ensure_ascii=False, indent=2))
    return 1 if report.errors else 0


if __name__ == '__main__':
    sys.exit(main())
