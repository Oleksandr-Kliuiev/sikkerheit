"""Validate the Development Package without writing any file.

Runs the bounded contract checks, document checks and, when jsonschema and openapi-spec-validator are
installed, the standard validators with format assertion. Exit code is non-zero on any failure.
"""
import sys

sys.dont_write_bytecode = True
from pathlib import Path  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
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
        observation = read_json(root / 'specs/observation.schema.json')
        batch = read_json(root / 'specs/scan-batch.schema.json')
        registry = Registry().with_resources([(s['$id'], Resource.from_contents(s)) for s in (observation, batch)])
        validator = jsonschema.Draft202012Validator(
            batch, registry=registry, format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER)
        for example in sorted((root / 'examples').glob('*.json')):
            for error in validator.iter_errors(read_json(example)):
                report.fail('contract', f'standard: examples/{example.name}: {error.message}')
        api = read_json(root / 'specs/openapi.json')
        check = getattr(openapi_spec_validator, 'validate', None) or openapi_spec_validator.validate_spec
        check(api)
        report.summary['standardValidation'] = True
    except Exception as error:  # noqa: BLE001 - any validator failure is a package failure
        report.fail('contract', f'standard validation failed: {error}')
        report.summary['standardValidation'] = True


def run(root=ROOT):
    report = Report()
    check_layout(report, root)
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
    documents.check_p0_plan(report, docs)
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
    report = run()
    for category, message in report.errors:
        print(f'[{category}] {message}')
    counts = {category: sum(1 for c, _ in report.errors if c == category) for category in ('contract', 'docs')}
    print(json.dumps({'errors': counts, **report.summary}, ensure_ascii=False, indent=2))
    return 1 if report.errors else 0


if __name__ == '__main__':
    sys.exit(main())
