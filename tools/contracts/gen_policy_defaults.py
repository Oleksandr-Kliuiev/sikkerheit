"""Generate portal policy defaults from the API schema, without copying defaults into UI code."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / 'src/Portal/src/lib/policy-defaults.g.json'


def defaults(schema):
    if 'default' in schema:
        return schema['default']
    properties = schema.get('properties', {})
    required = schema.get('required', [])
    return {key: defaults(value) for key, value in properties.items()
            if key in required or 'default' in value}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    api = json.loads((ROOT / 'development-package/specs/openapi.json').read_text())
    result = json.dumps(defaults(api['components']['schemas']['PolicyConfiguration']), indent=2) + '\n'
    sys.path.insert(0, str(ROOT / 'development-package/scripts'))
    from contract_policy_templates import SCOPES, PROTECTED
    from contract_catalog import DEFERRED_IDS
    checks = api['components']['schemas']['PolicyConfiguration']['properties']['checks']['properties']
    constraints = {cid: {'modes': ['informational'] if cid in DEFERRED_IDS else check['properties']['assessmentMode'].get('enum',
                         [check['properties']['assessmentMode'].get('const')]),
                        'parameters': {name: {key: value[key] for key in ['minimum', 'maximum'] if key in value}
                                       for name, value in check['properties']['parameters']['properties'].items()}}
                   for cid, check in checks.items()}
    metadata = json.dumps({'scopes': SCOPES, 'protectedParameters': PROTECTED, 'constraints': constraints}, indent=2) + '\n'
    metadata_path = TARGET.with_name('policy-template-fields.g.json')
    if args.check and (not metadata_path.exists() or metadata_path.read_text() != metadata):
        raise SystemExit('Portable template field map is stale')
    if not args.check:
        metadata_path.write_text(metadata)
    if args.check:
        if not TARGET.exists() or TARGET.read_text() != result:
            raise SystemExit('Policy defaults are stale: run python3 -I tools/contracts/gen_policy_defaults.py')
        print('Policy defaults are current')
    else:
        TARGET.write_text(result)
        print(TARGET)


if __name__ == '__main__':
    main()
