"""Build an offline review bundle and archive, with bounded contract checks.

The small schema checker covers the operators used by the supplied examples.
It is not a general JSON Schema or OpenAPI conformance validator.
"""
from pathlib import Path
import copy
from datetime import datetime
import hashlib
import json
import re
import uuid
from urllib.parse import urlsplit, unquote
import zipfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = '0.1.0'
DATE = '2026-10-12'


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8'))


def resolve_ref(reference, file):
    filename, _, pointer = reference.partition('#')
    if filename.startswith(('http:', 'https:')):
        raise ValueError('External schema reference not allowed by the offline package checker')
    target = (file.parent / filename).resolve() if filename else file.resolve()
    if not target.is_relative_to(ROOT):
        raise ValueError('Reference escapes package')
    document = read_json(target)
    value = document
    for token in pointer.lstrip('/').split('/') if pointer else []:
        value = value[token.replace('~1', '/').replace('~0', '~')]
    return value, target


def validate(value, schema, file, at='$'):
    """Check only the schema keywords used in this package's data examples."""
    def fail(message):
        raise ValueError(f'{at}: {message}')

    def matches(candidate):
        try:
            validate(value, candidate, file, at)
            return True
        except ValueError:
            return False

    if '$ref' in schema:
        referred, target = resolve_ref(schema['$ref'], file)
        validate(value, referred, target, at)
    typ = schema.get('type')
    if typ:
        kinds = typ if isinstance(typ, list) else [typ]
        type_match = {
            'object': isinstance(value, dict), 'array': isinstance(value, list),
            'string': isinstance(value, str), 'boolean': isinstance(value, bool),
            'null': value is None,
            'integer': isinstance(value, int) and not isinstance(value, bool),
            'number': isinstance(value, (int, float)) and not isinstance(value, bool),
        }
        if not any(type_match.get(kind, False) for kind in kinds):
            fail('type mismatch')
    if 'const' in schema and value != schema['const']:
        fail('const mismatch')
    if 'enum' in schema and value not in schema['enum']:
        fail('enum mismatch')
    if isinstance(value, dict):
        if set(schema.get('required', [])) - value.keys():
            fail('required property absent')
        properties = schema.get('properties', {})
        if schema.get('additionalProperties') is False and value.keys() - properties.keys():
            fail('additional properties rejected')
        for key, child in value.items():
            if key in properties:
                validate(child, properties[key], file, at + '.' + key)
    if isinstance(value, list):
        if len(value) < schema.get('minItems', 0) or len(value) > schema.get('maxItems', float('inf')):
            fail('array size')
        if schema.get('uniqueItems') and len({json.dumps(x, sort_keys=True) for x in value}) != len(value):
            fail('array uniqueness')
        for index, child in enumerate(value):
            if 'items' in schema:
                validate(child, schema['items'], file, f'{at}[{index}]')
    if isinstance(value, str):
        if len(value) < schema.get('minLength', 0) or len(value) > schema.get('maxLength', float('inf')):
            fail('string size')
        if 'pattern' in schema and re.search(schema['pattern'], value) is None:
            fail('pattern mismatch')
        if schema.get('format') == 'uuid':
            try:
                uuid.UUID(value)
            except ValueError:
                fail('uuid format')
        if schema.get('format') == 'date-time':
            try:
                if datetime.fromisoformat(value.replace('Z', '+00:00')).tzinfo is None:
                    fail('timezone absent')
            except ValueError:
                fail('date-time format')
        if schema.get('format') == 'uri' and not urlsplit(value).scheme:
            fail('uri format')
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value < schema.get('minimum', -float('inf')) or value > schema.get('maximum', float('inf')):
            fail('number range')
    for child in schema.get('allOf', []):
        validate(value, child, file, at)
    if 'oneOf' in schema and sum(matches(child) for child in schema['oneOf']) != 1:
        fail('oneOf mismatch')
    if 'not' in schema and matches(schema['not']):
        fail('not constraint')
    if 'if' in schema:
        branch = 'then' if matches(schema['if']) else 'else'
        if branch in schema:
            validate(value, schema[branch], file, at)


def walk(value):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


source = ROOT.parent / 'sikkerheit-app-chat-transcript.md'
source_copy = ROOT / 'source' / 'boss-chat.md'
source_copy.parent.mkdir(exist_ok=True)
if source.exists():
    source_copy.write_bytes(source.read_bytes())
assert source_copy.exists(), 'Source transcript missing'
assert len(re.findall(r'^## \d+\. (?:Шеф|ChatGPT)$', source_copy.read_text(), re.M)) == 12

json_files = sorted(ROOT.rglob('*.json'))
json_files = [p for p in json_files if p.name != 'manifest.json']
for file in json_files:
    for item in walk(read_json(file)):
        if isinstance(item, dict) and '$ref' in item:
            resolve_ref(item['$ref'], file)

catalog = read_json(ROOT / 'specs/check-catalog.json')['checks']
ids = [item['checkId'] for item in catalog]
assert len(ids) == len(set(ids)) == 16
catalog_doc = (ROOT / '03-check-catalog.md').read_text()
for cid in ids:
    assert f'| {cid} |' in catalog_doc, f'Check absent from narrative catalog: {cid}'
agent_ids = {c['checkId'] for c in catalog if c['checkId'].startswith('WIN-')}
schema_file = ROOT / 'specs/scan-batch.schema.json'
schema = read_json(schema_file)
for file in sorted((ROOT / 'examples').glob('*.json')):
    example = read_json(file)
    validate(example, schema, schema_file)
    assert {o['checkId'] for o in example['observations']} == agent_ids
    assert len(json.dumps(example).encode()) < 256 * 1024

good = read_json(ROOT / 'examples/scan-batch.json')
bad_examples = []
bad = copy.deepcopy(good); bad['organizationId'] = str(uuid.uuid4()); bad_examples.append(bad)
bad = copy.deepcopy(good); bad['observations'][0].pop('evidence'); bad_examples.append(bad)
bad = copy.deepcopy(good); bad['observations'][0]['collectionStatus'] = 'unavailable'; bad_examples.append(bad)
bad = copy.deepcopy(good); bad['observations'][0]['checkId'] = 'M365-001'; bad_examples.append(bad)
bad = copy.deepcopy(good); bad['observations'][0]['evidence']['freeBytes'] = -1; bad_examples.append(bad)
bad = copy.deepcopy(good); bad['observations'][1]['evidence']['encryptionPercentage'] = 101; bad_examples.append(bad)
bad = copy.deepcopy(good); bad['observations'][1]['evidence']['recoveryPassword'] = 'REJECTED'; bad_examples.append(bad)
for bad in bad_examples:
    try:
        validate(bad, schema, schema_file)
    except ValueError:
        continue
    raise AssertionError('Negative contract example accepted')

api = read_json(ROOT / 'specs/openapi.json')
assert api['openapi'] == '3.1.0'
operations = []
for path, definition in api['paths'].items():
    for method, operation in definition.items():
        if method not in ['get', 'post', 'patch', 'put', 'delete']:
            continue
        operations.append(operation['operationId'])
        variables = set(re.findall(r'\{([^}]+)\}', path))
        parameters = {p['name'] for p in operation.get('parameters', []) if p['in'] == 'path' and p['required']}
        assert variables == parameters, f'Path variables differ: {path}'
        assert operation.get('security'), f'Security not explicit: {path}'
        for alternative in operation['security']:
            assert set(alternative) <= api['components']['securitySchemes'].keys()
            if 'PortalSession' in alternative and method in ['post', 'patch', 'put', 'delete']:
                assert 'CsrfToken' in alternative
        if path.startswith('/api/v1/agent/') and not path.endswith('/enroll'):
            assert operation['security'] == [{'DeviceCertificate': []}]
            assert operation['servers'][0]['url'] == 'https://agent.example.invalid'
assert len(operations) == len(set(operations))

requirements_doc = (ROOT / '01-product-and-scope.md').read_text()
acceptance_doc = (ROOT / '07-delivery-plan-and-acceptance.md').read_text()
for number in range(1, 14):
    assert f'| FR-{number:02} |' in requirements_doc
for number in range(1, 18):
    assert f'| AT-{number:02} |' in acceptance_doc
for file in ROOT.rglob('*.md'):
    if file.name in ['REVIEW-BUNDLE.md', 'VALIDATION.md']:
        continue
    text = file.read_text(encoding='utf-8')
    assert text.count('```') % 2 == 0, f'Unclosed code fence: {file}'
    for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)', text):
        if target.startswith(('https:', 'http:', '#', 'mailto:')):
            continue
        local = (file.parent / unquote(target.split('#')[0])).resolve()
        assert local.exists(), f'Broken local link: {file.name} -> {target}'

validation = f'''# Проверка Development Package

Версия {VERSION}, дата {DATE}. Выполнена проверка файлов и контрактов пакета.

- Прочитаны все JSON-файлы и разрешены локальные schema references.
- Найдены 16 уникальных check IDs, 13 функциональных требований и 17 приёмочных сценариев.
- Два синтетических scan batch проходят ограниченную проверку операторов используемых JSON Schema.
- Семь отрицательных вариантов отклонены, включая чужой OrganizationId, отсутствие evidence и запрещённый recoveryPassword.
- Проверены {len(operations)} operation IDs, path parameters, схемы security, CSRF и отдельный mTLS host.
- Проверены локальные Markdown-ссылки, закрытие code fences и 12 сообщений исходной переписки.

Проверка в scripts/build_package.py использует стандартную библиотеку Python и только применённое подмножество операторов схем. Она не подтверждает полное соответствие OpenAPI или JSON Schema сторонним стандартным валидатором. Полная contract validation входит в WP-01 до code generation.

Приёмочные сценарии Windows/Azure/Entra, работоспособность API, производительность, стоимость и юридические условия должны быть подтверждены на соответствующих этапах. Данные примеров синтетические; клиентские системы не использовались.
'''
(ROOT / 'VALIDATION.md').write_text(validation, encoding='utf-8')

docs = [ROOT / 'README.md'] + sorted(ROOT.glob('[0-9][0-9]-*.md'))
docs += [source_copy, ROOT / 'VALIDATION.md']
parts = ['# Development Package для независимой оценки\n\n'
         f'Версия {VERSION} от 12 октября 2026 года. Полный комплект требований, '
         'архитектуры и предложенных контрактов.\n\n'
         'Рецензент начинает с запроса независимой оценки и проверяет весь комплект.\n']
for file in docs:
    relative = file.relative_to(ROOT).as_posix()
    parts.append(f'\n\nФайл `{relative}`\n\n' + file.read_text(encoding='utf-8'))
for file in sorted((ROOT / 'specs').glob('*.json')) + sorted((ROOT / 'examples').glob('*.json')):
    relative = file.relative_to(ROOT).as_posix()
    parts.append(f'\n\nФайл `{relative}`\n\n```json\n' + file.read_text(encoding='utf-8') + '```\n')
bundle = ROOT / 'REVIEW-BUNDLE.md'
bundle.write_text(''.join(parts), encoding='utf-8')

files = sorted(p for p in ROOT.rglob('*') if p.is_file() and p.name != 'manifest.json'
               and '__pycache__' not in p.parts)
manifest = {'packageVersion': VERSION, 'date': DATE, 'timezone': 'Europe/Oslo',
            'files': [{'path': p.relative_to(ROOT).as_posix(), 'bytes': p.stat().st_size,
                       'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in files]}
(ROOT / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
archive = ROOT.parent / f'sikkerheit-development-package-v{VERSION}.zip'
with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as handle:
    for file in files + [ROOT / 'manifest.json']:
        handle.write(file, 'development-package/' + file.relative_to(ROOT).as_posix())
with zipfile.ZipFile(archive) as handle:
    assert handle.testzip() is None
    for entry in manifest['files']:
        assert hashlib.sha256(handle.read('development-package/' + entry['path'])).hexdigest() == entry['sha256']
print(json.dumps({'packageVersion': VERSION, 'files': len(files) + 1,
                  'apiOperations': len(operations), 'archiveBytes': archive.stat().st_size,
                  'bundleBytes': bundle.stat().st_size, 'archive': str(archive),
                  'bundle': str(bundle)}, ensure_ascii=False, indent=2))
