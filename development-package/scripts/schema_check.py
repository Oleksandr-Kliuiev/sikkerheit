"""Bounded JSON Schema checker for the keyword subset used by this package.

It is not a general JSON Schema or OpenAPI validator: any keyword outside SUPPORTED fails.
"""
from datetime import datetime
import json
from pathlib import Path
import re
from urllib.parse import urlsplit
import uuid

SUPPORTED = {'$ref', '$id', '$schema', 'title', 'description', 'default', 'type', 'const', 'enum',
             'required', 'properties', 'additionalProperties', 'items', 'minItems', 'maxItems',
             'uniqueItems', 'minLength', 'maxLength', 'pattern', 'format', 'minimum', 'maximum',
             'allOf', 'oneOf', 'not', 'if', 'then', 'else', 'minProperties'}
TYPES = {
    'object': lambda v: isinstance(v, dict), 'array': lambda v: isinstance(v, list),
    'string': lambda v: isinstance(v, str), 'boolean': lambda v: isinstance(v, bool),
    'null': lambda v: v is None,
    'integer': lambda v: isinstance(v, int) and not isinstance(v, bool),
    'number': lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
}


class SchemaError(ValueError):
    pass


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def resolve_ref(reference, file, root):
    filename, _, pointer = reference.partition('#')
    if filename.startswith(('http:', 'https:', './', '../')) or '/' in filename:
        raise SchemaError(f'Only local sibling or internal references are allowed: {reference}')
    target = (file.parent / filename).resolve() if filename else file.resolve()
    if not target.is_relative_to(root):
        raise SchemaError(f'Reference escapes package: {reference}')
    value = read_json(target)
    for token in pointer.lstrip('/').split('/') if pointer else []:
        value = value[token.replace('~1', '/').replace('~0', '~')]
    return value, target


def subschemas(schema):
    """Direct child schemas of a schema object."""
    for key in ('properties',):
        yield from schema.get(key, {}).values()
    for key in ('items', 'not', 'if', 'then', 'else'):
        if isinstance(schema.get(key), dict):
            yield schema[key]
    if isinstance(schema.get('additionalProperties'), dict):
        yield schema['additionalProperties']
    for key in ('allOf', 'oneOf'):
        yield from schema.get(key, [])


def unsupported_keywords(schema, at='$'):
    """Return paths of keywords outside SUPPORTED anywhere in the schema tree."""
    found = [f'{at}.{key}' for key in schema if key not in SUPPORTED]
    for index, child in enumerate(subschemas(schema)):
        found.extend(unsupported_keywords(child, f'{at}/{index}'))
    return found


def _format_ok(value, name):
    if name == 'uuid':
        try:
            uuid.UUID(value)
        except ValueError:
            return False
        return True
    if name == 'date-time':
        try:
            return datetime.fromisoformat(value.replace('Z', '+00:00')).tzinfo is not None
        except ValueError:
            return False
    if name == 'uri':
        return bool(urlsplit(value).scheme)
    return True


def validate(value, schema, file, root, at='$'):
    def fail(message):
        raise SchemaError(f'{at}: {message}')

    def matches(candidate):
        try:
            validate(value, candidate, file, root, at)
            return True
        except SchemaError:
            return False

    unknown = set(schema) - SUPPORTED
    if unknown:
        fail(f'unsupported keyword {sorted(unknown)}')
    if '$ref' in schema:
        referred, target = resolve_ref(schema['$ref'], file, root)
        validate(value, referred, target, root, at)
    if 'type' in schema:
        kinds = schema['type'] if isinstance(schema['type'], list) else [schema['type']]
        if not any(TYPES[kind](value) for kind in kinds):
            fail('type mismatch')
    if 'const' in schema and value != schema['const']:
        fail('const mismatch')
    if 'enum' in schema and value not in schema['enum']:
        fail('enum mismatch')
    if isinstance(value, dict):
        if set(schema.get('required', [])) - value.keys():
            fail('required property absent')
        if len(value) < schema.get('minProperties', 0):
            fail('too few properties')
        properties = schema.get('properties', {})
        if schema.get('additionalProperties') is False and value.keys() - properties.keys():
            fail('additional properties rejected')
        for key, child in value.items():
            if key in properties:
                validate(child, properties[key], file, root, at + '.' + key)
    if isinstance(value, list):
        if not schema.get('minItems', 0) <= len(value) <= schema.get('maxItems', float('inf')):
            fail('array size')
        if schema.get('uniqueItems') and len({json.dumps(x, sort_keys=True) for x in value}) != len(value):
            fail('array uniqueness')
        if 'items' in schema:
            for index, child in enumerate(value):
                validate(child, schema['items'], file, root, f'{at}[{index}]')
    if isinstance(value, str):
        if not schema.get('minLength', 0) <= len(value) <= schema.get('maxLength', float('inf')):
            fail('string size')
        if 'pattern' in schema and re.search(schema['pattern'], value) is None:
            fail('pattern mismatch')
        if 'format' in schema and not _format_ok(value, schema['format']):
            fail(f'{schema["format"]} format')
    if TYPES['number'](value):
        if not schema.get('minimum', -float('inf')) <= value <= schema.get('maximum', float('inf')):
            fail('number range')
    for child in schema.get('allOf', []):
        validate(value, child, file, root, at)
    if 'oneOf' in schema and sum(matches(child) for child in schema['oneOf']) != 1:
        fail('oneOf mismatch')
    if 'not' in schema and matches(schema['not']):
        fail('not constraint')
    if 'if' in schema:
        branch = 'then' if matches(schema['if']) else 'else'
        if branch in schema:
            validate(value, schema[branch], file, root, at)


def is_valid(value, schema, file, root):
    try:
        validate(value, schema, file, root)
        return True
    except SchemaError:
        return False
