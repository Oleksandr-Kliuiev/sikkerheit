"""A small evaluator of compiled ARM templates for the IaC test (check_arm.py).

It expands copy loops, evaluates conditions and nested deployment parameters, and resolves reference() of a nested
deployment to that deployment's outputs. Values that exist only at deployment time (reference() of a resource,
uniqueString(), the subscription in a resource id) stay Unknown, or Partial inside strings; an Unknown from reference()
keeps the referenced resource id and property path in its source, so a check can tell whose principalId it is. A
function or form it does not support raises CannotEvaluate instead of a guess. Standard library only.
"""
import copy
import json
import re


class CannotEvaluate(Exception):
    """The template uses an expression the evaluator does not support: stop rather than guess."""


class Unknown:
    """A value known only at deployment time; origin is the function that produced it, source what reference() read."""

    def __init__(self, origin, source=''):
        self.origin, self.source = origin, source

    def __repr__(self):
        return f'<{self.origin}({self.source})>'


class Partial:
    """A string with deployment-time parts, such as a resource id with an unknown subscription."""

    def __init__(self, parts):
        self.parts = parts

    def __repr__(self):
        return ''.join(part if isinstance(part, str) else repr(part) for part in self.parts)


class _Missing:
    def __repr__(self):
        return 'missing'


MISSING = _Missing()


def text(parts):
    """Concatenates strings and unknown parts; a fully known result is a plain str."""
    flat = []
    for part in parts:
        for piece in part.parts if isinstance(part, Partial) else (part,):
            if isinstance(piece, str):
                if flat and isinstance(flat[-1], str):
                    flat[-1] += piece
                elif piece:
                    flat.append(piece)
            elif isinstance(piece, Unknown):
                flat.append(piece)
            else:
                raise CannotEvaluate(f'a string from {show(piece)}')
    if all(isinstance(piece, str) for piece in flat):
        return ''.join(flat)
    return Partial(tuple(flat))


def known_start(value):
    if isinstance(value, Partial):
        return value.parts[0] if isinstance(value.parts[0], str) else ''
    return value if isinstance(value, str) else ''


def known_end(value):
    if isinstance(value, Partial):
        return value.parts[-1] if isinstance(value.parts[-1], str) else ''
    return value if isinstance(value, str) else ''


def literals(value):
    """Every literal string inside a value (keys included)."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, Partial):
        return [part for part in value.parts if isinstance(part, str)]
    if isinstance(value, dict):
        return [item for key, inner in value.items() for item in literals(key) + literals(inner)]
    if isinstance(value, list):
        return [item for inner in value for item in literals(inner)]
    return []


def origins(value):
    """The functions that produced the unknown parts of a value."""
    if isinstance(value, Unknown):
        return [value.origin]
    if isinstance(value, Partial):
        return [part.origin for part in value.parts if isinstance(part, Unknown)]
    if isinstance(value, dict):
        return [item for key, inner in value.items() for item in origins(key) + origins(inner)]
    if isinstance(value, list):
        return [item for inner in value for item in origins(inner)]
    return []


def concrete(value):
    if isinstance(value, (Unknown, Partial, _Missing, Outputs)):
        return False
    if isinstance(value, dict):
        return all(concrete(key) and concrete(inner) for key, inner in value.items())
    if isinstance(value, list):
        return all(concrete(inner) for inner in value)
    return True


def show(value, limit=200):
    """A short one-line form of a value for messages."""
    shown = json.dumps(value, default=repr) if concrete(value) else repr(value)
    return shown if len(shown) <= limit else shown[:limit] + '...'


def is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def is_expression(value):
    return isinstance(value, str) and value.startswith('[') and value.endswith(']') and not value.startswith('[[')


def lookup(mapping, key, default=MISSING):
    """ARM property names are case-insensitive."""
    if key in mapping:
        return mapping[key]
    for candidate, value in mapping.items():
        if isinstance(candidate, str) and isinstance(key, str) and candidate.lower() == key.lower():
            return value
    return default


# --- Expressions -------------------------------------------------------------------------------------------------

TOKEN = re.compile(r"\s*(?:('(?:[^']|'')*')|(-?\d+)|([A-Za-z_$][\w$]*)|([(),.\[\]]))")


def parse(source):
    """Parses the inside of an ARM expression «[...]» into nested tuples."""
    tokens, position, source = [], 0, source.rstrip()
    while position < len(source):
        match = TOKEN.match(source, position)
        if not match:
            raise CannotEvaluate(f'syntax near {source[position:position + 30]!r}')
        position = match.end()
        string, number, name, operator = match.groups()
        if string is not None:
            tokens.append(('str', string[1:-1].replace("''", "'")))
        elif number is not None:
            tokens.append(('num', int(number)))
        elif name is not None:
            tokens.append(('name', name))
        else:
            tokens.append(('op', operator))
    index = 0

    def peek():
        return tokens[index] if index < len(tokens) else ('end', None)

    def take(kind, value=None):
        nonlocal index
        token = peek()
        if token[0] != kind or (value is not None and token[1] != value):
            raise CannotEvaluate(f'syntax in [{source}]')
        index += 1
        return token[1]

    def expression():
        nonlocal index
        kind, value = peek()
        if kind in ('str', 'num'):
            index += 1
            node = (kind, value)
        else:
            name, arguments = take('name'), []
            take('op', '(')
            if peek() != ('op', ')'):
                arguments.append(expression())
                while peek() == ('op', ','):
                    index += 1
                    arguments.append(expression())
            take('op', ')')
            node = ('call', name, arguments)
        while peek() in (('op', '.'), ('op', '[')):
            if take('op') == '.':
                node = ('member', node, ('str', take('name')))
            else:
                node = ('member', node, expression())
                take('op', ']')
        return node

    tree = expression()
    if index != len(tokens):
        raise CannotEvaluate(f'syntax in [{source}]')
    return tree


# Deployment-time functions: their result stays unknown. list*() functions (listKeys...) are added by prefix.
RUNTIME = {'resourcegroup', 'subscription', 'deployment', 'environment', 'tenant', 'managementgroup', 'uniquestring',
           'guid', 'utcnow', 'newguid'}
DEPLOYMENT_ID = re.compile(r'/providers/Microsoft\.Resources/deployments/([^/]+)$', re.IGNORECASE)


def evaluate(node, scope):
    kind = node[0]
    if kind in ('str', 'num'):
        return node[1]
    if kind == 'member':
        return member(evaluate(node[1], scope), evaluate(node[2], scope))
    name, arguments = node[1].lower(), node[2]
    if name == 'if':  # only the chosen branch is evaluated, as in ARM
        if len(arguments) != 3:
            raise CannotEvaluate('if() needs three arguments')
        condition = evaluate(arguments[0], scope)
        if isinstance(condition, bool):
            return evaluate(arguments[1] if condition else arguments[2], scope)
        if isinstance(condition, Unknown):
            return Unknown('if')
        raise CannotEvaluate(f'if() on {show(condition)}')
    if name in RUNTIME or name.startswith('list'):
        return Unknown(node[1])
    values = [evaluate(argument, scope) for argument in arguments]
    if name in ('parameters', 'variables'):
        if len(values) != 1 or not isinstance(values[0], str):
            raise CannotEvaluate(f'{node[1]}() of {values!r}')
        return scope.parameter(values[0]) if name == 'parameters' else scope.variable(values[0])
    if name == 'copyindex':
        return scope.copy_index(values)
    if name == 'reference':
        return scope.reference(values)
    function = FUNCTIONS.get(name)
    if function is None:
        raise CannotEvaluate(f'function {node[1]}()')
    try:
        return function(*values)
    except TypeError:
        raise CannotEvaluate(f'{node[1]}() with {len(values)} arguments') from None


def member(value, key):
    if isinstance(value, Unknown):
        return Unknown(value.origin, f'{value.source}.{key}' if value.source else '')
    if isinstance(value, Outputs):
        return value.get(key)
    if isinstance(value, dict) and isinstance(key, str):
        found = lookup(value, key)
        if found is MISSING:
            raise CannotEvaluate(f'no property {key!r} in {show(value)}')
        return found
    if isinstance(value, list) and is_int(key) and 0 <= key < len(value):
        return value[key]
    raise CannotEvaluate(f'[{show(key)}] of {show(value)}')


def same(left, right):
    if not (concrete(left) and concrete(right)):
        return Unknown('equals')
    return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)


def logical(values, short, empty):
    """and() / or(): short is the value that decides the result on its own."""
    if not all(isinstance(value, (bool, Unknown)) for value in values):
        raise CannotEvaluate(f'logical function on {values!r}')
    if any(value is short for value in values):
        return short
    return empty if all(isinstance(value, bool) for value in values) else Unknown('logical')


def negate(value):
    if isinstance(value, bool):
        return not value
    if isinstance(value, Unknown):
        return Unknown('not')
    raise CannotEvaluate(f'not() of {show(value)}')


def create_object(*values):
    if len(values) % 2:
        raise CannotEvaluate('createObject() with an odd number of arguments')
    return {values[index]: values[index + 1] for index in range(0, len(values), 2)}


def union(*values):
    if any(isinstance(value, (Unknown, Partial)) for value in values):
        return Unknown('union')
    if all(isinstance(value, dict) for value in values):
        merged = {}
        for value in values:
            for key, inner in value.items():
                if isinstance(merged.get(key), dict) and isinstance(inner, dict):
                    raise CannotEvaluate('union() of nested objects')
                merged[key] = inner
        return merged
    if all(isinstance(value, list) for value in values):
        merged = []
        for item in (item for value in values for item in value):
            if not concrete(item):
                raise CannotEvaluate('union() of arrays with unknown items')
            if item not in merged:
                merged.append(item)
        return merged
    raise CannotEvaluate('union() of different types')


FORMAT_ITEM = re.compile(r'\{\{|\}\}|\{(\d+)\}|\{[^}]*\}?|\}')


def format_(pattern, *values):
    if not isinstance(pattern, str):
        raise CannotEvaluate(f'format() with the pattern {show(pattern)}')
    parts, last = [], 0
    for match in FORMAT_ITEM.finditer(pattern):
        parts.append(pattern[last:match.start()])
        last, item = match.end(), match.group(0)
        if item in ('{{', '}}'):
            parts.append(item[0])
            continue
        if match.group(1) is None or int(match.group(1)) >= len(values):
            raise CannotEvaluate(f'format item {item} in {pattern!r}')
        value = values[int(match.group(1))]
        if isinstance(value, bool):
            value = 'True' if value else 'False'  # .NET formatting, as ARM does
        elif is_int(value):
            value = str(value)
        elif not isinstance(value, (str, Partial, Unknown)):
            raise CannotEvaluate(f'format() of {show(value)}')
        parts.append(value)
    parts.append(pattern[last:])
    return text(parts)


def empty(value):
    if isinstance(value, (str, list, dict)) or value is None:
        return not value
    if isinstance(value, (Unknown, Partial)):
        return Unknown('empty')
    raise CannotEvaluate(f'empty() of {show(value)}')


def length(value):
    if isinstance(value, (str, list, dict)):
        return len(value)
    if isinstance(value, (Unknown, Partial)):
        return Unknown('length')
    raise CannotEvaluate(f'length() of {show(value)}')


def take_(value, count):
    if not is_int(count):
        raise CannotEvaluate(f'take() of {show(count)} items')
    if isinstance(value, (str, list)):
        return value[:max(count, 0)]
    if isinstance(value, (Unknown, Partial)):
        return Unknown('take')
    raise CannotEvaluate(f'take() of {show(value)}')


def replace(value, old, new):
    if not (isinstance(old, str) and isinstance(new, str)):
        raise CannotEvaluate('replace() with unknown arguments')
    if isinstance(value, str):
        return value.replace(old, new)
    if isinstance(value, (Unknown, Partial)):
        return Unknown('replace')
    raise CannotEvaluate(f'replace() of {show(value)}')


def resource_id(prefix, values):
    """resourceId(type, names...) in the deployment's own subscription or resource group: the prefix stays unknown."""
    if not values or not isinstance(values[0], str) or '/' not in values[0]:
        raise CannotEvaluate(f'resourceId() with a subscription or resource group: {values!r}')
    namespace, *kinds = values[0].split('/')
    names = values[1:]
    if len(kinds) != len(names):
        raise CannotEvaluate(f'resourceId() of {values[0]} with {len(names)} names')
    parts = [prefix, '/providers/', namespace]
    for kind, name in zip(kinds, names):
        parts += ['/', kind, '/', name]
    return text(parts)


FUNCTIONS = {
    'equals': same,
    'not': negate,
    'and': lambda *values: logical(values, False, True),
    'or': lambda *values: logical(values, True, False),
    'true': lambda: True,
    'false': lambda: False,
    'null': lambda: None,
    'createobject': create_object,
    'createarray': lambda *values: list(values),
    'union': union,
    'format': format_,
    'empty': empty,
    'length': length,
    'take': take_,
    'replace': replace,
    'resourceid': lambda *values: resource_id(Unknown('resourceGroup'), values),
    'subscriptionresourceid': lambda *values: resource_id(Unknown('subscription'), values),
}


def deep(value, scope):
    """Evaluates raw template JSON: expression strings anywhere inside it, object keys included."""
    if isinstance(value, str):
        if value.startswith('[['):
            return value[1:]
        return evaluate(parse(value[1:-1]), scope) if is_expression(value) else value
    if isinstance(value, list):
        return [deep(item, scope) for item in value]
    if isinstance(value, dict):
        if isinstance(value.get('copy'), list):
            raise CannotEvaluate('property copy loops')
        return {deep(key, scope): deep(inner, scope) for key, inner in value.items()}
    return value


class Outputs:
    """reference() of a nested deployment: its outputs, evaluated in the nested template on access."""

    def __init__(self, scope):
        self.scope = scope

    def get(self, name):
        definition = lookup(self.scope.template.get('outputs') or {}, name)
        if not isinstance(definition, dict) or 'copy' in definition:
            raise CannotEvaluate(f'output {name}')
        return {'type': definition.get('type'), 'value': deep(definition.get('value'), self.scope)}


class Scope:
    """One template with its parameter values; copies holds the active copy loop indexes."""

    def __init__(self, template):
        variables = template.get('variables') or {}
        if 'copy' in variables:
            raise CannotEvaluate('variable copy loops')
        self.template, self.bindings, self.cache, self.copies, self.children = template, {}, {}, {}, {}
        # Nested deployments that reference() can resolve to their outputs: literal names, no loops.
        self.deployments = {raw['name']: raw for raw in resource_list(template) if is_deployment(raw)
                            and 'copy' not in raw and isinstance(raw.get('name'), str) and not is_expression(raw['name'])}

    def with_copy(self, loop, index):
        clone = copy.copy(self)
        clone.copies = {**self.copies, loop: index, '': index}
        return clone

    def parameter(self, name):
        key = ('parameter', name.lower())
        if key not in self.cache:
            binding = lookup(self.bindings, name, None)
            if binding is None:
                raise CannotEvaluate(f'unknown parameter {name!r}')
            self.cache[key] = binding()
        return self.cache[key]

    def variable(self, name):
        key = ('variable', name.lower())
        if key not in self.cache:
            raw = lookup(self.template.get('variables') or {}, name)
            if raw is MISSING:
                raise CannotEvaluate(f'unknown variable {name!r}')
            self.cache[key] = deep(raw, self)
        return self.cache[key]

    def copy_index(self, values):
        loop, offset = '', 0
        for value in values:
            if isinstance(value, str):
                loop = value
            elif is_int(value):
                offset = value
            else:
                raise CannotEvaluate(f'copyIndex({show(value)})')
        if loop not in self.copies:
            raise CannotEvaluate(f'copyIndex({loop!r}) outside its loop')
        return self.copies[loop] + offset

    def reference(self, values):
        match = DEPLOYMENT_ID.search(known_end(values[0])) if values else None
        if match and len(values) < 3 and match.group(1) in self.deployments:
            name = match.group(1)
            if name not in self.children:
                self.children[name] = self.nested(self.deployments[name])
            return {'outputs': Outputs(self.children[name])}
        target = values[0] if values else ''
        return Unknown('reference', target if isinstance(target, str) else repr(target) if isinstance(target, Partial) else '')

    def nested(self, raw):
        """The scope of a nested deployment; its parameters are evaluated here, on first use."""
        properties = raw.get('properties')
        template = properties.get('template') if isinstance(properties, dict) else None
        if not isinstance(template, dict):
            raise CannotEvaluate(f'deployment {raw.get("name")!r} without an inline template')
        options = properties.get('expressionEvaluationOptions') or {}
        if str(options.get('scope', 'outer')).lower() != 'inner':
            raise CannotEvaluate(f'deployment {raw.get("name")!r} with the outer expression scope')
        supplied = properties.get('parameters') or {}
        if not isinstance(supplied, dict):
            raise CannotEvaluate(f'parameters of deployment {raw.get("name")!r}')
        child = Scope(template)
        for name, definition in (template.get('parameters') or {}).items():
            entry = lookup(supplied, name)
            if entry is not MISSING:
                child.bindings[name] = lambda entry=entry, name=name: unwrap(deep(entry, self), name)
            elif 'defaultValue' in definition:
                child.bindings[name] = lambda raw=definition['defaultValue']: deep(raw, child)
            else:
                child.bindings[name] = lambda name=name: missing_parameter(name)
        return child


def unwrap(entry, name):
    if isinstance(entry, dict) and 'value' in entry:
        return entry['value']
    raise CannotEvaluate(f'parameter {name} is not a plain value: {show(entry)}')


def missing_parameter(name):
    raise CannotEvaluate(f'parameter {name} has no value')


def root_scope(template, environment, overrides=None):
    """The deployment of one environment; overrides gives other parameters values, as «--parameters» would."""
    scope = Scope(template)
    parameters = template.get('parameters') or {}
    definition = lookup(parameters, 'environmentName')
    if not isinstance(definition, dict):
        raise CannotEvaluate('the template has no environmentName parameter')
    if environment not in definition.get('allowedValues', [environment]):
        raise CannotEvaluate(f'environmentName does not allow {environment!r}')
    for name, definition in parameters.items():
        if name.lower() == 'environmentname':
            scope.bindings[name] = lambda: environment
        elif name in (overrides or {}):
            scope.bindings[name] = lambda value=overrides[name]: value
        elif 'defaultValue' in definition:
            scope.bindings[name] = lambda raw=definition['defaultValue']: deep(raw, scope)
        else:
            scope.bindings[name] = lambda name=name: Unknown(f'parameter {name}')
    return scope


# --- Resources ---------------------------------------------------------------------------------------------------

def resource_list(template):
    resources = template.get('resources') or []
    return list(resources.values()) if isinstance(resources, dict) else resources  # languageVersion 2.0: by name


def is_deployment(raw):
    return isinstance(raw, dict) and str(raw.get('type', '')).lower() == 'microsoft.resources/deployments'


class Resource:
    """A deployed resource instance: copy loops expanded, condition true, values evaluated on access."""

    def __init__(self, raw, scope, kind, name):
        self.raw, self.scope, self.type, self.name = raw, scope, kind, name

    def get(self, *path):
        value, evaluated = self.raw, False
        for key in path:
            if not evaluated and is_expression(value):
                value, evaluated = deep(value, self.scope), True
            if isinstance(value, Unknown):
                return Unknown(value.origin)
            if not isinstance(value, dict):
                return MISSING
            value = lookup(value, key)
            if value is MISSING:
                return MISSING
        return value if evaluated else deep(value, self.scope)

    def segments(self, count):
        """The last count segments of the name, or None when they are known only at deployment time."""
        if isinstance(self.name, str):
            parts = self.name.split('/')
        else:
            end = known_end(self.name)
            if end.count('/') < count:
                return None
            parts = end.split('/')
        return tuple(parts[-count:]) if len(parts) >= count else None

    def describe(self):
        tail = self.segments(2) or self.segments(1) or ('?',)
        return f'{self.type.split("/", 1)[-1]} {"/".join(tail)}'


def walk(template, scope, parent=None):
    for raw in resource_list(template):
        if not isinstance(raw, dict) or raw.get('existing'):
            continue  # languageVersion 2.0 «existing» resources are references, not deployments
        yield from expand(raw, scope, parent)


def expand(raw, scope, parent):
    loop, scopes = raw.get('copy'), [scope]
    if loop is not None:
        count = deep(loop.get('count'), scope)
        if not is_int(count):
            raise CannotEvaluate(f'copy count {loop.get("count")!r} of {raw.get("type")}')
        scopes = [scope.with_copy(loop.get('name', ''), index) for index in range(count)]
    for current in scopes:
        condition = deep(raw.get('condition', True), current)
        if not isinstance(condition, bool):
            raise CannotEvaluate(f'condition {raw.get("condition")!r} of {raw.get("type")}')
        if not condition:
            continue
        kind, name = raw.get('type'), deep(raw.get('name', ''), current)
        if not isinstance(kind, str) or is_expression(kind):
            raise CannotEvaluate(f'resource type {kind!r}')
        if parent is not None:  # a child resource nested in its parent (hand-written ARM)
            if '/' in kind:
                raise CannotEvaluate(f'nested child resource with the full type {kind}')
            kind, name = f'{parent.type}/{kind}', text([parent.name, '/', name])
        resource = Resource(raw, current, kind, name)
        yield resource
        yield from walk({'resources': raw.get('resources') or []}, current, resource)
        if is_deployment(raw):
            child = current.nested(raw)
            yield from walk(child.template, child)


def raw_resources(template, parent=''):
    """(full type, raw resource) of every resource in the template, whatever its condition."""
    for raw in resource_list(template):
        if not isinstance(raw, dict):
            continue
        kind = str(raw.get('type', ''))
        full = f'{parent}/{kind}' if parent and '/' not in kind else kind
        yield full, raw
        yield from raw_resources({'resources': raw.get('resources') or []}, full)
        properties = raw.get('properties')
        if is_deployment(raw) and isinstance(properties, dict) and isinstance(properties.get('template'), dict):
            yield from raw_resources(properties['template'])


class Context:
    def __init__(self, template, environment, overrides=None):
        self.template, self.environment, self.overrides = template, environment, overrides or {}
        self.scope = root_scope(template, environment, overrides)
        self.resources = list(walk(template, self.scope))

    def of(self, kind):
        return [resource for resource in self.resources if resource.type.lower() == kind.lower()]
