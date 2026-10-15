"""Contract checks: JSON files, catalog, agent and M365 schemas, examples, negative variants, OpenAPI, responses."""
import copy
import json
import re

from contract_catalog import (ACCEPT_LANGUAGE_MAX, ADMIN_ROLES, AUDIT_DETAILS, AUDIT_READS, CROSS_ORG_OPERATIONS,
                              DOWNLOAD_OPERATIONS, GRAPH_MODULES, LANGUAGES, LOCALIZED_OPERATIONS, PROBLEM_CODES,
                              PROBLEM_HTTP, REASON_CODES, RETENTION_PURGE_ORDER, ROLES)
from schema_check import SchemaError, is_valid, read_json, resolve_ref, unsupported_keywords, validate

METHODS = ['get', 'post', 'patch', 'put', 'delete']
MUTATIONS = ['post', 'patch', 'put', 'delete']
SUCCESS = {'200', '201', '202', '204'}
SAFE_TEXT_SAMPLE = 'Ærlig Vern æøå®'
AGENT_PREFIX = '/api/v1/agent/'
AGENT_HOST = 'https://agent.example.invalid'
BOOTSTRAP = {'createAgentChallenge': [{}], 'enrollAgent': [{'EnrollmentKey': []}], 'createAgentSession': [{}]}
STANDALONE = ['observation', 'batch', 'graph_observation', 'graph_collection']


def walk(value):
    yield value
    children = value.values() if isinstance(value, dict) else value if isinstance(value, list) else []
    for child in children:
        yield from walk(child)


def load(root):
    spec = root / 'specs'
    ctx = {'root': root, 'catalog': read_json(spec / 'check-catalog.json')['checks'],
           'observation_file': spec / 'observation.schema.json', 'batch_file': spec / 'scan-batch.schema.json',
           'graph_observation_file': spec / 'graph-observation.schema.json',
           'graph_collection_file': spec / 'graph-collection.schema.json',
           'api': read_json(spec / 'openapi.json'), 'invariants': read_json(spec / 'invariants.json')['invariants'],
           'examples': {p.name: read_json(p) for p in sorted((root / 'examples').glob('*.json'))}}
    for name in STANDALONE:
        ctx[name] = read_json(ctx[name + '_file'])
    ctx['schemas'] = ctx['api']['components']['schemas']
    ctx['agent_ids'] = [c['checkId'] for c in ctx['catalog'] if c['source'] == 'agent']
    ctx['graph_ids'] = [c['checkId'] for c in ctx['catalog'] if c['source'] == 'graph']
    ctx['volume_ids'] = [c['checkId'] for c in ctx['catalog']
                         if c['source'] == 'agent' and c['subjectType'] == 'volume']
    ctx['operations'] = [(path, method, op) for path, item in ctx['api']['paths'].items()
                         for method, op in item.items() if method in METHODS]
    ctx['operation_ids'] = [op['operationId'] for _, _, op in ctx['operations']]
    ctx['max_batch_bytes'] = ctx['schemas']['Configuration']['properties']['maxBatchBytes']['maximum']
    evidence = {b['if']['properties']['checkId']['const']: b['then']['properties']['evidence']
                for b in ctx['observation'].get('allOf', []) if 'evidence' in b['then']['properties']}
    ctx['products_max'] = evidence['WIN-003']['properties']['products']['maxItems']
    return ctx


def check_json_files(report, root):
    for file in sorted(root.rglob('*.json')):
        if file.name == 'manifest.json':
            continue
        try:
            data = read_json(file)
            for item in walk(data):
                if isinstance(item, dict) and isinstance(item.get('$ref'), str):
                    resolve_ref(item['$ref'], file, root)
        except (ValueError, KeyError, OSError, SchemaError) as error:
            report.fail('contract', f'{file.relative_to(root)}: {error}')


def check_catalog(report, ctx):
    ids = [c['checkId'] for c in ctx['catalog']]
    report.check(len(ids) == len(set(ids)), 'contract', 'Duplicate check IDs in catalog')
    for item in ctx['catalog']:
        cid = item['checkId']
        report.check(item.get('defaultAssessmentMode') in ('assessed', 'informational'), 'contract',
                     f'{cid}: defaultAssessmentMode out of range')
        report.check(item.get('source') in ('agent', 'server', 'graph'), 'contract', f'{cid}: source out of range')
        expected = 'P1' if item.get('source') == 'graph' else 'P2'
        report.check(item.get('phase') == expected, 'contract', f'{cid}: phase must be {expected}')
    active = ctx['schemas']['Configuration']['properties']['activeCheckIds']
    report.check(active['maxItems'] == len(ctx['agent_ids']) and active['items']['enum'] == ctx['agent_ids'],
                 'contract', 'Configuration.activeCheckIds differs from the WIN-* checks')
    policy = ctx['schemas']['PolicyConfiguration']['properties']
    report.check(policy['activeCheckIds']['items']['enum'] == ctx['graph_ids'] + ctx['agent_ids'], 'contract',
                 'PolicyConfiguration.activeCheckIds must list the collected checks (M365 and WIN)')
    report.check(list(policy['checks']['properties']) == ids, 'contract',
                 'PolicyConfiguration.checks must have one entry per catalog check')
    report.summary.update(checkIds=len(ids), agentCheckIds=len(ctx['agent_ids']), graphCheckIds=len(ctx['graph_ids']))


def _required_leaves_without_default(schema, path):
    """Required non-object properties of a closed object tree that carry no default."""
    missing = []
    for name in schema.get('required', []):
        child = schema['properties'][name]
        if child.get('type') == 'object':
            missing += _required_leaves_without_default(child, f'{path}.{name}')
        elif 'default' not in child:
            missing.append(f'{path}.{name}')
    return missing


def _branch_count(branches, cid, field):
    return sum(1 for b in branches if b.get('if', {}).get('properties', {}).get('checkId', {}).get('const') == cid
               and field in b.get('then', {}).get('properties', {}))


def check_schemas(report, ctx):
    api = ctx['api']
    for path in _required_leaves_without_default(ctx['schemas']['PolicyConfiguration'], 'PolicyConfiguration'):
        report.fail('contract', f'{path}: required field without default')
    for name in STANDALONE:
        report.check('$id' in ctx[name], 'contract', f'Standalone schema without $id: {name}')
    for item in walk(api):
        if isinstance(item, dict) and isinstance(item.get('$ref'), str):
            report.check(item['$ref'].startswith('#/components/schemas/'), 'contract',
                         f'External reference in openapi.json: {item["$ref"]}')
    for name, schema in ctx['schemas'].items():
        report.check('$id' not in schema and '$schema' not in schema, 'contract',
                     f'components.schemas.{name} carries $id or $schema')
    trees = [(name, ctx[name]) for name in STANDALONE]
    trees += [(f'components.{name}', schema) for name, schema in ctx['schemas'].items()]
    for _, _, op in ctx['operations']:
        trees += [(f'{op["operationId"]}.{p["name"]}', p['schema']) for p in op.get('parameters', [])]
    for label, schema in trees:
        for path in unsupported_keywords(schema):
            report.fail('contract', f'Unsupported schema keyword in {label}: {path}')
    for schema, ids in ((ctx['observation'], ctx['agent_ids']), (ctx['graph_observation'], ctx['graph_ids'])):
        branches = schema.get('allOf', [])
        for cid in ids:
            report.check(_branch_count(branches, cid, 'evidence') == 1, 'contract', f'{cid}: one evidence branch')
            report.check(_branch_count(branches, cid, 'subject') == 1, 'contract', f'{cid}: one subject branch')
        report.check(len(branches) == 2 * len(ids), 'contract', f'Extra allOf branches in {schema["title"]}')


def semantic_errors(batch, ctx):
    """Server-side rules for a batch with all WIN-* active: unique key, expected pairs, freeBytes <= totalBytes."""
    keys, errors = set(), []
    for item in batch.get('observations', []):
        evidence = item.get('evidence', {})
        if item.get('checkId') == 'WIN-001' and evidence.get('freeBytes', 0) > evidence.get('totalBytes', 0):
            errors.append('WIN-001 freeBytes > totalBytes')
        subject = item.get('subject', {})
        key = (item.get('checkId'), subject.get('type'),
               subject.get('volumeId') if subject.get('type') == 'volume' else 'device')
        if key in keys:
            errors.append(f'duplicate_observation {key}')
        keys.add(key)
    for cid in ctx['agent_ids']:
        expected = 'volume' if cid in ctx['volume_ids'] else 'device'
        found = [k for k in keys if k[0] == cid]
        if len(found) != 1 or found[0][1] != expected:
            errors.append(f'expected pair for {cid}: one {expected}')
    return errors


COMPLETE_STATUSES = {'available', 'license_missing', 'skipped'}


def graph_semantic_errors(run):
    """Server-side rules for a collection run: every module exactly once, state derived from module statuses,
    tenant and users available, unique (checkId, subject.key)."""
    errors = []
    modules = [m.get('module') for m in run.get('modules', [])]
    if sorted(modules) != sorted(GRAPH_MODULES):
        errors.append('modules must list every Graph module exactly once')
    status = {m.get('module'): m.get('status') for m in run.get('modules', [])}
    if status.get('tenant') != 'available' or status.get('users') not in ('available', 'partial'):
        errors.append('a run with observations needs modules tenant and users')
    expected = 'completed' if set(status.values()) <= COMPLETE_STATUSES else 'partial'
    if run.get('state') != expected:
        errors.append(f'state must be {expected} for these module statuses')
    keys = [(o.get('checkId'), o.get('subject', {}).get('key')) for o in run.get('observations', [])]
    if len(keys) != len(set(keys)):
        errors.append('duplicate (checkId, subject.key) in a collection run')
    return errors


def accepted(batch, ctx):
    return is_valid(batch, ctx['batch'], ctx['batch_file'], ctx['root']) and not semantic_errors(batch, ctx)


def graph_accepted(run, ctx):
    return (is_valid(run, ctx['graph_collection'], ctx['graph_collection_file'], ctx['root'])
            and not graph_semantic_errors(run))


def check_examples(report, ctx):
    scans = {name: e for name, e in ctx['examples'].items() if name.startswith('scan-batch')}
    for name, example in scans.items():
        try:
            validate(example, ctx['batch'], ctx['batch_file'], ctx['root'])
        except SchemaError as error:
            report.fail('contract', f'examples/{name}: {error}')
        for error in semantic_errors(example, ctx):
            report.fail('contract', f'examples/{name}: {error}')
        report.check(sorted(o['checkId'] for o in example['observations']) == sorted(ctx['agent_ids']),
                     'contract', f'examples/{name} must contain exactly all WIN-* checks once')
        size = len(json.dumps(example, ensure_ascii=False).encode('utf-8'))
        report.check(size < ctx['max_batch_bytes'], 'contract', f'examples/{name} exceeds maxBatchBytes')
    main = scans.get('scan-batch.json', {})
    bitlocker = [o.get('evidence') for o in main.get('observations', []) if o['checkId'] == 'WIN-002']
    report.check(bitlocker == [{'volumeStatus': 'fully_encrypted', 'protectionStatus': 'off',
                                'encryptionPercentage': 100}], 'contract',
                 'examples/scan-batch.json lacks the BitLocker reference case')
    run = ctx['examples'].get('m365-collection.json')
    report.check(run is not None, 'contract', 'examples/m365-collection.json missing')
    if run:
        try:
            validate(run, ctx['graph_collection'], ctx['graph_collection_file'], ctx['root'])
        except SchemaError as error:
            report.fail('contract', f'examples/m365-collection.json: {error}')
        for error in graph_semantic_errors(run):
            report.fail('contract', f'examples/m365-collection.json: {error}')
        report.check(sorted({o['checkId'] for o in run['observations']}) == sorted(ctx['graph_ids']), 'contract',
                     'examples/m365-collection.json must cover every M365 check')
        enforcement = [o['evidence'] for o in run['observations'] if o['checkId'] == 'M365-003']
        report.check(bool(enforcement) and enforcement[0]['securityDefaults'] == 'disabled'
                     and [p['state'] for p in enforcement[0]['mfaPolicies']] == ['enabledForReportingButNotEnforced']
                     and (enforcement[0]['perUserMfa'] or {}).get('notRequired', 0) > 0,
                     'contract', 'examples/m365-collection.json lacks the report-only M365-003 reference case')
    report.summary['examples'] = len(ctx['examples'])


def _by(container, cid):
    return next(o for o in container['observations'] if o['checkId'] == cid)


def _variant(good, mutate):
    bad = copy.deepcopy(good)
    mutate(bad)
    return bad


def _negatives(good, ctx):
    volume = copy.deepcopy(_by(good, 'WIN-001')['subject'])
    product = _by(good, 'WIN-003')['evidence']['products'][0]
    mutations = [
        lambda b: b.update(organizationId='55555555-5555-4555-8555-555555555555'),
        lambda b: b.update(schemaVersion='1.0'),
        lambda b: _by(b, 'WIN-001').pop('evidence'),
        lambda b: _by(b, 'WIN-001').update(collectionStatus='unavailable', reasonCode='unsupported'),
        lambda b: _by(b, 'WIN-001').update(checkId='M365-001'),
        lambda b: _by(b, 'WIN-001')['evidence'].update(freeBytes=-1),
        lambda b: _by(b, 'WIN-001')['evidence'].update(freeBytes=_by(b, 'WIN-001')['evidence']['totalBytes'] + 1),
        lambda b: _by(b, 'WIN-002')['evidence'].update(encryptionPercentage=101),
        lambda b: _by(b, 'WIN-002')['evidence'].update(recoveryPassword='REJECTED'),
        lambda b: _by(b, 'WIN-003')['evidence']['products'][0].update(provider='<script>alert(1)</script>'),
        lambda b: _by(b, 'WIN-003')['evidence']['products'][0].update(provider='Vendor‮X'),
        lambda b: _by(b, 'WIN-005').update(collectionStatus='unavailable', reasonCode='clock_inconsistent')
        or _by(b, 'WIN-005').pop('evidence'),
        lambda b: _by(b, 'WIN-005').update(collectionStatus='unavailable', reasonCode='license_missing')
        or _by(b, 'WIN-005').pop('evidence'),
        lambda b: _by(b, 'WIN-002').update(subject={'type': 'device'}),
        lambda b: _by(b, 'WIN-003').update(subject=volume),
        lambda b: _by(b, 'WIN-001')['subject'].pop('volumeId'),
        lambda b: _by(b, 'WIN-001')['subject'].update(volumeId='C:'),
        lambda b: _by(b, 'WIN-003')['evidence']['products'][0].update(productState='unknown')
        or _by(b, 'WIN-003')['evidence']['products'][0].pop('rawState'),
        lambda b: _by(b, 'WIN-003')['evidence'].update(products=[
            {**product, 'provider': f'Vendor {n}'} for n in range(ctx['products_max'] + 1)]),
        lambda b: _by(b, 'WIN-003')['evidence']['defender'].update(amRunningMode='disabled'),
        lambda b: _by(b, 'WIN-006')['evidence'].update(pendingSecurityUpdates=[]),
        lambda b: _by(b, 'WIN-006')['evidence'].update(lastSearchSuccessAt='2026-10-12 06:15'),
        lambda b: _by(b, 'WIN-007')['evidence'].update(statusSource='windows_update_api'),
        lambda b: _by(b, 'WIN-009').update(collectionStatus='not_applicable', reasonCode='policy_excluded')
        or _by(b, 'WIN-009').pop('evidence'),
        lambda b: b['observations'].append(copy.deepcopy(_by(b, 'WIN-005'))),
        lambda b: _by(b, 'WIN-010')['evidence'].update(joinType='registered'),
        lambda b: _by(b, 'WIN-011')['evidence'].update(displayVersion='25h2'),
        lambda b: _by(b, 'WIN-008')['evidence']['members'][0].update(kind='administrator'),
        lambda b: _by(b, 'WIN-002')['evidence'].update(volumeStatus='paused'),
        lambda b: b.update(sentAt='2026-10-14T10:01:31Z'),
        lambda b: b.update(scanId=b['scanId'].replace('-', '')),
        lambda b: b.update(startedAt=b['startedAt'][:16] + 'Z'),
    ]
    return [_variant(good, mutate) for mutate in mutations]


def _graph_negatives(run):
    def first(cid):
        return lambda r: _by(r, cid)
    mutations = [
        lambda r: first('M365-001')(r)['evidence'].update(phoneNumber='+4799999999'),
        lambda r: first('M365-001')(r)['evidence'].update(methodKinds=['sms_otp']),
        lambda r: first('M365-001')(r)['subject'].pop('key'),
        lambda r: first('M365-001')(r)['subject'].update(userPrincipalName='<img src=x>@example.invalid'),
        lambda r: first('M365-001')(r).update(collectionStatus='unavailable', reasonCode='collector_timeout')
        or first('M365-001')(r).pop('evidence'),
        lambda r: first('M365-003')(r).update(subject={'type': 'user', 'key': r['tenantId'],
                                                       'userPrincipalName': 'x@example.invalid'}),
        lambda r: first('M365-003')(r)['evidence']['mfaPolicies'][0].update(displayName='Require MFA'),
        lambda r: first('M365-006')(r)['evidence'].update(permissionGrantPolicies=['microsoft-user-default-legacy']),
        lambda r: first('M365-002')(r)['evidence'].update(roleTemplateIds=['Global Administrator']),
        lambda r: first('M365-003')(r)['evidence']['mfaPolicies'][0].update(conditions=['ip_ranges']),
        lambda r: first('M365-003')(r)['evidence'].update(securityDefaultsEnabled=False),
        lambda r: first('M365-006')(r).update(collectionStatus='unavailable', reasonCode='unsupported')
        or first('M365-006')(r).pop('evidence'),
        lambda r: r['modules'].pop(),
        lambda r: r['modules'].__setitem__(0, {**r['modules'][1]}),
        lambda r: r['modules'][4].update(status='partial'),
        lambda r: r['modules'][0].update(status='temporary_error') or r.update(state='partial'),
        lambda r: r['observations'].append(copy.deepcopy(first('M365-003')(r))),
    ]
    return [_variant(run, mutate) for mutate in mutations]


def _defaults(schema):
    """Object assembled from the default values of a closed PolicyConfiguration tree."""
    if 'default' in schema:
        return copy.deepcopy(schema['default'])
    return {name: _defaults(schema['properties'][name]) for name in schema.get('required', [])}


def _policy_negatives(ctx):
    """createPolicyRevision bodies that must give 422 schema_violation; the default body must pass."""
    body_schema = {'$ref': '#/components/schemas/PolicyRevisionCreate'}
    api_file = ctx['root'] / 'specs' / 'openapi.json'
    good = {'configuration': _defaults(ctx['schemas']['PolicyConfiguration'])}

    def changed(mutate):
        bad = copy.deepcopy(good)
        mutate(bad['configuration'])
        return bad

    def ok(body):
        return is_valid(body, body_schema, api_file, ctx['root'])
    bad = [changed(lambda c: c['checks']['WIN-006']['parameters'].update(maxSearchAgeDays=61)),
           changed(lambda c: c['checks']['M365-001'].update(freshnessWindowHours=0)),
           changed(lambda c: c['checks']['SYS-001'].update(assessmentMode='assessed')),
           changed(lambda c: c['checks']['M365-001'].update(notApplicableEditionIds=[])),
           changed(lambda c: c['m365'].update(excludedUserIds=['break-glass'])),
           changed(lambda c: c.update(activeCheckIds=c['activeCheckIds'] + ['SYS-001']))]
    return ok(good), [ok(body) for body in bad]


def check_negatives(report, ctx):
    good = ctx['examples'].get('scan-batch.json')
    run = ctx['examples'].get('m365-collection.json')
    if not good or not run:
        report.fail('contract', 'examples/scan-batch.json or examples/m365-collection.json missing')
        return
    negatives = _negatives(good, ctx)
    for index, bad in enumerate(negatives, 1):
        report.check(not accepted(bad, ctx), 'contract', f'Negative scan variant {index} accepted')
    graph = _graph_negatives(run)
    for index, bad in enumerate(graph, 1):
        report.check(not graph_accepted(bad, ctx), 'contract', f'Negative M365 variant {index} accepted')
    default_ok, policy_results = _policy_negatives(ctx)
    report.check(default_ok, 'contract', 'createPolicyRevision with the default configuration rejected')
    for index, result in enumerate(policy_results, 1):
        report.check(not result, 'contract', f'Negative policy variant {index} accepted')
    positive = copy.deepcopy(good)
    _by(positive, 'WIN-003')['evidence']['products'][0]['provider'] = SAFE_TEXT_SAMPLE
    report.check(accepted(positive, ctx), 'contract', 'Positive SAFE_TEXT variant rejected')
    never = copy.deepcopy(good)
    _by(never, 'WIN-006')['evidence'].update(lastSearchSuccessAt=None, lastInstallSuccessAt=None)
    report.check(accepted(never, ctx), 'contract', 'Positive WIN-006 without successful search rejected')
    norwegian = copy.deepcopy(run)
    _by(norwegian, 'M365-001')['subject']['userPrincipalName'] = 'åse.østby@example.invalid'
    report.check(graph_accepted(norwegian, ctx), 'contract', 'Positive Norwegian UPN rejected')
    report.summary.update(negativeVariants=len(negatives) + len(graph) + len(policy_results), positiveVariants=3)


def _check_security(report, path, method, op, schemes):
    name = op['operationId']
    report.check(bool(op.get('security')), 'contract', f'{name}: security not explicit')
    for alternative in op.get('security', []):
        report.check(set(alternative) <= schemes.keys(), 'contract', f'{name}: unknown security scheme')
        if 'PortalSession' in alternative and method in MUTATIONS:
            report.check('CsrfToken' in alternative, 'contract', f'{name}: mutation without CsrfToken')
        if 'EnrollmentKey' in alternative:
            report.check(name == 'enrollAgent', 'contract', f'{name}: EnrollmentKey outside enrollAgent')
    if path.startswith(AGENT_PREFIX):
        expected = BOOTSTRAP.get(name, [{'AgentSession': []}])
        report.check(op['security'] == expected, 'contract', f'{name}: agent security')
        report.check([s['url'] for s in op.get('servers', [])] == [AGENT_HOST], 'contract', f'{name}: agent host')
        report.check(op.get('x-phase') == 'P2' and 'x-allowed-roles' not in op, 'contract',
                     f'{name}: agent operation must be P2 without roles')
    else:
        roles = op.get('x-allowed-roles', [])
        report.check(bool(roles) and set(roles) <= set(ROLES), 'contract', f'{name}: x-allowed-roles')
        report.check(op['security'][0].get('PortalSession') == [], 'contract', f'{name}: portal session')
        report.check(('{organizationId}' not in path) == (name in CROSS_ORG_OPERATIONS), 'contract',
                     f'{name}: portal operation outside an organization must be in CROSS_ORG_OPERATIONS')
        report.check(bool(op.get('x-audit-read')) == (name in AUDIT_READS), 'contract', f'{name}: x-audit-read')


def check_openapi(report, ctx):
    api, schemes = ctx['api'], ctx['api']['components']['securitySchemes']
    report.check(api['openapi'] == '3.1.0', 'contract', 'OpenAPI version must be 3.1.0')
    ids = ctx['operation_ids']
    report.check(len(ids) == len(set(ids)), 'contract', 'Duplicate operationId')
    for path, method, op in ctx['operations']:
        name = op['operationId']
        params = op.get('parameters', [])
        variables = set(re.findall(r'\{([^}]+)\}', path))
        declared = {p['name'] for p in params if p['in'] == 'path' and p.get('required')}
        report.check(variables == declared, 'contract', f'{name}: path parameters differ from path')
        report.check(op.get('x-phase') in ('P1', 'P2'), 'contract', f'{name}: x-phase must be P1 or P2')
        _check_security(report, path, method, op, schemes)
        language = [p for p in params if p['in'] == 'header' and p['name'] == 'Accept-Language']
        if name in LOCALIZED_OPERATIONS:
            report.check(len(language) == 1, 'contract', f'{name}: Accept-Language header parameter missing')
            schema = language[0]['schema'] if language else {}
            report.check(schema.get('type') == 'string' and 'enum' not in schema
                         and schema.get('maxLength') == ACCEPT_LANGUAGE_MAX, 'contract',
                         f'{name}: Accept-Language must be a string without enum, maxLength {ACCEPT_LANGUAGE_MAX}')
            success = next(iter(op['responses'].values()))
            content = success.get('headers', {}).get('Content-Language', {}).get('schema', {})
            report.check(content.get('enum') == LANGUAGES, 'contract', f'{name}: Content-Language enum')
        else:
            report.check(not language, 'contract', f'{name}: unexpected Accept-Language parameter')
    by_id = {op['operationId']: op for _, _, op in ctx['operations']}
    schemas = ctx['schemas']
    for name in ('decideFindingRisk', 'createPolicyRevision', 'changeOrganizationLifecycle', 'startTenantConsent',
                 'verifyTenantConnection', 'createEnrollmentKey', 'revokeDevice'):
        report.check(by_id[name].get('x-allowed-roles') == ADMIN_ROLES, 'contract', f'{name}: roles must be Admin')
    report.check(schemas['FindingPatch']['properties']['workflowState']['enum'] == ['new', 'in_progress'],
                 'contract', 'FindingPatch.workflowState must be {new, in_progress}')
    for name in ('listFindings', 'listFindingsAcrossOrganizations'):
        queue = next((p for p in by_id[name].get('parameters', []) if p['name'] == 'workflowState'), {})
        report.check(queue.get('style') == 'form' and queue.get('explode') is False
                     and queue.get('schema', {}).get('items', {}).get('enum') == schemas['Finding']['properties']
                     ['workflowState']['enum'], 'contract', f'{name}.workflowState must be a form-style enum array')
    for name in ('Organization', 'OrganizationCreate', 'OrganizationUpdate'):
        report.check(schemas[name]['properties']['reportLanguage']['enum'] == LANGUAGES, 'contract',
                     f'{name}.reportLanguage enum')
    report.check(schemas['ReportCreate']['properties']['format']['enum'] == ['html'], 'contract',
                 'ReportCreate.format must be [html]')
    download = by_id['downloadReport']['responses']['200']
    report.check(list(download.get('content', {})) == ['text/html'], 'contract', 'downloadReport: only text/html')
    report.check({'Content-Disposition', 'Content-Security-Policy', 'X-Content-Type-Options'}
                 <= set(download.get('headers', {})), 'contract', 'downloadReport: delivery headers missing')
    report.check('16384' in by_id['enrollAgent'].get('description', ''), 'contract',
                 'enrollAgent: body limit missing from description')
    report.check('1024' in by_id['createAgentChallenge'].get('description', ''), 'contract',
                 'createAgentChallenge: body limit missing from description')
    _check_audit_details(report, ctx)
    agent_ops = sum(1 for path, _, _ in ctx['operations'] if path.startswith(AGENT_PREFIX))
    phases = [op['x-phase'] for _, _, op in ctx['operations']]
    report.summary.update(operations=len(ids), agentOperations=agent_ops, portalOperations=len(ids) - agent_ops,
                          operationsP1=phases.count('P1'), operationsP2=phases.count('P2'))


def _audit_samples():
    base = {'id': '66666666-6666-4666-8666-666666666666', 'occurredAt': '2026-10-15T10:00:00Z',
            'actorType': 'staff', 'actorId': '77777777-7777-4777-8777-777777777777',
            'action': 'organization.lifecycle_change', 'targetType': 'organization',
            'targetId': '88888888-8888-4888-8888-888888888888', 'outcome': 'success', 'correlationId': 'c-1'}
    lifecycle = {'lifecycleAction': 'disable', 'reason': '<img src=x onerror=alert(1)>', 'exportWaived': False}
    deleted = {name: 0 for name in RETENTION_PURGE_ORDER if name != 'device'}
    good = {**base, 'details': lifecycle}
    bad = [{**base, 'action': 'report.download', 'details': {'reason': 'x'}},
           {**base, 'details': None},
           {**base, 'details': {**lifecycle, 'lifecycleAction': 'enable', 'exportWaived': True}},
           {**base, 'action': 'retention.purge_summary', 'details': {'deleted': deleted, 'snapshotted': 0}},
           {**base, 'action': 'finding.assignment_change', 'details': {}},
           {**base, 'actorType': 'platform_admin'}]
    return good, bad


def _check_audit_details(report, ctx):
    schemas = ctx['schemas']
    audit = schemas['AuditEvent']
    report.check('details' in audit.get('required', []), 'contract', 'AuditEvent.details must be required')
    branch, actions = (audit.get('allOf') or [{}])[0], {}
    while 'if' in branch:
        action = branch['if']['properties']['action']['const']
        actions[action] = branch['then']['properties']['details'].get('$ref', '').rsplit('/', 1)[-1]
        branch = branch.get('else', {})
    report.check(actions == AUDIT_DETAILS and branch == {'properties': {'details': {'type': 'null'}}}, 'contract',
                 'AuditEvent.allOf: details branches differ from AUDIT_DETAILS or the null fallback')
    lifecycle = schemas['OrganizationLifecycleAuditDetails']['properties']
    change = schemas['OrganizationLifecycleChange']['properties']
    report.check(lifecycle['lifecycleAction']['enum'] == change['action']['enum']
                 and lifecycle['reason']['maxLength'] == change['reason']['maxLength'], 'contract',
                 'OrganizationLifecycleAuditDetails differs from OrganizationLifecycleChange')
    patch = [name for name in schemas['FindingPatch']['properties'] if name != 'workflowState']
    report.check(list(schemas['FindingAssignmentAuditDetails']['properties']) == patch, 'contract',
                 'FindingAssignmentAuditDetails keys differ from FindingPatch without workflowState')
    deleted = schemas['RetentionPurgeAuditDetails']['properties']['deleted']['properties']
    report.check(list(deleted) == RETENTION_PURGE_ORDER, 'contract',
                 'RetentionPurgeAuditDetails.deleted differs from RETENTION_PURGE_ORDER')
    finding = schemas['Finding']['properties']['assigneeId'].get('description', '')
    report.check(finding == schemas['FindingPatch']['properties']['assigneeId'].get('description')
                 and 'StaffUser.entraUserId' in finding, 'contract',
                 'Finding.assigneeId and FindingPatch.assigneeId must share the StaffUser.entraUserId description')
    file = ctx['root'] / 'specs' / 'openapi.json'
    good, bad = _audit_samples()
    report.check(is_valid(good, audit, file, ctx['root']), 'contract', 'Valid AuditEvent with details rejected')
    for index, sample in enumerate(bad, 1):
        report.check(not is_valid(sample, audit, file, ctx['root']), 'contract',
                     f'Invalid AuditEvent variant {index} accepted')


def check_responses(report, ctx):
    problem = ctx['schemas']['Problem']['properties']['code']['enum']
    report.check(sorted(problem) == sorted(code for code, _, _ in PROBLEM_CODES), 'contract',
                 'Problem.code enum differs from the code catalog')
    reasons = ctx['schemas']['Assessment']['properties']['reasonCode']['enum']
    report.check([r for r in reasons if r] == REASON_CODES, 'contract', 'Assessment.reasonCode enum differs')
    allowed = SUCCESS | {str(status) for status in PROBLEM_HTTP.values()}
    for path, method, op in ctx['operations']:
        name, codes = op['operationId'], set(op['responses'])
        if_match = any(p['name'] == 'If-Match' and p.get('required') for p in op.get('parameters', []))
        report.check(codes <= allowed, 'contract', f'{name}: status outside the allowed set')
        if method == 'get':
            report.check(not codes & {'412', '413', '415', '428'}, 'contract', f'{name}: GET with 412/413/415/428')
            report.check(('409' in codes) == (name in DOWNLOAD_OPERATIONS), 'contract', f'{name}: GET 409 rule')
        report.check(bool(codes & {'412', '428'}) <= if_match, 'contract', f'{name}: 412/428 without If-Match')
        if if_match:
            report.check({'412', '428'} <= codes, 'contract', f'{name}: If-Match without 412/428')
        report.check(bool(codes & {'413', '415'}) <= ('requestBody' in op), 'contract',
                     f'{name}: 413/415 without requestBody')
        if path.startswith(AGENT_PREFIX):
            authenticated = name != 'createAgentChallenge'
            report.check({'429', '503'} <= codes and ('401' in codes) == authenticated
                         and ('403' in codes) == authenticated, 'contract', f'{name}: agent 401/403/429/503 rule')
        for status in ('429', '503'):
            if status in codes:
                report.check('Retry-After' in op['responses'][status].get('headers', {}), 'contract',
                             f'{name}: {status} without Retry-After')
    report.summary.update(problemCodes=len(problem), reasonCodes=len(REASON_CODES))
