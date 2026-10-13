"""Contract checks: JSON files, catalog, agent schemas, examples, negative variants, OpenAPI, responses."""
import copy
import json
import re

from contract_catalog import (ACCEPT_LANGUAGE_MAX, AUDIT_ALWAYS, AUDIT_DETAILS, DOWNLOAD_OPERATIONS, LANGUAGES,
                              LOCALIZED_OPERATIONS, MANAGE_ROLES, PLATFORM_AUDIT_READS, PROBLEM_CODES,
                              PROBLEM_HTTP, REASON_CODES, RETENTION_PURGE_ORDER)
from schema_check import SchemaError, is_valid, read_json, resolve_ref, unsupported_keywords, validate

METHODS = ['get', 'post', 'patch', 'put', 'delete']
MUTATIONS = ['post', 'patch', 'put', 'delete']
SUCCESS = {'200', '201', '202', '204'}
SAFE_TEXT_SAMPLE = 'Ærlig Vern æøå®'


def walk(value):
    yield value
    children = value.values() if isinstance(value, dict) else value if isinstance(value, list) else []
    for child in children:
        yield from walk(child)


def load(root):
    spec = root / 'specs'
    ctx = {'root': root, 'catalog': read_json(spec / 'check-catalog.json')['checks'],
           'observation_file': spec / 'observation.schema.json', 'batch_file': spec / 'scan-batch.schema.json',
           'api': read_json(spec / 'openapi.json'), 'invariants': read_json(spec / 'invariants.json')['invariants'],
           'examples': {p.name: read_json(p) for p in sorted((root / 'examples').glob('*.json'))}}
    ctx['observation'] = read_json(ctx['observation_file'])
    ctx['batch'] = read_json(ctx['batch_file'])
    ctx['schemas'] = ctx['api']['components']['schemas']
    ctx['agent_ids'] = [c['checkId'] for c in ctx['catalog'] if c['source'] == 'agent']
    ctx['volume_ids'] = [c['checkId'] for c in ctx['catalog']
                         if c['source'] == 'agent' and c['subjectType'] == 'volume']
    ctx['operations'] = [(path, method, op) for path, item in ctx['api']['paths'].items()
                         for method, op in item.items() if method in METHODS]
    ctx['operation_ids'] = [op['operationId'] for _, _, op in ctx['operations']]
    ctx['max_batch_bytes'] = ctx['schemas']['Configuration']['properties']['maxBatchBytes']['maximum']
    evidence = {b['if']['properties']['checkId']['const']: b['then']['properties']['evidence']
                for b in ctx['observation'].get('allOf', []) if 'evidence' in b['then']['properties']}
    ctx['pending_max'] = evidence['WIN-006']['properties']['pendingSecurityUpdates']['maxItems']
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
        report.check(item.get('defaultAssessmentMode') in ('assessed', 'informational'), 'contract',
                     f'{item["checkId"]}: defaultAssessmentMode out of range')
        report.check(item.get('source') in ('agent', 'server', 'graph'), 'contract',
                     f'{item["checkId"]}: source out of range')
    active = ctx['schemas']['Configuration']['properties']['activeCheckIds']
    report.check(active['maxItems'] == len(ctx['agent_ids']), 'contract',
                 'Configuration.activeCheckIds.maxItems differs from the number of WIN-* checks')
    report.check(active['items']['enum'] == ctx['agent_ids'], 'contract',
                 'Configuration.activeCheckIds.items.enum differs from WIN-* checks')
    report.summary.update(checkIds=len(ids), agentCheckIds=len(ctx['agent_ids']))


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


def check_schemas(report, ctx):
    api = ctx['api']
    for path in _required_leaves_without_default(ctx['schemas']['PolicyConfiguration'], 'PolicyConfiguration'):
        report.fail('contract', f'{path}: required field without default')
    for name in ('observation', 'batch'):
        report.check('$id' in ctx[name], 'contract', f'Standalone agent schema without $id: {name}')
    for item in walk(api):
        if isinstance(item, dict) and isinstance(item.get('$ref'), str):
            report.check(item['$ref'].startswith('#/components/schemas/'), 'contract',
                         f'External reference in openapi.json: {item["$ref"]}')
    for name, schema in ctx['schemas'].items():
        report.check('$id' not in schema and '$schema' not in schema, 'contract',
                     f'components.schemas.{name} carries $id or $schema')
    trees = [('observation', ctx['observation']), ('scan-batch', ctx['batch'])]
    trees += [(f'components.{name}', schema) for name, schema in ctx['schemas'].items()]
    for _, _, op in ctx['operations']:
        trees += [(f'{op["operationId"]}.{p["name"]}', p['schema']) for p in op.get('parameters', [])]
    for label, schema in trees:
        for path in unsupported_keywords(schema):
            report.fail('contract', f'Unsupported schema keyword in {label}: {path}')
    branches = ctx['observation'].get('allOf', [])
    for cid in ctx['agent_ids']:
        def count(field):
            return sum(1 for b in branches if b.get('if', {}).get('properties', {}).get('checkId', {}).get('const')
                       == cid and field in b.get('then', {}).get('properties', {}))
        report.check(count('evidence') == 1, 'contract', f'{cid}: expected one evidence branch')
        report.check(count('subject') == 1, 'contract', f'{cid}: expected one subject branch')
    report.check(len(branches) == 2 * len(ctx['agent_ids']), 'contract', 'Extra allOf branches in observation')


def semantic_errors(batch, ctx):
    """Server-side semantic rules for a batch with all WIN-* active: unique key, expected pairs and the
    WIN-006 list consistency."""
    keys, errors = set(), []
    for item in batch.get('observations', []):
        if item.get('checkId') == 'WIN-006' and item.get('collectionStatus') == 'collected':
            update = item.get('evidence', {})
            total = update.get('pendingSecurityUpdatesTotal', 0)
            if len(update.get('pendingSecurityUpdates', [])) != min(total, ctx['pending_max']) \
                    or update.get('truncated') != (total > ctx['pending_max']):
                errors.append('WIN-006 list inconsistent with pendingSecurityUpdatesTotal and truncated')
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


def accepted(batch, ctx):
    return (is_valid(batch, ctx['batch'], ctx['batch_file'], ctx['root'])
            and not semantic_errors(batch, ctx))


def check_examples(report, ctx):
    for name, example in ctx['examples'].items():
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
    main = ctx['examples'].get('scan-batch.json', {})
    bitlocker = [o.get('evidence') for o in main.get('observations', []) if o['checkId'] == 'WIN-002']
    report.check(bitlocker == [{'volumeStatus': 'fully_encrypted', 'protectionStatus': 'off',
                                'encryptionPercentage': 100}], 'contract',
                 'examples/scan-batch.json lacks the BitLocker reference case')
    report.summary['examples'] = len(ctx['examples'])


def _negatives(good, ctx):
    def by(batch, cid):
        return next(o for o in batch['observations'] if o['checkId'] == cid)

    def variant(mutate):
        bad = copy.deepcopy(good)
        mutate(bad)
        return bad

    volume = copy.deepcopy(by(good, 'WIN-001')['subject'])
    product = by(good, 'WIN-003')['evidence']['products'][0]
    update = by(good, 'WIN-006')['evidence']['pendingSecurityUpdates'][0]
    return [
        variant(lambda b: b.update(organizationId='55555555-5555-4555-8555-555555555555')),
        variant(lambda b: by(b, 'WIN-001').pop('evidence')),
        variant(lambda b: by(b, 'WIN-001').update(collectionStatus='unavailable', reasonCode='unsupported')),
        variant(lambda b: by(b, 'WIN-001').update(checkId='M365-001')),
        variant(lambda b: by(b, 'WIN-001')['evidence'].update(freeBytes=-1)),
        variant(lambda b: by(b, 'WIN-002')['evidence'].update(encryptionPercentage=101)),
        variant(lambda b: by(b, 'WIN-002')['evidence'].update(recoveryPassword='REJECTED')),
        variant(lambda b: by(b, 'WIN-006')['evidence']['pendingSecurityUpdates'][0].update(title='KB')),
        variant(lambda b: by(b, 'WIN-006')['evidence'].update(pendingSecurityUpdates=[
            {**update, 'revisionNumber': n} for n in range(ctx['pending_max'] + 1)])),
        variant(lambda b: by(b, 'WIN-003')['evidence']['products'][0].update(provider='<script>alert(1)</script>')),
        variant(lambda b: by(b, 'WIN-003')['evidence']['products'][0].update(provider='Vendor\u202eX')),
        variant(lambda b: by(b, 'WIN-005').update(collectionStatus='unavailable', reasonCode='clock_inconsistent')
                or by(b, 'WIN-005').pop('evidence')),
        variant(lambda b: by(b, 'WIN-002').update(subject={'type': 'device'})),
        variant(lambda b: by(b, 'WIN-003').update(subject=volume)),
        variant(lambda b: by(b, 'WIN-001')['subject'].pop('volumeId')),
        variant(lambda b: by(b, 'WIN-001')['subject'].update(volumeId='C:')),
        variant(lambda b: by(b, 'WIN-003')['evidence']['products'][0].update(productState='unknown')
                or by(b, 'WIN-003')['evidence']['products'][0].pop('rawState')),
        variant(lambda b: by(b, 'WIN-003')['evidence'].update(products=[
            {**product, 'provider': f'Vendor {n}'} for n in range(ctx['products_max'] + 1)])),
        variant(lambda b: by(b, 'WIN-003')['evidence']['defender'].update(amRunningMode='disabled')),
        variant(lambda b: by(b, 'WIN-009').update(collectionStatus='not_applicable', reasonCode='policy_excluded')
                or by(b, 'WIN-009').pop('evidence')),
        variant(lambda b: b['observations'].append(copy.deepcopy(by(b, 'WIN-005')))),
        variant(lambda b: by(b, 'WIN-010')['evidence'].update(joinType='registered')),
        variant(lambda b: b.update(scanId=b['scanId'].replace('-', ''))),
        variant(lambda b: b.update(startedAt=b['startedAt'][:16] + 'Z')),
        variant(lambda b: by(b, 'WIN-006')['evidence']['agentSearch'].update(completedAt=None)),
        variant(lambda b: by(b, 'WIN-006')['evidence'].update(pendingSecurityUpdates=[],
                                                              pendingSecurityUpdatesTotal=3, truncated=False)),
        variant(lambda b: by(b, 'WIN-006')['evidence'].update(
            pendingSecurityUpdates=[{**update, 'revisionNumber': n} for n in range(ctx['pending_max'])],
            pendingSecurityUpdatesTotal=ctx['pending_max'] + 10, truncated=False)),
    ]


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

    def search_age(hours):
        bad = copy.deepcopy(good)
        bad['configuration']['checks']['WIN-006']['parameters']['maxSearchAgeHours'] = hours
        return bad

    def ok(body):
        return is_valid(body, body_schema, api_file, ctx['root'])
    return ok(good), [ok(body) for body in (search_age(169), search_age(0))]


def check_negatives(report, ctx):
    good = ctx['examples'].get('scan-batch.json')
    if not good:
        report.fail('contract', 'examples/scan-batch.json missing')
        return
    negatives = _negatives(good, ctx)
    for index, bad in enumerate(negatives, 1):
        report.check(not accepted(bad, ctx), 'contract', f'Negative variant {index} accepted')
    default_ok, policy_results = _policy_negatives(ctx)
    report.check(default_ok, 'contract', 'createPolicyRevision with the default configuration rejected')
    for index, result in enumerate(policy_results, len(negatives) + 1):
        report.check(not result, 'contract', f'Negative variant {index} (createPolicyRevision) accepted')
    positive = copy.deepcopy(good)
    next(o for o in positive['observations'] if o['checkId'] == 'WIN-003')['evidence']['products'][0][
        'provider'] = SAFE_TEXT_SAMPLE
    report.check(accepted(positive, ctx), 'contract', 'Positive SAFE_TEXT variant rejected')
    truncated = copy.deepcopy(good)
    update = next(o for o in truncated['observations'] if o['checkId'] == 'WIN-006')['evidence']
    update.update(pendingSecurityUpdates=[{**update['pendingSecurityUpdates'][0], 'revisionNumber': n}
                                          for n in range(ctx['pending_max'])],
                  pendingSecurityUpdatesTotal=120, truncated=True)
    report.check(accepted(truncated, ctx), 'contract', 'Positive truncated WIN-006 list rejected')
    not_started = copy.deepcopy(good)
    next(o for o in not_started['observations'] if o['checkId'] == 'WIN-006')['evidence']['agentSearch'].update(
        resultCode='not_started', completedAt=None)
    report.check(accepted(not_started, ctx), 'contract', 'Positive WIN-006 search without completedAt rejected')
    report.summary.update(negativeVariants=len(negatives) + len(policy_results), positiveVariants=3)


def check_openapi(report, ctx):
    api, schemes = ctx['api'], ctx['api']['components']['securitySchemes']
    agent_host = 'https://agent.example.invalid'
    report.check(api['openapi'] == '3.1.0', 'contract', 'OpenAPI version must be 3.1.0')
    ids = ctx['operation_ids']
    report.check(len(ids) == len(set(ids)), 'contract', 'Duplicate operationId')
    for path, method, op in ctx['operations']:
        name = op['operationId']
        params = op.get('parameters', [])
        variables = set(re.findall(r'\{([^}]+)\}', path))
        declared = {p['name'] for p in params if p['in'] == 'path' and p.get('required')}
        report.check(variables == declared, 'contract', f'{name}: path parameters differ from path')
        report.check(bool(op.get('security')), 'contract', f'{name}: security not explicit')
        for alternative in op.get('security', []):
            report.check(set(alternative) <= schemes.keys(), 'contract', f'{name}: unknown security scheme')
            if 'PortalSession' in alternative and method in MUTATIONS:
                report.check('CsrfToken' in alternative, 'contract', f'{name}: mutation without CsrfToken')
            if 'EnrollmentToken' in alternative:
                report.check(path.endswith('/agent/enroll'), 'contract', f'{name}: EnrollmentToken outside /enroll')
        agent = path.startswith('/api/v1/agent/')
        if agent and not path.endswith('/enroll'):
            report.check(op['security'] == [{'DeviceCertificate': []}], 'contract', f'{name}: agent security')
            report.check([s['url'] for s in op.get('servers', [])] == [agent_host], 'contract',
                         f'{name}: agent host')
        if not agent and method == 'get':
            report.check(op.get('x-audit-read') in ('always', 'platform_admin'), 'contract',
                         f'{name}: x-audit-read missing or invalid')
            report.check((op.get('x-audit-read') == 'always') == (name in AUDIT_ALWAYS), 'contract',
                         f'{name}: x-audit-read=always mismatch')
            outside = '{organizationId}' not in path
            report.check(outside == (name in PLATFORM_AUDIT_READS), 'contract',
                         f'{name}: portal GET without organizationId must be in PLATFORM_AUDIT_READS')
            if outside:
                report.check(op.get('x-audit-read') == 'platform_admin'
                             and 'platform_audit_event' in op.get('description', ''), 'contract',
                             f'{name}: platform audit read must declare platform_admin and platform_audit_event')
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
    report.check(by_id['decideFindingRisk'].get('x-allowed-roles') == MANAGE_ROLES, 'contract',
                 'decideFindingRisk roles must equal MANAGE_ROLES')
    report.check(schemas['FindingPatch']['properties']['workflowState']['enum'] == ['new', 'in_progress'],
                 'contract', 'FindingPatch.workflowState must be {new, in_progress}')
    queue = next((p for p in by_id['listFindings'].get('parameters', []) if p['name'] == 'workflowState'), {})
    report.check(queue.get('style') == 'form' and queue.get('explode') is False
                 and queue.get('schema', {}).get('type') == 'array'
                 and queue['schema'].get('items', {}).get('enum') == schemas['Finding']['properties']
                 ['workflowState']['enum'], 'contract',
                 'listFindings.workflowState must be an enum array with style=form, explode=false')
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
    _check_audit_details(report, ctx)
    agent_ops = sum(1 for path, _, _ in ctx['operations'] if path.startswith('/api/v1/agent/'))
    report.summary.update(operations=len(ids), agentOperations=agent_ops, portalOperations=len(ids) - agent_ops)


def _audit_samples():
    base = {'id': '66666666-6666-4666-8666-666666666666', 'occurredAt': '2026-10-13T10:00:00Z',
            'actorType': 'platform_admin', 'actorId': '77777777-7777-4777-8777-777777777777',
            'action': 'organization.lifecycle_change', 'targetType': 'organization',
            'targetId': '88888888-8888-4888-8888-888888888888', 'outcome': 'success', 'correlationId': 'c-1'}
    lifecycle = {'lifecycleAction': 'disable', 'reason': '<img src=x onerror=alert(1)>', 'exportWaived': False}
    deleted = {name: 0 for name in RETENTION_PURGE_ORDER if name != 'device'}
    good = {**base, 'details': lifecycle}
    bad = [{**base, 'action': 'platform.access', 'details': {'reason': 'x'}},
           {**base, 'details': None},
           {**base, 'details': {**lifecycle, 'lifecycleAction': 'enable', 'exportWaived': True}},
           {**base, 'action': 'retention.purge_summary', 'details': {'deleted': deleted, 'snapshotted': 0}},
           {**base, 'action': 'finding.assignment_change', 'details': {}}]
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
                 and 'OrganizationMember.entraUserId' in finding, 'contract',
                 'Finding.assigneeId and FindingPatch.assigneeId must share the entraUserId description')
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
        if path.startswith('/api/v1/agent/'):
            report.check({'401', '429', '503'} <= codes, 'contract', f'{name}: agent operation lacks 401/429/503')
            report.check(('403' in codes) == (name != 'enrollAgent'), 'contract', f'{name}: agent 403 rule')
        for status in ('429', '503'):
            if status in codes:
                report.check('Retry-After' in op['responses'][status].get('headers', {}), 'contract',
                             f'{name}: {status} without Retry-After')
    report.summary.update(problemCodes=len(problem), reasonCodes=len(REASON_CODES))
