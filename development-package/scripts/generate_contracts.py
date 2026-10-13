"""Generate the proposed P1 contracts and synthetic examples; no network calls."""
from pathlib import Path
import copy
import json

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / 'specs'
EXAMPLES = ROOT / 'examples'
SPEC.mkdir(exist_ok=True)
EXAMPLES.mkdir(exist_ok=True)


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def obj(properties, required=None):
    return {'type': 'object', 'additionalProperties': False,
            'properties': properties, 'required': required or list(properties)}


def string(maximum=256, **extra):
    return {'type': 'string', 'minLength': 1, 'maxLength': maximum, **extra}


def integer(minimum=0, **extra):
    return {'type': 'integer', 'minimum': minimum, **extra}


def enum(*values):
    return {'type': 'string', 'enum': list(values)}


UUID = string(36, format='uuid')
TIME = string(40, format='date-time')
VERSION = string(40, pattern=r'^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$')
BOOL = {'type': 'boolean'}

checks = [
    ('WIN-001', 'disk_space', 'P1', 'assessed'),
    ('WIN-002', 'bitlocker_protection', 'P1', 'assessed'),
    ('WIN-003', 'antivirus_state', 'P1', 'assessed'),
    ('WIN-004', 'defender_signature_age', 'P1', 'assessed'),
    ('WIN-005', 'firewall_profiles', 'P1', 'assessed'),
    ('WIN-006', 'windows_update', 'P1', 'assessed'),
    ('WIN-007', 'reboot_required', 'P1', 'assessed'),
    ('WIN-008', 'local_admin_membership', 'P1', 'assessed'),
    ('WIN-009', 'secure_boot', 'P1', 'assessed'),
    ('WIN-010', 'entra_device_join', 'P1', 'informational'),
    ('SYS-001', 'agent_freshness', 'P1', 'server_generated'),
    ('M365-001', 'mfa_registration', 'P2', 'assessed'),
    ('M365-002', 'security_defaults', 'P2', 'informational'),
    ('M365-003', 'conditional_access_inventory', 'P2', 'informational'),
    ('M365-004', 'intune_compliance', 'P2', 'assessed'),
    ('M365-005', 'sign_in_evidence', 'P3', 'informational'),
]
save(SPEC / 'check-catalog.json', {
    'catalogVersion': '0.1.0',
    'checks': [{'checkId': cid, 'name': name, 'phase': phase, 'assessmentMode': mode}
               for cid, name, phase, mode in checks],
})

evidence = {
    'WIN-001': obj({'totalBytes': integer(1), 'freeBytes': integer()}),
    'WIN-002': obj({'volumeStatus': enum('fully_encrypted', 'encrypting', 'decrypting', 'fully_decrypted'),
                    'protectionStatus': enum('on', 'off'),
                    'encryptionPercentage': integer(0, maximum=100)}),
    'WIN-003': obj({'provider': string(120), 'productState': enum('on', 'off', 'expired', 'snoozed'),
                    'statusSource': enum('defender', 'windows_security_center')}),
    'WIN-004': obj({'signatureLastUpdatedAt': TIME}),
    'WIN-005': obj({'domainEnabled': BOOL, 'privateEnabled': BOOL, 'publicEnabled': BOOL}),
    'WIN-006': obj({'securityUpdatesPending': integer(), 'lastSuccessfulSearchAt': TIME,
                    'configuredSource': enum('windows_update', 'wsus', 'other_approved')}),
    'WIN-007': obj({'rebootRequired': BOOL, 'statusSource': enum('windows_update_api')}),
    'WIN-008': obj({'memberSids': {'type': 'array', 'items': string(184, pattern=r'^S-\d+(?:-\d+)+$'),
                                  'maxItems': 100, 'uniqueItems': True},
                    'membershipScope': enum('direct_members')}),
    'WIN-009': obj({'enabled': BOOL, 'platform': enum('uefi', 'legacy_bios')}),
    'WIN-010': obj({'joinType': enum('entra_joined', 'hybrid_joined', 'registered', 'not_joined'),
                    'tenantId': {'type': ['string', 'null'], 'format': 'uuid'},
                    'entraDeviceId': {'type': ['string', 'null'], 'format': 'uuid'}}),
}
agent_ids = list(evidence)
observation = {
    '$schema': 'https://json-schema.org/draft/2020-12/schema',
    'title': 'Sikkerheit Agent Observation',
    **obj({
        'checkId': {'type': 'string', 'enum': agent_ids},
        'collectorVersion': VERSION,
        'subject': obj({'type': enum('device', 'volume'), 'reference': string(100)}),
        'observedAt': TIME,
        'collectionStatus': enum('collected', 'unavailable', 'not_applicable'),
        'evidence': {'type': 'object'},
        'reasonCode': enum('permission_denied', 'unsupported', 'collector_timeout',
                           'temporary_error', 'clock_inconsistent', 'policy_excluded'),
    }, ['checkId', 'collectorVersion', 'subject', 'observedAt', 'collectionStatus']),
    'oneOf': [
        {'properties': {'collectionStatus': {'const': 'collected'}},
         'required': ['evidence'], 'not': {'required': ['reasonCode']}},
        {'properties': {'collectionStatus': {'const': 'unavailable'},
                        'reasonCode': enum('permission_denied', 'unsupported', 'collector_timeout',
                                           'temporary_error', 'clock_inconsistent')},
         'required': ['reasonCode'], 'not': {'required': ['evidence']}},
        {'properties': {'collectionStatus': {'const': 'not_applicable'},
                        'reasonCode': {'const': 'policy_excluded'}},
         'required': ['reasonCode'], 'not': {'required': ['evidence']}},
    ],
    'allOf': [
        {'if': {'properties': {'checkId': {'const': cid}, 'collectionStatus': {'const': 'collected'}}},
         'then': {'properties': {'evidence': definition}}}
        for cid, definition in evidence.items()
    ],
    'description': 'Только allowlisted P1 Windows evidence. Проверка timestamps, применимости, '
                   'субъекта и ожидаемых проверок выполняется backend согласно 05-data-and-api.md.',
}
save(SPEC / 'observation.schema.json', observation)
batch = {
    '$schema': 'https://json-schema.org/draft/2020-12/schema',
    'title': 'Sikkerheit Agent Scan Batch',
    **obj({
        'schemaVersion': {'const': '1.0'}, 'scanId': UUID, 'sequence': integer(1),
        'agentVersion': VERSION, 'policyVersion': integer(1),
        'startedAt': TIME, 'completedAt': TIME,
        'scanRequestId': {'type': ['string', 'null'], 'format': 'uuid'},
        'observations': {'type': 'array', 'minItems': 1, 'maxItems': 200,
                         'items': {'$ref': './observation.schema.json'}},
    }, ['schemaVersion', 'scanId', 'sequence', 'agentVersion', 'policyVersion',
         'startedAt', 'completedAt', 'observations']),
    'description': 'DeviceId и OrganizationId определяются аутентификацией. Byte limit, '
                   'idempotency, sequence и время проверяются сервером дополнительно.',
}
save(SPEC / 'scan-batch.schema.json', batch)

synthetic_evidence = {
    'WIN-001': {'totalBytes': 256000000000, 'freeBytes': 18000000000},
    'WIN-002': {'volumeStatus': 'fully_encrypted', 'protectionStatus': 'off', 'encryptionPercentage': 100},
    'WIN-003': {'provider': 'Microsoft Defender', 'productState': 'on', 'statusSource': 'defender'},
    'WIN-004': {'signatureLastUpdatedAt': '2026-10-12T08:00:00Z'},
    'WIN-005': {'domainEnabled': True, 'privateEnabled': True, 'publicEnabled': True},
    'WIN-006': {'securityUpdatesPending': 0, 'lastSuccessfulSearchAt': '2026-10-12T09:59:00Z',
                'configuredSource': 'windows_update'},
    'WIN-007': {'rebootRequired': False, 'statusSource': 'windows_update_api'},
    'WIN-008': {'memberSids': ['S-1-5-21-1000-2000-3000-500'], 'membershipScope': 'direct_members'},
    'WIN-009': {'enabled': True, 'platform': 'uefi'},
    'WIN-010': {'joinType': 'entra_joined', 'tenantId': '22222222-2222-4222-8222-222222222222',
                'entraDeviceId': '33333333-3333-4333-8333-333333333333'},
}
sample = {
    'schemaVersion': '1.0', 'scanId': '11111111-1111-4111-8111-111111111111',
    'sequence': 1, 'agentVersion': '0.1.0', 'policyVersion': 1,
    'startedAt': '2026-10-12T10:00:00Z', 'completedAt': '2026-10-12T10:01:30Z',
    'observations': [
        {'checkId': cid, 'collectorVersion': '0.1.0',
         'subject': {'type': 'volume' if cid in ['WIN-001', 'WIN-002'] else 'device',
                     'reference': 'C:' if cid in ['WIN-001', 'WIN-002'] else 'self'},
         'observedAt': '2026-10-12T10:01:00Z', 'collectionStatus': 'collected',
         'evidence': value}
        for cid, value in synthetic_evidence.items()
    ],
}
save(EXAMPLES / 'scan-batch.json', sample)
unavailable = copy.deepcopy(sample)
unavailable['scanId'] = '44444444-4444-4444-8444-444444444444'
unavailable['sequence'] = 2
for item in unavailable['observations']:
    if item['checkId'] in ['WIN-002', 'WIN-009']:
        item.pop('evidence')
        item['collectionStatus'] = 'unavailable'
        item['reasonCode'] = 'permission_denied' if item['checkId'] == 'WIN-002' else 'unsupported'
save(EXAMPLES / 'scan-batch-unavailable.json', unavailable)

def ref(name):
    return {'$ref': '#/components/schemas/' + name}


schemas = {
    'ScanBatch': {'$ref': './scan-batch.schema.json'},
    'Problem': obj({'type': string(500), 'title': string(200), 'status': integer(400, maximum=599),
                    'code': string(80), 'correlationId': string(100)}),
    'EnrollmentRequest': obj({'registrationRequestId': UUID, 'installationId': UUID,
                              'displayName': string(120),
                              'csrPem': string(8192, pattern='^-----BEGIN CERTIFICATE REQUEST-----')}),
    'DeviceCertificate': obj({'deviceId': UUID, 'certificatePem': string(12000),
                              'expiresAt': TIME, 'agentApiUrl': string(500, format='uri')}),
    'RenewalRequest': obj({'renewalRequestId': UUID,
                           'csrPem': string(8192, pattern='^-----BEGIN CERTIFICATE REQUEST-----')}),
    'Configuration': obj({'policyVersion': integer(1),
                           'activeCheckIds': {'type': 'array', 'items': {'enum': agent_ids},
                                              'minItems': 1, 'maxItems': 10, 'uniqueItems': True},
                           'scanIntervalHours': integer(1), 'heartbeatIntervalHours': integer(1),
                           'maxBatchBytes': integer(1), 'maxBufferBytes': integer(1),
                           'maxBufferDays': integer(1),
                           'minimumAgentVersion': VERSION,
                           'pendingScanRequestId': {'type': ['string', 'null'], 'format': 'uuid'}}),
    'Heartbeat': obj({'observedAt': TIME, 'agentVersion': VERSION, 'queueDepth': integer(),
                     'bufferBytes': integer(), 'droppedBatchCount': integer()}),
    'HeartbeatReceipt': obj({'serverTime': TIME}),
    'ScanReceipt': obj({'scanId': UUID, 'acceptedAt': TIME, 'duplicate': BOOL,
                       'state': enum('queued', 'processed')}),
    'OrganizationCreate': obj({'name': string(120), 'timezone': string(80)}),
    'Organization': obj({'id': UUID, 'name': string(120), 'timezone': string(80),
                         'status': enum('active', 'disabled', 'deleted')}),
    'EnrollmentTokenRequest': obj({'displayName': string(120)}),
    'EnrollmentToken': obj({'enrollmentToken': string(200), 'expiresAt': TIME}),
    'Device': obj({'id': UUID, 'displayName': string(120), 'status': enum('active', 'revoked'),
                   'lastSeenAt': {'type': ['string', 'null'], 'format': 'date-time'}}),
    'ScanRequestCreate': obj({'idempotencyKey': UUID, 'reason': enum('verify_remediation')}),
    'ScanRequest': obj({'id': UUID, 'state': enum('pending', 'completed', 'expired'), 'expiresAt': TIME}),
    'Assessment': obj({'id': UUID, 'checkId': string(40), 'subjectReference': string(150),
                       'observedAt': TIME, 'receivedAt': TIME, 'ruleVersion': VERSION,
                       'policyVersion': integer(1), 'result': enum('pass', 'fail', 'unknown', 'not_applicable'),
                       'freshness': enum('fresh', 'stale'),
                       'reasonCode': {'type': ['string', 'null'], 'maxLength': 80},
                       'evidence': {'type': 'object'}, 'explanation': string(2000)}),
    'FindingEvent': obj({'id': UUID, 'occurredAt': TIME,
                         'eventType': enum('opened', 'resolved', 'reopened', 'quality_changed',
                                           'workflow_changed', 'policy_changed', 'object_retired'),
                         'cause': enum('device_change', 'rule_change', 'manual_action', 'data_quality'),
                         'assessmentId': {'type': ['string', 'null'], 'format': 'uuid'}}),
    'Finding': obj({'id': UUID, 'checkId': string(40), 'subjectReference': string(150),
                    'technicalState': enum('open', 'resolved'),
                    'workflowState': enum('new', 'in_progress', 'risk_accepted', 'suppressed'),
                    'assessmentResult': enum('pass', 'fail', 'unknown', 'not_applicable'),
                    'freshness': enum('fresh', 'stale'),
                    'severity': enum('critical', 'warning', 'information'),
                    'revision': integer(1), 'title': string(200), 'recommendation': string(2000),
                    'latestObservedAt': TIME,
                    'assigneeId': {'type': ['string', 'null'], 'format': 'uuid'},
                    'dueAt': {'type': ['string', 'null'], 'format': 'date-time'},
                    'workflowReason': {'type': ['string', 'null'], 'maxLength': 1000},
                    'reviewAt': {'type': ['string', 'null'], 'format': 'date-time'}}),
    'FindingPatch': {
        **obj({'workflowState': enum('new', 'in_progress', 'risk_accepted', 'suppressed'),
               'reason': string(1000), 'reviewAt': TIME,
               'assigneeId': {'type': ['string', 'null'], 'format': 'uuid'},
               'dueAt': {'type': ['string', 'null'], 'format': 'date-time'}}, ['workflowState']),
        'allOf': [{'if': {'properties': {'workflowState': {'enum': ['risk_accepted', 'suppressed']}}},
                   'then': {'required': ['reason', 'reviewAt']}}],
    },
    'ReportCreate': obj({'periodStart': TIME, 'periodEnd': TIME, 'format': enum('html', 'pdf')}),
    'Report': obj({'id': UUID, 'periodStart': TIME, 'periodEnd': TIME,
                   'state': enum('queued', 'ready', 'failed'), 'format': enum('html', 'pdf')}),
}
for entity in ['Organization', 'Device', 'Finding', 'Report', 'Assessment', 'FindingEvent']:
    schemas[entity + 'Page'] = obj({'items': {'type': 'array', 'maxItems': 100, 'items': ref(entity)},
                                   'nextCursor': {'type': ['string', 'null'], 'maxLength': 2048}})

security = {
    'PortalSession': {'type': 'apiKey', 'in': 'cookie', 'name': '__Host-sikkerheit-session',
                      'description': 'Backend OIDC session, HttpOnly Secure SameSite, role and organization checks.'},
    'CsrfToken': {'type': 'apiKey', 'in': 'header', 'name': 'X-CSRF-Token',
                  'description': 'Required together with PortalSession for portal mutations.'},
    'EnrollmentToken': {'type': 'apiKey', 'in': 'header', 'name': 'Authorization',
                        'description': 'Enrollment <one-time-token>; never written to logs.'},
    'DeviceCertificate': {'type': 'mutualTLS', 'description': 'Registered, unexpired, unrevoked device certificate. '
                           'Only trusted ingress forwarding is accepted; no organization IDs from payload.'},
}


def response(description, schema=None, headers=None, content_type='application/json'):
    item = {'description': description}
    if schema:
        item['content'] = {content_type: {'schema': schema}}
    if headers:
        item['headers'] = headers
    return item


def body(name):
    return {'required': True, 'content': {'application/json': {'schema': ref(name)}}}


def operation(operation_id, summary, mode, code, output=None, request=None, roles=None, parameters=None):
    sec = {'device': [{'DeviceCertificate': []}],
           'bootstrap': [{'EnrollmentToken': []}],
           'portal': [{'PortalSession': []}],
           'portal_mutation': [{'PortalSession': [], 'CsrfToken': []}]}[mode]
    result = {'operationId': operation_id, 'summary': summary, 'security': sec,
              'responses': {str(code): response('Успешный результат по семантике 05-data-and-api.md.',
                                               ref(output) if output else None)}}
    for error in ['400', '401', '403', '404', '409', '412', '413', '422', '429', '503']:
        result['responses'][error] = response('Ошибка с безопасным кодом и correlationId.', ref('Problem'),
            {'Retry-After': {'schema': integer(1), 'description': 'Seconds; present for rate limiting/temporary retry.'}}
            if error in ['429', '503'] else None, 'application/problem+json')
    if request:
        result['requestBody'] = body(request)
    if roles:
        result['x-allowed-roles'] = roles
    if parameters:
        result['parameters'] = parameters
    if mode == 'device':
        result['servers'] = [{'url': 'https://agent.example.invalid', 'description': 'Agent API mTLS host'}]
    return result


def pathparam(name):
    return {'name': name, 'in': 'path', 'required': True, 'schema': UUID}


PAGE = [{'name': 'cursor', 'in': 'query', 'schema': string(2048)},
        {'name': 'limit', 'in': 'query', 'schema': integer(1, maximum=100, default=50)}]
ORG = [pathparam('organizationId')]
READ_ROLES = ['PlatformAdmin', 'ServiceManager', 'Technician']
MANAGE_ROLES = ['PlatformAdmin', 'ServiceManager']
paths = {
    '/api/v1/agent/enroll': {'post': operation('enrollAgent', 'Регистрация по одноразовому токену',
                                             'bootstrap', 201, 'DeviceCertificate', 'EnrollmentRequest')},
    '/api/v1/agent/configuration': {'get': operation('getAgentConfiguration', 'Конфигурация устройства',
                                                    'device', 200, 'Configuration')},
    '/api/v1/agent/heartbeat': {'post': operation('submitHeartbeat', 'Подтверждение связи', 'device',
                                                200, 'HeartbeatReceipt', 'Heartbeat')},
    '/api/v1/agent/scans': {'post': operation('submitScan', 'Приём пакета после транзакционной записи',
                                            'device', 202, 'ScanReceipt', 'ScanBatch', parameters=[
         {'name': 'Idempotency-Key', 'in': 'header', 'required': True, 'schema': UUID,
          'description': 'Equals scanId; same immutable bytes may be retried.'}])},
    '/api/v1/agent/certificate/renew': {'post': operation('renewDeviceCertificate', 'Ротация локального ключа',
                                                         'device', 200, 'DeviceCertificate', 'RenewalRequest')},
    '/api/v1/organizations': {
        'get': operation('listOrganizations', 'Клиенты по назначениям сотрудника', 'portal', 200,
                         'OrganizationPage', roles=READ_ROLES, parameters=PAGE),
        'post': operation('createOrganization', 'Создание клиента', 'portal_mutation', 201,
                          'Organization', 'OrganizationCreate', ['PlatformAdmin']),
    },
    '/api/v1/organizations/{organizationId}/enrollment-tokens': {
        'post': operation('createEnrollmentToken', 'Одноразовый код регистрации', 'portal_mutation', 201,
                          'EnrollmentToken', 'EnrollmentTokenRequest', MANAGE_ROLES, ORG)},
    '/api/v1/organizations/{organizationId}/devices': {
        'get': operation('listDevices', 'Устройства назначенного клиента', 'portal', 200,
                         'DevicePage', roles=READ_ROLES, parameters=ORG + PAGE)},
    '/api/v1/organizations/{organizationId}/devices/{deviceId}/revoke': {
        'post': operation('revokeDevice', 'Отзыв идентичности устройства', 'portal_mutation', 204,
                          roles=MANAGE_ROLES, parameters=ORG + [pathparam('deviceId')])},
    '/api/v1/organizations/{organizationId}/devices/{deviceId}/scan-requests': {
        'post': operation('requestDeviceScan', 'Проверка по фиксированному расписанию без произвольной команды',
                          'portal_mutation', 202, 'ScanRequest', 'ScanRequestCreate', READ_ROLES,
                          ORG + [pathparam('deviceId')])},
    '/api/v1/organizations/{organizationId}/devices/{deviceId}/assessments': {
        'get': operation('listDeviceAssessments', 'Наблюдения и основания оценок устройства', 'portal', 200,
                         'AssessmentPage', roles=READ_ROLES, parameters=ORG + [pathparam('deviceId')] + PAGE)},
    '/api/v1/organizations/{organizationId}/findings': {
        'get': operation('listFindings', 'Проблемы и качество данных', 'portal', 200, 'FindingPage',
            roles=READ_ROLES, parameters=ORG + PAGE + [
                {'name': 'technicalState', 'in': 'query', 'schema': enum('open', 'resolved')},
                {'name': 'freshness', 'in': 'query', 'schema': enum('fresh', 'stale')}])},
    '/api/v1/organizations/{organizationId}/findings/{findingId}': {
        'get': operation('getFinding', 'Проблема назначенного клиента', 'portal', 200, 'Finding',
                         roles=READ_ROLES, parameters=ORG + [pathparam('findingId')]),
        'patch': operation('patchFinding', 'Workflow без подмены технической оценки', 'portal_mutation', 200,
                          'Finding', 'FindingPatch', READ_ROLES,
                          ORG + [pathparam('findingId'), {'name': 'If-Match', 'in': 'header', 'required': True,
                                  'schema': string(40, pattern=r'^"[0-9]+"$'),
                                  'description': 'Quoted revision; risk acceptance/suppression additionally requires ServiceManager.'}]),
    },
    '/api/v1/organizations/{organizationId}/reports': {
        'get': operation('listReports', 'Сформированные отчёты', 'portal', 200, 'ReportPage',
                         roles=READ_ROLES, parameters=ORG + PAGE),
        'post': operation('createReport', 'Задание формирования отчёта', 'portal_mutation', 202,
                          'Report', 'ReportCreate', MANAGE_ROLES, ORG),
    },
    '/api/v1/organizations/{organizationId}/findings/{findingId}/events': {
        'get': operation('listFindingEvents', 'История состояния проблемы', 'portal', 200,
                         'FindingEventPage', roles=READ_ROLES, parameters=ORG + [pathparam('findingId')] + PAGE)},
    '/api/v1/organizations/{organizationId}/reports/{reportId}/download': {
        'get': operation('downloadReport', 'Авторизованная выдача файла', 'portal', 200,
                         roles=READ_ROLES, parameters=ORG + [pathparam('reportId')])},
}
for method in ['get', 'patch']:
    paths['/api/v1/organizations/{organizationId}/findings/{findingId}'][method]['responses']['200']['headers'] = {
        'ETag': {'schema': string(40, pattern=r'^"[0-9]+"$'), 'description': 'Quoted finding revision.'}}
paths['/api/v1/organizations/{organizationId}/reports/{reportId}/download']['get']['responses']['200'] = {
    'description': 'Приватный файл после проверки контекста клиента. Cache-Control: private, no-store.',
    'content': {'application/pdf': {'schema': {'type': 'string', 'format': 'binary'}},
                'text/html': {'schema': {'type': 'string'}}},
}
spec = {
    'openapi': '3.1.0',
    'jsonSchemaDialect': 'https://json-schema.org/draft/2020-12/schema',
    'info': {'title': 'Sikkerheit P1 Proposed API', 'version': '0.1.0',
             'description': 'Проект контракта. Example hosts не являются развёрнутыми сервисами. '
                'Валидация бизнес-инвариантов и полномочий обязательна дополнительно к схемам. '
                'P2 интеграции требуют отдельного расширения после P0.'},
    'servers': [{'url': 'https://portal.example.invalid', 'description': 'Portal API and bootstrap host'}],
    'paths': paths, 'components': {'securitySchemes': security, 'schemas': schemas},
}
save(SPEC / 'openapi.json', spec)
print('Generated P1 OpenAPI, schemas, catalog and two synthetic scan examples.')
