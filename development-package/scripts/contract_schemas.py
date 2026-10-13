"""Agent schemas, evidence, policy configuration and portal API schemas (one dictionary source)."""
import copy

from contract_catalog import (AGENT_IDS, ALWAYS_INFORMATIONAL, AUDIT_DETAILS, CHECKS, COLLECTOR_REASONS,
                              EVENT_CAUSES, EVENT_TABLE, INFORMATIONAL_REASONS, LANGUAGES, LIFECYCLE_ACTIONS,
                              P1_IDS, PROBLEM_CODES, REASON_CODES, RESULTS, RETENTION_PURGE_ORDER,
                              SUBJECT_TYPES, VOLUME_IDS, WORKFLOW_STATES)

DRAFT = 'https://json-schema.org/draft/2020-12/schema'
CONTRACT_BASE = 'https://contracts.sikkerheit.example.invalid/agent/'


def obj(properties, required=None):
    return {'type': 'object', 'additionalProperties': False,
            'properties': properties, 'required': list(properties) if required is None else required}


def string(maximum=256, minimum=1, **extra):
    return {'type': 'string', 'minLength': minimum, 'maxLength': maximum, **extra}


def integer(minimum=0, **extra):
    return {'type': 'integer', 'minimum': minimum, **extra}


def enum(*values):
    return {'type': 'string', 'enum': list(values)}


def array(items, maximum, minimum=0, unique=False, **extra):
    result = {'type': 'array', 'items': items, 'minItems': minimum, 'maxItems': maximum, **extra}
    if unique:
        result['uniqueItems'] = True
    return result


def nullable(schema):
    result = copy.deepcopy(schema)
    result['type'] = [result['type'], 'null']
    if 'enum' in result:
        result['enum'] = result['enum'] + [None]
    return result


UUID_PATTERN = r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
DATE_TIME = r'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?'
UUID = string(36, format='uuid', pattern=UUID_PATTERN)
TIME_UTC = string(40, format='date-time', pattern=DATE_TIME + 'Z$')
TIME = string(40, format='date-time', pattern=DATE_TIME + '(Z|[+-][0-9]{2}:[0-9]{2})$')
VERSION = string(40, pattern=r'^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$')
SAFE_TEXT_PATTERN = r'^[^\u0000-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2066-\u2069<>]+$'
FINGERPRINT = string(64, pattern=r'^[0-9a-f]{64}$')
SID = string(184, pattern=r'^S-[0-9]+(?:-[0-9]+)+$')
EDITION_ID = string(64, pattern=r'^[A-Za-z]+$')
CSR = string(8192, pattern='^-----BEGIN CERTIFICATE REQUEST-----')
BOOL = {'type': 'boolean'}
ETAG = string(40, pattern=r'^"[0-9]+"$')
TIMEZONE_RULE = 'Идентификатор часового пояса IANA; неизвестная зона — 422 validation_failed.'
TIMEZONE = string(80, description=TIMEZONE_RULE)
TIMEZONE_CREATE = string(80, description=TIMEZONE_RULE + ' Обязателен при создании, портал предлагает '
                                                         'Europe/Oslo.')
ASSIGNEE = {**nullable(UUID), 'description': 'entraUserId участника организации (OrganizationMember.entraUserId), '
                                             'не organization_member.id; null — без ответственного.'}


def safe_text(maximum, **extra):
    return string(maximum, pattern=SAFE_TEXT_PATTERN, **extra)


def ref(name):
    return {'$ref': '#/components/schemas/' + name}


def _products():
    product = obj({'provider': safe_text(120),
                   'productState': enum('on', 'off', 'snoozed', 'expired', 'unknown'),
                   'statusSource': enum('windows_security_center', 'defender'),
                   'rawState': {'type': ['integer', 'null']}},
                  ['provider', 'productState', 'statusSource'])
    product['allOf'] = [{'if': {'properties': {'productState': {'const': 'unknown'}},
                                'required': ['productState']},
                         'then': {'required': ['rawState'], 'properties': {'rawState': {'type': 'integer'}}}}]
    return array(product, 10, description='Больше 10 продуктов: collectionStatus=unavailable, '
                                          'reasonCode=unsupported; список не усекается.')


def _pending_update():
    return obj({'updateId': UUID, 'revisionNumber': integer(0),
                'kbArticleIds': array(string(8, pattern=r'^[0-9]{6,8}$'), 10, unique=True),
                'categoryIds': array(UUID, 10, unique=True),
                'msrcSeverity': nullable(enum('Critical', 'Important', 'Moderate', 'Low')),
                'lastDeploymentChangeAt': nullable(TIME_UTC), 'deadlineAt': nullable(TIME_UTC),
                'firstSeenPendingAt': {**TIME_UTC, 'description': (
                    'observedAt первого сбора, в котором агент нашёл обновление у этого configuredSource; не позже '
                    'observedAt наблюдения. Агент хранит значение по (configuredSource, updateId) и удаляет его '
                    'только после поиска с resultCode=succeeded того же configuredSource без этого updateId.')}})


def _agent_search():
    search = obj({'mode': enum('offline_cache', 'online'), 'completedAt': nullable(TIME_UTC),
                  'resultCode': enum('not_started', 'succeeded', 'succeeded_with_errors', 'failed', 'aborted')})
    search['allOf'] = [{'if': {'properties': {'resultCode': {'const': 'succeeded'}}, 'required': ['resultCode']},
                        'then': {'properties': {'completedAt': TIME_UTC}}}]
    return search


EVIDENCE = {
    'WIN-001': obj({'totalBytes': integer(1), 'freeBytes': integer(0)}),
    'WIN-002': obj({'volumeStatus': enum('fully_encrypted', 'encrypting', 'decrypting', 'fully_decrypted'),
                    'protectionStatus': enum('on', 'off'),
                    'encryptionPercentage': integer(0, maximum=100)}),
    'WIN-003': obj({'products': _products(),
                    'defender': nullable(obj({
                        'amRunningMode': enum('normal', 'passive', 'edr_block', 'sxs_passive', 'not_running',
                                              'other'),
                        'realTimeProtectionEnabled': BOOL}))}),
    'WIN-004': obj({'signatureLastUpdatedAt': TIME_UTC}),
    'WIN-005': obj({'domainEnabled': BOOL, 'privateEnabled': BOOL, 'publicEnabled': BOOL}),
    'WIN-006': obj({
        'configuredSource': {**enum('windows_update', 'wsus', 'other_approved'), 'description': (
            'Источник, к которому относится наблюдение. Сервер хранит историю ожидания по (deviceId, '
            'configuredSource, updateId): наблюдение источника обновляет и закрывает эпизоды только этого '
            'источника и задаёт previousCompleteAt только для него (03, «Правило WIN-006»).')},
        'auLastSearchSuccessAt': {**nullable(TIME_UTC), 'description': (
            'LastSearchSuccessDate, прочитанный до начала agentSearch; основа свежести при offline_cache, '
            'null — основы нет (03, «Правило WIN-006»).')},
        'agentSearch': _agent_search(),
        'pendingSecurityUpdates': array(_pending_update(), 50, unique=True,
                                        description='Только Security Updates по CategoryID, по возрастанию '
                                                    'min(deadlineAt, firstSeenPendingAt); без заголовков.'),
        'pendingSecurityUpdatesTotal': integer(0, description='Длина pendingSecurityUpdates = min(total, 50); '
                                                              'иначе 422 schema_violation.'),
        'truncated': {**BOOL, 'description': 'true тогда и только тогда, когда pendingSecurityUpdatesTotal > 50; '
                                             'иначе 422 schema_violation.'}}),
    'WIN-007': obj({'rebootRequired': BOOL, 'lastBootAt': TIME_UTC,
                    'statusSource': enum('windows_update_api')}),
    'WIN-008': obj({'memberSids': array(SID, 100, unique=True), 'membershipScope': enum('direct_members')}),
    'WIN-009': obj({'enabled': BOOL, 'platform': enum('uefi', 'legacy_bios')}),
    'WIN-010': obj({'joinType': enum('entra_joined', 'hybrid_joined', 'domain_joined', 'not_joined'),
                    'tenantId': nullable(UUID), 'entraDeviceId': nullable(UUID)}),
    'WIN-011': obj({'editionId': EDITION_ID, 'displayVersion': string(8, pattern=r'^[0-9]{2}H[0-9]$'),
                    'build': integer(1), 'ubr': integer(0), 'architecture': enum('x64', 'arm64')}),
}
assert list(EVIDENCE) == AGENT_IDS, 'Evidence must cover exactly the agent checks of the catalog'

VOLUME_SUBJECT = obj({'type': {'const': 'volume'},
                      'volumeId': string(64, pattern=r'^\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\$'),
                      'mountPoint': string(2, pattern=r'^[A-Z]:$'), 'role': {'const': 'os'}},
                     ['type', 'volumeId', 'role'])
DEVICE_SUBJECT = obj({'type': {'const': 'device'}})


def observation_schema():
    schema = {
        '$schema': DRAFT, '$id': CONTRACT_BASE + 'observation.schema.json',
        'title': 'Sikkerheit Agent Observation',
        **obj({'checkId': {'type': 'string', 'enum': AGENT_IDS}, 'collectorVersion': VERSION,
               'subject': {'type': 'object', 'description': 'Форма объекта задаётся по checkId (allOf).'},
               'observedAt': TIME_UTC, 'collectionStatus': enum('collected', 'unavailable'),
               'evidence': {'type': 'object'}, 'reasonCode': enum(*COLLECTOR_REASONS)},
              ['checkId', 'collectorVersion', 'subject', 'observedAt', 'collectionStatus']),
        'oneOf': [
            {'properties': {'collectionStatus': {'const': 'collected'}},
             'required': ['evidence'], 'not': {'required': ['reasonCode']}},
            {'properties': {'collectionStatus': {'const': 'unavailable'}},
             'required': ['reasonCode'], 'not': {'required': ['evidence']}},
        ],
        'allOf': [
            {'if': {'properties': {'checkId': {'const': cid}}, 'required': ['checkId']},
             'then': {'properties': {'subject': VOLUME_SUBJECT if cid in VOLUME_IDS else DEVICE_SUBJECT}}}
            for cid in AGENT_IDS
        ] + [
            {'if': {'properties': {'checkId': {'const': cid}, 'collectionStatus': {'const': 'collected'}},
                    'required': ['checkId', 'collectionStatus']},
             'then': {'properties': {'evidence': definition}}}
            for cid, definition in EVIDENCE.items()
        ],
        'description': 'Закрытые allowlisted evidence-структуры P1 для каждого checkId. Применимость '
                       'определяет сервер: агент не передаёт not_applicable. Межполевые и семантические '
                       'инварианты (freeBytes <= totalBytes, согласованность списка WIN-006, ожидаемые '
                       'объекты, время) проверяет backend '
                       'по 05-data-and-api.md и specs/invariants.json.',
    }
    return schema


def batch_schema():
    return {
        '$schema': DRAFT, '$id': CONTRACT_BASE + 'scan-batch.schema.json',
        'title': 'Sikkerheit Agent Scan Batch',
        **obj({'schemaVersion': {'const': '1.0'}, 'scanId': UUID, 'sequence': integer(1),
               'agentVersion': VERSION, 'policyVersion': integer(1, description='Версия политики источника.'),
               'machineFingerprint': FINGERPRINT, 'startedAt': TIME_UTC, 'completedAt': TIME_UTC,
               'scanRequestId': {**nullable(UUID), 'description': (
                   'Только вариант A. Чужой или просроченный scanRequestId не отклоняет пакет: он '
                   'принимается как обычный сбор, scanRequestId игнорируется, пишется запись диагностики.')},
               'observations': array({'$ref': 'observation.schema.json'}, 200, 1,
                                     description='Ключ (checkId, subject.type, localKey) уникален внутри '
                                                 'пакета; localKey = device для устройства и volumeId '
                                                 'для тома. Повтор ключа: 422 duplicate_observation.')},
              ['schemaVersion', 'scanId', 'sequence', 'agentVersion', 'policyVersion',
               'machineFingerprint', 'startedAt', 'completedAt', 'observations']),
        'description': 'DeviceId и OrganizationId определяются сертификатом, а не телом пакета. Лимит '
                       'байтов, idempotency, sequence, окна и время проверяются сервером дополнительно. '
                       'Внутренне противоречивый пакет (completedAt раньше startedAt, observedAt вне '
                       '[startedAt, completedAt]) отклоняется 422 batch_time_inconsistent. startedAt, completedAt '
                       'или observedAt позже receivedAt + 5 мин пакет не отклоняют: он принимается с признаком '
                       'часов clock_inconsistent (05, «Время и часы устройства»). Метки времени внутри evidence '
                       'при приёме не проверяются и оцениваются по правилам проверки (03).',
    }


DEFAULT_MODES = {c[0]: c[3] for c in CHECKS}
# Starting notApplicableEditionIds that differ from the general default [] (05 «Политика клиента»).
DEFAULT_EDITIONS = {'WIN-002': ['Core', 'CoreN', 'CoreSingleLanguage', 'CoreCountrySpecific']}


def _check_policy(cid, parameters):
    mode = {'const': 'informational'} if cid in ALWAYS_INFORMATIONAL else enum('assessed', 'informational')
    return obj({'assessmentMode': {**mode, 'default': DEFAULT_MODES[cid]},
                'freshnessWindowHours': integer(1, maximum=720, default=72),
                'notApplicableEditionIds': array(EDITION_ID, 64, unique=True,
                                                 default=DEFAULT_EDITIONS.get(cid, [])),
                'parameters': parameters},
               ['assessmentMode', 'freshnessWindowHours', 'parameters'])


def policy_configuration():
    days = {'critical': 7, 'important': 14, 'moderate': 30, 'low': 30, 'unrated': 14}
    parameters = {
        'WIN-001': obj({'warnFreePercent': integer(0, maximum=100, default=10),
                        'warnFreeBytes': integer(0, default=10737418240),
                        'criticalFreePercent': integer(0, maximum=100, default=5),
                        'criticalFreeBytes': integer(0, default=2147483648)}),
        'WIN-002': obj({'encryptionRequired': {**BOOL, 'default': True}}),
        'WIN-003': obj({'approvedProviders': array(safe_text(120), 50, unique=True, default=[]),
                        'defenderApproved': {**BOOL, 'default': True}}),
        'WIN-004': obj({'warnDays': integer(1, default=3), 'criticalDays': integer(1, default=7)}),
        'WIN-005': obj({'requiredProfiles': array(enum('domain', 'private', 'public'), 3, unique=True,
                                                  default=['domain', 'private', 'public'])}),
        'WIN-006': obj({'expectedSource': {**nullable(enum('windows_update', 'wsus', 'other_approved')),
                                           'default': None},
                        'maxSearchAgeHours': integer(1, maximum=168, default=72,
                                                     description='Временная верхняя граница 168 ч до ответа '
                                                                 'владельца (08, вопрос 15).'),
                        'graceDaysBySeverity': obj({k: integer(0, default=v) for k, v in days.items()}),
                        'referenceTimeBasis': {**enum('deadline', 'first_seen'), 'default': 'first_seen'}}),
        'WIN-007': obj({'warnDays': integer(1, default=3)}),
        'WIN-008': obj({'allowedSids': array(SID, 100, unique=True, default=[])}),
        'WIN-009': obj({'secureBootRequired': {**BOOL, 'default': True}}),
        'WIN-010': obj({'expectedTenantId': {**nullable(UUID), 'default': None}}),
    }
    checks = {cid: _check_policy(cid, parameters.get(cid, obj({}))) for cid in P1_IDS}
    return {
        **obj({'activeCheckIds': array({'type': 'string', 'enum': AGENT_IDS}, len(AGENT_IDS), 1, unique=True,
                                       default=list(AGENT_IDS)),
               'schedule': obj({'scanIntervalHours': integer(1, maximum=168, default=24),
                                'heartbeatIntervalHours': integer(1, maximum=24, default=4),
                                'scanJitterMinutes': integer(0, maximum=60, default=10)}),
               'buffer': obj({'maxBufferDays': integer(1, maximum=30, default=7),
                              'maxBatchAgeDays': integer(2, maximum=32, default=9)}),
               'checks': obj(checks)}),
        'description': 'Закрытая конфигурация policy_revision. WIN-011 обязательна в activeCheckIds; '
                       'assessed без входных настроек, отсутствие WIN-011 и активная WIN-004 без WIN-003 '
                       'дают 422 policy_inputs_missing. maxBatchAgeDays >= maxBufferDays + 1, иначе 422 '
                       'schema_violation. У каждого обязательного поля-значения есть default; объект по умолчанию '
                       'составляется из default вложенных полей. Политика v1 по умолчанию: значения default '
                       'этой схемы — все WIN активны, режимы равны defaultAssessmentMode каталога.',
    }


def _event_branches():
    branches = []
    for event, (causes, assessment) in EVENT_TABLE.items():
        then = {'properties': {'cause': {'enum': causes}}}
        if assessment == 'required':
            then['properties']['assessmentId'] = {'type': 'string'}
        elif assessment == 'null':
            then['properties']['assessmentId'] = {'type': 'null'}
        branches.append({'if': {'properties': {'eventType': {'const': event}}, 'required': ['eventType']},
                         'then': then})
    branches.append({'if': {'properties': {'cause': {'const': 'manual_action'}}, 'required': ['cause']},
                     'then': {'properties': {'actorId': {'type': 'string'}}},
                     'else': {'properties': {'actorId': {'type': 'null'}}}})
    return branches


def _audit_details_branches():
    branch = {'properties': {'details': {'type': 'null'}}}
    for action, schema in reversed(list(AUDIT_DETAILS.items())):
        branch = {'if': {'properties': {'action': {'const': action}}, 'required': ['action']},
                  'then': {'properties': {'details': ref(schema)}}, 'else': branch}
    return [branch]


def api_schemas(observation, batch):
    workflow = enum(*WORKFLOW_STATES)
    subject = obj({'type': enum(*SUBJECT_TYPES), 'key': string(200), 'displayName': nullable(safe_text(200))})
    page_of = {}
    schemas = {
        'ScanBatch': batch, 'Observation': observation,
        'Problem': obj({'type': string(500), 'title': string(200), 'status': integer(400, maximum=599),
                        'code': enum(*[code for code, _, _ in PROBLEM_CODES]), 'correlationId': string(100),
                        'detail': string(1000), 'instance': string(500), 'minimumAgentVersion': VERSION},
                       ['type', 'title', 'status', 'code', 'correlationId']),
        'EnrollmentRequest': obj({'registrationRequestId': UUID, 'installationId': UUID,
                                  'displayName': safe_text(120), 'csrPem': CSR,
                                  'machineFingerprint': FINGERPRINT}),
        'DeviceCertificate': obj({'deviceId': UUID, 'certificatePem': string(12000), 'notBefore': TIME_UTC,
                                  'expiresAt': TIME_UTC, 'previousCertificateValidUntil': nullable(TIME_UTC),
                                  'agentApiUrl': string(500, format='uri')}),
        'RenewalRequest': {**obj({'renewalRequestId': UUID, 'csrPem': CSR, 'machineFingerprint': FINGERPRINT}),
                           'description': 'Идемпотентно по renewalRequestId и CSR: повтор возвращает прежний '
                                          'сертификат, тот же id с другим CSR даёт 409 '
                                          'renewal_request_conflict; повтор, сертификат которого отозван, тоже '
                                          'получает 409 renewal_request_conflict, а не отозванный сертификат.'},
        'Configuration': obj({
            'policyVersion': integer(1),
            'activeCheckIds': array({'type': 'string', 'enum': AGENT_IDS}, len(AGENT_IDS), 1, unique=True),
            'scanIntervalHours': integer(1, maximum=168), 'heartbeatIntervalHours': integer(1, maximum=24),
            'scanJitterMinutes': integer(0, maximum=60), 'maxBatchBytes': integer(1, maximum=262144),
            'maxBufferBytes': integer(1, maximum=104857600), 'maxBufferDays': integer(1, maximum=30),
            'lastAcceptedSequence': integer(0), 'minimumAgentVersion': VERSION,
            'pendingScanRequestId': nullable(UUID), 'renewBeforeExpiryHours': integer(1)}),
        'Heartbeat': obj({'observedAt': TIME_UTC, 'agentVersion': VERSION, 'queueDepth': integer(),
                          'bufferBytes': integer(), 'droppedBatchCount': integer(),
                          'machineFingerprint': FINGERPRINT}),
        'HeartbeatReceipt': obj({'serverTime': TIME_UTC}),
        'ScanReceipt': obj({'scanId': UUID, 'acceptedAt': TIME_UTC, 'duplicate': BOOL,
                            'state': enum('queued', 'processed')}),
        'Organization': {
            **obj({'id': UUID, 'name': safe_text(120), 'timezone': TIMEZONE,
                   'reportLanguage': enum(*LANGUAGES),
                   'status': enum('active', 'disabled', 'deletion_scheduled'),
                   'deletionDueAt': nullable(TIME)}),
            'allOf': [{'if': {'properties': {'status': {'const': 'deletion_scheduled'}}, 'required': ['status']},
                       'then': {'properties': {'deletionDueAt': {'type': 'string'}}},
                       'else': {'properties': {'deletionDueAt': {'type': 'null'}}}}]},
        'OrganizationCreate': obj({'name': safe_text(120), 'timezone': TIMEZONE_CREATE,
                                   'reportLanguage': enum(*LANGUAGES)}),
        'OrganizationUpdate': {**obj({'name': safe_text(120), 'timezone': TIMEZONE,
                                      'reportLanguage': enum(*LANGUAGES)}, []), 'minProperties': 1},
        'OrganizationMember': obj({'entraUserId': {**UUID, 'description': (
                                       'Object id сотрудника в Entra tenant компании; значение '
                                       'FindingPatch.assigneeId и параметра пути entraUserId.')}, 'role': enum('ServiceManager', 'Technician'),
                                   'displayName': nullable(safe_text(120)), 'grantedAt': TIME,
                                   'grantedBy': UUID}),
        'OrganizationMemberPut': obj({'role': enum('ServiceManager', 'Technician')}),
        'PolicyConfiguration': policy_configuration(),
        'PolicyRevision': obj({'version': integer(1), 'effectiveFrom': TIME, 'createdAt': TIME,
                               'createdBy': UUID, 'configuration': ref('PolicyConfiguration')}),
        'PolicyRevisionCreate': obj({'configuration': ref('PolicyConfiguration')}),
        'OrganizationLifecycleChange': {
            **obj({'action': enum(*LIFECYCLE_ACTIONS),
                   'reason': string(1000, description='Обязательный свободный текст; недоверенная строка. '
                                                     'Сохраняется без изменений в details.reason записей аудита '
                                                     'organization.lifecycle_change и выдаётся только как '
                                                     'AuditEvent.details.reason.'),
                   'idempotencyKey': UUID, 'exportWaived': BOOL},
                  ['action', 'reason', 'idempotencyKey']),
            'allOf': [{'if': {'properties': {'action': {'const': 'schedule_deletion'}}, 'required': ['action']},
                       'else': {'not': {'required': ['exportWaived']}}}]},
        'OrganizationExportCreate': obj({'idempotencyKey': UUID}),
        'OrganizationExport': obj({'id': UUID, 'state': enum('queued', 'ready', 'failed', 'expired'),
                                   'createdAt': TIME, 'expiresAt': nullable(TIME), 'requestedBy': UUID}),
        'OrganizationLifecycleAuditDetails': {
            **obj({'lifecycleAction': enum(*LIFECYCLE_ACTIONS),
                   'reason': string(1000, description='Недоверенная строка из OrganizationLifecycleChange.reason; '
                                                     'выводится только как текст.'),
                   'exportWaived': BOOL}),
            'allOf': [{'if': {'properties': {'lifecycleAction': {'const': 'schedule_deletion'}},
                              'required': ['lifecycleAction']},
                       'else': {'properties': {'exportWaived': {'const': False}}}}]},
        'FindingAssignmentAuditDetails': {
            **obj({'assigneeId': obj({'from': nullable(UUID), 'to': nullable(UUID)}),
                   'dueAt': obj({'from': nullable(TIME), 'to': nullable(TIME)})}, []),
            'minProperties': 1, 'description': 'Только изменившиеся поля.'},
        'RetentionPurgeAuditDetails': obj({
            'deleted': obj({name: integer(0) for name in RETENTION_PURGE_ORDER}),
            'snapshotted': integer(0, description='Оценки, у которых evidence заменён basisSnapshot.')}),
        'AuditEvent': {
            **obj({'id': UUID, 'occurredAt': TIME,
                   'actorType': enum('user', 'platform_admin', 'device', 'system'),
                   'actorId': {**nullable(UUID), 'description': 'entraUserId при actorType user или '
                                                                'platform_admin; deviceId при device; null при '
                                                                'system.'},
                   'action': string(80, pattern=r'^[a-z_]+(\.[a-z_]+)+$'),
                   'targetType': string(40), 'targetId': string(100),
                   'outcome': enum('success', 'denied', 'failed'), 'correlationId': string(100),
                   'details': {'type': ['object', 'null']}}),
            'allOf': _audit_details_branches()},
        'EnrollmentTokenRequest': {
            **obj({'mode': enum('single_use', 'batch'),
                   'expiresInHours': integer(1, maximum=168, default=72),
                   'maxUses': integer(1, maximum=100, default=25), 'label': safe_text(120)}, ['mode']),
            'allOf': [{'if': {'properties': {'mode': {'const': 'batch'}}, 'required': ['mode']},
                       'else': {'allOf': [{'not': {'required': ['expiresInHours']}},
                                          {'not': {'required': ['maxUses']}}]}}],
            'description': 'single_use: срок 30 мин по умолчанию (платформенный параметр), maxUses = 1.'},
        'EnrollmentToken': obj({'id': UUID,
                                'enrollmentToken': string(200, pattern=r'^[A-Za-z0-9_-]+$',
                                                          description='Секрет; показывается один раз.'),
                                'mode': enum('single_use', 'batch'), 'expiresAt': TIME,
                                'maxUses': integer(1, maximum=100), 'useCount': integer(0),
                                'label': nullable(safe_text(120))}),
        'EnrollmentTokenSummary': obj({'id': UUID, 'mode': enum('single_use', 'batch'),
                                       'label': nullable(safe_text(120)), 'expiresAt': TIME,
                                       'maxUses': integer(1, maximum=100), 'useCount': integer(0),
                                       'revokedAt': nullable(TIME), 'createdAt': TIME, 'createdBy': UUID}),
        'Device': obj({'id': UUID, 'displayName': safe_text(120), 'status': enum('active', 'revoked'),
                       'identityState': enum('ok', 'identity_conflict'),
                       'clockStatus': enum('ok', 'inconsistent'), 'lastSeenAt': nullable(TIME),
                       'lastFullScanAt': nullable(TIME), 'enrollmentTokenId': nullable(UUID)}),
        'DeviceUpdate': obj({'displayName': safe_text(120)}),
        'ScanRequestCreate': obj({'idempotencyKey': UUID, 'reason': enum('verify_remediation')}),
        'ScanRequest': obj({'id': UUID, 'state': enum('requested', 'delivered', 'completed', 'expired'),
                            'expiresAt': TIME}),
        'Subject': subject,
        'Assessment': {
            **obj({'id': UUID, 'deviceId': nullable(UUID), 'subject': ref('Subject'),
                   'checkId': string(40), 'ruleId': string(80), 'ruleVersion': VERSION,
                   'sourcePolicyVersion': integer(1), 'evaluatedPolicyVersion': integer(1),
                   'assessmentScope': enum('historical', 'current'),
                   'assessmentMode': enum('assessed', 'informational'),
                   'result': nullable(enum(*RESULTS)), 'freshness': enum('fresh', 'stale'),
                   'reasonCode': nullable(enum(*REASON_CODES)), 'late': BOOL,
                   'observedAt': TIME, 'receivedAt': TIME, 'evidence': {'type': ['object', 'null']},
                   'evidenceAvailability': enum('available', 'expired'), 'explanation': string(2000)}),
            'allOf': [{'if': {'properties': {'assessmentMode': {'const': 'informational'}},
                              'required': ['assessmentMode']},
                       'then': {'properties': {'result': {'type': 'null'},
                                               'reasonCode': nullable(enum(*INFORMATIONAL_REASONS))}},
                       'else': {'properties': {'result': {'type': 'string'}}}},
                      {'if': {'properties': {'result': {'enum': ['pass', 'fail']}}, 'required': ['result']},
                       'then': {'properties': {'reasonCode': {'type': 'null'}}}}],
            'description': 'Режим informational: result всегда null, finding не создаётся. reasonCode '
                           'допускается при result unknown или not_applicable, а также у informational-оценки '
                           'с result=null, когда данных нет: коды недоступности наблюдения, '
                           'missing_observation, clock_inconsistent, applicability_input_missing; такая '
                           'оценка получает result=null с той же причиной. Остальные причины правил '
                           '(unmapped_state, update_*, os_version_unknown, os_inventory_missing, '
                           'evidence_time_invalid, policy_not_applicable) informational-оценке не '
                           'присваиваются: result=null, reasonCode=null. Признак '
                           'часов действует на все оценки пакета: assessed — unknown и clock_inconsistent, '
                           'informational — null и clock_inconsistent; applicability_input_missing '
                           'применяется, только если у пакета нет признака часов.'},
        'Finding': obj({'id': UUID, 'checkId': string(40), 'deviceId': nullable(UUID), 'subject': ref('Subject'),
                        'technicalState': enum('open', 'resolved'), 'workflowState': workflow,
                        'assessmentResult': enum(*RESULTS), 'freshness': enum('fresh', 'stale'),
                        'severity': enum('critical', 'warning'),
                        'revision': integer(1), 'title': string(200), 'recommendation': string(2000),
                        'latestObservedAt': TIME, 'assigneeId': ASSIGNEE, 'dueAt': nullable(TIME),
                        'workflowReason': nullable(string(1000)), 'reviewAt': nullable(TIME),
                        'workflowDecidedBy': nullable(UUID)}),
        'FindingEvent': {
            **obj({'id': UUID, 'occurredAt': TIME, 'eventType': enum(*EVENT_TABLE),
                   'cause': enum(*EVENT_CAUSES), 'assessmentId': nullable(UUID), 'actorId': nullable(UUID),
                   'fromWorkflowState': nullable(workflow), 'toWorkflowState': nullable(workflow)}),
            'allOf': _event_branches()},
        'FindingPatch': {**obj({'workflowState': enum('new', 'in_progress'), 'assigneeId': ASSIGNEE,
                                'dueAt': nullable(TIME)}, []), 'minProperties': 1},
        'RiskDecision': {
            **obj({'decision': enum('risk_accepted', 'suppressed', 'withdrawn'), 'reason': string(1000),
                   'reviewAt': TIME}, ['decision']),
            'allOf': [{'if': {'properties': {'decision': {'const': 'withdrawn'}}, 'required': ['decision']},
                       'then': {'not': {'required': ['reviewAt']}},
                       'else': {'required': ['reason', 'reviewAt']}}]},
        'ReportCreate': {**obj({'periodStart': TIME, 'periodEnd': TIME, 'format': enum('html')}),
                         'description': 'Только границы ISO-недели в timezone организации: periodStart — '
                                        'понедельник 00:00, periodEnd — следующий понедельник 00:00; иные '
                                        'границы — 422 validation_failed (05, «Отчёт и покрытие»).'},
        'Report': obj({'id': UUID, 'periodStart': TIME, 'periodEnd': TIME, 'timezone': string(80),
                       'language': enum(*LANGUAGES), 'state': enum('queued', 'ready', 'failed'),
                       'format': enum('html'),
                       'failureCode': {**nullable(enum('translation_missing', 'generation_error')),
                                       'description': 'translation_missing — нет перевода; generation_error — '
                                                      'сбой генерации по иной причине, чем translation_missing.'}}),
    }
    for entity in ['Organization', 'Device', 'Finding', 'Report', 'Assessment', 'FindingEvent',
                   'OrganizationMember', 'PolicyRevision', 'AuditEvent', 'EnrollmentTokenSummary']:
        page_of[entity + 'Page'] = obj({'items': array(ref(entity), 100),
                                        'nextCursor': nullable(string(2048))})
    schemas.update(page_of)
    return schemas
