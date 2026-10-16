"""Agent and M365 observation schemas, policy configuration and API schemas (one dictionary source)."""
import copy

from contract_catalog import (AGENT_COLLECTOR_REASONS, AGENT_IDS, ALWAYS_INFORMATIONAL, AUDIT_DETAILS, CA_CONDITIONS,
                              CA_GRANT_CONTROLS, CHECKS, CAPABILITY_STATUSES, CHECK_IDS, EVENT_CAUSES, EVENT_TABLE,
                              GRAPH_COLLECTOR_REASONS,
                              GRAPH_IDS, GRAPH_MODULES, GRAPH_SUBJECTS, INFORMATIONAL_REASONS, LANGUAGES,
                              LIFECYCLE_ACTIONS, LOCAL_ADMIN_KINDS, METHOD_KINDS, OS_FAMILIES, PROBLEM_CODES,
                              PRIVILEGED_ROLE_TEMPLATES, REASON_CODES, RELEASE_KINDS, RESULTS, SERVER_IDS,
                              RETENTION_PURGE_ORDER, ROLES, SUBJECT_TYPES, VOLUME_IDS, WORKFLOW_STATES)

DRAFT = 'https://json-schema.org/draft/2020-12/schema'
CONTRACT_BASE = 'https://contracts.sikkerheit.example.invalid/'


def obj(properties, required=None):
    return {'type': 'object', 'additionalProperties': False,
            'properties': properties, 'required': list(properties) if required is None else required}


def string(maximum=256, minimum=1, **extra):
    return {'type': 'string', 'minLength': minimum, 'maxLength': maximum, **extra}


def integer(minimum=0, **extra):
    return {'type': 'integer', 'minimum': minimum, **extra}


def number(minimum, maximum, **extra):
    return {'type': 'number', 'minimum': minimum, 'maximum': maximum, **extra}


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
SAFE_TEXT_PATTERN = r'^[^\u0000-\u001F\u007F-\u009F​-‏‪-‮⁦-⁩<>]+$'
FINGERPRINT = string(64, pattern=r'^[0-9a-f]{64}$')
SID = string(184, pattern=r'^S-[0-9]+(?:-[0-9]+)+$')
EDITION_ID = string(64, pattern=r'^[A-Za-z]+$')
BOOL = {'type': 'boolean'}
ETAG = string(40, pattern=r'^"[0-9]+"$')
B64_32 = string(43, 43, pattern=r'^[A-Za-z0-9_-]{43}$')
NONCE = {**B64_32, 'description': '32 байта в base64url без дополнения: 12 случайных, 4 байта срока и 16 байт '
                                   'HMAC сервера; одноразовый, 5 минут (05, «Регистрация и сессия»).'}
SIGNATURE = string(86, 86, pattern=r'^[A-Za-z0-9_-]{86}$',
                   description='ECDSA P-256 SHA-256 в формате IEEE P1363 (r||s, 64 байта), base64url.')
ENROLLMENT_KEY = string(48, 48, pattern=r'^sikk_[A-Za-z0-9_-]{43}$')
CONSENT_POLICY = string(120, pattern=r'^ManagePermissionGrantsForSelf\.[A-Za-z0-9._-]+$')
MONTH = string(7, 7, pattern=r'^[0-9]{4}-(0[1-9]|1[0-2])$')
KB = string(8, 6, pattern=r'^[0-9]{6,8}$')
TIMEZONE_RULE = 'Идентификатор часового пояса IANA; неизвестная зона — 422 validation_failed.'
TIMEZONE = string(80, description=TIMEZONE_RULE)
TIMEZONE_CREATE = string(80, description=TIMEZONE_RULE + ' Обязателен при создании, портал предлагает '
                                                         'Europe/Oslo.')
ASSIGNEE = {**nullable(UUID), 'description': 'entraUserId сотрудника с ролью Admin или Technician '
                                             '(StaffUser.entraUserId); null — без ответственного.'}
CONNECTION_STATUSES = ['not_connected', 'consent_pending', 'active', 'disconnected']
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


EVIDENCE = {
    'WIN-001': obj({'totalBytes': integer(1), 'freeBytes': integer(0)}),
    'WIN-002': obj({'volumeStatus': enum('fully_encrypted', 'encrypting', 'decrypting', 'fully_decrypted',
                                         'encryption_paused', 'decryption_paused'),
                    'protectionStatus': enum('on', 'off', 'unknown'),
                    'encryptionPercentage': integer(0, maximum=100)}),
    'WIN-003': obj({'products': _products(),
                    'defender': nullable(obj({
                        'amRunningMode': enum('normal', 'passive', 'edr_block', 'sxs_passive', 'not_running',
                                              'other'),
                        'realTimeProtectionEnabled': BOOL}))}),
    'WIN-004': obj({'signatureLastUpdatedAt': TIME_UTC}),
    'WIN-005': obj({'domainEnabled': BOOL, 'privateEnabled': BOOL, 'publicEnabled': BOOL,
                    'firewallProducts': array(obj({'provider': safe_text(120),
                                                   'productState': enum('on', 'off', 'snoozed', 'expired', 'unknown')}),
                                              10, description='Сторонние firewall из Windows Security Center.')}),
    'WIN-006': obj({
        'lastSearchSuccessAt': {**nullable(TIME_UTC), 'description': 'LastSearchSuccessDate службы '
                                                                     'автоматического обновления; null — нет.'},
        'lastInstallSuccessAt': {**nullable(TIME_UTC), 'description': 'LastInstallationSuccessDate; null — нет.'},
        'wsusConfigured': {**BOOL, 'description': 'Политика задаёт сервер WSUS (WUServer и UseWUServer).'}}),
    'WIN-007': obj({'rebootRequired': BOOL, 'lastBootAt': TIME_UTC}),
    'WIN-008': obj({'members': array(obj({'sid': SID, 'kind': enum(*LOCAL_ADMIN_KINDS),
                                          'relativeId': {**nullable(integer(0)), 'description': (
                                              'RID относительно SID машины или домена; null для entra и well_known.')}}),
                                     100, unique=True),
                    'membershipScope': enum('direct_members')}),
    'WIN-009': obj({'enabled': BOOL, 'platform': enum('uefi', 'legacy_bios')}),
    'WIN-010': obj({'joinType': enum('entra_joined', 'hybrid_joined', 'domain_joined', 'not_joined'),
                    'tenantId': nullable(UUID), 'entraDeviceId': nullable(UUID)}),
    'WIN-011': obj({'editionId': EDITION_ID,
                    'displayVersion': {**nullable(string(8, pattern=r'^([0-9]{2}H[0-9]|[0-9]{4})$')), 'description': (
                        'DisplayVersion, у старых сборок — ReleaseId; null, если нет обоих.')},
                    'build': integer(1), 'ubr': integer(0), 'architecture': enum('x64', 'arm64')}),
}
assert list(EVIDENCE) == AGENT_IDS, 'Evidence must cover exactly the agent checks of the catalog'


def _methods():
    return {**nullable(array(enum(*METHOD_KINDS), len(METHOD_KINDS), unique=True)),
            'description': 'Нормализованные виды зарегистрированных методов; номера телефонов, адреса и названия '
                           'устройств не сохраняются. null — методы не запрашивались (03, «Правило M365-001 и '
                           'M365-002»).'}


USER_TYPE = {**nullable(enum('Member', 'Guest')), 'description': 'null у части старых учётных записей; правило '
                                                                 'считает такую учётную запись member.'}


def _exclusions():
    return {'excludedUsersOutsidePolicy': integer(0, description=(
                'Пользователи, исключённые прямо, через группы или роли, которых нет в excludedUserIds политики.')),
            'unresolvedExclusions': integer(0, description='Исключённые группы и роли, членов которых прочитать не '
                                                           'удалось.')}


def _scope():
    return {'policyId': UUID, 'state': enum('enabled', 'enabledForReportingButNotEnforced', 'disabled'),
            'allUsers': BOOL, 'allApplications': BOOL, 'excludedApplications': integer(0),
            'conditions': array(enum(*CA_CONDITIONS), len(CA_CONDITIONS), unique=True, description=(
                'Заданные условия, которые сужают действие политики; пустой список — без условий.')),
            **_exclusions()}


def _ca_policy():
    return obj({**_scope(), 'allClientAppTypes': BOOL, 'grantOperator': enum('AND', 'OR'),
                'grantControls': array(enum(*CA_GRANT_CONTROLS), len(CA_GRANT_CONTROLS), 1, unique=True),
                'authStrengthRequiresMfa': {**nullable(BOOL), 'description': (
                    'requirementsSatisfied = mfa у authentication strength политики; null — strength не задана.')}})


def _legacy_policy():
    return obj({**_scope(), 'coversExchangeActiveSync': BOOL, 'coversOtherClients': BOOL})


GRAPH_EVIDENCE = {
    'M365-001': obj({'accountEnabled': BOOL, 'userType': USER_TYPE, 'directorySyncAccount': BOOL,
                     'methodKinds': _methods()}),
    'M365-002': obj({'accountEnabled': BOOL, 'userType': USER_TYPE,
                     'roleTemplateIds': array(UUID, 50, unique=True, description=(
                         'Активные роли из privilegedRoleTemplateIds, включая временные активации PIM; пустой список — '
                         'роль снята.')),
                     'temporaryRoleTemplateIds': array(UUID, 50, unique=True, description=(
                         'Роли из roleTemplateIds, которые действуют только как активация PIM (assignmentType Activated '
                         'при Entra ID P2). Нет поля — активации не отделялись.')),
                     'assignment': enum('direct', 'group', 'direct_and_group', 'none'), 'methodKinds': _methods()},
                    ['accountEnabled', 'userType', 'roleTemplateIds', 'assignment', 'methodKinds']),
    'M365-003': obj({'securityDefaults': enum('enabled', 'disabled'),
                     'conditionalAccess': enum('available', 'license_missing'),
                     'mfaPolicies': array(_ca_policy(), 200, description='Политики CA с grant control mfa или '
                                                                         'authentication strength в любом state.'),
                     'perUserMfa': {**nullable(obj({'required': integer(0), 'notRequired': integer(0),
                                                    'unknown': integer(0), 'enabled': integer(0)},
                                                   ['required', 'notRequired', 'unknown'])), 'description': (
                         'Счётчики per-user MFA включённых member-пользователей вне excludedUserIds и без роли '
                         'синхронизации: required — enforced, notRequired — disabled, enabled — enabled (до '
                         'подтверждения в SP-01 не принуждение), unknown — отсутствующее или нераспознанное '
                         'состояние, а без поля enabled — и enabled. null — модуль per_user_mfa не выполнялся.')}}),
    'M365-004': obj({'securityDefaults': enum('enabled', 'disabled'),
                     'conditionalAccess': enum('available', 'license_missing'),
                     'legacyBlockPolicies': array(_legacy_policy(), 200, description=(
                         'Политики CA с grant control block и типами клиентов устаревшей аутентификации.'))}),
    'M365-005': obj({'globalAdminUserIds': array(UUID, 100, unique=True, description='Включённые учётные записи.'),
                     'disabledGlobalAdminUserIds': array(UUID, 100, unique=True),
                     'unresolvedGroupAssignments': integer(0),
                     'uncoveredRoleTemplateIds': array(UUID, 200, unique=True, description=(
                         'Роли каталога вне privilegedRoleTemplateIds, назначенные включённым пользователям; на '
                         'результат не влияют.'))},
                    ['globalAdminUserIds', 'disabledGlobalAdminUserIds', 'unresolvedGroupAssignments']),
    'M365-006': obj({'permissionGrantPolicies': array(CONSENT_POLICY, 20, unique=True, description=(
        'Только записи ManagePermissionGrantsForSelf.* из defaultUserRolePermissions.permissionGrantPoliciesAssigned, '
        'префикс приведён к этому написанию; пустой список — согласие пользователей выключено.'))}),
    'M365-007': obj({'accountEnabled': BOOL, 'userType': USER_TYPE, 'directorySyncAccount': BOOL,
                     'lastSuccessfulSignInAt': nullable(TIME_UTC),
                     'createdAt': {**nullable(TIME_UTC), 'description': 'null у части учётных записей, созданных до '
                                                                       'июня 2018 года.'}}),
}
assert list(GRAPH_EVIDENCE) == GRAPH_IDS, 'Graph evidence must cover exactly the M365 checks of the catalog'

VOLUME_SUBJECT = obj({'type': {'const': 'volume'},
                      'volumeId': string(64, pattern=r'^\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\$'),
                      'mountPoint': string(2, pattern=r'^[A-Z]:$'), 'role': {'const': 'os'}},
                     ['type', 'volumeId', 'role'])
DEVICE_SUBJECT = obj({'type': {'const': 'device'}})
TENANT_SUBJECT = obj({'type': {'const': 'tenant'}, 'key': UUID})
USER_SUBJECT = obj({'type': {'const': 'user'}, 'key': UUID, 'userPrincipalName': safe_text(256)})


def _observation(title, file, ids, subjects, evidence, reasons, description):
    return {
        '$schema': DRAFT, '$id': CONTRACT_BASE + file, 'title': title,
        **obj({'checkId': {'type': 'string', 'enum': ids}, 'collectorVersion': VERSION,
               'subject': {'type': 'object', 'description': 'Форма объекта задаётся по checkId (allOf).'},
               'observedAt': TIME_UTC, 'collectionStatus': enum('collected', 'unavailable'),
               'evidence': {'type': 'object'}, 'reasonCode': enum(*reasons)},
              ['checkId', 'collectorVersion', 'subject', 'observedAt', 'collectionStatus']),
        'oneOf': [
            {'properties': {'collectionStatus': {'const': 'collected'}},
             'required': ['evidence'], 'not': {'required': ['reasonCode']}},
            {'properties': {'collectionStatus': {'const': 'unavailable'}},
             'required': ['reasonCode'], 'not': {'required': ['evidence']}},
        ],
        'allOf': [
            {'if': {'properties': {'checkId': {'const': cid}}, 'required': ['checkId']},
             'then': {'properties': {'subject': subjects[cid]}}} for cid in ids
        ] + [
            {'if': {'properties': {'checkId': {'const': cid}, 'collectionStatus': {'const': 'collected'}},
                    'required': ['checkId', 'collectionStatus']},
             'then': {'properties': {'evidence': definition}}} for cid, definition in evidence.items()
        ],
        'description': description,
    }


def observation_schema():
    subjects = {cid: VOLUME_SUBJECT if cid in VOLUME_IDS else DEVICE_SUBJECT for cid in AGENT_IDS}
    return _observation(
        'Sikkerheit Agent Observation', 'agent/observation.schema.json', AGENT_IDS, subjects, EVIDENCE,
        AGENT_COLLECTOR_REASONS,
        'Закрытые allowlisted evidence-структуры агента для каждой WIN-проверки. Применимость определяет сервер: '
        'агент не передаёт not_applicable. Межполевые и семантические инварианты (freeBytes <= totalBytes, '
        'ожидаемые объекты, время) проверяет backend по 05-data-and-api.md и specs/invariants.json.')


def batch_schema():
    return {
        '$schema': DRAFT, '$id': CONTRACT_BASE + 'agent/scan-batch.schema.json',
        'title': 'Sikkerheit Agent Scan Batch',
        **obj({'schemaVersion': {'const': '2.0'}, 'scanId': UUID, 'sequence': integer(1),
               'agentVersion': VERSION, 'policyVersion': integer(1, description='Версия политики источника.'),
               'machineFingerprint': FINGERPRINT, 'startedAt': TIME_UTC, 'completedAt': TIME_UTC,
               'scanRequestId': {**nullable(UUID), 'description': (
                   'Чужой или просроченный scanRequestId не отклоняет пакет: он принимается как обычный сбор, '
                   'scanRequestId игнорируется, пишется запись диагностики.')},
               'observations': array({'$ref': 'observation.schema.json'}, 200, 1,
                                     description='Ключ (checkId, subject.type, localKey) уникален внутри '
                                                 'пакета; localKey = device для устройства и volumeId '
                                                 'для тома. Повтор ключа: 422 duplicate_observation.')},
              ['schemaVersion', 'scanId', 'sequence', 'agentVersion', 'policyVersion',
               'machineFingerprint', 'startedAt', 'completedAt', 'observations']),
        'description': 'DeviceId и OrganizationId определяются сессией устройства, а не телом пакета. Лимит '
                       'байтов, idempotency, sequence, окна и время проверяются сервером дополнительно '
                       '(05, «Порядок приёма пакета»). Пакет с completedAt раньше startedAt или observedAt вне '
                       '[startedAt, completedAt] отклоняется 422 batch_time_inconsistent. Время отправки передаётся '
                       'заголовком Sikkerheit-Sent-At каждой попытки и в тело не входит, поэтому повтор отправляет '
                       'те же байты (05, «Время и часы устройства»).',
    }


def graph_observation_schema():
    subjects = {cid: TENANT_SUBJECT if GRAPH_SUBJECTS[cid] == 'tenant' else USER_SUBJECT for cid in GRAPH_IDS}
    return _observation(
        'Sikkerheit M365 Observation', 'm365/graph-observation.schema.json', GRAPH_IDS, subjects,
        GRAPH_EVIDENCE, GRAPH_COLLECTOR_REASONS,
        'Allowlist данных, которые сборщик M365 сохраняет по каждой проверке. Сервер проверяет наблюдение этой '
        'схемой до записи; лишние поля ответа Graph не сохраняются (04, «Минимизация данных»).')


def graph_collection_schema():
    module = obj({'module': enum(*GRAPH_MODULES), 'status': enum(*CAPABILITY_STATUSES)})
    return {
        '$schema': DRAFT, '$id': CONTRACT_BASE + 'm365/graph-collection.schema.json',
        'title': 'Sikkerheit M365 Collection Run',
        **obj({'schemaVersion': {'const': '1.0'}, 'collectionRunId': UUID, 'tenantId': UUID,
               'startedAt': TIME_UTC, 'completedAt': TIME_UTC,
               'state': {**enum('completed', 'partial'), 'description': (
                   'completed — все модули available, license_missing или skipped; иначе partial. Запуск без модулей '
                   'tenant и users наблюдений не даёт и получает failed (05, «Подключение M365 и сбор»).')},
               'entraP1': {**nullable(BOOL), 'description': 'Есть ли в tenant план Entra ID P1 или P2 по '
                                                            'subscribedSkus; null — лицензии прочитать не удалось.'},
               'usersComplete': {**BOOL, 'description': 'Все страницы /users получены; без этого объекты user '
                                                        'не выводятся из учёта (05, «Подключение M365 и сбор»).'},
               'modules': array(module, len(GRAPH_MODULES), len(GRAPH_MODULES), unique=True),
               'observations': array({'$ref': 'graph-observation.schema.json'}, 20000)}),
        'description': 'Результат одного запуска сбора по tenant. Каждый модуль из закрытого перечня имеет '
                       'ровно один статус; оценка выполняется по наблюдениям запуска в одной транзакции.',
    }


# Closed evidence of the server checks (03 «Поддержка ОС и уровень патчей»); published in check-catalog.json.
SERVER_EVIDENCE = {
    'SYS-001': obj({'lastFullScanAt': nullable(TIME_UTC), 'lastSeenAt': nullable(TIME_UTC)}),
    'SYS-002': obj({'product': nullable(enum('windows_10', 'windows_11')), 'family': nullable(enum(*OS_FAMILIES)),
                    'displayVersion': nullable(string(8)), 'build': integer(1), 'architecture': enum('x64', 'arm64'),
                    'servicingEndsAt': nullable(TIME_UTC)}),
    'SYS-003': obj({'branchBuild': integer(1), 'ubr': integer(0), 'deviceSecurityMonth': nullable(MONTH),
                    'expectedSecurityMonth': nullable(MONTH), 'monthsBehind': nullable(integer(0)),
                    'missingKb': nullable(KB), 'verifiedThroughMonth': nullable(MONTH)}),
}
assert list(SERVER_EVIDENCE) == SERVER_IDS, 'Server evidence must cover exactly the SYS checks of the catalog'
DEFAULT_MODES = {c[0]: c[3] for c in CHECKS}
# Starting notApplicableEditionIds that differ from the general default [] (05 «Политика клиента»).
DEFAULT_EDITIONS = {'WIN-002': ['Core', 'CoreN', 'CoreSingleLanguage', 'CoreCountrySpecific']}


def _check_policy(cid, parameters):
    mode = {'const': 'informational'} if cid in ALWAYS_INFORMATIONAL else enum('assessed', 'informational')
    properties = {'assessmentMode': {**mode, 'default': DEFAULT_MODES[cid]},
                  'freshnessWindowHours': integer(1, maximum=720, default=48 if cid in GRAPH_IDS else 72),
                  'parameters': parameters}
    if cid not in GRAPH_IDS:
        properties['notApplicableEditionIds'] = array(EDITION_ID, 64, unique=True,
                                                      default=DEFAULT_EDITIONS.get(cid, []))
    return obj(properties, ['assessmentMode', 'freshnessWindowHours', 'parameters'])


def policy_configuration():
    parameters = {
        'M365-001': obj({'phoneMethodsAccepted': {**BOOL, 'default': True}}),
        'M365-003': obj({'deviceAlternativeAccepted': {**BOOL, 'default': False, 'description': (
                             'Засчитывать grant «MFA или соответствующее либо гибридное устройство».')},
                         'trustedLocationsExclusionAccepted': {**BOOL, 'default': False, 'description': (
                             'Засчитывать политику, которая не требует MFA из доверенных расположений.')}}),
        'M365-002': obj({'privilegedRoleTemplateIds': array(UUID, 50, 1, unique=True,
                                                            default=PRIVILEGED_ROLE_TEMPLATES)}),
        'M365-005': obj({'minGlobalAdmins': integer(0, maximum=10, default=2),
                         'maxGlobalAdmins': integer(1, maximum=20, default=4)}),
        'M365-006': obj({'allowedPermissionGrantPolicies': array(
            CONSENT_POLICY, 10, unique=True, default=['ManagePermissionGrantsForSelf.microsoft-user-default-low'])}),
        'M365-007': obj({'inactiveDays': integer(30, maximum=365, default=90)}),
        'WIN-001': obj({'warnFreePercent': integer(0, maximum=100, default=10),
                        'warnFreeBytes': integer(0, default=10737418240),
                        'criticalFreePercent': integer(0, maximum=100, default=5),
                        'criticalFreeBytes': integer(0, default=2147483648)}),
        'WIN-002': obj({'encryptionRequired': {**BOOL, 'default': True}}),
        'WIN-003': obj({'approvedProviders': array(safe_text(120), 50, unique=True, default=[]),
                        'defenderApproved': {**BOOL, 'default': True}}),
        'WIN-004': obj({'warnDays': integer(1, default=3), 'criticalDays': integer(1, default=7)}),
        'WIN-005': obj({'requiredProfiles': array(enum('domain', 'private', 'public'), 3, unique=True,
                                                  default=['domain', 'private', 'public']),
                        'approvedFirewallProviders': array(safe_text(120), 20, unique=True, default=[])}),
        'WIN-006': obj({'maxSearchAgeDays': integer(1, maximum=60, default=7)}),
        'WIN-007': obj({'warnDays': integer(1, maximum=60, default=3)}),
        'WIN-008': obj({'allowBuiltinAdministrator': {**BOOL, 'default': True},
                        'allowedDomainRids': array(integer(500), 20, unique=True, default=[512]),
                        'allowedSids': array(SID, 100, unique=True, default=[]),
                        'maxOtherLocalAccounts': integer(0, maximum=10, default=0)}),
        'WIN-009': obj({'secureBootRequired': {**BOOL, 'default': True}}),
        'WIN-010': obj({'expectedTenantId': {**nullable(UUID), 'default': None}}),
        'SYS-003': obj({'graceDays': integer(0, maximum=60, default=14),
                        'criticalBehindMonths': integer(2, maximum=12, default=2)}),
    }
    collected = GRAPH_IDS + AGENT_IDS
    return {
        **obj({'activeCheckIds': array({'type': 'string', 'enum': collected}, len(collected), 1, unique=True,
                                       default=list(collected)),
               'm365': obj({'collectionHourLocal': integer(0, maximum=23, default=3),
                            'excludedUserIds': array(UUID, 50, unique=True, default=[], description=(
                                'Учётные записи аварийного доступа и служебные; для них M365-001 и M365-007 '
                                'дают not_applicable/policy_not_applicable. На M365-002 исключение не '
                                'действует.'))}),
               'agent': obj({'scanIntervalHours': integer(1, maximum=168, default=24),
                             'checkInIntervalHours': integer(1, maximum=24, default=4),
                             'scanJitterMinutes': integer(0, maximum=60, default=10),
                             'maxBufferDays': integer(1, maximum=30, default=7),
                             'maxBatchAgeDays': integer(2, maximum=32, default=9)}),
               'checks': obj({cid: _check_policy(cid, parameters.get(cid, obj({}))) for cid in CHECK_IDS})}),
        'description': 'Закрытая конфигурация policy_revision. WIN-011 обязательна в activeCheckIds; assessed без '
                       'входных настроек или для отложенной M365-007, отсутствие WIN-011 и активная WIN-004 без '
                       'WIN-003 дают 422 policy_inputs_missing. maxBatchAgeDays >= maxBufferDays + 1, minGlobalAdmins <= '
                       'maxGlobalAdmins, пороги warning WIN-001 не ниже critical и WIN-004 warnDays <= criticalDays, '
                       'иначе 422 validation_failed. У каждого обязательного поля-значения есть default; политика v1 '
                       'по умолчанию — значения default этой схемы.',
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


def _agent_schemas():
    capability = obj({'module': enum(*GRAPH_MODULES), 'status': enum(*CAPABILITY_STATUSES)})
    return {
        'Capability': capability,
        'ChallengeRequest': {
            **obj({'purpose': enum('enroll', 'session'), 'deviceId': nullable(UUID)}, ['purpose']),
            'allOf': [{'if': {'properties': {'purpose': {'const': 'session'}}, 'required': ['purpose']},
                       'then': {'required': ['deviceId'], 'properties': {'deviceId': UUID}},
                       'else': {'not': {'required': ['deviceId']}}}]},
        'Challenge': obj({'nonce': NONCE, 'expiresAt': TIME_UTC}),
        'PublicKeyJwk': obj({'kty': {'const': 'EC'}, 'crv': {'const': 'P-256'}, 'x': B64_32, 'y': B64_32}),
        'EnrollmentRequest': {
            **obj({'registrationRequestId': UUID, 'installationId': UUID, 'displayName': safe_text(120),
                   'machineFingerprint': FINGERPRINT, 'publicKey': ref('PublicKeyJwk'),
                   'keyProtection': enum('tpm', 'software'), 'nonce': NONCE, 'signature': SIGNATURE,
                   'previousKeySignature': SIGNATURE}, ['registrationRequestId', 'installationId', 'displayName',
                                                        'machineFingerprint', 'publicKey', 'keyProtection', 'nonce',
                                                        'signature']),
            'description': 'signature — подпись ключом publicKey строки "sikkerheit-enroll-v1\\n<nonce>\\n'
                           '<registrationRequestId>\\n<installationId>\\n<machineFingerprint>\\n<keyProtection>\\n'
                           '<JWK thumbprint RFC 7638>" в UTF-8. previousKeySignature — подпись той же строки текущим '
                           'ключом устройства на сервере, когда агент меняет ключ, который у него ещё есть; без неё '
                           'замена ключа идёт через разбор конфликта идентичности. keyProtection — заявление агента, '
                           'для решений доверия не используется.'},
        'Enrollment': obj({'deviceId': UUID, 'enrolledAt': TIME_UTC, 'reenrolled': BOOL}),
        'SessionRequest': {
            **obj({'deviceId': UUID, 'nonce': NONCE, 'signature': SIGNATURE}),
            'description': 'signature — подпись ключом устройства строки "sikkerheit-session-v1\\n<nonce>\\n'
                           '<deviceId>" в UTF-8.'},
        'AgentSession': obj({'accessToken': B64_32, 'expiresAt': TIME_UTC}),
        'CheckIn': obj({'observedAt': TIME_UTC, 'agentVersion': VERSION, 'configSchemaVersion': integer(1),
                        'machineFingerprint': FINGERPRINT, 'reportedDisplayName': safe_text(120),
                        'queueDepth': integer(), 'bufferBytes': integer(), 'droppedBatchCount': integer(),
                        'rejectedBatchCount': integer(), 'configRejected': BOOL, 'serviceStarts': integer(),
                        'lastCrashAt': nullable(TIME_UTC), 'workingSetMb': integer(), 'cpuSeconds': integer(),
                        'abandonedCollectors': integer()}),
        'Configuration': obj({
            'configSchemaVersion': integer(1, description='Версия схемы, которую агент указал в CheckIn.'),
            'policyVersion': integer(1),
            'activeCheckIds': array({'type': 'string', 'enum': AGENT_IDS}, len(AGENT_IDS), 1, unique=True),
            'scanIntervalHours': integer(1, maximum=168), 'checkInIntervalHours': integer(1, maximum=24),
            'scanJitterMinutes': integer(0, maximum=60), 'maxBatchBytes': integer(1, maximum=262144),
            'maxBufferBytes': integer(1, maximum=104857600), 'maxBufferDays': integer(1, maximum=30),
            'lastAcceptedSequence': integer(0), 'lastAcceptedCompletedAt': nullable(TIME_UTC),
            'minimumAgentVersion': VERSION, 'pendingScanRequestId': nullable(UUID), 'serverTime': TIME_UTC}),
        'ScanReceipt': obj({'scanId': UUID, 'sequence': integer(1), 'acceptedAt': TIME_UTC, 'duplicate': BOOL,
                            'clockInconsistent': BOOL}),
    }


def _portal_schemas():
    workflow = enum(*WORKFLOW_STATES)
    return {
        'Organization': {
            **obj({'id': UUID, 'name': safe_text(120), 'timezone': TIMEZONE, 'reportLanguage': enum(*LANGUAGES),
                   'status': enum('active', 'disabled', 'deletion_scheduled'), 'deletionDueAt': nullable(TIME),
                   'createdAt': TIME}),
            'allOf': [{'if': {'properties': {'status': {'const': 'deletion_scheduled'}}, 'required': ['status']},
                       'then': {'properties': {'deletionDueAt': {'type': 'string'}}},
                       'else': {'properties': {'deletionDueAt': {'type': 'null'}}}}]},
        'OrganizationOverview': obj({
            'organization': ref('Organization'), 'm365Status': enum(*CONNECTION_STATUSES),
            'lastCollectedAt': nullable(TIME), 'openCritical': integer(0), 'openWarning': integer(0),
            'activeDevices': integer(0), 'coverageAt': {**nullable(number(0, 1)), 'description': (
                'coverageAt на момент запроса по всем обязательным парам организации; null — нет пар.')}}),
        'OrganizationCreate': obj({'name': safe_text(120), 'timezone': TIMEZONE_CREATE,
                                   'reportLanguage': enum(*LANGUAGES)}),
        'OrganizationUpdate': {**obj({'name': safe_text(120), 'timezone': TIMEZONE,
                                      'reportLanguage': enum(*LANGUAGES)}, []), 'minProperties': 1},
        'OrganizationLifecycleChange': {
            **obj({'action': enum(*LIFECYCLE_ACTIONS),
                   'reason': string(1000, description='Обязательный свободный текст; недоверенная строка. '
                                                     'Сохраняется в details.reason записи аудита '
                                                     'organization.lifecycle_change и выводится только как текст.'),
                   'idempotencyKey': UUID, 'exportWaived': BOOL}, ['action', 'reason', 'idempotencyKey']),
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
            **obj({'id': UUID, 'occurredAt': TIME, 'actorType': enum('staff', 'device', 'system'),
                   'actorId': {**nullable(UUID), 'description': 'entraUserId при staff; deviceId при device; '
                                                                'null при system.'},
                   'action': string(80, pattern=r'^[a-z0-9_]+(\.[a-z0-9_]+)+$'),
                   'targetType': string(40), 'targetId': string(100),
                   'outcome': enum('success', 'denied', 'failed'), 'correlationId': string(100),
                   'details': {'type': ['object', 'null']}}),
            'allOf': _audit_details_branches()},
        'StaffUser': obj({'entraUserId': UUID, 'displayName': nullable(safe_text(120)),
                          'roles': array(enum(*ROLES), len(ROLES), 1, unique=True), 'lastSignInAt': nullable(TIME),
                          'active': {**BOOL, 'description': 'Вход за последние 30 дней и последнее обновление сессии '
                                                            'не отклонено Entra; только активный сотрудник может '
                                                            'быть ответственным.'}}),
        'CurrentStaff': obj({'entraUserId': UUID, 'displayName': nullable(safe_text(120)),
                             'roles': array(enum(*ROLES), len(ROLES), 1, unique=True),
                             'csrfToken': {**B64_32, 'description': 'Значение заголовка X-CSRF-Token для изменений.'}}),
        'PolicyConfiguration': policy_configuration(),
        'PolicyRevision': obj({'version': integer(1), 'effectiveFrom': TIME, 'createdAt': TIME,
                               'createdBy': nullable(UUID), 'configuration': ref('PolicyConfiguration')}),
        'PolicyRevisionCreate': obj({'configuration': ref('PolicyConfiguration')}),
        'TenantConnection': obj({
            'status': enum(*CONNECTION_STATUSES), 'entraTenantId': nullable(UUID),
            'tenantDisplayName': nullable(safe_text(256)), 'primaryDomain': nullable(safe_text(256)),
            'pendingTenantId': nullable(UUID), 'pendingExpiresAt': nullable(TIME), 'connectedAt': nullable(TIME),
            'lastCollectedAt': nullable(TIME),
            'lastCollectionState': nullable(enum('completed', 'partial', 'failed')),
            'entraP1': nullable(BOOL), 'capabilities': array(ref('Capability'), len(GRAPH_MODULES))}),
        'TenantConsentStart': obj({
            'tenantHint': string(255, description='Tenant ID или проверенный домен клиента; домен сервис переводит '
                                                  'в tenant ID через OpenID discovery.'),
            'allowCompanyTenant': {**BOOL, 'default': False, 'description': 'Разрешить tenant самой компании.'}},
            ['tenantHint']),
        'ConsentStart': obj({'consentUrl': string(2048, format='uri',
                                                  pattern='^https://login\\.microsoftonline\\.com/[0-9a-fA-F-]{36}/'),
                             'expectedTenantId': UUID, 'expiresAt': TIME}),
        'CollectionRunCreate': obj({'idempotencyKey': UUID}),
        'CollectionRun': obj({'id': UUID, 'trigger': enum('scheduled', 'manual'),
                              'state': enum('queued', 'running', 'completed', 'partial', 'failed'),
                              'queuedAt': TIME, 'startedAt': nullable(TIME), 'completedAt': nullable(TIME),
                              'failureCode': {**nullable(enum('consent_missing', 'tenant_mismatch', 'credential_error',
                                                              'cancelled', 'run_timeout', 'temporary_error')),
                                              'description': 'run_timeout — 30 минут истекли до чтения пользователей, '
                                                             'или запуск открыт дольше 6 часов и закрыт плановым '
                                                             'заданием (05, «Подключение M365 и сбор»).'},
                              'capabilities': array(ref('Capability'), len(GRAPH_MODULES))}),
        'Subject': obj({'type': enum(*SUBJECT_TYPES), 'key': string(200), 'displayName': nullable(safe_text(256)),
                        'deviceId': nullable(UUID)}),
        'Assessment': {
            **obj({'id': UUID, 'subject': ref('Subject'), 'checkId': enum(*CHECK_IDS), 'ruleId': string(80),
                   'ruleVersion': VERSION, 'sourcePolicyVersion': integer(1), 'evaluatedPolicyVersion': integer(1),
                   'assessmentScope': enum('historical', 'current'),
                   'assessmentMode': enum('assessed', 'informational'),
                   'result': nullable(enum(*RESULTS)), 'severity': nullable(enum('critical', 'warning')),
                   'freshness': enum('fresh', 'stale'), 'reasonCode': nullable(enum(*REASON_CODES)),
                   'observedAt': TIME, 'receivedAt': TIME, 'evidence': {'type': ['object', 'null']},
                   'evidenceAvailability': enum('available', 'expired'), 'explanation': string(2000)}),
            'allOf': [{'if': {'properties': {'assessmentMode': {'const': 'informational'}},
                              'required': ['assessmentMode']},
                       'then': {'properties': {'result': {'type': 'null'}, 'severity': {'type': 'null'},
                                               'reasonCode': nullable(enum(*INFORMATIONAL_REASONS))}},
                       'else': {'properties': {'result': {'type': 'string'}}}},
                      {'if': {'properties': {'result': {'enum': ['pass', 'fail']}}, 'required': ['result']},
                       'then': {'properties': {'reasonCode': {'type': 'null'}}}},
                      {'if': {'properties': {'result': {'const': 'fail'}}, 'required': ['result']},
                       'then': {'properties': {'severity': {'type': 'string'}}},
                       'else': {'properties': {'severity': {'type': 'null'}}}}],
            'description': 'Режим informational: result и severity всегда null, finding не создаётся. reasonCode '
                           'допускается при result unknown или not_applicable, а у informational — только '
                           'переносимые причины отсутствия данных (03, «Семантика результата»).'},
        'Finding': obj({'id': UUID, 'organizationId': UUID, 'checkId': enum(*CHECK_IDS), 'subject': ref('Subject'),
                        'technicalState': enum('open', 'resolved'), 'workflowState': workflow,
                        'assessmentResult': enum(*RESULTS), 'freshness': enum('fresh', 'stale'),
                        'severity': enum('critical', 'warning'), 'revision': integer(1), 'title': string(200),
                        'recommendation': string(2000), 'openedAt': TIME, 'latestObservedAt': TIME,
                        'assigneeId': ASSIGNEE, 'dueAt': nullable(TIME), 'workflowReason': nullable(string(1000)),
                        'reviewAt': nullable(TIME), 'workflowDecidedBy': nullable(UUID)}),
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
                         'description': 'Только завершённая ISO-неделя в timezone организации: periodStart — '
                                        'понедельник 00:00, periodEnd — следующий понедельник 00:00 не позже '
                                        'текущего момента; иные границы, текущая и будущая неделя — 422 '
                                        'validation_failed (05, «Отчёт и покрытие»).'},
        'Report': {**obj({'id': UUID, 'periodStart': TIME, 'periodEnd': TIME, 'timezone': string(80),
                       'language': enum(*LANGUAGES), 'state': enum('queued', 'ready', 'failed'),
                       'format': enum('html'),
                       'failureCode': {**nullable(enum('translation_missing', 'generation_error')),
                                       'description': 'translation_missing — нет перевода; generation_error — '
                                                      'сбой генерации по иной причине.'}}),
                   'description': 'Отчёт ready неизменяем: снимок, записанный при генерации, не переписывается, а '
                                  'потерянный файл строится заново из снимка. Отчёт failed повторный createReport '
                                  'ставит в генерацию заново (05, «Отчёт и покрытие»).'},
        'EnrollmentKeyCreate': obj({'label': safe_text(120)}),
        'EnrollmentKey': obj({'id': UUID, 'enrollmentKey': {**ENROLLMENT_KEY, 'description': (
                                  'Секрет; показывается один раз, хранится только SHA-256.')},
                              'label': safe_text(120), 'createdAt': TIME}),
        'EnrollmentKeySummary': obj({'id': UUID, 'label': safe_text(120),
                                     'keyPrefix': string(9, 9, pattern=r'^sikk_[A-Za-z0-9_-]{4}$'),
                                     'createdAt': TIME, 'createdBy': UUID, 'revokedAt': nullable(TIME),
                                     'lastUsedAt': nullable(TIME), 'enrolledDevices': integer(0)}),
        'Device': obj({'id': UUID, 'displayName': safe_text(120), 'status': enum('active', 'revoked'),
                       'dormant': {**BOOL, 'description': 'Нет check-in дольше 14 суток; устройство вне покрытия.'},
                       'identityState': enum('ok', 'identity_conflict'),
                       'identityConflict': nullable(obj({'at': TIME, 'kind': {**enum('fingerprint', 'key'), 'description': (
                           'fingerprint — не совпал признак машины; key — новый ключ без подписи прежним.')},
                                                         'reportedDisplayName': nullable(safe_text(120))})),
                       'clockStatus': enum('ok', 'inconsistent'), 'keyProtection': enum('tpm', 'software'),
                       'agentVersion': nullable(VERSION),
                       'enrolledAt': TIME, 'lastSeenAt': nullable(TIME), 'lastFullScanAt': nullable(TIME),
                       'enrollmentKeyId': nullable(UUID)}),
        'DeviceIdentityResolution': obj({'decision': enum('accept_new_fingerprint', 'accept_new_key', 'keep')}),
        'WindowsRelease': obj({'product': enum('client'), 'branchBuild': integer(10000), 'ubr': integer(0), 'kb': KB,
                               'releaseAt': TIME, 'kind': enum(*RELEASE_KINDS),
                               'securityMonth': {**nullable(MONTH), 'description': (
                                   'Месяц, исправления безопасности которого включены; null — без исправлений.')},
                               'autoOffered': BOOL, 'state': enum('draft', 'verified'), 'importedBy': UUID}),
        'WindowsReleaseImport': {
            **obj({'source': enum('msrc_cvrf', 'manual'), 'securityMonth': MONTH,
                   'entries': array(obj({'branchBuild': integer(10000), 'ubr': integer(0), 'kb': KB,
                                         'releaseAt': TIME, 'kind': enum(*RELEASE_KINDS),
                                         'securityMonth': nullable(MONTH), 'autoOffered': BOOL}), 100)},
                  ['source', 'securityMonth']),
            'allOf': [{'if': {'properties': {'source': {'const': 'manual'}}, 'required': ['source']},
                       'then': {'required': ['entries']}, 'else': {'not': {'required': ['entries']}}}],
            'description': 'Создаёт записи в состоянии draft; в оценку они попадают только после '
                           'verifyWindowsReleaseMonth.'},
        'WindowsReleaseMonth': obj({'securityMonth': MONTH, 'state': enum('draft', 'verified'),
                                    'releases': integer(0), 'verifiedAt': nullable(TIME), 'verifiedBy': nullable(UUID),
                                    'noNewReleases': BOOL}),
        'WindowsReleaseMonthVerification': obj({'noNewReleases': {**BOOL, 'default': False, 'description': (
            'Подтвердить месяц без новых записей (например, только внеочередные выпуски не для клиентов).')}}),
        'DeviceUpdate': obj({'displayName': safe_text(120)}),
        'ScanRequestCreate': obj({'idempotencyKey': UUID, 'reason': enum('verify_remediation')}),
        'ScanRequest': obj({'id': UUID, 'state': enum('requested', 'delivered', 'completed', 'expired'),
                            'expiresAt': TIME}),
    }


PAGED = ['OrganizationOverview', 'StaffUser', 'PolicyRevision', 'AuditEvent', 'CollectionRun', 'Assessment',
         'Finding', 'FindingEvent', 'Report', 'EnrollmentKeySummary', 'Device', 'WindowsRelease']


def api_schemas(observation, batch):
    schemas = {
        'ScanBatch': batch, 'Observation': observation,
        'Problem': obj({'type': string(500), 'title': string(200), 'status': integer(400, maximum=599),
                        'code': enum(*[code for code, _, _ in PROBLEM_CODES]), 'correlationId': string(100),
                        'detail': string(1000), 'instance': string(500), 'minimumAgentVersion': VERSION},
                       ['type', 'title', 'status', 'code', 'correlationId']),
        **_agent_schemas(), **_portal_schemas(),
    }
    for entity in PAGED:
        schemas[entity + 'Page'] = obj({'items': array(ref(entity), 100), 'nextCursor': nullable(string(2048))})
    return schemas
