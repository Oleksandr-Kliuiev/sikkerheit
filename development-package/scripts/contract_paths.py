"""OpenAPI operations of the contract: paths, phases, security, responses and headers."""
from contract_catalog import (ACCEPT_LANGUAGE_MAX, ADMIN_ROLES, AUDIT_READS, CHECK_IDS, DOWNLOAD_OPERATIONS,
                              LANGUAGES, LOCALIZED_OPERATIONS, READ_ROLES, SUBJECT_TYPES, WORK_ROLES, WORKFLOW_STATES)
from contract_schemas import ETAG, TIME_UTC, UUID, array, enum, integer, ref, string

AGENT_HOST = 'https://agent.example.invalid'
PORTAL_HOST = 'https://portal.example.invalid'
ORG_PATH = '/api/v1/organizations/{organizationId}'
AGENT_PATH = '/api/v1/agent'

SECURITY = {
    'PortalSession': {'type': 'apiKey', 'in': 'cookie', 'name': '__Host-sikkerheit-session',
                      'description': 'Серверная OIDC-сессия сотрудника (Entra ID компании), HttpOnly Secure '
                                     'SameSite=Lax; роль из app roles проверяется на каждом запросе.'},
    'CsrfToken': {'type': 'apiKey', 'in': 'header', 'name': 'X-CSRF-Token',
                  'description': 'Обязателен вместе с PortalSession для изменений; значение — CurrentStaff.csrfToken.'},
    'EnrollmentKey': {'type': 'apiKey', 'in': 'header', 'name': 'Authorization',
                      'description': 'Enrollment <key>: ключ регистрации организации; хранится на сервере только '
                                     'SHA-256, в логи не пишется (04, «Ключ регистрации организации»).'},
    'AgentSession': {'type': 'http', 'scheme': 'bearer',
                     'description': 'Сессионный токен устройства на 60 минут, полученный createAgentSession по '
                                    'подписи ключа устройства. Сервер хранит SHA-256 токена и на каждом запросе '
                                    'проверяет срок, статус устройства и организации по БД, без кэша.'},
}

ERROR_DESCRIPTION = 'Problem с безопасным кодом из каталога Problem.code (05) и correlationId.'
AGENT_SETS = {
    'createAgentChallenge': ['400', '413', '415', '422', '429', '503'],
    'enrollAgent': ['400', '401', '403', '409', '413', '415', '422', '429', '503'],
    'createAgentSession': ['400', '401', '403', '413', '415', '422', '429', '503'],
}
AGENT_WRITE_SET = ['400', '401', '403', '409', '413', '415', '422', '429', '503']
PORTAL_GET_SET = ['400', '401', '403', '404', '429', '503']
PORTAL_MUTATION_SET = ['400', '401', '403', '404', '409', '422', '429', '503']


def response(description, schema=None, headers=None, content_type='application/json'):
    item = {'description': description}
    if schema:
        item['content'] = {content_type: {'schema': schema}}
    if headers:
        item['headers'] = headers
    return item


def header(schema, description):
    return {'schema': schema, 'description': description}


def pathparam(name, schema=UUID):
    return {'name': name, 'in': 'path', 'required': True, 'schema': schema}


IF_MATCH = {'name': 'If-Match', 'in': 'header', 'required': True, 'schema': ETAG,
            'description': 'Текущая ревизия в кавычках. Устаревшая: 412 revision_mismatch; '
                           'отсутствует: 428 if_match_required.'}
ACCEPT_LANGUAGE = {'name': 'Accept-Language', 'in': 'header', 'required': False,
                   'schema': string(ACCEPT_LANGUAGE_MAX),
                   'description': 'Язык title, recommendation и explanation. Принимаются nb, nn и en; без '
                                  'заголовка или при любом другом значении используется nb, ошибки нет.'}
PAGE = [{'name': 'cursor', 'in': 'query', 'schema': string(2048),
         'description': 'Непрозрачный cursor, связанный с запросом и фильтром; иначе 400 invalid_cursor.'},
        {'name': 'limit', 'in': 'query', 'schema': integer(1, maximum=100, default=50)}]
ORG = [pathparam('organizationId')]
FINDING_FILTERS = [
    {'name': 'technicalState', 'in': 'query', 'schema': enum('open', 'resolved')},
    {'name': 'freshness', 'in': 'query', 'schema': enum('fresh', 'stale')},
    {'name': 'severity', 'in': 'query', 'schema': enum('critical', 'warning')},
    {'name': 'checkId', 'in': 'query', 'schema': enum(*CHECK_IDS)},
    {'name': 'workflowState', 'in': 'query', 'style': 'form', 'explode': False,
     'schema': array(enum(*WORKFLOW_STATES), len(WORKFLOW_STATES), 1, unique=True),
     'description': 'Несколько значений через запятую, например workflowState=new,in_progress. '
                    'Очередь по умолчанию — technicalState=open&workflowState=new,in_progress.'}]


def _error_codes(operation_id, kind, has_body, if_match):
    if kind in ('agent', 'agent_bootstrap'):
        return AGENT_SETS.get(operation_id, AGENT_WRITE_SET)
    if kind == 'portal':
        return PORTAL_GET_SET + (['409'] if operation_id in DOWNLOAD_OPERATIONS else [])
    codes = list(PORTAL_MUTATION_SET)
    if has_body:
        codes += ['413', '415']
    if if_match:
        codes += ['412', '428']
    return codes


def operation(operation_id, summary, phase, kind, code, output=None, request=None, roles=None, parameters=None,
              description=None, security=None):
    default_security = {'agent': [{'AgentSession': []}], 'agent_bootstrap': [{}],
                        'portal': [{'PortalSession': []}],
                        'portal_mutation': [{'PortalSession': [], 'CsrfToken': []}]}[kind]
    parameters = list(parameters or [])
    if operation_id in LOCALIZED_OPERATIONS:
        parameters.append(ACCEPT_LANGUAGE)
    if_match = any(p['name'] == 'If-Match' and p.get('required') for p in parameters)
    result = {'operationId': operation_id, 'summary': summary, 'x-phase': phase,
              'security': security or default_security,
              'responses': {str(code): response('Успешный результат по семантике 05-data-and-api.md.',
                                                ref(output) if output else None)}}
    if description:
        result['description'] = description
    for error in sorted(_error_codes(operation_id, kind, bool(request), if_match)):
        retry = {'Retry-After': header(integer(1), 'Seconds before retry.')} if error in ('429', '503') else None
        result['responses'][error] = response(ERROR_DESCRIPTION, ref('Problem'), retry, 'application/problem+json')
    if request:
        result['requestBody'] = {'required': True, 'content': {'application/json': {'schema': ref(request)}}}
    if roles:
        result['x-allowed-roles'] = roles
    if operation_id in AUDIT_READS:
        result['x-audit-read'] = True
    if parameters:
        result['parameters'] = parameters
    if kind.startswith('agent'):
        result['servers'] = [{'url': AGENT_HOST, 'description': 'Hostname агента того же сервиса'}]
    success = result['responses'][str(code)]
    if operation_id in LOCALIZED_OPERATIONS:
        success['headers'] = {'Content-Language': header(enum(*LANGUAGES), 'Язык локализованных текстов ответа.')}
    return result


def _add_etag(op):
    success = next(iter(op['responses'].values()))
    success.setdefault('headers', {})['ETag'] = header(ETAG, 'Текущая ревизия в кавычках.')
    return op


def _download(op, content_type, schema, headers):
    op['responses']['200'] = response('Приватная выдача после проверки организации и роли.', schema,
                                      headers, content_type)
    return op


def _const_header(value, description):
    return header({'type': 'string', 'const': value}, description)


def _agent_paths():
    a = AGENT_PATH
    return {
        a + '/challenges': {'post': operation(
            'createAgentChallenge', 'Одноразовый nonce для регистрации или сессии', 'P2', 'agent_bootstrap', 201,
            'Challenge', 'ChallengeRequest', description=(
                'Без аутентификации; лимит частоты по IP. Тело больше 1024 байт — 413. Для purpose=session '
                'deviceId обязателен; nonce связан с purpose и deviceId (05, «Регистрация и сессия»).'))},
        a + '/enrollments': {'post': operation(
            'enrollAgent', 'Регистрация устройства ключом организации', 'P2', 'agent_bootstrap', 201, 'Enrollment',
            'EnrollmentRequest', security=[{'EnrollmentKey': []}], description=(
                'Тело больше 16384 байт — 413 payload_too_large до разбора JSON. Идемпотентно по '
                'registrationRequestId: идентичный повтор в течение 24 ч возвращает прежний ответ. Порядок проверок '
                'и коды отказа — 05, «Регистрация и сессия».'))},
        a + '/sessions': {'post': operation(
            'createAgentSession', 'Сессионный токен по подписи ключа устройства', 'P2', 'agent_bootstrap', 201,
            'AgentSession', 'SessionRequest', description=(
                'Nonce одноразовый и связан с deviceId; неизвестное устройство — 401 device_unknown, отозванное — '
                '401 device_revoked (05, «Регистрация и сессия»).'))},
        a + '/check-ins': {'post': operation(
            'agentCheckIn', 'Подтверждение связи и конфигурация устройства', 'P2', 'agent', 200, 'Configuration',
            'CheckIn', description='Доступна агенту в состояниях VersionBlocked, Suspended и IdentityConflict.')},
        a + '/scans': {'post': operation(
            'submitScan', 'Синхронный приём и оценка пакета', 'P2', 'agent', 200, 'ScanReceipt', 'ScanBatch',
            parameters=[{'name': 'Idempotency-Key', 'in': 'header', 'required': True, 'schema': UUID,
                         'description': 'Равен scanId; повтор тех же байтов возвращает исходный receipt.'},
                        {'name': 'Sikkerheit-Sent-At', 'in': 'header', 'required': True, 'schema': TIME_UTC,
                         'description': 'Время ПК в момент этой попытки; не входит в тело и payloadHash. По нему '
                                        'считаются возраст пакета и признак часов.'}],
            description='Ответ 200 после записи и оценки в одной транзакции; порядок — 05, «Порядок приёма пакета».')},
    }


def _organization_paths():
    o = ORG_PATH
    export_id = [pathparam('exportId')]
    return {
        '/api/v1/me': {'get': operation('getCurrentStaff', 'Текущий сотрудник, роли и CSRF-токен', 'P1', 'portal',
                                        200, 'CurrentStaff', roles=READ_ROLES)},
        '/api/v1/staff': {'get': operation('listStaff', 'Сотрудники, входившие в портал', 'P1', 'portal', 200,
                                           'StaffUserPage', roles=READ_ROLES, parameters=PAGE, description=(
                                               'Источник значений FindingPatch.assigneeId.'))},
        '/api/v1/organizations': {
            'get': operation('listOrganizations', 'Клиенты с краткой сводкой', 'P1', 'portal', 200,
                             'OrganizationOverviewPage', roles=READ_ROLES, parameters=PAGE, description=(
                                 'Чтение во всех организациях (область чтения all, 02 «Разделение клиентов»).')),
            'post': operation('createOrganization', 'Создание клиента и политики v1 по умолчанию', 'P1',
                              'portal_mutation', 201, 'Organization', 'OrganizationCreate', ADMIN_ROLES)},
        o: {'get': operation('getOrganization', 'Клиент', 'P1', 'portal', 200, 'Organization', roles=READ_ROLES,
                             parameters=ORG),
            'patch': operation('updateOrganization', 'Изменение имени, timezone или языка отчёта', 'P1',
                               'portal_mutation', 200, 'Organization', 'OrganizationUpdate', ADMIN_ROLES, ORG)},
        o + '/lifecycle': {'post': operation(
            'changeOrganizationLifecycle', 'Переход жизненного цикла организации', 'P1', 'portal_mutation', 200,
            'Organization', 'OrganizationLifecycleChange', ADMIN_ROLES, ORG,
            description='Повтор с тем же idempotencyKey возвращает прежний результат; недопустимый переход: '
                        '409 lifecycle_transition_forbidden. Ограничивающие переходы сначала пишутся в журнал '
                        'безопасности (04).')},
        o + '/exports': {'post': operation('createOrganizationExport', 'Экспорт данных клиента', 'P1',
                                           'portal_mutation', 202, 'OrganizationExport', 'OrganizationExportCreate',
                                           ADMIN_ROLES, ORG)},
        o + '/exports/{exportId}': {'get': operation('getOrganizationExport', 'Состояние экспорта', 'P1', 'portal',
                                                     200, 'OrganizationExport', roles=ADMIN_ROLES,
                                                     parameters=ORG + export_id)},
        o + '/exports/{exportId}/download': {'get': _download(
            operation('downloadOrganizationExport', 'Выдача файла экспорта', 'P1', 'portal', 200,
                      roles=ADMIN_ROLES, parameters=ORG + export_id),
            'application/zip', {'type': 'string', 'format': 'binary'},
            {'Content-Disposition': header(string(200, pattern='^attachment'), 'attachment'),
             'X-Content-Type-Options': _const_header('nosniff', 'Запрет MIME sniffing.'),
             'Cache-Control': _const_header('private, no-store', 'Без кэширования.')})},
        o + '/audit-events': {'get': operation('listAuditEvents', 'Журнал аудита клиента', 'P1', 'portal', 200,
                                               'AuditEventPage', roles=ADMIN_ROLES, parameters=ORG + PAGE)},
        o + '/policy-revisions': {
            'get': operation('listPolicyRevisions', 'Версии политики клиента', 'P1', 'portal', 200,
                             'PolicyRevisionPage', roles=READ_ROLES, parameters=ORG + PAGE),
            'post': _add_etag(operation('createPolicyRevision', 'Новая версия политики', 'P1', 'portal_mutation',
                                        201, 'PolicyRevision', 'PolicyRevisionCreate', ADMIN_ROLES,
                                        ORG + [IF_MATCH]))},
    }


def _m365_paths():
    o = ORG_PATH
    return {
        o + '/m365-connection': {'get': operation('getTenantConnection', 'Подключение Microsoft 365', 'P1',
                                                  'portal', 200, 'TenantConnection', roles=READ_ROLES,
                                                  parameters=ORG)},
        o + '/m365-connection/consent': {'post': operation(
            'startTenantConsent', 'Ссылка admin consent для ожидаемого tenant клиента', 'P1', 'portal_mutation', 201,
            'ConsentStart', 'TenantConsentStart', ADMIN_ROLES, ORG, description=(
                'tenantHint переводится в expectedTenantId; ссылка ведёт только в этот tenant и действует 7 суток. '
                'Tenant компании — только при allowCompanyTenant=true, иначе 422 validation_failed; tenant другой '
                'организации или отличный от действующего подключения — 409 tenant_conflict (05, «Подключение M365 '
                'и сбор»).'))},
        o + '/m365-connection/verify': {'post': operation(
            'verifyTenantConnection', 'Проверка consent и активация подключения', 'P1', 'portal_mutation', 200,
            'TenantConnection', roles=ADMIN_ROLES, parameters=ORG, description=(
                'Получает токен для ожидаемого tenant и сверяет его запросом /organization; без ожидаемого tenant — '
                '409 connection_state_conflict, без consent — 422 consent_not_granted. Повтор после успеха '
                'возвращает активное подключение.'))},
        o + '/m365-connection/disconnect': {'post': operation(
            'disconnectTenant', 'Отключение Microsoft 365', 'P1', 'portal_mutation', 200, 'TenantConnection',
            roles=ADMIN_ROLES, parameters=ORG, description=(
                'Идемпотентно; сначала журнал безопасности. Удалить приложение в tenant клиента — RB-03.'))},
        o + '/collection-runs': {
            'get': operation('listCollectionRuns', 'Запуски сбора Microsoft 365', 'P1', 'portal', 200,
                             'CollectionRunPage', roles=READ_ROLES, parameters=ORG + PAGE),
            'post': operation('requestCollection', 'Внеплановый сбор Microsoft 365', 'P1', 'portal_mutation', 202,
                              'CollectionRun', 'CollectionRunCreate', WORK_ROLES, ORG, description=(
                                  'Подключение не active — 409 connection_state_conflict. Один незавершённый '
                                  'запуск на организацию объединяет повторные запросы.'))},
    }


def _finding_paths():
    o = ORG_PATH
    finding_id = [pathparam('findingId')]
    report_id = [pathparam('reportId')]
    return {
        '/api/v1/findings': {'get': operation(
            'listFindingsAcrossOrganizations', 'Очередь проблем всех клиентов', 'P1', 'portal', 200, 'FindingPage',
            roles=READ_ROLES, parameters=PAGE + FINDING_FILTERS, description=(
                'Чтение во всех организациях (область чтения all, 02 «Разделение клиентов»).'))},
        o + '/assessments': {'get': operation(
            'listAssessments', 'Оценки и основания', 'P1', 'portal', 200, 'AssessmentPage', roles=READ_ROLES,
            parameters=ORG + PAGE + [
                {'name': 'subjectType', 'in': 'query', 'schema': enum(*SUBJECT_TYPES)},
                {'name': 'subjectKey', 'in': 'query', 'schema': string(200)},
                {'name': 'checkId', 'in': 'query', 'schema': enum(*CHECK_IDS)},
                {'name': 'scope', 'in': 'query', 'schema': enum('current', 'all'),
                 'description': 'current (по умолчанию) — текущие проекции; all — вся история.'}])},
        o + '/findings': {'get': operation('listFindings', 'Проблемы клиента', 'P1', 'portal', 200, 'FindingPage',
                                           roles=READ_ROLES, parameters=ORG + PAGE + FINDING_FILTERS)},
        o + '/findings/{findingId}': {
            'get': _add_etag(operation('getFinding', 'Проблема', 'P1', 'portal', 200, 'Finding', roles=READ_ROLES,
                                       parameters=ORG + finding_id)),
            'patch': _add_etag(operation('patchFinding', 'Workflow, ответственный и срок без подмены оценки', 'P1',
                                         'portal_mutation', 200, 'Finding', 'FindingPatch', WORK_ROLES,
                                         ORG + finding_id + [IF_MATCH]))},
        o + '/findings/{findingId}/risk-decisions': {'post': _add_etag(operation(
            'decideFindingRisk', 'Решение о риске: принятие, подавление или отзыв решения', 'P1', 'portal_mutation',
            200, 'Finding', 'RiskDecision', ADMIN_ROLES, ORG + finding_id + [IF_MATCH]))},
        o + '/findings/{findingId}/events': {'get': operation(
            'listFindingEvents', 'История проблемы', 'P1', 'portal', 200, 'FindingEventPage', roles=READ_ROLES,
            parameters=ORG + finding_id + PAGE)},
        o + '/reports': {
            'get': operation('listReports', 'Сформированные отчёты', 'P1', 'portal', 200, 'ReportPage',
                             roles=READ_ROLES, parameters=ORG + PAGE),
            'post': operation('createReport', 'Формирование отчёта за неделю', 'P1', 'portal_mutation', 202,
                              'Report', 'ReportCreate', WORK_ROLES, ORG)},
        o + '/reports/{reportId}/download': {'get': _download(
            operation('downloadReport', 'Выдача HTML-отчёта', 'P1', 'portal', 200, roles=READ_ROLES,
                      parameters=ORG + report_id),
            'text/html', {'type': 'string'},
            {'Content-Disposition': header(string(200, pattern=r'^attachment; filename="report-[0-9a-fA-F-]{36}\.html"$'),
                                           'attachment; filename="report-<reportId>.html"'),
             'Content-Security-Policy': _const_header(
                 "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:",
                 'Отчёт без скриптов и внешних ресурсов.'),
             'X-Content-Type-Options': _const_header('nosniff', 'Запрет MIME sniffing.'),
             'Cache-Control': _const_header('private, no-store', 'Без кэширования.')})},
    }


def _device_paths():
    o = ORG_PATH
    device_id = [pathparam('deviceId')]
    key_id = [pathparam('keyId')]
    return {
        o + '/enrollment-keys': {
            'post': operation('createEnrollmentKey', 'Ключ регистрации агентов организации', 'P2', 'portal_mutation',
                              201, 'EnrollmentKey', 'EnrollmentKeyCreate', ADMIN_ROLES, ORG, description=(
                                  'Секрет показывается один раз. Активных ключей у организации не больше двух.')),
            'get': operation('listEnrollmentKeys', 'Ключи регистрации без секрета', 'P2', 'portal', 200,
                             'EnrollmentKeySummaryPage', roles=ADMIN_ROLES, parameters=ORG + PAGE)},
        o + '/enrollment-keys/{keyId}/revoke': {'post': operation(
            'revokeEnrollmentKey', 'Отзыв ключа регистрации', 'P2', 'portal_mutation', 204, roles=ADMIN_ROLES,
            parameters=ORG + key_id, description='Идемпотентно; сначала журнал безопасности.')},
        o + '/devices': {'get': operation(
            'listDevices', 'Устройства клиента', 'P2', 'portal', 200, 'DevicePage', roles=READ_ROLES,
            parameters=ORG + PAGE + [{'name': 'enrollmentKeyId', 'in': 'query', 'schema': UUID},
                                     {'name': 'status', 'in': 'query', 'schema': enum('active', 'revoked')}])},
        o + '/devices/{deviceId}': {'patch': operation(
            'updateDevice', 'Имя устройства', 'P2', 'portal_mutation', 200, 'Device', 'DeviceUpdate', ADMIN_ROLES,
            ORG + device_id)},
        o + '/devices/{deviceId}/revoke': {'post': operation(
            'revokeDevice', 'Отзыв устройства', 'P2', 'portal_mutation', 204, roles=ADMIN_ROLES,
            parameters=ORG + device_id, description='Идемпотентно; сначала журнал безопасности.')},
        o + '/devices/{deviceId}/identity-resolutions': {'post': operation(
            'resolveDeviceIdentity', 'Разбор конфликта идентичности устройства', 'P2', 'portal_mutation', 200,
            'Device', 'DeviceIdentityResolution', ADMIN_ROLES, ORG + device_id, description=(
                'accept_new_fingerprint принимает последний несовпавший признак машины (замена платы); keep '
                'оставляет прежний, клон продолжает получать 409 identity_conflict. Без конфликта возвращает '
                'устройство без изменений (05, «Субъекты и идентичность устройства»).'))},
        o + '/devices/{deviceId}/scan-requests': {'post': operation(
            'requestDeviceScan', 'Повторная проверка фиксированного набора без произвольной команды', 'P2',
            'portal_mutation', 202, 'ScanRequest', 'ScanRequestCreate', WORK_ROLES, ORG + device_id,
            description='idempotencyKey, срок 24 ч, не больше одного незавершённого запроса на устройство.')},
    }


def _release_paths():
    month = [pathparam('securityMonth', string(7, 7, pattern=r'^[0-9]{4}-(0[1-9]|1[0-2])$'))]
    return {
        '/api/v1/windows-releases': {'get': operation(
            'listWindowsReleases', 'Каталог выпусков Windows', 'P2', 'portal', 200, 'WindowsReleasePage',
            roles=READ_ROLES, parameters=PAGE + [{'name': 'securityMonth', 'in': 'query', 'schema': month[0]['schema']},
                                                 {'name': 'state', 'in': 'query', 'schema': enum('draft', 'verified')}],
            description='Платформенные данные правила SYS-003 (03, «Правило SYS-003 и каталог выпусков»).')},
        '/api/v1/windows-releases/imports': {'post': operation(
            'importWindowsReleases', 'Черновик записей каталога за месяц', 'P2', 'portal_mutation', 202,
            'WindowsReleaseMonth', 'WindowsReleaseImport', ADMIN_ROLES, description=(
                'Импорт из MSRC CVRF или ручной ввод; записи draft в оценку не попадают; автор — importedBy.'))},
        '/api/v1/windows-releases/months/{securityMonth}/verify': {'post': operation(
            'verifyWindowsReleaseMonth', 'Сверка и ввод месяца в действие', 'P2', 'portal_mutation', 200,
            'WindowsReleaseMonth', 'WindowsReleaseMonthVerification', ADMIN_ROLES, month, description=(
                'Переводит записи месяца в verified и сдвигает verifiedThroughMonth; месяц без записей — только с '
                'noNewReleases=true; повтор идемпотентен; ставит пересчёт SYS-003.'))},
    }


def build_paths():
    paths = {}
    for part in (_organization_paths, _m365_paths, _finding_paths, _device_paths, _release_paths, _agent_paths):
        paths.update(part())
    return paths
