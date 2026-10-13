"""OpenAPI operations of the P1 contract: paths, security, responses and headers."""
from contract_catalog import (ACCEPT_LANGUAGE_MAX, AUDIT_ALWAYS, DOWNLOAD_OPERATIONS, LANGUAGES,
                              LOCALIZED_OPERATIONS, MANAGE_ROLES, PLATFORM_ROLES, READ_ROLES,
                              WORKFLOW_STATES)
from contract_schemas import ETAG, UUID, array, enum, integer, ref, string

AGENT_HOST = 'https://agent.example.invalid'
PORTAL_HOST = 'https://portal.example.invalid'
ORG_PATH = '/api/v1/organizations/{organizationId}'

SECURITY = {
    'PortalSession': {'type': 'apiKey', 'in': 'cookie', 'name': '__Host-sikkerheit-session',
                      'description': 'Backend OIDC session, HttpOnly Secure SameSite; role, platform_role '
                                     'and organization checks on every request.'},
    'CsrfToken': {'type': 'apiKey', 'in': 'header', 'name': 'X-CSRF-Token',
                  'description': 'Required together with PortalSession for portal mutations.'},
    'EnrollmentToken': {'type': 'apiKey', 'in': 'header', 'name': 'Authorization',
                        'description': 'Enrollment <token>: organization-scoped single_use or batch token '
                                       'with expiry, maxUses and revocation; never written to logs or MSI.'},
    'DeviceCertificate': {
        'type': 'mutualTLS',
        'description': 'Agent API runs in a dedicated Container Apps environment without other apps and is '
                       'not an environment-level route target. The app accepts exactly one '
                       'X-Forwarded-Client-Cert header, checks Hash = SHA-256 of Cert, builds the chain to the '
                       'internal CA with its own trust (not the system store), requires the hash to be a '
                       'registered device_certificate (pending, active, or superseded within overlap), unexpired '
                       'and unrevoked. Organization and device IDs come only from the certificate.'},
}

ENROLL_DESCRIPTION = (
    'Идемпотентно по registrationRequestId и CSR: повтор возвращает исходный ответ и не увеличивает useCount. '
    'Порядок проверок: (1) токен недействителен — 401 enrollment_token_invalid; (2) тот же '
    'registrationRequestId с тем же телом — идемпотентный повтор прежнего ответа; (3) installationId известен '
    'и устройство отозвано — 409 installation_already_enrolled; (4) machineFingerprint не совпадает — 409 '
    'identity_conflict; (5) у устройства есть pending или active сертификат и reenrollAllowedUntil не задан '
    'или истёк — 409 installation_already_enrolled; (6) иначе новый сертификат тому же deviceId. '
    'reenrollAllowedUntil = now + 7 суток сервер записывает в той же транзакции, в которой отвечает 401 '
    'certificate_expired на mTLS-запрос зарегистрированным сертификатом устройства в состоянии superseded '
    'после окончания перекрытия. В случае (6) при reenrollAllowedUntil > now новый сертификат выдаётся как '
    'pending, прежний active переходит в superseded при первом mTLS-запросе новым, reenrollAllowedUntil '
    'обнуляется в транзакции выдачи, previousCertificateValidUntil = null.')
ERROR_DESCRIPTION = 'Problem с безопасным кодом из каталога Problem.code (05) и correlationId.'
AGENT_SETS = {
    'enrollAgent': ['400', '401', '409', '413', '415', '422', '429', '503'],
    'getAgentConfiguration': ['401', '403', '429', '503'],
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
         'description': 'Непрозрачный cursor, связанный с организацией и фильтром; иначе 400 invalid_cursor.'},
        {'name': 'limit', 'in': 'query', 'schema': integer(1, maximum=100, default=50)}]
ORG = [pathparam('organizationId')]


def _error_codes(operation_id, kind, has_body, if_match):
    if kind in ('device', 'bootstrap'):
        return AGENT_SETS.get(operation_id, AGENT_WRITE_SET)
    if kind == 'portal':
        return PORTAL_GET_SET + (['409'] if operation_id in DOWNLOAD_OPERATIONS else [])
    codes = list(PORTAL_MUTATION_SET)
    if has_body:
        codes += ['413', '415']
    if if_match:
        codes += ['412', '428']
    return codes


def operation(operation_id, summary, kind, code, output=None, request=None, roles=None, parameters=None,
              description=None):
    security = {'device': [{'DeviceCertificate': []}], 'bootstrap': [{'EnrollmentToken': []}],
                'portal': [{'PortalSession': []}],
                'portal_mutation': [{'PortalSession': [], 'CsrfToken': []}]}[kind]
    parameters = list(parameters or [])
    if operation_id in LOCALIZED_OPERATIONS:
        parameters.append(ACCEPT_LANGUAGE)
    if_match = any(p['name'] == 'If-Match' and p.get('required') for p in parameters)
    result = {'operationId': operation_id, 'summary': summary, 'security': security,
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
    if kind == 'portal':
        result['x-audit-read'] = 'always' if operation_id in AUDIT_ALWAYS else 'platform_admin'
    if parameters:
        result['parameters'] = parameters
    if kind == 'device':
        result['servers'] = [{'url': AGENT_HOST, 'description': 'Agent API mTLS host'}]
    success = result['responses'][str(code)]
    if operation_id in LOCALIZED_OPERATIONS:
        success['headers'] = {'Content-Language': header(enum(*LANGUAGES), 'Язык локализованных текстов ответа.')}
    return result


def _add_etag(op):
    success = next(iter(op['responses'].values()))
    success.setdefault('headers', {})['ETag'] = header(ETAG, 'Текущая ревизия в кавычках.')
    return op


def _download(op, content_type, schema, headers):
    op['responses']['200'] = response('Приватная выдача после проверки контекста клиента.', schema,
                                      headers, content_type)
    return op


def _const_header(value, description):
    return header({'type': 'string', 'const': value}, description)


def build_paths():
    device_id = [pathparam('deviceId')]
    finding_id = [pathparam('findingId')]
    entra = [pathparam('entraUserId')]
    export_id = [pathparam('exportId')]
    token_id = [pathparam('tokenId')]
    report_id = [pathparam('reportId')]
    o = ORG_PATH
    paths = {
        '/api/v1/agent/enroll': {'post': operation(
            'enrollAgent', 'Регистрация по токену организации', 'bootstrap', 201, 'DeviceCertificate',
            'EnrollmentRequest', description=ENROLL_DESCRIPTION)},
        '/api/v1/agent/configuration': {'get': operation(
            'getAgentConfiguration', 'Конфигурация устройства', 'device', 200, 'Configuration',
            description='Доступна агенту в состояниях VersionBlocked, Suspended и TrustFailed.')},
        '/api/v1/agent/heartbeat': {'post': operation(
            'submitHeartbeat', 'Подтверждение связи', 'device', 200, 'HeartbeatReceipt', 'Heartbeat')},
        '/api/v1/agent/scans': {'post': operation(
            'submitScan', 'Приём пакета после транзакционной записи', 'device', 202, 'ScanReceipt', 'ScanBatch',
            parameters=[{'name': 'Idempotency-Key', 'in': 'header', 'required': True, 'schema': UUID,
                         'description': 'Равен scanId; повтор тех же байтов возвращает исходный receipt.'}],
            description='Порядок приёма и коды отказа — 05, раздел «Порядок приёма пакета».')},
        '/api/v1/agent/certificate/renew': {'post': operation(
            'renewDeviceCertificate', 'Продление сертификата устройства', 'device', 200, 'DeviceCertificate',
            'RenewalRequest', description='Идемпотентно по renewalRequestId и CSR; другой CSR с тем же id: '
                                          '409 renewal_request_conflict.')},
        '/api/v1/organizations': {
            'get': operation('listOrganizations', 'Доступные клиенты', 'portal', 200, 'OrganizationPage',
                             roles=READ_ROLES, parameters=PAGE),
            'post': operation('createOrganization', 'Создание клиента и политики v1 по умолчанию',
                              'portal_mutation', 201, 'Organization', 'OrganizationCreate', PLATFORM_ROLES)},
        o: {'patch': operation('updateOrganization', 'Изменение имени, timezone или языка отчёта',
                               'portal_mutation', 200, 'Organization', 'OrganizationUpdate', MANAGE_ROLES, ORG)},
        o + '/members': {'get': operation('listOrganizationMembers', 'Назначенные сотрудники', 'portal', 200,
                                          'OrganizationMemberPage', roles=READ_ROLES, parameters=ORG + PAGE)},
        o + '/members/{entraUserId}': {
            'put': operation('putOrganizationMember', 'Назначение сотрудника', 'portal_mutation', 200,
                             'OrganizationMember', 'OrganizationMemberPut', PLATFORM_ROLES, ORG + entra),
            'delete': operation('deleteOrganizationMember', 'Отзыв назначения; повтор даёт 204',
                                'portal_mutation', 204, roles=PLATFORM_ROLES, parameters=ORG + entra)},
        o + '/policy-revisions': {
            'get': operation('listPolicyRevisions', 'Версии клиентской политики', 'portal', 200,
                             'PolicyRevisionPage', roles=READ_ROLES, parameters=ORG + PAGE),
            'post': _add_etag(operation('createPolicyRevision', 'Новая версия политики', 'portal_mutation', 201,
                                        'PolicyRevision', 'PolicyRevisionCreate', MANAGE_ROLES,
                                        ORG + [IF_MATCH]))},
        o + '/lifecycle': {'post': operation(
            'changeOrganizationLifecycle', 'Переход жизненного цикла организации', 'portal_mutation', 202,
            'Organization', 'OrganizationLifecycleChange', PLATFORM_ROLES, ORG,
            description='Повтор с тем же idempotencyKey возвращает прежний результат; недопустимый переход: '
                        '409 lifecycle_transition_forbidden.')},
        o + '/exports': {'post': operation('createOrganizationExport', 'Экспорт данных клиента',
                                           'portal_mutation', 202, 'OrganizationExport',
                                           'OrganizationExportCreate', PLATFORM_ROLES, ORG)},
        o + '/exports/{exportId}': {'get': operation('getOrganizationExport', 'Состояние экспорта', 'portal',
                                                     200, 'OrganizationExport', roles=PLATFORM_ROLES,
                                                     parameters=ORG + export_id)},
        o + '/exports/{exportId}/download': {'get': _download(
            operation('downloadOrganizationExport', 'Выдача файла экспорта', 'portal', 200,
                      roles=PLATFORM_ROLES, parameters=ORG + export_id),
            'application/zip', {'type': 'string', 'format': 'binary'},
            {'Content-Disposition': header(string(200, pattern='^attachment'), 'attachment'),
             'X-Content-Type-Options': _const_header('nosniff', 'Запрет MIME sniffing.'),
             'Cache-Control': _const_header('private, no-store', 'Без кэширования.')})},
        o + '/audit-events': {'get': operation('listAuditEvents', 'Журнал аудита клиента', 'portal', 200,
                                               'AuditEventPage', roles=PLATFORM_ROLES, parameters=ORG + PAGE)},
        o + '/enrollment-tokens': {
            'post': operation('createEnrollmentToken', 'Токен регистрации организации', 'portal_mutation', 201,
                              'EnrollmentToken', 'EnrollmentTokenRequest', MANAGE_ROLES, ORG),
            'get': operation('listEnrollmentTokens', 'Токены регистрации без секрета', 'portal', 200,
                             'EnrollmentTokenSummaryPage', roles=MANAGE_ROLES, parameters=ORG + PAGE)},
        o + '/enrollment-tokens/{tokenId}/revoke': {'post': operation(
            'revokeEnrollmentToken', 'Отзыв токена регистрации', 'portal_mutation', 204, roles=MANAGE_ROLES,
            parameters=ORG + token_id, description='Идемпотентно; сначала журнал жизненного цикла, затем БД.')},
        o + '/devices': {'get': operation(
            'listDevices', 'Устройства клиента', 'portal', 200, 'DevicePage', roles=READ_ROLES,
            parameters=ORG + PAGE + [{'name': 'enrollmentTokenId', 'in': 'query', 'schema': UUID}])},
        o + '/devices/{deviceId}': {'patch': operation(
            'updateDevice', 'Имя устройства', 'portal_mutation', 200, 'Device', 'DeviceUpdate', MANAGE_ROLES,
            ORG + device_id)},
        o + '/devices/{deviceId}/revoke': {'post': operation(
            'revokeDevice', 'Отзыв идентичности устройства', 'portal_mutation', 204, roles=MANAGE_ROLES,
            parameters=ORG + device_id, description='Идемпотентно; сначала журнал жизненного цикла, затем БД.')},
        o + '/devices/{deviceId}/scan-requests': {'post': operation(
            'requestDeviceScan', 'Повторная проверка по фиксированному набору без произвольной команды',
            'portal_mutation', 202, 'ScanRequest', 'ScanRequestCreate', READ_ROLES, ORG + device_id,
            description='Только вариант A. idempotencyKey, срок 24 ч, не больше одного незавершённого '
                        'запроса (requested или delivered) на устройство.')},
        o + '/devices/{deviceId}/assessments': {'get': operation(
            'listDeviceAssessments', 'Оценки и основания по устройству', 'portal', 200, 'AssessmentPage',
            roles=READ_ROLES, parameters=ORG + device_id + PAGE)},
        o + '/findings': {'get': operation(
            'listFindings', 'Проблемы', 'portal', 200, 'FindingPage', roles=READ_ROLES,
            parameters=ORG + PAGE + [
                {'name': 'technicalState', 'in': 'query', 'schema': enum('open', 'resolved')},
                {'name': 'freshness', 'in': 'query', 'schema': enum('fresh', 'stale')},
                {'name': 'deviceId', 'in': 'query', 'schema': UUID},
                {'name': 'workflowState', 'in': 'query', 'style': 'form', 'explode': False,
                 'schema': array(enum(*WORKFLOW_STATES), len(WORKFLOW_STATES), 1, unique=True),
                 'description': 'Несколько значений через запятую, например workflowState=new,in_progress. '
                                'Очередь по умолчанию — technicalState=open&workflowState=new,in_progress.'}])},
        o + '/findings/{findingId}': {
            'get': _add_etag(operation('getFinding', 'Проблема клиента', 'portal', 200, 'Finding',
                                       roles=READ_ROLES, parameters=ORG + finding_id)),
            'patch': _add_etag(operation('patchFinding', 'Workflow, ответственный и срок без подмены оценки',
                                         'portal_mutation', 200, 'Finding', 'FindingPatch', READ_ROLES,
                                         ORG + finding_id + [IF_MATCH]))},
        o + '/findings/{findingId}/risk-decisions': {'post': _add_etag(operation(
            'decideFindingRisk', 'Решение о риске: принятие, подавление или отзыв решения', 'portal_mutation',
            200, 'Finding', 'RiskDecision', MANAGE_ROLES, ORG + finding_id + [IF_MATCH]))},
        o + '/findings/{findingId}/events': {'get': operation(
            'listFindingEvents', 'История проблемы', 'portal', 200, 'FindingEventPage', roles=READ_ROLES,
            parameters=ORG + finding_id + PAGE)},
        o + '/reports': {
            'get': operation('listReports', 'Сформированные отчёты', 'portal', 200, 'ReportPage',
                             roles=READ_ROLES, parameters=ORG + PAGE),
            'post': operation('createReport', 'Задание формирования отчёта', 'portal_mutation', 202,
                              'Report', 'ReportCreate', MANAGE_ROLES, ORG)},
        o + '/reports/{reportId}/download': {'get': _download(
            operation('downloadReport', 'Выдача HTML-отчёта', 'portal', 200, roles=READ_ROLES,
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
    return paths
