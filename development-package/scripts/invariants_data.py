"""Registry of invariants that JSON Schema does not express (source of specs/invariants.json).

IDs are assigned in list order: P1, then P2, then P1_ADDED. New records go to the end of the last
block, so that existing INV-nnn identifiers stay stable.
"""

DOCS = {'02': '02-architecture-and-stack.md', '03': '03-check-catalog.md', '04': '04-security-and-privacy.md',
        '05': '05-data-and-api.md', '06': '06-azure-and-operations.md'}

INTAKE = ('05', 'Порядок приёма пакета')
UNIQUE = ('05', 'Уникальность и ожидаемые объекты')
CLOCK = ('05', 'Время и часы устройства')
EXTRA = ('05', 'Инварианты вне JSON Schema')
ERRORS = ('05', 'Ошибки и действия агента')
AGENT_FSM = ('05', 'Конечный автомат агента')
LIFECYCLE = ('05', 'Жизненный цикл организации')
TRANSITIONS = ('05', 'Таблица переходов finding')
WORKFLOW = ('05', 'Автомат workflowState')
CURRENT = ('05', 'Выбор текущего состояния')
IDENTITY = ('05', 'Канонический объект и идентичность устройства')
PORTAL = ('05', 'API портала')
REPORT = ('05', 'Отчёт и покрытие')
SEMANTICS = ('03', 'Семантика результата')
WINDOWS = ('03', 'Проверки Windows')
OS_MATRIX = ('03', 'Матрица совместимости и жизненный цикл ОС')
ENROLL = ('04', 'Enrollment-токены')
CERT = ('04', 'Профиль и продление сертификата')
XFCC = ('04', 'Доверие ingress и XFCC')
ROLES = ('04', 'Вход в портал и роли')
UNTRUSTED = ('04', 'Недоверенные строки и выдача отчёта')
LOCAL = ('02', 'Выполнение локальной проверки')
JOBS = ('02', 'Очередь заданий')
TENANCY = ('02', 'Разделение клиентов')
RESTORE = ('06', 'Журнал жизненного цикла и restore в карантине')
M365 = ('03', 'Проверки Microsoft 365')
CAPABILITY = ('03', 'Возможности интеграции')
GRAPH = ('04', 'Разрешения интеграций')
AGENT_API = ('05', 'API агента')
CONTEXT = ('04', 'Контекст организации и аудит PlatformAdmin')
WIN006 = ('03', 'Правило WIN-006')


def http(status, code):
    return {'http': status, 'code': code}


def result(mode, value, reason=None):
    return {'assessmentMode': mode, 'result': value, **({'reasonCode': reason} if reason else {})}


def event(event_type, cause):
    return {'event': {'eventType': event_type, 'cause': cause}}


# (rule, sourceDoc, enforcement, negativeExample, expectedError, acceptance)
P1 = [
    # Agent API intake (order of checks: 05 «Порядок приёма пакета»).
    ('Тело submitScan с Content-Encoding или Content-Type не application/json отклоняется до разбора JSON.',
     INTAKE, 'agent_api', 'Пакет с Content-Encoding: gzip.', http(415, 'unsupported_media_type'), 'AT-04'),
    ('Тело submitScan больше maxBatchBytes отклоняется до разбора.', INTAKE, 'agent_api',
     'Пакет размером maxBatchBytes + 1 байт.', http(413, 'payload_too_large'), 'AT-04'),
    ('Тело, которое не разбирается как JSON, отклоняется; агент удаляет пакет.', INTAKE, 'agent_api',
     'Обрезанный JSON в submitScan.', http(400, 'invalid_json'), 'AT-04'),
    ('Повтор с тем же Idempotency-Key и теми же байтами возвращает исходный receipt без повторной оценки '
     'независимо от возраста пакета.', INTAKE, 'agent_api',
     'Потеря ответа и повтор после границы maxBatchAgeDays.', {'replay': {'http': 202, 'duplicate': True}}, 'AT-04'),
    ('Тот же Idempotency-Key с другими байтами отклоняется.', INTAKE, 'agent_api',
     'Повтор scanId с изменённым observedAt.', http(409, 'idempotency_conflict'), 'AT-04'),
    ('scanId в теле равен заголовку Idempotency-Key.', INTAKE, 'agent_api',
     'Idempotency-Key отличается от scanId.', http(422, 'schema_violation'), 'AT-04'),
    ('agentVersion ниже minimumAgentVersion отклоняется, Problem содержит minimumAgentVersion.', INTAKE,
     'agent_api', 'agentVersion 0.0.9 при minimumAgentVersion 0.1.0.', http(422, 'agent_version_unsupported'),
     'AT-13'),
    ('Неподдерживаемый schemaVersion отклоняется.', INTAKE, 'agent_api', 'schemaVersion 2.0.',
     http(422, 'unsupported_schema_version'), 'AT-04'),
    ('machineFingerprint пакета совпадает с зафиксированным при регистрации.', IDENTITY, 'agent_api',
     'Клон VM отправляет пакет с другим признаком машины.', http(409, 'identity_conflict'), 'AT-04'),
    ('Пакет старше maxBatchAgeDays по completedAt относительно receivedAt отклоняется.', INTAKE, 'agent_api',
     'Пакет возрастом maxBufferDays + 3 суток.', http(422, 'batch_too_old'), 'AT-04'),
    ('Внутренне противоречивый пакет — completedAt раньше startedAt либо observedAt вне [startedAt, completedAt] — '
     'отклоняется. Метки позже receivedAt + 5 мин пакет не отклоняют, а метки времени внутри evidence при приёме '
     'не проверяются.', CLOCK, 'agent_api', 'observedAt наблюдения WIN-005 на 2 мин позже completedAt пакета.',
     http(422, 'batch_time_inconsistent'), 'AT-04'),
    ('policyVersion пакета известна серверу и не из будущего.', INTAKE, 'agent_api',
     'policyVersion больше текущей версии политики.', http(422, 'unknown_policy_version'), 'AT-06'),
    ('Тот же sequence с другим scanId вызывает ресинхронизацию, не чаще раза в 24 ч.', IDENTITY, 'agent_api',
     'Восстановление VM из checkpoint повторяет sequence.', http(409, 'sequence_conflict'), 'AT-04'),
    ('Ресинхронизация sequence пишется в аудит устройства.', IDENTITY, 'agent_api',
     'Принятая ресинхронизация после sequence_conflict.', {'audit': 'device.sequence_rollback'}, 'AT-04'),
    ('checkId из каталога вне activeCheckIds версии политики пакета отклоняется.', UNIQUE, 'agent_api',
     'Наблюдение WIN-008 при activeCheckIds без WIN-008.', http(422, 'unknown_check_id'), 'AT-04'),
    ('Ключ (checkId, subject.type, localKey) уникален внутри пакета.', UNIQUE, 'agent_api',
     'Два наблюдения WIN-005 с subject.type=device.', http(422, 'duplicate_observation'), 'AT-04'),
    ('Для WIN-001 и WIN-002 ожидается ровно один volume с role=os; лишний объект отклоняется.', UNIQUE,
     'agent_api', 'Два тома с role=os для WIN-001.', http(422, 'unexpected_subject'), 'AT-04'),
    ('freeBytes не больше totalBytes (межполевой инвариант тела).', EXTRA, 'agent_api',
     'WIN-001 с freeBytes больше totalBytes.', http(422, 'schema_violation'), 'AT-05'),
    ('В режиме assessed отсутствующая ожидаемая пара даёт unknown без отклонения пакета.', UNIQUE, 'worker',
     'Пакет без наблюдения WIN-005 при активной WIN-005.', result('assessed', 'unknown', 'missing_observation'), 'AT-04'),
    ('Пакет с признаком часов сохраняется в истории и не меняет текущую проекцию. Признак действует на все '
     'оценки пакета: assessed получают unknown, informational — result=null, обе с clock_inconsistent.', CLOCK,
     'worker', 'completedAt раньше maxAcceptedSourceTime при большем sequence.',
     result('assessed', 'unknown', 'clock_inconsistent'), 'AT-04'),
    ('Рост droppedBatchCount в heartbeat пишется в аудит устройства.', INTAKE, 'agent_api',
     'droppedBatchCount вырос с 0 до 2.', {'audit': 'device.data_loss'}, 'AT-04'),
    # Identity, enrollment and certificates.
    ('Истёкший, отозванный или исчерпанный enrollment-токен и токен неактивной организации не регистрируют '
     'устройство; при конкурентных запросах создаётся не больше maxUses записей enrollment (гарантия транзакции '
     'регистрации Portal API); идентичный повтор записанной регистрации в окне 7 суток регистрацией не считается.',
     ENROLL, 'portal_api',
     'Одиннадцатая регистрация пакетным токеном с maxUses 10.', http(401, 'enrollment_token_invalid'), 'AT-02'),
    ('Проверки enrollAgent выполняются в едином порядке 05, раздел «API агента»; первая сработавшая определяет '
     'ответ. В частности, идемпотентный повтор (шаг 2) проверяется раньше срока, отзыва и исчерпания токена, а '
     'active-сертификат с validTo > now при reenrollAllowedUntil, который не задан или истёк, даёт 409 '
     'installation_already_enrolled (шаг 7; неактивированный pending не учитывается).',
     AGENT_API, 'portal_api',
     'enrollAgent с installationId активного устройства с действующим active-сертификатом, новым '
     'registrationRequestId и reenrollAllowedUntil=null.',
     http(409, 'installation_already_enrolled'), 'AT-02'),
    ('Agent API принимает ровно один X-Forwarded-Client-Cert с зарегистрированным hash и цепочкой '
     'внутреннего CA.', XFCC, 'agent_api', 'Дублированный XFCC или XFCC из соседнего приложения.',
     http(401, 'certificate_unknown'), 'AT-02'),
    ('Тот же renewalRequestId с другим CSR отклоняется.', CERT, 'agent_api',
     'Повтор renew с тем же id и новым CSR.', http(409, 'renewal_request_conflict'), 'AT-17'),
    ('Повтор renew с тем же renewalRequestId и CSR возвращает прежний сертификат.', CERT, 'agent_api',
     'Потеря ответа renew и повтор.', {'replay': {'http': 200, 'duplicate': True}}, 'AT-17'),
    ('Истёкший сертификат не принимается; восстановление — повторная регистрация.', CERT, 'agent_api',
     'Запрос сертификатом тестового профиля после истечения срока.', http(401, 'certificate_expired'), 'AT-17'),
    ('Обрыв TLS при истёкшем локальном сертификате переводит агент в ReenrollRequired.', AGENT_FSM, 'agent',
     'Ingress обрывает рукопожатие с истёкшим сертификатом.', {'agentState': 'ReenrollRequired'}, 'AT-17'),
    ('agent_version_unsupported останавливает отправку scans до обновления.', AGENT_FSM, 'agent',
     'Ответ 422 agent_version_unsupported на submitScan.', {'agentState': 'VersionBlocked'}, 'AT-13'),
    ('identity_conflict останавливает агент до решения ServiceManager; сертификат не отзывается.', AGENT_FSM,
     'agent', 'Ответ 409 identity_conflict клону.', {'agentState': 'IdentityConflict'}, 'AT-04'),
    # Organization lifecycle (05 «Жизненный цикл организации»).
    ('Агенты организации в статусе disabled или deletion_scheduled получают отказ и приостанавливаются.',
     LIFECYCLE, 'agent_api', 'submitScan после disable организации.', http(403, 'organization_inactive'), 'AT-12'),
    ('schedule_deletion требует готового экспорта после перехода в disabled либо exportWaived=true.',
     LIFECYCLE, 'portal_api', 'schedule_deletion без экспорта и без exportWaived.',
     http(409, 'lifecycle_transition_forbidden'), 'AT-12'),
    ('После удаления организации агенты получают certificate_revoked до validTo сертификата: sha256, revokedAt и '
     'validTo хранятся в платформенной таблице revoked_certificate без связи с организацией, а вход в контекст с '
     'purpose=agent ищет hash в ней и в device_certificate одним запросом.', LIFECYCLE,
     'agent_api', 'getAgentConfiguration сертификатом устройства удалённой организации сразу после завершения '
     'organization_delete.', http(401, 'certificate_revoked'), 'AT-12'),
    ('Restore выполняется в карантине: журнал жизненного цикла применяется до открытия доступа, отозванное '
     'устройство остаётся отозванным, а повторное применение delete переносит сертификаты удалённой организации в '
     'revoked_certificate.', RESTORE, 'infra', 'Restore на точку до отзыва устройства или до удаления организации.',
     http(401, 'certificate_revoked'), 'AT-12'),
    # Portal API.
    ('Запрос портала без действительной сессии отклоняется.', PORTAL, 'portal_api', 'GET findings без cookie.',
     http(401, 'session_required'), 'AT-01'),
    ('Мутация портала без верного CSRF-токена отклоняется.', PORTAL, 'portal_api',
     'PATCH finding без X-CSRF-Token.', http(403, 'csrf_failed'), 'AT-01'),
    ('Technician не принимает решения о риске.', WORKFLOW, 'portal_api', 'Technician вызывает decideFindingRisk.',
     http(403, 'forbidden'), 'AT-08'),
    ('Сущность недоступной организации неотличима от отсутствующей.', TENANCY, 'portal_api',
     'getFinding с findingId чужой организации.', http(404, 'not_found'), 'AT-01'),
    ('Cursor связан с организацией и фильтром.', PORTAL, 'portal_api', 'Cursor другой организации.',
     http(400, 'invalid_cursor'), 'AT-01'),
    ('Устаревший If-Match отклоняется.', WORKFLOW, 'portal_api', 'patchFinding с прошлой ревизией.',
     http(412, 'revision_mismatch'), 'AT-08'),
    ('Мутации finding и политики требуют If-Match.', WORKFLOW, 'portal_api', 'patchFinding без If-Match.',
     http(428, 'if_match_required'), 'AT-08'),
    ('Решение о риске допустимо только при technicalState=open.', WORKFLOW, 'portal_api',
     'decideFindingRisk risk_accepted для resolved finding.', http(409, 'workflow_transition_forbidden'), 'AT-08'),
    ('reviewAt решения о риске лежит в (now, now + 365 сут].', WORKFLOW, 'portal_api',
     'reviewAt через 400 суток.', http(422, 'validation_failed'), 'AT-08'),
    ('PATCH не принимает risk_accepted и suppressed.', WORKFLOW, 'schema', 'patchFinding workflowState=risk_accepted.',
     http(422, 'schema_violation'), 'AT-08'),
    ('Файл отчёта выдаётся только в состоянии ready.', REPORT, 'portal_api', 'downloadReport для queued отчёта.',
     http(409, 'resource_not_ready'), 'AT-07'),
    ('periodStart раньше periodEnd (межполевой инвариант тела).', EXTRA, 'portal_api',
     'createReport с periodStart = periodEnd.', http(422, 'schema_violation'), 'AT-07'),
    ('maxBatchAgeDays не меньше maxBufferDays + 1 (межполевой инвариант тела).', EXTRA, 'portal_api',
     'createPolicyRevision с maxBufferDays 7 и maxBatchAgeDays 7.', http(422, 'schema_violation'), 'AT-04'),
    ('Режим assessed требует входных настроек; WIN-011 обязательна; WIN-004 активна только вместе с WIN-003.',
     EXTRA, 'portal_api', 'WIN-008 в режиме assessed с пустым allowedSids.', http(422, 'policy_inputs_missing'),
     'AT-05'),
    ('Строки SAFE_TEXT не содержат < и >, управляющих и bidi-символов.', UNTRUSTED, 'schema',
     'Organization.name со строкой <script>.', http(422, 'schema_violation'), 'AT-07'),
    # Tenancy, roles and audit.
    ('Запрос без контекста организации возвращает 0 строк (FORCE ROW LEVEL SECURITY).', TENANCY, 'db_rls',
     'Первый SELECT из клиентской таблицы на новом соединении без app.begin_org_context.', {'rows': 0}, 'AT-01'),
    ('Каждый вход с purpose=portal в режиме PlatformAdmin (субъект с platform_role, даже при членстве в '
     'организации), кроме createOrganization, пишет audit_event platform.access внутри app.begin_org_context после '
     'установки контекста и до первого чтения данных, в той же транзакции; в режиме restore аудит пишет команда '
     'восстановления.', CONTEXT, 'db_rls', 'PlatformAdmin с членством читает listFindings.',
     {'audit': 'platform.access'}, 'AT-01'),
    # Evaluation (03 and 05).
    ('В режиме assessed наблюдение unavailable применимой проверки (применимость известна и не даёт '
     'not_applicable) даёт unknown с reasonCode наблюдения.', SEMANTICS, 'worker',
     'WIN-002 unavailable/permission_denied; WIN-011 collected, editionId=Professional.', result('assessed', 'unknown', 'permission_denied'), 'AT-05'),
    ('В режиме assessed неподдерживаемый сбор применимой проверки даёт unknown, а не fail.', SEMANTICS, 'worker', 'WIN-009 unavailable/unsupported.',
     result('assessed', 'unknown', 'unsupported'), 'AT-05'),
    ('В режиме assessed временная ошибка сборщика применимой проверки даёт unknown.', SEMANTICS, 'worker', 'WIN-005 unavailable/temporary_error.',
     result('assessed', 'unknown', 'temporary_error'), 'AT-05'),
    ('Ожидание результата сборщика — 30 с, по истечении collector_timeout; зависшая привилегированная работа '
     'принудительно завершается не позже 120 с; дочерние процессы не запускаются; в режиме assessed оценка — '
     'unknown/collector_timeout.', LOCAL, 'agent',
     'Сборщик WIN-005 не отвечает 60 с.', result('assessed', 'unknown', 'collector_timeout'),
     'AT-03'),
    ('Эталонный отрицательный тест BitLocker в режиме assessed: fully_encrypted при protectionStatus=off и encryptionRequired=true '
     'даёт fail.', WINDOWS, 'worker', 'WIN-002 из examples/scan-batch.json.', result('assessed', 'fail'), 'AT-05'),
    ('WIN-003 в режиме assessed: ни один одобренный продукт не активен, а у одного одобренного productState=unknown.', WINDOWS,
     'worker', 'Одобренный VendorX с productState=unknown и rawState без сопоставления.',
     result('assessed', 'unknown', 'unmapped_state'), 'AT-05'),
    ('WIN-006 в режиме assessed: неуспешный поиск обновлений даёт unknown.', WINDOWS, 'worker', 'agentSearch.resultCode=failed.',
     result('assessed', 'unknown', 'update_search_failed'), 'AT-05'),
    ('WIN-006 в режиме assessed: основа свежести поиска старше maxSearchAgeHours (разность, равная '
     'maxSearchAgeHours, — ещё свежая) даёт unknown.', WINDOWS, 'worker',
     'auLastSearchSuccessAt 100 ч назад при offline_cache.', result('assessed', 'unknown', 'update_search_outdated'), 'AT-05'),
    ('WIN-006 в режиме assessed: configuredSource отличается от expectedSource.', WINDOWS, 'worker',
     'configuredSource=wsus при expectedSource=windows_update.', result('assessed', 'unknown', 'update_source_mismatch'),
     'AT-05'),
    ('WIN-006 в режиме assessed: усечённый список без просрочки среди переданных элементов даёт unknown.', WINDOWS, 'worker',
     'truncated=true, все переданные обновления в пределах grace.', result('assessed', 'unknown', 'update_list_truncated'),
     'AT-05'),
    ('WIN-006 в режиме assessed: просрочка хотя бы одного переданного обновления даёт fail независимо от truncated.', WINDOWS,
     'worker', 'truncated=true и одно Critical обновление старше 7 суток.', result('assessed', 'fail'), 'AT-05'),
    ('SYS-002 в режиме assessed: версия, редакция или архитектура вне матрицы совместимости даёт fail.', OS_MATRIX, 'worker',
     'WIN-011 displayVersion=27H1.', result('assessed', 'fail'), 'AT-05'),
    ('SYS-002 в режиме assessed: нет свежего WIN-011.', OS_MATRIX, 'worker', 'Последний WIN-011 старше окна свежести.',
     result('assessed', 'unknown', 'os_inventory_missing'), 'AT-05'),
    ('В режиме assessed межпроверочная применимость берётся из того же пакета; без пригодного входа зависимая проверка unknown. '
     'Правило применяется, только если у пакета нет признака часов.',
     SEMANTICS, 'worker', 'WIN-002 в пакете без WIN-011.', result('assessed', 'unknown', 'applicability_input_missing'),
     'AT-05'),
    ('В режиме assessed редакция из notApplicableEditionIds даёт not_applicable.', SEMANTICS, 'worker',
     'WIN-011 editionId=Core, WIN-002 при стартовой политике.', result('assessed', 'not_applicable', 'policy_not_applicable'),
     'AT-05'),
    ('WIN-007 в режиме assessed: перезагрузка между двумя rebootRequired=true начинает новый эпизод и не даёт ложного fail.',
     WINDOWS, 'worker', 'Два наблюдения rebootRequired=true с разным lastBootAt через 4 суток.', result('assessed', 'pass'),
     'AT-06'),
    # Finding events (05 «Таблица переходов finding», «Допустимые сочетания eventType и cause»).
    ('Свежий fail без finding создаёт open/new и событие opened.', TRANSITIONS, 'worker',
     'Первый fail WIN-005.', event('opened', 'device_change'), 'AT-06'),
    ('Свежий pass открытого finding даёт resolved; workflowState не меняется. Исправлением считается только '
     'resolved с device_change.', TRANSITIONS, 'worker', 'fail → pass WIN-005.', event('resolved', 'device_change'),
     'AT-06'),
    ('Свежий fail resolved finding даёт reopened; действующее решение о риске сохраняется.', TRANSITIONS,
     'worker', 'fail → pass → fail WIN-005.', event('reopened', 'device_change'), 'AT-06'),
    ('Смена ruleVersion пересчитывает проекции с rule_change и не входит в исправления.', CURRENT, 'worker',
     'Новая ruleVersion WIN-001 открывает finding.', event('opened', 'rule_change'), 'AT-06'),
    ('Перевод проверки в not_applicable или informational политикой закрывает finding событием policy_changed.',
     TRANSITIONS, 'worker', 'Исключение WIN-005 из activeCheckIds.', event('policy_changed', 'policy_change'),
     'AT-06'),
    ('Отзыв устройства выводит его объекты.', TRANSITIONS, 'worker', 'revokeDevice с открытым finding.',
     event('object_retired', 'manual_action'), 'AT-06'),
    ('По наступлении reviewAt решение истекает: workflowState=new, одно событие review_expired.', WORKFLOW,
     'worker', 'Двойной запуск review_expiry после reviewAt.', event('workflow_changed', 'review_expired'), 'AT-08'),
    # Scheduler and fencing (02 «Очередь заданий»).
    ('freshness_sweep идемпотентен: переход свежести открытого finding пишет одно событие quality_changed.',
     JOBS, 'worker', 'Два такта планировщика в одном часе в двух репликах worker.',
     event('quality_changed', 'data_quality'), 'AT-14'),
    ('Завершение задания с устаревшим leaseToken откатывается и не создаёт второго бизнес-эффекта.', JOBS,
     'worker', 'Lease истекает у живого worker, второй worker обрабатывает тот же evaluate_batch.',
     event('opened', 'device_change'), 'AT-14'),
]

P2 = [
    ('Неполная выборка Graph без пройденного nextLink не даёт вывода по отсутствующим страницам.', CAPABILITY,
     'worker', 'Ответ Graph с @odata.nextLink, который не запрошен.', {'capabilityStatus': 'partial'}, 'AT-15'),
    ('Свойство, которое не вернулось из-за прав или лицензии, не трактуется как значение.', CAPABILITY,
     'worker', 'Sign-in без appliedConditionalAccessPolicies.', {'capabilityStatus': 'partial'}, 'AT-15'),
    ('Регистрация MFA не означает требования MFA политикой доступа: если политики Conditional Access не '
     'прочитаны из-за неподтверждённой лицензии, вывод о требовании MFA не делается.', M365, 'worker',
     'isMfaRegistered=true, политики CA не читаются: лицензия Entra ID P1 не подтверждена.',
     {'capabilityStatus': 'license_unconfirmed'}, 'AT-10'),
    ('Устройство сопоставляется с Intune только по подтверждённому идентификатору.', M365, 'worker',
     'Совпадение только по имени устройства.', {'capabilityStatus': 'partial'}, 'AT-11'),
    ('Consent запрашивается только для включённых модулей; модуль, включённый после consent, не расширяет '
     'выданные права сам и до нового consent работает без своего права.', GRAPH, 'infra',
     'Модуль M365-004 включён после consent без DeviceManagementManagedDevices.Read.All.',
     {'capabilityStatus': 'permission_missing'}, 'AT-09'),
]

# P1 records added after the P2 block; numbering continues after P2.
P1_ADDED = [
    ('Зарегистрированный сертификат устройства в состоянии superseded после окончания перекрытия, например в '
     'образе старше ротации, получает 401 certificate_expired; в той же транзакции сервер записывает '
     'device.reenrollAllowedUntil = now + 7 суток и аудит device.reenroll_allowed, независимо от validTo, если '
     'запрос дошёл до приложения. Отозванный сертификат или отозванное устройство это поле не выставляют. '
     'Повторная регистрация при reenrollAllowedUntil > now, том же installationId и совпадающем признаке машины '
     'выдаёт pending-сертификат тому же deviceId, история сохраняется: useCount увеличивается, создаётся запись '
     'enrollment, reenrollAllowedUntil обнуляется, пишутся аудит device.reenroll_over_active и оповещение — в '
     'транзакции регистрации Portal API; неактивированный pending отзывается (аудит device.pending_revoked) и '
     'перекрытие прежних superseded заканчивается — в транзакции выпуска Issuer; прежний active переходит в '
     'superseded при первом mTLS-запросе новым; previousCertificateValidUntil = null.', CERT, 'agent_api',
     'Восстановленный образ старше ротации отправляет heartbeat старым сертификатом после перекрытия.',
     http(401, 'certificate_expired'), 'AT-17'),
    ('enrollAgent с уже зарегистрированным installationId и несовпадающим признаком машины отклоняется; '
     'агент переходит в IdentityConflict; identityState существующего устройства не меняется, пишется аудит '
     'device.enroll_identity_conflict.', IDENTITY, 'portal_api',
     'Повторная регистрация после истечения сертификата с installationId другой машины.',
     http(409, 'identity_conflict'), 'AT-02'),
    ('Проверка, ставшая not_applicable по фактам устройства в пакете без смены policy_revision, закрывает '
     'finding событием resolved с applicability_change; это не исправление.', TRANSITIONS, 'worker',
     'WIN-011 editionId сменился на Core при открытом finding WIN-002 и той же ревизии политики.',
     event('resolved', 'applicability_change'), 'AT-06'),
    ('WIN-004 в режиме assessed: signatureLastUpdatedAt позже observedAt этого наблюдения даёт unknown/evidence_time_invalid; '
     'пакет не отклоняется.',
     WINDOWS, 'worker', 'signatureLastUpdatedAt на двое суток позже observedAt.',
     result('assessed', 'unknown', 'evidence_time_invalid'), 'AT-05'),
    ('Пакет с чужим или просроченным scanRequestId принимается как обычный сбор: scanRequestId игнорируется, '
     'пишется запись диагностики, новых кодов нет.', PORTAL, 'agent_api',
     'Пакет с scanRequestId другого устройства и свежим pass WIN-005 после исправления.',
     event('resolved', 'device_change'), 'AT-05'),
    ('Повторная проверка по requestDeviceScan (только вариант A) закрывает исправленную проблему событием '
     'resolved с device_change.', PORTAL, 'worker',
     'Пакет с действующим scanRequestId и pass WIN-005 после исправления.',
     event('resolved', 'device_change'), 'AT-05'),
    ('SYS-002 в режиме assessed: версия из матрицы совместимости, которой нет в таблице жизненного цикла, даёт unknown.',
     OS_MATRIX, 'worker', 'Тестовая версия данных правила: матрица расширена версией 27H1, строки 27H1 в таблице '
     'жизненного цикла ещё нет; WIN-011 displayVersion=27H1.',
     result('assessed', 'unknown', 'os_version_unknown'), 'AT-05'),
    # Enrollment and certificates.
    ('Новый выпуск (renew с новым renewalRequestId или выпуск по записи enrollment) в транзакции выпуска Issuer под '
     'блокировкой строки устройства отзывает неактивированный pending и устанавливает overlapEndsAt равным моменту '
     'выдачи у каждого superseded с overlapEndsAt > now; активация pending выполняется под той же блокировкой, '
     'поэтому у устройства в любой момент не больше одного pending и не больше двух действующих сертификатов. '
     'Идемпотентный повтор новым выпуском не является и перекрытие не меняет.', CERT, 'agent_api',
     'После активации B сертификат A superseded в перекрытии; renew сертификатом B с новым renewalRequestId выдаёт '
     'C; затем heartbeat сертификатом A.', http(401, 'certificate_expired'), 'AT-17'),
    ('Идентичный повтор enrollAgent (тот же токен, registrationRequestId, CSR и installationId) в течение 7 суток от '
     'записи enrollment проверяется раньше срока, отзыва и исчерпания токена и, если устройство записи не отозвано и '
     'её сертификат действующий, возвращает прежний ответ; если сбой '
     'Issuer после commit транзакции регистрации помешал выпуску, повтор выпускает недостающий сертификат записи. '
     'useCount не меняется, новых enrollment и device нет, у записи не больше одного сертификата.', AGENT_API,
     'portal_api', 'Регистрация записана, Issuer недоступен (ответ 503); одноразовый токен истёк; через 2 ч повтор '
     'с тем же токеном, registrationRequestId, CSR и installationId.', {'replay': {'http': 201, 'duplicate': True}},
     'AT-02'),
    ('Тело enrollAgent больше 16384 байт отклоняется до разбора JSON и до проверки токена; лимит портальных '
     'запросов 64 KiB к enrollAgent не применяется.', AGENT_API, 'portal_api',
     'Тело enrollAgent размером 16385 байт с недействительным токеном.', http(413, 'payload_too_large'), 'AT-02'),
    # Organization context and audit.
    ('Ошибка вставки audit_event при входе субъекта с platform_role в контекст организации прерывает транзакцию: '
     'контекст откатывается, данные клиента не выдаются; ответ портала отправляется только после COMMIT.',
     CONTEXT, 'db_rls', 'PlatformAdmin вызывает listFindings; вставка audit_event отклонена тестовым триггером.',
     http(503, 'temporarily_unavailable'), 'AT-01'),
    ('Контекст организации устанавливается один раз за транзакцию и действует до её конца: соединение, '
     'возвращённое в pool после запроса организации A, без нового вызова app.begin_org_context видит 0 строк; '
     'повторный вызов функции в той же транзакции отклоняется.', CONTEXT, 'db_rls',
     'Соединение после запроса организации A взято запросом организации B; SELECT из finding до вызова функции.',
     {'rows': 0}, 'AT-01'),
    ('listOrganizations не входит в контекст организации: app.list_accessible_organizations возвращает субъекту с '
     'platform_role все неудалённые организации и до выдачи строк пишет ровно одну запись platform_audit_event '
     'platform.access (target listOrganizations) на запрос, даже при членстве, и ни одной audit_event; участнику '
     'без platform_role — только организации с его членством, без записи аудита.', CONTEXT, 'db_rls',
     'PlatformAdmin, член одной из трёх организаций, вызывает listOrganizations.', {'audit': 'platform.access'},
     'AT-01'),
    ('Переход changeOrganizationLifecycle в одной транзакции со сменой статуса пишет audit_event организации и '
     'platform_audit_event с action=organization.lifecycle_change, одним correlationId и одинаковыми details '
     '{lifecycleAction, reason, exportWaived}; listAuditEvents возвращает reason без изменений; повтор с тем же '
     'idempotencyKey новых записей не создаёт; reason не попадает в журнал жизненного цикла, операционные логи и '
     'Log Analytics.', LIFECYCLE, 'portal_api', 'disable с reason «R-7f3c <img src=x onerror=alert(1)>».',
     {'audit': 'organization.lifecycle_change'}, 'AT-12'),
    ('patchFinding, изменивший assigneeId или dueAt, пишет audit_event finding.assignment_change с details.from и '
     'details.to только для изменившихся полей; если ни одно из них не изменилось, запись не создаётся; смена '
     'workflowState в details не входит.', WORKFLOW, 'portal_api',
     'patchFinding с новыми assigneeId и dueAt у finding в состоянии risk_accepted.',
     {'audit': 'finding.assignment_change'}, 'AT-08'),
    ('FindingPatch.assigneeId — entraUserId участника этой организации с ролью ServiceManager или Technician '
     '(OrganizationMember.entraUserId); organization_member.id и entraUserId сотрудника без членства в этой '
     'организации, в том числе участника только другой организации или отозванного участника, отклоняются.',
     WORKFLOW, 'portal_api', 'patchFinding с assigneeId, равным organization_member.id участника.',
     http(422, 'validation_failed'), 'AT-08'),
    # Lifecycle journal and restore.
    ('Понижение роли ServiceManager → Technician и отзыв назначения записываются в журнал жизненного цикла до '
     'изменения БД и переживают restore.', RESTORE, 'infra',
     'Restore на точку до понижения роли ServiceManager → Technician; после открытия доступа пользователь вызывает '
     'decideFindingRisk.', http(403, 'forbidden'), 'AT-12'),
    ('Replay применяет по каждому объекту запись журнала с наибольшей targetVersion; порядок добавления и '
     'occurredAt не учитываются.', RESTORE, 'infra',
     'Запись enable создана в журнале позже записи disable той же организации, но с меньшей targetVersion; '
     'restore на точку до disable; агент вызывает submitScan.', http(403, 'organization_inactive'), 'AT-12'),
    ('Ограничивающая запись, созданная в журнале без commit в БД, применяется при restore; версия неудачной '
     'попытки повторно не используется.', RESTORE, 'infra',
     'revokeDevice: запись в журнале создана, commit сорвался (ответ 503); restore; агент устройства вызывает '
     'submitHeartbeat.', http(401, 'certificate_revoked'), 'AT-12'),
    ('Restore в карантине отзывает все неотозванные enrollment-токены восстановленной базы: погашения и useCount '
     'после точки restore в ней не отражены.', RESTORE, 'infra',
     'Batch-токен исчерпан после точки restore (в восстановленной базе useCount < maxUses); после открытия доступа '
     'enrollAgent этим токеном с новым registrationRequestId.', http(401, 'enrollment_token_invalid'), 'AT-12'),
    # WIN-006 and assessment modes.
    ('WIN-006 в режиме assessed: при agentSearch.mode=offline_cache и auLastSearchSuccessAt=null основы свежести '
     'нет; успешный поиск агента её не заменяет, результат unknown/update_search_outdated; наблюдение непригодно '
     'для истории ожидания.', WIN006, 'worker',
     'offline_cache, resultCode=succeeded, auLastSearchSuccessAt=null, configuredSource=expectedSource='
     'windows_update, полный пустой список.', result('assessed', 'unknown', 'update_search_outdated'), 'AT-05'),
    ('WIN-006 в режиме assessed: agentSearch.completedAt или firstSeenPendingAt хотя бы одного переданного '
     'обновления позже observedAt, а при offline_cache также auLastSearchSuccessAt позже agentSearch.completedAt, '
     'дают unknown/evidence_time_invalid раньше проверки свежести и просрочки; пакет не отклоняется, наблюдение '
     'непригодно для истории ожидания.', WIN006, 'worker',
     'offline_cache со свежей основой, configuredSource=expectedSource; Critical-обновление с firstSeenPendingAt '
     'на 3 суток позже observedAt.', result('assessed', 'unknown', 'evidence_time_invalid'), 'AT-05'),
    ('WIN-006 в режиме assessed: deadlineAt в будущем не нарушает отношений времени; при '
     'referenceTimeBasis=deadline такое обновление не просрочено и не требует подтверждения возраста.', WIN006,
     'worker', 'expectedSource=configuredSource=windows_update, referenceTimeBasis=deadline, online/succeeded с '
     'completedAt за 1 ч до observedAt; единственное Critical-обновление: deadlineAt через 10 суток, '
     'firstSeenPendingAt 30 суток назад; total=1, truncated=false.', result('assessed', 'pass'), 'AT-05'),
    ('Длина pendingSecurityUpdates в WIN-006 равна min(pendingSecurityUpdatesTotal, 50), а truncated=true тогда и '
     'только тогда, когда pendingSecurityUpdatesTotal > 50 (межполевой инвариант тела).', EXTRA, 'agent_api',
     'WIN-006 с pendingSecurityUpdates=[], pendingSecurityUpdatesTotal=3, truncated=false.',
     http(422, 'schema_violation'), 'AT-05'),
    ('WIN-006 в режиме assessed: если точка отсчёта переданного обновления — firstSeenRef (основа first_seen либо '
     'deadline без deadlineAt), просрочки и усечения нет, а previousCompleteAt равен null или previousCompleteAt + '
     'grace + maxSearchAgeHours раньше observedAt, результат unknown/update_age_unconfirmed, а не pass.', WIN006,
     'worker', 'Первый пакет нового устройства, referenceTimeBasis=first_seen, свежий успешный поиск, '
     'configuredSource=expectedSource; Important-обновление, опубликованное 60 дней назад; firstSeenPendingAt = '
     'observedAt этого сбора, серверный firstSeenAt — время поиска этого сбора, previousCompleteAt = null.',
     result('assessed', 'unknown', 'update_age_unconfirmed'), 'AT-05'),
    ('WIN-006 в режиме assessed: при основе first_seen либо deadline без deadlineAt точка отсчёта firstSeenRef = '
     'min(серверный firstSeenAt, firstSeenPendingAt); история ожидания хранится сервером по (deviceId, updateId) и '
     'не зависит от состояния агента.', WIN006, 'worker',
     'Потеря локальной SQLite при том же deviceId, referenceTimeBasis=first_seen, свежий успешный поиск, '
     'configuredSource=expectedSource: firstSeenPendingAt Important-обновления = observedAt, серверный firstSeenAt '
     '— 15 суток назад.', result('assessed', 'fail'), 'AT-05'),
    ('В режиме informational наблюдение unavailable применимой проверки даёт result=null с reasonCode наблюдения; '
     'finding не создаётся.', SEMANTICS, 'worker',
     'WIN-002 unavailable/permission_denied, WIN-011 collected с editionId=Professional, политика с WIN-002 в '
     'режиме informational.', result('informational', None, 'permission_denied'), 'AT-05'),
    ('В режиме informational причина правила, которая не переносится (unmapped_state, update_*, '
     'evidence_time_invalid, os_version_unknown, os_inventory_missing, policy_not_applicable), даёт result=null и '
     'reasonCode=null; finding не создаётся.', SEMANTICS, 'worker',
     'WIN-006 при политике v1 (informational) с agentSearch.resultCode=failed.', result('informational', None),
     'AT-05'),
    # Device clock, current projection and OS lifecycle.
    ('Признак часов вычисляется один раз — при приёме, в транзакции записи scan_batch под блокировкой строки '
     'устройства, по receivedAt и значениям устройства до этого пакета (lastAcceptedSequence, '
     'maxAcceptedSourceTime, heartbeatClockSkewExceeded) — и хранится в scan_batch вместе с projectionEligible; '
     'worker его не пересчитывает, повтор возвращает исходный receipt. lastAcceptedSequence учитывает и пакеты с '
     'признаком, maxAcceptedSourceTime — только пакеты без признака.', CLOCK, 'agent_api',
     'Принят sequence 100; затем sequence 101 с completedAt раньше maxAcceptedSourceTime при нормальном последнем '
     'heartbeat; задание пакета 101 выполнено раньше задания пакета 100; WIN-005 в политике в режиме assessed.',
     result('assessed', 'unknown', 'clock_inconsistent'), 'AT-04'),
    ('Текущую проекцию устройства меняет только пакет с projectionEligible, если его sequence больше '
     'device.projectionSequence; сравнение и замена выполняются в evaluate_batch под блокировкой строки '
     'устройства. Пакеты с признаком часов и пакеты вне порядка пополняют только историю и событий не создают, '
     'кроме переоценки WIN-006 текущей проекции, когда такой пакет изменил историю ожидания (05, «Выбор текущего '
     'состояния», п. 5); '
     'при любом порядке заданий совпадают текущая проекция, projectionSequence и множество открытых finding.',
     CURRENT, 'worker',
     'Finding WIN-005 открыт; пакет 100 — fail, пакет 101 — pass; задание пакета 101 выполнено раньше задания '
     'пакета 100, и пакет 100 finding не переоткрывает.',
     event('resolved', 'device_change'), 'AT-04'),
    ('SYS-002 в режиме assessed: окончание обслуживания — исключающее UTC-мгновение servicingEndsAt из данных '
     'правила; observedAt, равное servicingEndsAt или позже, даёт fail, а observedAt на 1 с раньше по сроку '
     'обслуживания fail не даёт.', OS_MATRIX, 'worker',
     'SYS-002 в политике в режиме assessed; WIN-011 Professional x64 displayVersion=25H2 с '
     'observedAt=2027-10-13T07:00:00Z (servicingEndsAt версии 25H2).', result('assessed', 'fail'), 'AT-05'),
    # Clock jump forward, timezone and report period rules.
    ('Пакет, у которого startedAt, completedAt или какое-либо observedAt позже receivedAt + 5 мин, не отклоняется: '
     'он принимается с признаком часов, его оценки исторические, текущая проекция не меняется, droppedBatchCount '
     'не растёт.', CLOCK, 'agent_api',
     'Часы устройства на 6 мин впереди: completedAt на 6 мин позже receivedAt; WIN-005 в политике в режиме '
     'assessed.', result('assessed', 'unknown', 'clock_inconsistent'), 'AT-04'),
    ('Organization.timezone — идентификатор часового пояса IANA; неизвестная зона отклоняется.', PORTAL,
     'portal_api', 'createOrganization с timezone=Europe/Oslow.', http(422, 'validation_failed'), 'AT-07'),
    ('createReport принимает только границы ISO-недели в timezone организации (понедельник 00:00 — следующий '
     'понедельник 00:00); иные границы отклоняются.', REPORT, 'portal_api',
     'createReport с periodStart во вторник 00:00 и periodEnd через 7 суток в timezone организации.',
     http(422, 'validation_failed'), 'AT-07'),
    # Restore sequence floor.
    ('Карантин устанавливает lifecycle_decision_seq выше максимума из её текущего значения, наибольшей '
     'targetVersion журнала и наибольших decisionVersion и journalPendingVersion в базе: последовательность не '
     'уменьшается, и переход после restore получает версию выше любой версии, уже назначенной объекту.', RESTORE,
     'infra', 'enable организации: commit выполнен, запись в журнал не создана; restore на точку после commit; после '
     'открытия доступа задание дописывает запись enable, затем disable той же организации; повторный restore; агент '
     'вызывает submitScan.', http(403, 'organization_inactive'), 'AT-12'),
]


def build_invariants():
    records = []
    for phase, rows in (('P1', P1), ('P2', P2), ('P1', P1_ADDED)):
        for rule, (doc, section), enforcement, negative, expected, acceptance in rows:
            records.append({'id': f'INV-{len(records) + 1:03}', 'rule': rule,
                            'sourceDoc': {'file': DOCS[doc], 'section': section}, 'phase': phase,
                            'enforcement': enforcement, 'negativeExample': negative,
                            'expectedError': expected, 'acceptance': acceptance})
    return records
