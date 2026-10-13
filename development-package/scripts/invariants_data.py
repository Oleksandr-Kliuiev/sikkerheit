"""Registry of invariants that JSON Schema does not express (source of specs/invariants.json).

IDs are assigned in list order; append new records at the end of their phase block so that
existing INV-nnn identifiers stay stable.
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


def http(status, code):
    return {'http': status, 'code': code}


def result(value, reason=None):
    return {'result': value, **({'reasonCode': reason} if reason else {})}


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
    ('completedAt не раньше startedAt, observedAt не позже completedAt, время не позже receivedAt + 5 мин.',
     CLOCK, 'agent_api', 'completedAt на 10 мин позже receivedAt.', http(422, 'batch_time_inconsistent'), 'AT-04'),
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
    ('Отсутствующая ожидаемая пара даёт unknown без отклонения пакета.', UNIQUE, 'worker',
     'Пакет без наблюдения WIN-005 при активной WIN-005.', result('unknown', 'missing_observation'), 'AT-04'),
    ('Пакет с признаком часов сохраняется в истории; его оценки unknown и не меняют текущую проекцию.', CLOCK,
     'worker', 'completedAt раньше maxAcceptedSourceTime при большем sequence.',
     result('unknown', 'clock_inconsistent'), 'AT-04'),
    ('Рост droppedBatchCount в heartbeat пишется в аудит устройства.', INTAKE, 'agent_api',
     'droppedBatchCount вырос с 0 до 2.', {'audit': 'device.data_loss'}, 'AT-04'),
    # Identity, enrollment and certificates.
    ('Истёкший, отозванный или исчерпанный enrollment-токен и токен неактивной организации не регистрируют '
     'устройство; не больше maxUses устройств при конкурентных запросах.', ENROLL, 'portal_api',
     'Одиннадцатая регистрация пакетным токеном с maxUses 10.', http(401, 'enrollment_token_invalid'), 'AT-02'),
    ('installationId отозванного устройства или активного устройства с другим CSR не регистрируется повторно.',
     IDENTITY, 'portal_api', 'enrollAgent с installationId отозванного устройства.',
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
    ('После удаления организации агенты получают certificate_revoked, пока хранится запись отзыва.', LIFECYCLE,
     'agent_api', 'submitHeartbeat после выполнения organization_delete.', http(401, 'certificate_revoked'),
     'AT-12'),
    ('Restore выполняется в карантине: журнал жизненного цикла применяется до открытия доступа, отозванное '
     'устройство остаётся отозванным.', RESTORE, 'infra', 'Restore на точку до отзыва устройства.',
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
     'SELECT из клиентской таблицы без app.begin_org_context.', {'rows': 0}, 'AT-01'),
    ('Каждый доступ субъекта с platform_role к данным клиента пишет audit_event в той же транзакции, '
     'даже при членстве в организации.', ROLES, 'db_rls', 'PlatformAdmin с членством читает listFindings.',
     {'audit': 'platform.access'}, 'AT-01'),
    # Evaluation (03 and 05).
    ('Наблюдение unavailable даёт unknown с reasonCode наблюдения.', SEMANTICS, 'worker',
     'WIN-002 unavailable/permission_denied.', result('unknown', 'permission_denied'), 'AT-05'),
    ('Неподдерживаемый сбор даёт unknown, а не fail.', SEMANTICS, 'worker', 'WIN-009 unavailable/unsupported.',
     result('unknown', 'unsupported'), 'AT-05'),
    ('Временная ошибка сборщика даёт unknown.', SEMANTICS, 'worker', 'WIN-005 unavailable/temporary_error.',
     result('unknown', 'temporary_error'), 'AT-05'),
    ('Зависший сборщик завершается не дольше чем за 30 с, сессия укладывается в 120 с; дочерние процессы '
     'не запускаются.', LOCAL, 'agent', 'Сборщик WIN-006 не отвечает 60 с.', result('unknown', 'collector_timeout'),
     'AT-03'),
    ('Эталонный отрицательный тест BitLocker: fully_encrypted при protectionStatus=off и encryptionRequired=true '
     'даёт fail.', WINDOWS, 'worker', 'WIN-002 из examples/scan-batch.json.', result('fail'), 'AT-05'),
    ('WIN-003: ни один одобренный продукт не активен, а у одного одобренного productState=unknown.', WINDOWS,
     'worker', 'Одобренный VendorX с productState=unknown и rawState без сопоставления.',
     result('unknown', 'unmapped_state'), 'AT-05'),
    ('WIN-006: неуспешный поиск обновлений даёт unknown.', WINDOWS, 'worker', 'agentSearch.resultCode=failed.',
     result('unknown', 'update_search_failed'), 'AT-05'),
    ('WIN-006: основа свежести поиска старше maxSearchAgeHours даёт unknown.', WINDOWS, 'worker',
     'auLastSearchSuccessAt 100 ч назад при offline_cache.', result('unknown', 'update_search_outdated'), 'AT-05'),
    ('WIN-006: configuredSource отличается от expectedSource.', WINDOWS, 'worker',
     'configuredSource=wsus при expectedSource=windows_update.', result('unknown', 'update_source_mismatch'),
     'AT-05'),
    ('WIN-006: усечённый список без просрочки среди переданных элементов даёт unknown.', WINDOWS, 'worker',
     'truncated=true, все переданные обновления в пределах grace.', result('unknown', 'update_list_truncated'),
     'AT-05'),
    ('WIN-006: просрочка хотя бы одного переданного обновления даёт fail независимо от truncated.', WINDOWS,
     'worker', 'truncated=true и одно Critical обновление старше 7 суток.', result('fail'), 'AT-05'),
    ('SYS-002: версии нет в таблице жизненного цикла.', OS_MATRIX, 'worker', 'WIN-011 displayVersion=27H1.',
     result('unknown', 'os_version_unknown'), 'AT-05'),
    ('SYS-002: нет свежего WIN-011.', OS_MATRIX, 'worker', 'Последний WIN-011 старше окна свежести.',
     result('unknown', 'os_inventory_missing'), 'AT-05'),
    ('Межпроверочная применимость берётся из того же пакета; без пригодного входа зависимая проверка unknown.',
     SEMANTICS, 'worker', 'WIN-002 в пакете без WIN-011.', result('unknown', 'applicability_input_missing'),
     'AT-05'),
    ('Редакция из notApplicableEditionIds даёт not_applicable по политике.', SEMANTICS, 'worker',
     'WIN-011 editionId=Core, WIN-002 при стартовой политике.', result('not_applicable', 'policy_not_applicable'),
     'AT-05'),
    ('WIN-007: перезагрузка между двумя rebootRequired=true начинает новый эпизод и не даёт ложного fail.',
     WINDOWS, 'worker', 'Два наблюдения rebootRequired=true с разным lastBootAt через 4 суток.', result('pass'),
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
    ('Регистрация MFA не означает требования MFA политикой доступа.', M365, 'worker',
     'isMfaRegistered=true без политики CA, требующей MFA.', {'capabilityStatus': 'license_unconfirmed'}, 'AT-10'),
    ('Устройство сопоставляется с Intune только по подтверждённому идентификатору.', M365, 'worker',
     'Совпадение только по имени устройства.', {'capabilityStatus': 'partial'}, 'AT-11'),
    ('Consent запрашивается только для включённых модулей.', GRAPH, 'infra',
     'Запрос права модуля M365-005 при выключенном модуле.', {'capabilityStatus': 'permission_missing'}, 'AT-09'),
]


def build_invariants():
    records = []
    for phase, rows in (('P1', P1), ('P2', P2)):
        for rule, (doc, section), enforcement, negative, expected, acceptance in rows:
            records.append({'id': f'INV-{len(records) + 1:03}', 'rule': rule,
                            'sourceDoc': {'file': DOCS[doc], 'section': section}, 'phase': phase,
                            'enforcement': enforcement, 'negativeExample': negative,
                            'expectedError': expected, 'acceptance': acceptance})
    return records
