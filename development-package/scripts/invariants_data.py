"""Registry of invariants that JSON Schema does not express (source of specs/invariants.json).

IDs are assigned in list order: P1, then P2. New records go to the end of their block before a release;
after a release IDs stay stable and new records are appended to the end of the last block.
"""

DOCS = {'02': '02-architecture-and-stack.md', '03': '03-check-catalog.md', '04': '04-security-and-privacy.md',
        '05': '05-data-and-api.md', '06': '06-azure-and-operations.md'}

TENANCY = ('02', 'Разделение клиентов')
JOBS = ('02', 'Фоновые задания')
LOCAL = ('02', 'Выполнение локальной проверки')
DEPLOY = ('02', 'Развёртывание и окружения')
SEMANTICS = ('03', 'Семантика результата')
MFA_RULE = ('03', 'Правило M365-001 и M365-002')
ENFORCEMENT_RULE = ('03', 'Правило M365-003')
ADMINS_RULE = ('03', 'Правило M365-005')
CONSENT_RULE = ('03', 'Правило M365-006')
INACTIVE_RULE = ('03', 'Правило M365-007')
CAPABILITY = ('03', 'Возможности подключения')
WINDOWS = ('03', 'Проверки Windows')
WIN006 = ('03', 'Правило WIN-006')
WIN007 = ('03', 'Правило WIN-007')
BITLOCKER = ('03', 'Эталонный отрицательный тест BitLocker')
LIFECYCLE_OS = ('03', 'Жизненный цикл ОС')
PATCH = ('03', 'Правило SYS-003 и каталог выпусков')
ROLES = ('04', 'Вход сотрудников и роли')
CONNECT = ('04', 'Подключение и отзыв')
ENROLL_KEY = ('04', 'Ключ регистрации организации')
SESSION = ('04', 'Ключ устройства и сессия')
SECURITY_LOG = ('04', 'Журнал безопасности')
UNTRUSTED = ('04', 'Недоверенные строки и выдача отчёта')
POLICY = ('05', 'Политика клиента')
LIFECYCLE = ('05', 'Жизненный цикл организации')
COLLECTION = ('05', 'Подключение M365 и сбор')
TRANSITIONS = ('05', 'Таблица переходов finding')
WORKFLOW = ('05', 'Автомат workflowState')
CURRENT = ('05', 'Выбор текущего состояния')
SCHEDULER = ('05', 'Фоновые задания и планировщик')
SUBJECTS = ('05', 'Субъекты и идентичность устройства')
REGISTRATION = ('05', 'Регистрация и сессия')
INTAKE = ('05', 'Порядок приёма пакета')
CLOCK = ('05', 'Время и часы устройства')
AGENT_FSM = ('05', 'Конечный автомат агента')
PORTAL = ('05', 'API портала')
REPORT = ('05', 'Отчёт и покрытие')
RESTORE = ('06', 'Резервное копирование и восстановление')


def http(status, code):
    return {'http': status, 'code': code}


def result(mode, value, reason=None):
    return {'assessmentMode': mode, 'result': value, **({'reasonCode': reason} if reason else {})}


def event(event_type, cause):
    return {'event': {'eventType': event_type, 'cause': cause}}


def audit(action):
    return {'audit': action}


def state(name):
    return {'agentState': name}


def effect(kind):
    return {'effect': kind}


A, I = 'assessed', 'informational'

# (rule, sourceDoc, enforcement, negativeExample, expectedError, acceptance)
P1 = [
    # Staff sign-in, roles and isolation.
    ('Запрос портала без действующей сессии отклоняется.', ROLES, 'portal_api',
     'GET /api/v1/organizations без cookie.', http(401, 'session_required'), 'AT-02'),
    ('Токен входа без признака MFA (amr без mfa), из другого tenant или без app role не создаёт сессию.',
     ROLES, 'portal_api', 'Вход учётной записью без MFA.', http(401, 'session_required'), 'AT-02'),
    ('Мутация портала без X-CSRF-Token или с токеном другой сессии отклоняется.', ROLES, 'portal_api',
     'PATCH finding без заголовка X-CSRF-Token.', http(403, 'csrf_failed'), 'AT-02'),
    ('Reader не выполняет изменений; Technician не выполняет операций с ролью Admin (решения о риске, '
     'политика, жизненный цикл, ключи, подключение M365).', ROLES, 'portal_api',
     'Technician вызывает decideFindingRisk.', http(403, 'forbidden'), 'AT-02'),
    ('Сущность другой организации по ID в пути отвечает 404 без раскрытия существования.', TENANCY,
     'portal_api', 'getFinding с findingId другой организации.', http(404, 'not_found'), 'AT-01'),
    ('Cursor связан с операцией, организацией и фильтром; чужой или изменённый cursor отклоняется.', PORTAL,
     'portal_api', 'Cursor listFindings организации A в запросе организации B.', http(400, 'invalid_cursor'),
     'AT-01'),
    ('Без установленной области запрос к клиентской таблице возвращает 0 строк.', TENANCY, 'db_rls',
     'SELECT из finding на новом соединении без app.set_scope.', {'rows': 0}, 'AT-01'),
    ('Изменения клиентских таблиц (INSERT, UPDATE, DELETE) возможны только в области одной организации: в области '
     'чтения all и для строк чужой организации они затрагивают 0 строк.', TENANCY, 'db_rls',
     'DELETE FROM finding в области чтения all.', {'rows': 0}, 'AT-01'),
    ('Область чтения all открывается только в транзакции READ ONLY и только операциями и системными компонентами '
     'из перечня 02.', TENANCY, 'db_rls', 'UPDATE в транзакции планировщика с областью all.', {'rows': 0},
     'AT-01'),
    ('Задание обрабатывает только сущности своей organizationId: inputId другой организации не читается.',
     TENANCY, 'db_rls', 'report_generate с reportId другой организации.', {'rows': 0}, 'AT-01'),
    # Microsoft 365 connection.
    ('startTenantConsent строит ссылку только для expectedTenantId, полученного из tenantHint; tenant компании без '
     'allowCompanyTenant отклоняется.', CONNECT, 'portal_api', 'tenantHint — домен самой компании.',
     http(422, 'validation_failed'), 'AT-03'),
    ('verifyTenantConnection активирует подключение, только если токен для ожидаемого tenant выдан и /organization '
     'вернул тот же id; иначе подключение не меняется.', CONNECT, 'portal_api',
     'Проверка до того, как администратор клиента выдал consent.', http(422, 'consent_not_granted'), 'AT-03'),
    ('Tenant, подключённый к другой организации, или tenant, отличный от действующего подключения, не '
     'подключается.', CONNECT, 'portal_api', 'startTenantConsent для tenant, подключённого к другой организации.',
     http(409, 'tenant_conflict'), 'AT-03'),
    ('requestCollection при подключении не в статусе active и verifyTenantConnection без ожидаемого tenant '
     'отклоняются.', COLLECTION, 'portal_api', 'Внеплановый сбор после disconnectTenant.',
     http(409, 'connection_state_conflict'), 'AT-03'),
    ('disconnectTenant сначала пишет журнал безопасности, затем прекращает сбор; повтор идемпотентен.',
     SECURITY_LOG, 'portal_api', 'Двойной вызов disconnectTenant.', audit('m365.disconnect'), 'AT-03'),
    ('Сбор сверяет tenant ответом /organization; другой id прерывает запуск (failureCode=tenant_mismatch) без '
     'записи наблюдений.', COLLECTION, 'collector', 'Подключение указывает на tenant T, токен выдан для U.',
     audit('m365.tenant_mismatch'), 'AT-03'),
    ('Если токен для tenant не выдан из-за отозванного consent, запуск получает failed/consent_missing, '
     'поднимается оповещение, а открытые finding не закрываются.', COLLECTION, 'collector',
     'Приложение удалено из tenant клиента.', audit('m365.collection_failed'), 'AT-03'),
    ('Запуск, во время которого подключение отключено, tenant сменился или организация перестала быть active, '
     'ничего не записывает и получает failed/cancelled.', COLLECTION, 'collector',
     'disconnectTenant во время запуска.', effect('none'), 'AT-03'),
    # Microsoft 365 collection robustness.
    ('Следующая страница Graph запрашивается только по @odata.nextLink с хостом graph.microsoft.com и тем же '
     'путём; иной URL прерывает модуль со статусом partial.', CAPABILITY, 'collector',
     'nextLink на https://example.invalid/v1.0/users.', {'capabilityStatus': 'partial'}, 'AT-04'),
    ('Ответ 200 без обязательного свойства не считается полным: модуль получает partial.', CAPABILITY,
     'collector', 'Список методов без @odata.type у элемента.', {'capabilityStatus': 'partial'}, 'AT-04'),
    ('403 Authorization_RequestDenied модуля даёт permission_missing; отсутствие лицензии этим не '
     'доказывается.', CAPABILITY, 'collector', '403 на /identity/conditionalAccess/policies в tenant с P1.',
     {'capabilityStatus': 'permission_missing'}, 'AT-04'),
    ('Модуль, требующий Entra ID P1, в tenant без плана P1 или P2 по subscribedSkus получает license_missing без '
     'запроса.', CAPABILITY, 'collector', 'Tenant Business Standard.', {'capabilityStatus': 'license_missing'},
     'AT-04'),
    ('429 и 503 Graph соблюдают Retry-After; после исчерпания попыток модуль получает temporary_error.',
     CAPABILITY, 'collector', 'Пять ответов 429 подряд.', {'capabilityStatus': 'temporary_error'}, 'AT-04'),
    ('Обязательный модуль проверки с temporary_error делает её наблюдение unavailable с той же причиной: M365-003 '
     'при сбое Conditional Access в tenant с P1 — unknown/temporary_error, а не fail.', CAPABILITY, 'evaluator',
     '429 подряд на политики CA.', result(A, 'unknown', 'temporary_error'), 'AT-04'),
    ('Наблюдение, которое не проходит allowlist-схему, сохраняется как unavailable/partial_data, а модуль получает '
     'partial.', COLLECTION, 'collector', 'Неожиданное значение userType у одного пользователя.',
     result(A, 'unknown', 'partial_data'), 'AT-04'),
    ('Отказ 403 при чтении методов пользователя даёт unknown/permission_denied, а не fail.', MFA_RULE,
     'evaluator', '403 на /users/{id}/authentication/methods.', result(A, 'unknown', 'permission_denied'),
     'AT-04'),
    ('403 на членов группы с ролью даёт модулю roles статус partial: прямые администраторы оцениваются, а M365-005 '
     '— unknown/partial_data.', ADMINS_RULE, 'evaluator',
     'Глобальный администратор назначен группе с ролью, 403 на её членов.', result(A, 'unknown', 'partial_data'),
     'AT-04'),
    ('Проверка, зависящая от модуля без лицензии, даёт license_missing: в режиме informational — result=null с '
     'этой причиной.', SEMANTICS, 'evaluator', 'M365-007 в tenant без Entra ID P1.',
     result(I, None, 'license_missing'), 'AT-05'),
    # Microsoft 365 rules.
    ('M365-001: включённый member-пользователь без метода из MFA_METHOD_KINDS — fail; password, email и '
     'temporary_access_pass методом MFA не считаются.', MFA_RULE, 'evaluator',
     'methodKinds = [password, email].', result(A, 'fail'), 'AT-05'),
    ('M365-001: при phoneMethodsAccepted=false пользователь только с phone — fail.', MFA_RULE, 'evaluator',
     'methodKinds = [password, phone].', result(A, 'fail'), 'AT-05'),
    ('M365-001 и M365-007: пользователь из excludedUserIds, гость, отключённый или учётная запись синхронизации '
     'Entra Connect — not_applicable.', MFA_RULE, 'evaluator', 'Учётная запись аварийного доступа в excludedUserIds.',
     result(A, 'not_applicable', 'policy_not_applicable'), 'AT-05'),
    ('M365-002 не учитывает excludedUserIds: методы администраторов читаются всегда, и администратор аварийного '
     'доступа только с паролем — fail critical.', MFA_RULE, 'evaluator',
     'Администратор в excludedUserIds, methodKinds = [password].', result(A, 'fail'), 'AT-05'),
    ('M365-002: гость с привилегированной ролью — fail warning независимо от методов.', MFA_RULE, 'evaluator',
     'Гостевая учётная запись с ролью Global Administrator.', result(A, 'fail'), 'AT-05'),
    ('M365-002: пользователь, у которого снята последняя привилегированная роль, — not_applicable; finding '
     'закрывается событием resolved/applicability_change.', MFA_RULE, 'evaluator', 'Роль Global Administrator снята.',
     result(A, 'not_applicable', 'policy_not_applicable'), 'AT-06'),
    ('Временная активация роли в PIM не создаёт пару M365-002 и не меняет счёт M365-005.', ADMINS_RULE,
     'collector', 'Активация роли во время ночного сбора.', effect('none'), 'AT-05'),
    ('M365-003: единственная политика CA с MFA в режиме report-only при выключенных Security Defaults и per-user MFA '
     '— fail, а не pass.', ENFORCEMENT_RULE, 'evaluator', 'Пример examples/m365-collection.json.', result(A, 'fail'),
     'AT-05'),
    ('M365-003: включённые политики с MFA есть, но ни одна не охватывает всех пользователей, все приложения и все '
     'типы клиентов — unknown/enforcement_unconfirmed.', ENFORCEMENT_RULE, 'evaluator',
     'Политика MFA только для группы «Ansatte».', result(A, 'unknown', 'enforcement_unconfirmed'), 'AT-05'),
    ('M365-003: политика на всех с условием (риск, расположения, платформы, устройства) или с grant «MFA или '
     'устройство» даёт unknown/enforcement_unconfirmed, если параметры политики клиента этого не разрешают.',
     ENFORCEMENT_RULE, 'evaluator', 'Политика MFA только при высоком риске входа.',
     result(A, 'unknown', 'enforcement_unconfirmed'), 'AT-05'),
    ('M365-003: authentication strength без requirementsSatisfied = mfa или исключённые пользователи вне '
     'excludedUserIds не дают pass.', ENFORCEMENT_RULE, 'evaluator', 'Из политики исключена группа из 30 '
     'пользователей.', result(A, 'unknown', 'enforcement_unconfirmed'), 'AT-05'),
    ('M365-003: per-user MFA enabled или enforced у всех включённых member-пользователей вне исключений даёт pass '
     'и в tenant с Entra ID P1.', ENFORCEMENT_RULE, 'evaluator',
     'Business Premium без политики CA с MFA, per-user MFA enforced у всех.', result(A, 'pass'), 'AT-05'),
    ('M365-003: в tenant без Conditional Access и без Security Defaults хотя бы один включённый member-пользователь с '
     'per-user MFA disabled даёт fail critical; если модуль per_user_mfa выключен — unknown/enforcement_unconfirmed.',
     ENFORCEMENT_RULE, 'evaluator', 'Tenant Business Standard, perUserMfa.notRequired = 3.', result(A, 'fail'),
     'AT-05'),
    ('M365-005: число включённых глобальных администраторов вне [minGlobalAdmins, maxGlobalAdmins] — fail warning; '
     'отключённые учётные записи не считаются.', ADMINS_RULE, 'evaluator',
     'Один включённый и один отключённый глобальный администратор при minGlobalAdmins=2.', result(A, 'fail'),
     'AT-05'),
    ('M365-006: политика согласия ManagePermissionGrantsForSelf.microsoft-user-default-legacy — fail; пустой '
     'список или только разрешённые политики — pass.', CONSENT_RULE, 'evaluator',
     'permissionGrantPolicies = [...microsoft-user-default-legacy].', result(A, 'fail'), 'AT-05'),
    ('M365-006: известная политика Microsoft вне allowedPermissionGrantPolicies — fail; по умолчанию так '
     'оценивается …microsoft-user-default-recommended.', CONSENT_RULE, 'evaluator',
     'permissionGrantPolicies = [...microsoft-user-default-recommended].', result(A, 'fail'), 'AT-05'),
    ('M365-006: собственная политика согласия клиента вне allowedPermissionGrantPolicies — unknown/unmapped_state.',
     CONSENT_RULE, 'evaluator', 'Собственная политика согласия клиента.', result(A, 'unknown', 'unmapped_state'),
     'AT-05'),
    ('M365-007 в режиме assessed: lastSuccessfulSignInAt и createdAt равны null — fail, потому что учётная запись '
     'создана до июня 2018 года и с декабря 2023 года не входила.', INACTIVE_RULE, 'evaluator',
     'Учётная запись 2016 года без входа.', result(A, 'fail'), 'AT-05'),
    ('Наблюдение, которого нет в запуске для активной проверки и известного субъекта, даёт '
     'unknown/missing_observation.', SEMANTICS, 'evaluator', 'Запуск без методов одного пользователя.',
     result(A, 'unknown', 'missing_observation'), 'AT-05'),
    ('Informational-оценка с причиной правила, а не отсутствия данных, получает result=null без reasonCode.',
     SEMANTICS, 'evaluator', 'M365-004 informational при неизвестной форме политики.', result(I, None), 'AT-05'),
    # Findings and history.
    ('Свежий fail без finding создаёт open/new и событие opened с cause=source_change.', TRANSITIONS,
     'evaluator', 'Пользователь без MFA в первом сборе.', event('opened', 'source_change'), 'AT-06'),
    ('Свежий pass при open — resolved с cause=source_change; только эта категория считается исправлением.',
     TRANSITIONS, 'evaluator', 'Пользователь зарегистрировал Authenticator.', event('resolved', 'source_change'),
     'AT-06'),
    ('Fail после resolved — reopened; workflowState=new, если нет действующего решения о риске.', TRANSITIONS,
     'evaluator', 'Метод MFA удалён через неделю.', event('reopened', 'source_change'), 'AT-06'),
    ('Новая ревизия политики, после которой проверка неприменима или выключена, закрывает finding событием '
     'policy_changed/policy_change.', TRANSITIONS, 'evaluator', 'Пользователь добавлен в excludedUserIds.',
     event('policy_changed', 'policy_change'), 'AT-06'),
    ('Неприменимость по фактам источника без смены политики закрывает finding событием '
     'resolved/applicability_change.', TRANSITIONS, 'evaluator', 'Пользователь с открытым M365-001 отключён.',
     event('resolved', 'applicability_change'), 'AT-06'),
    ('Смена ruleVersion пересчитывает текущие проекции с cause=rule_change.', CURRENT, 'evaluator',
     'Новая версия правила M365-003 начинает учитывать authentication strength.', event('opened', 'rule_change'),
     'AT-06'),
    ('Смена качества открытого finding (fresh ↔ stale или переход к unknown) пишет quality_changed/data_quality '
     'один раз; повтор freshness_sweep второго события не пишет.', TRANSITIONS, 'evaluator',
     'Сбор M365 не выполнялся 49 часов.', event('quality_changed', 'data_quality'), 'AT-06'),
    ('Исчезновение пользователя из полного списка /users или тома из пакета выводит его finding событием '
     'subject_retired/source_change; при usersComplete=false пользователи не выводятся.', CURRENT, 'evaluator',
     'Пользователь удалён в tenant.', event('subject_retired', 'source_change'), 'AT-06'),
    ('assessed без входных настроек, activeCheckIds без WIN-011 и WIN-004 без WIN-003 отклоняются.', POLICY,
     'portal_api', 'WIN-010 assessed при expectedTenantId = null.', http(422, 'policy_inputs_missing'), 'AT-06'),
    ('maxBatchAgeDays меньше maxBufferDays + 1, minGlobalAdmins больше maxGlobalAdmins и порог warning строже '
     'порога critical (WIN-001, WIN-004) отклоняются.', POLICY, 'portal_api', 'warnDays=10 при criticalDays=7.',
     http(422, 'validation_failed'), 'AT-06'),
    # Workflow and risk decisions.
    ('patchFinding и decideFindingRisk без If-Match отклоняются.', WORKFLOW, 'portal_api',
     'PATCH без If-Match.', http(428, 'if_match_required'), 'AT-08'),
    ('patchFinding и decideFindingRisk с устаревшей ревизией отклоняются.', WORKFLOW, 'portal_api',
     'Два сотрудника меняют срок одновременно.', http(412, 'revision_mismatch'), 'AT-08'),
    ('PATCH с workflowState=risk_accepted или suppressed отклоняется схемой.', WORKFLOW, 'schema',
     'FindingPatch {workflowState: risk_accepted}.', http(422, 'schema_violation'), 'AT-08'),
    ('risk_accepted и suppressed допустимы только при technicalState=open; withdrawn — только из них.', WORKFLOW,
     'portal_api', 'Принятие риска для resolved.', http(409, 'workflow_transition_forbidden'), 'AT-08'),
    ('reviewAt вне (now, now + 365 сут] и assigneeId не из сотрудников с ролью Admin или Technician '
     'отклоняются.', WORKFLOW, 'portal_api', 'reviewAt через 400 суток.', http(422, 'validation_failed'),
     'AT-08'),
    ('Каждое решение о риске пишет workflow_changed/manual_action с actorId и заполняет workflowDecidedBy.',
     WORKFLOW, 'portal_api', 'Решение без записи события.', event('workflow_changed', 'manual_action'), 'AT-08'),
    ('Наступление reviewAt возвращает finding в new событием workflow_changed/review_expired; повтор задания '
     'второго события не пишет.', WORKFLOW, 'worker', 'review_expiry выполнен дважды за час.',
     event('workflow_changed', 'review_expired'), 'AT-08'),
    ('Изменение ответственного или срока пишет аудит finding.assignment_change только с изменившимися полями.',
     WORKFLOW, 'portal_api', 'Смена assigneeId без записи аудита.', audit('finding.assignment_change'), 'AT-08'),
    # Organization lifecycle, exports, retention.
    ('Переход вне таблицы жизненного цикла, в том числе schedule_deletion без экспорта после disable и без '
     'exportWaived, отклоняется.', LIFECYCLE, 'portal_api', 'schedule_deletion из active.',
     http(409, 'lifecycle_transition_forbidden'), 'AT-09'),
    ('Повтор changeOrganizationLifecycle с тем же idempotencyKey возвращает прежний результат без второго '
     'эффекта.', LIFECYCLE, 'portal_api', 'Повтор disable после таймаута.', {'replay': {'http': 200,
                                                                                     'duplicate': True}},
     'AT-09'),
    ('Тот же idempotencyKey с другим телом отклоняется.', LIFECYCLE, 'portal_api',
     'disable и enable с одним idempotencyKey.', http(409, 'idempotency_conflict'), 'AT-09'),
    ('Ограничивающий переход сначала пишется в журнал безопасности; если запись не создана, переход не '
     'выполняется и операция отвечает 503.', SECURITY_LOG, 'portal_api', 'Хранилище журнала недоступно при disable.',
     http(503, 'temporarily_unavailable'), 'AT-09'),
    ('retention_purge удаляет данные в порядке RETENTION_PURGE_ORDER и пишет сводку retention.purge_summary.',
     LIFECYCLE, 'worker', 'Удаление finding раньше его событий.', audit('retention.purge_summary'), 'AT-09'),
    ('Выдача файла экспорта и чтение журнала аудита пишут аудит при каждом чтении.', PORTAL, 'portal_api',
     'downloadOrganizationExport без записи аудита.', audit('organization_export.download'), 'AT-09'),
    # Reports.
    ('Выдача отчёта или экспорта до состояния ready отклоняется.', REPORT, 'portal_api',
     'downloadReport для queued.', http(409, 'resource_not_ready'), 'AT-07'),
    ('createReport с границами не ISO-недели в timezone организации отклоняется.', REPORT, 'portal_api',
     'periodStart во вторник.', http(422, 'validation_failed'), 'AT-07'),
    ('Отчёт без перевода правила на языке организации получает failed/translation_missing и оповещение '
     'сотрудникам; резервный язык не подставляется.', REPORT, 'worker', 'Нет nn-текста новой ruleVersion.',
     audit('report.failed'), 'AT-07'),
    ('downloadReport пишет аудит report.download при каждом чтении.', UNTRUSTED, 'portal_api',
     'Скачивание без записи аудита.', audit('report.download'), 'AT-07'),
    # Jobs and scheduler.
    ('Периодическое задание одного периода создаётся один раз при нескольких экземплярах сервиса.', JOBS,
     'worker', 'Два экземпляра во время развёртывания создают weekly_report.', effect('single'), 'AT-10'),
    ('Задание с истёкшим lease захватывается заново; завершение прежним владельцем с устаревшим leaseToken не '
     'даёт эффекта.', SCHEDULER, 'worker', 'Пауза процесса дольше lease.', effect('none'), 'AT-10'),
    ('Сбор M365 одной организации не выполняется параллельно: внеплановый запрос объединяется с незавершённым '
     'запуском.', SCHEDULER, 'worker', 'requestCollection во время планового запуска.', effect('single'), 'AT-10'),
    # Restore.
    ('После PITR команда восстановления повторно применяет все записи журнала безопасности с occurredAt не раньше '
     'точки restore минус 5 минут в порядке времени; повтор идемпотентен.', RESTORE, 'infra',
     'Отключение организации после точки restore.', audit('restore.replay_applied'), 'AT-11'),
    ('Файлы Blob без строк в восстановленной базе переносятся в карантин restore-orphans с удалением через 30 суток; '
     'учебное восстановление их только перечисляет.', RESTORE, 'infra', 'Отчёт создан после точки restore.',
     effect('none'), 'AT-11'),
    ('Отмена удаления, записанная в журнал после планирования, после restore возвращает организацию в disabled; '
     'любое удаление после restore выполняется не раньше чем через 7 суток.', RESTORE, 'infra',
     'Удаление запланировано до точки restore, отменено после неё, срок уже прошёл.', effect('none'), 'AT-11'),
    ('Записи журнала безопасности нельзя изменить или удалить до конца срока неизменяемости.', SECURITY_LOG,
     'infra', 'Удаление blob identity приложения.', effect('none'), 'AT-11'),
    ('Периодическое задание без организации уникально по (type, periodKey): индекс NULLS NOT DISTINCT не даёт '
     'второй сводки Teams.', SCHEDULER, 'worker', 'Два экземпляра при переключении слотов планируют teams_digest '
     'за одни сутки.', effect('single'), 'AT-10'),
    ('Задания выполняет только production-слот: в слоте staging они выключены настройкой слота, а слот '
     'останавливается после переключения.', DEPLOY, 'infra', 'Прежняя версия в staging после swap захватывает '
     'retention_purge.', effect('none'), 'AT-10'),
]

P2 = [
    # Registration and session.
    ('createAgentChallenge с телом больше 1024 байт отклоняется до разбора JSON.', REGISTRATION, 'agent_api',
     'Тело 2 КиБ.', http(413, 'payload_too_large'), 'AT-12'),
    ('Nonce одноразовый, действует 5 минут и только для своего purpose и deviceId.', REGISTRATION, 'agent_api',
     'Второй createAgentSession с тем же nonce.', http(401, 'challenge_invalid'), 'AT-12'),
    ('Подпись enrollAgent проверяется ключом publicKey по канонической строке; неверная подпись не создаёт '
     'устройство.', SESSION, 'agent_api', 'Подпись другим ключом.', http(401, 'challenge_invalid'), 'AT-12'),
    ('Неизвестный или отозванный ключ регистрации отклоняется без создания устройства.', ENROLL_KEY, 'agent_api',
     'Ключ после revokeEnrollmentKey.', http(401, 'enrollment_key_invalid'), 'AT-12'),
    ('Регистрация в организации не в статусе active отклоняется.', LIFECYCLE, 'agent_api',
     'enrollAgent ключом отключённой организации.', http(403, 'organization_inactive'), 'AT-09'),
    ('Идентичный повтор enrollAgent с тем же registrationRequestId в течение 24 ч возвращает прежний ответ и не '
     'создаёт второе устройство.', REGISTRATION, 'agent_api', 'Повтор после потери ответа.',
     {'replay': {'http': 201, 'duplicate': True}}, 'AT-12'),
    ('Повтор enrollAgent с тем же телом проверяется до статуса ключа регистрации: ротация ключа после потерянного '
     'ответа не блокирует агент.', REGISTRATION, 'agent_api', 'Ответ потерян, ключ отозван при ротации, повтор.',
     {'replay': {'http': 201, 'duplicate': True}}, 'AT-12'),
    ('Повторная регистрация с тем же ключом устройства (тот же отпечаток JWK) отвечает 201 без аудита '
     'device.key_replaced.', REGISTRATION, 'agent_api', 'Регистрация заново после двух challenge_invalid из-за '
     'истёкшего nonce.', effect('none'), 'AT-12'),
    ('createAgentChallenge не пишет в базу: nonce проверяется по HMAC и сроку, в базу попадает только погашенный '
     'nonce.', REGISTRATION, 'agent_api', 'Повтор погашенного nonce после перезапуска сервиса.',
     http(401, 'challenge_invalid'), 'AT-12'),
    ('Тот же registrationRequestId с другим installationId или публичным ключом отклоняется.', REGISTRATION,
     'agent_api', 'Повтор с новым ключом.', http(409, 'idempotency_conflict'), 'AT-12'),
    ('Регистрация с installationId отозванного устройства не возвращает доступ.', REGISTRATION, 'agent_api',
     'Агент отозванного ПК регистрируется сохранённым ключом.', http(401, 'device_revoked'), 'AT-12'),
    ('Регистрация с installationId существующего устройства и другим признаком машины не меняет ключ '
     'устройства и выставляет identity_conflict.', REGISTRATION, 'agent_api', 'Клон VM с тем же installationId.',
     http(409, 'identity_conflict'), 'AT-12'),
    ('Повторная регистрация с тем же installationId и признаком машины заменяет публичный ключ с сохранением '
     'deviceId и истории.', REGISTRATION, 'agent_api', 'TPM очищен, агент регистрируется заново.',
     audit('device.key_replaced'), 'AT-12'),
    ('createAgentSession для неизвестного deviceId отвечает device_unknown.', REGISTRATION, 'agent_api',
     'Устройство отсутствует в восстановленной базе.', http(401, 'device_unknown'), 'AT-11'),
    ('Подпись createAgentSession проверяется сохранённым публичным ключом устройства.', SESSION, 'agent_api',
     'Подпись ключом другого устройства.', http(401, 'challenge_invalid'), 'AT-12'),
    ('Токен сессии принимается до expiresAt и только для своего устройства.', SESSION, 'agent_api',
     'Запрос через 61 минуту после выдачи.', http(401, 'session_invalid'), 'AT-12'),
    ('Статус устройства проверяется по БД на каждом запросе с токеном: отзыв действует со следующего запроса.',
     SESSION, 'agent_api', 'submitScan после revokeDevice с действующим токеном.', http(401, 'device_revoked'),
     'AT-12'),
    ('Отзыв устройства, которого нет в восстановленной базе, создаёт запись revoked_installation, и регистрация с '
     'этим installationId отклоняется.', RESTORE, 'infra', 'Устройство зарегистрировано и отозвано после точки '
     'restore, агент был офлайн.', http(401, 'device_revoked'), 'AT-11'),
    ('После restore отозванное позже точки restore устройство остаётся отозванным благодаря replay журнала '
     'безопасности.', RESTORE, 'infra', 'revokeDevice после точки restore.', http(401, 'device_revoked'),
     'AT-11'),
    # Agent state machine.
    ('device_unknown переводит агент к повторной регистрации сохранённым ключом организации без участия техника.',
     AGENT_FSM, 'agent', 'Сервер не знает устройство после restore.', state('Unenrolled'), 'AT-11'),
    ('Повторный challenge_invalid при доступном локальном ключе ведёт к регистрации заново с тем же installationId '
     'не чаще раза в сутки; при совпадающем признаке машины сервер заменяет публичный ключ.', AGENT_FSM, 'agent',
     'Восстановление базы на точку до прежней замены ключа.', state('Unenrolled'), 'AT-11'),
    ('enrollment_key_invalid переводит агент в EnrollmentBlocked: попытка регистрации не чаще раза в сутки до '
     'нового ключа через RMM.', AGENT_FSM, 'agent', 'Ключ организации отозван.', state('EnrollmentBlocked'),
     'AT-12'),
    ('После удаления организации агент получает device_unknown, а регистрация — enrollment_key_invalid.',
     LIFECYCLE, 'agent', 'Организация удалена заданием.', state('EnrollmentBlocked'), 'AT-09'),
    ('device_revoked окончателен для установки: агент удаляет ключ устройства и прекращает обращения до '
     'переустановки.', AGENT_FSM, 'agent', 'Устройство отозвано.', state('Revoked'), 'AT-12'),
    ('organization_inactive приостанавливает отправку пакетов; check-in выполняется раз в сутки.', AGENT_FSM,
     'agent', 'Организация отключена.', state('Suspended'), 'AT-09'),
    ('agent_version_unsupported останавливает отправку пакетов; check-in продолжается.', AGENT_FSM, 'agent',
     'Версия ниже minimumAgentVersion.', state('VersionBlocked'), 'AT-16'),
    ('resolveDeviceIdentity с accept_new_fingerprint принимает новый признак машины, сохраняя deviceId и историю; '
     'identityState без несовпадений 7 суток сам возвращается в ok.', REGISTRATION, 'portal_api',
     'Замена материнской платы.', audit('device.identity_resolved'), 'AT-12'),
    ('identity_conflict останавливает отправку пакетов до разбора по RB-11.', AGENT_FSM, 'agent',
     'Признак машины не совпал.', state('IdentityConflict'), 'AT-12'),
    ('Агент проверяет каждое наблюдение своей схемой до отправки: недопустимое значение даёт '
     'unavailable/unsupported только этому наблюдению, остальные проверки пакета принимаются.', LOCAL, 'agent',
     'ConversionStatus BitLocker вне перечня.', result(A, 'unknown', 'unsupported'), 'AT-13'),
    ('Сервер отвечает конфигурацией той версии схемы, которую агент указал в check-in; новые поля появляются только '
     'с новой версией схемы.', AGENT_FSM, 'agent_api', 'Агент предыдущей версии после расширения конфигурации.',
     state('Active'), 'AT-16'),
    ('Конфигурация с полем вне схемы отклоняется агентом целиком; агент продолжает с прежней конфигурацией и '
     'не выполняет команд.', LOCAL, 'agent', 'Ответ check-in с полем command.', state('Active'), 'AT-15'),
    # Intake.
    ('Тело submitScan с Content-Encoding или Content-Type не application/json отклоняется до разбора.', INTAKE,
     'agent_api', 'Content-Encoding: gzip.', http(415, 'unsupported_media_type'), 'AT-13'),
    ('Тело submitScan больше maxBatchBytes (262144 байт) отклоняется до разбора.', INTAKE, 'agent_api',
     'Пакет 300 КиБ.', http(413, 'payload_too_large'), 'AT-13'),
    ('Невалидный JSON отклоняется до проверки схемы.', INTAKE, 'agent_api', 'Обрезанное тело.',
     http(400, 'invalid_json'), 'AT-13'),
    ('Неизвестная schemaVersion пакета отклоняется после проверки версии агента и переводит агент в '
     'VersionBlocked.', INTAKE, 'agent_api', 'schemaVersion 1.0.',
     http(422, 'unsupported_schema_version'), 'AT-13'),
    ('Поле вне схемы, organizationId в теле или evidence чужой проверки отклоняют пакет целиком.', INTAKE,
     'schema', 'Пакет с organizationId.', http(422, 'schema_violation'), 'AT-01'),
    ('freeBytes больше totalBytes отклоняет пакет.', INTAKE, 'agent_api', 'WIN-001 freeBytes > totalBytes.',
     http(422, 'schema_violation'), 'AT-13'),
    ('Версия агента ниже minimumAgentVersion не отправляет пакеты.', INTAKE, 'agent_api', 'agentVersion 0.0.9.',
     http(422, 'agent_version_unsupported'), 'AT-16'),
    ('Повторы одного scanId, пришедшие одновременно, дают один эффект: под блокировкой устройства scanId '
     'проверяется до sequence.', INTAKE, 'agent_api', 'Повтор после таймаута ответа, пока первый запрос ещё '
     'обрабатывается.', {'replay': {'http': 200, 'duplicate': True}}, 'AT-13'),
    ('Пакет с completedAt раньше completedAt пакета текущей проекции идёт только в историю: проекция и проблемы не '
     'меняются, событий нет.', CURRENT, 'evaluator', 'Перенумерованный старый пакет после восстановления ПК из '
     'checkpoint.', effect('none'), 'AT-13'),
    ('Повтор после паузы отправляет те же байты с новым заголовком времени: признак часов считается по текущей '
     'попытке, а повтор принятого пакета получает прежний receipt.', CLOCK, 'agent_api', 'Пакет принят с третьей '
     'попытки через 20 минут после 503.', {'replay': {'http': 200, 'duplicate': True}}, 'AT-13'),
    ('Повтор тех же байтов с тем же scanId возвращает исходный receipt с duplicate=true без второго эффекта.',
     INTAKE, 'agent_api', 'Повтор после потери ответа.', {'replay': {'http': 200, 'duplicate': True}}, 'AT-13'),
    ('Тот же scanId с другим содержимым отклоняется.', INTAKE, 'agent_api', 'Изменён evidence при том же scanId.',
     http(409, 'idempotency_conflict'), 'AT-13'),
    ('Признак машины в пакете или check-in, не совпадающий с устройством сессии, отклоняется и выставляет '
     'identityState=identity_conflict.', INTAKE, 'agent_api', 'Восстановленный на другом ПК образ.',
     http(409, 'identity_conflict'), 'AT-13'),
    ('completedAt раньше startedAt или observedAt вне [startedAt, completedAt] отклоняют пакет.', INTAKE,
     'agent_api', 'observedAt после completedAt.', http(422, 'batch_time_inconsistent'), 'AT-13'),
    ('Пакет старше maxBatchAgeDays по часам ПК (заголовок Sikkerheit-Sent-At минус completedAt) отклоняется.',
     INTAKE, 'agent_api',
     'Пакет десятидневной давности.', http(422, 'batch_too_old'), 'AT-13'),
    ('policyVersion пакета больше текущей или без ревизии у организации отклоняется.', INTAKE, 'agent_api',
     'policyVersion 9 при текущей 3; номер ревизии, потерянной при восстановлении базы.',
     http(422, 'unknown_policy_version'), 'AT-13'),
    ('Повтор ключа (checkId, subject.type, localKey) отклоняет пакет.', INTAKE, 'agent_api',
     'Два наблюдения WIN-005.', http(422, 'duplicate_observation'), 'AT-13'),
    ('Наблюдение проверки, не активной в policyVersion пакета, или объект не того типа отклоняют пакет.',
     INTAKE, 'agent_api', 'WIN-003 с объектом volume.', http(422, 'unexpected_subject'), 'AT-13'),
    ('sequence не больше lastAcceptedSequence при новом scanId отклоняется; агент перенумеровывает очередь от '
     'lastAcceptedSequence + 1.', INTAKE, 'agent_api', 'VM восстановлена из checkpoint.',
     http(409, 'sequence_conflict'), 'AT-13'),
    ('Том выводится из учёта только по положительному доказательству — полный пакет с томом ОС другого volumeId; '
     'сбой сборщика тома даёт unknown.', SUBJECTS, 'evaluator', 'Win32_Volume не ответил за 30 секунд.',
     result(A, 'unknown', 'collector_timeout'), 'AT-13'),
    ('Задания, меняющие проблемы субъектов устройства, берут блокировку строки устройства, как приём пакета.',
     SCHEDULER, 'worker', 'recalculate_policy во время приёма пакета того же устройства.', effect('single'), 'AT-10'),
    ('Активная проверка без наблюдения ожидаемого объекта в пакете даёт unknown/missing_observation.', INTAKE,
     'evaluator', 'Пакет без WIN-005.', result(A, 'unknown', 'missing_observation'), 'AT-13'),
    ('Расхождение времени отправки (Sikkerheit-Sent-At) и receivedAt больше 5 минут в любую сторону даёт признак '
     'часов; SYS-002 и SYS-003 считаются на receivedAt.', CLOCK, 'evaluator', 'Часы ПК отстают на трое суток.',
     result(A, 'unknown', 'clock_inconsistent'), 'AT-13'),
    ('Метки пакета позже receivedAt + 5 мин: пакет принимается, оценки assessed получают '
     'unknown/clock_inconsistent и не меняют текущую проекцию.', CLOCK, 'evaluator',
     'Часы ПК на сутки вперёд.', result(A, 'unknown', 'clock_inconsistent'), 'AT-13'),
    ('В режиме informational признак часов даёт result=null с clock_inconsistent.', CLOCK, 'evaluator',
     'WIN-011 при часах на сутки вперёд.', result(I, None, 'clock_inconsistent'), 'AT-13'),
    # Windows rules.
    ('WIN-002: fully_encrypted, protectionStatus=off, encryptionPercentage=100 при encryptionRequired=true — '
     'fail.', BITLOCKER, 'evaluator', 'Пример examples/scan-batch.json.', result(A, 'fail'), 'AT-14'),
    ('WIN-002: идущее шифрование — unknown/unmapped_state, пауза шифрования или расшифровки — fail.', WINDOWS,
     'evaluator', 'volumeStatus=encrypting при первичном шифровании нового ПК.', result(A, 'unknown', 'unmapped_state'),
     'AT-14'),
    ('WIN-008: встроенный администратор (RID 500) при allowBuiltinAdministrator=true и доменная группа с RID из '
     'allowedDomainRids — разрешены; лишняя локальная учётная запись сверх maxOtherLocalAccounts — fail.', WINDOWS,
     'evaluator', 'Пользователь ПК добавлен в локальные администраторы.', result(A, 'fail'), 'AT-14'),
    ('WIN-010 при заданном expectedTenantId: присоединение к другому tenant, только к домену или его отсутствие — '
     'fail.', WINDOWS, 'evaluator', 'joinType=domain_joined.', result(A, 'fail'), 'AT-14'),
    ('WIN-005: выключенные профили Windows Firewall при активном одобренном стороннем firewall — pass.', WINDOWS,
     'evaluator', 'Firewall антивирусного пакета из approvedFirewallProviders включён.', result(A, 'pass'), 'AT-14'),
    ('WIN-002 для редакции из notApplicableEditionIds по editionId WIN-011 того же пакета — not_applicable.',
     WINDOWS, 'evaluator', 'editionId Core.', result(A, 'not_applicable', 'policy_not_applicable'), 'AT-14'),
    ('WIN-002 и WIN-004 без пригодного входного наблюдения того же пакета — unknown/applicability_input_missing.',
     WINDOWS, 'evaluator', 'WIN-011 unavailable.', result(A, 'unknown', 'applicability_input_missing'), 'AT-14'),
    ('WIN-003: нет активного одобренного продукта, а у одобренного productState=unknown — unknown/unmapped_state.',
     WINDOWS, 'evaluator', 'Сторонний AV с неизвестным rawState.', result(A, 'unknown', 'unmapped_state'),
     'AT-14'),
    ('WIN-004: signatureLastUpdatedAt позже observedAt — unknown/evidence_time_invalid.', WINDOWS, 'evaluator',
     'Сигнатуры «из будущего».', result(A, 'unknown', 'evidence_time_invalid'), 'AT-14'),
    ('Наблюдение unavailable в режиме informational даёт result=null с причиной сборщика.', SEMANTICS,
     'evaluator', 'WIN-008 unavailable/permission_denied.', result(I, None, 'permission_denied'), 'AT-14'),
    ('Больше 10 антивирусных продуктов передаются как unavailable/unsupported.', WINDOWS, 'agent',
     '11 продуктов в WSC.', result(A, 'unknown', 'unsupported'), 'AT-14'),
    ('Сборщик ограничен 30 с, сессия сбора — 120 с; оставшиеся проверки получают collector_timeout.', LOCAL,
     'agent', 'WMI не отвечает.', result(A, 'unknown', 'collector_timeout'), 'AT-15'),
    ('Временная ошибка API Windows даёт unavailable/temporary_error.', WINDOWS, 'agent',
     'RPC_E_SERVERCALL_RETRYLATER.', result(A, 'unknown', 'temporary_error'), 'AT-14'),
    ('WIN-006 assessed: lastSearchSuccessAt null или старше maxSearchAgeDays — fail.', WIN006, 'evaluator',
     'Последний успешный поиск 20 суток назад.', result(A, 'fail'), 'AT-14'),
    ('WIN-007: эпизод начинается первым сбором с rebootRequired=true в сеансе загрузки и прерывается значением '
     'false или сменой lastBootAt; fail только при observedAt − начало эпизода ≥ warnDays.', WIN007, 'evaluator',
     'true в день 0, false в день 1, true в день 3.', result(A, 'pass'), 'AT-14'),
    ('WIN-007: lastBootAt, отличающийся от начала сеанса не больше чем на 2 минуты, — тот же сеанс загрузки.',
     WIN007, 'evaluator', 'Сдвиг LastBootUpTime на 40 секунд после синхронизации времени при эпизоде дольше '
     'warnDays.', result(A, 'fail'), 'AT-14'),
    ('WIN-009: при secureBootRequired=true выключенный Secure Boot или platform=legacy_bios — fail critical.',
     WINDOWS, 'evaluator', 'enabled=false на UEFI.', result(A, 'fail'), 'AT-14'),
    ('SYS-002: версия вне срока обслуживания — fail; Windows 10 22H2 после окончания обслуживания — fail.',
     LIFECYCLE_OS, 'evaluator', 'Windows 10 Pro 22H2.', result(A, 'fail'), 'AT-14'),
    ('SYS-002: архитектура или редакция вне матрицы агента не даёт fail: unknown/os_version_unknown.',
     LIFECYCLE_OS, 'evaluator', 'Windows 11 25H2 на ARM64.', result(A, 'unknown', 'os_version_unknown'), 'AT-14'),
    ('SYS-002: сборка home_pro или enterprise_education ниже 19045 без строки таблицы — fail.', LIFECYCLE_OS,
     'evaluator', 'Windows 10 Enterprise 21H2 (19044).', result(A, 'fail'), 'AT-14'),
    ('SYS-002: IoTEnterpriseS относится к семейству iot_ltsc со своими сроками обслуживания.', LIFECYCLE_OS,
     'evaluator', 'Windows 10 IoT Enterprise LTSC 2021 в феврале 2027 года.', result(A, 'pass'), 'AT-14'),
    ('SYS-002: сборка без DisplayVersion определяется по build; LTSC 2019 (17763) до 2029-01-09 — pass.',
     LIFECYCLE_OS, 'evaluator', 'Windows 10 Enterprise LTSC 2019 с ReleaseId 1809.', result(A, 'pass'), 'AT-14'),
    ('SYS-002: версия из матрицы без строки в таблице жизненного цикла — unknown/os_version_unknown.',
     LIFECYCLE_OS, 'evaluator', 'Новая displayVersion до обновления таблицы.',
     result(A, 'unknown', 'os_version_unknown'), 'AT-14'),
    ('SYS-002 и SYS-003 без свежего WIN-011 — unknown/os_inventory_missing.', LIFECYCLE_OS, 'evaluator',
     'WIN-011 старше окна свежести.', result(A, 'unknown', 'os_inventory_missing'), 'AT-14'),
    ('SYS-003: ветки build нет в каталоге выпусков — unknown/build_not_in_catalog.', PATCH, 'evaluator',
     'Insider build.', result(A, 'unknown', 'build_not_in_catalog'), 'AT-14'),
    ('SYS-003: месяц безопасности, срок grace которого наступил, не сверен — unknown/release_catalog_stale, а не '
     'pass.', PATCH, 'evaluator', 'Сверка октябрьского выпуска не выполнена через 14 суток после второго вторника.',
     result(A, 'unknown', 'release_catalog_stale'), 'AT-14'),
    ('SYS-003: UBR hotpatch ниже UBR месячного выпуска того же месяца даёт уровень этого месяца — pass.', PATCH,
     'evaluator', '26100.8390 (hotpatch мая 2026) при месячном выпуске .8457.', result(A, 'pass'), 'AT-14'),
    ('SYS-003: отставание на один месяц безопасности с истёкшим graceDays — fail warning, на criticalBehindMonths и '
     'больше — fail critical; внеочередные выпуски месяца отставание не увеличивают.', PATCH, 'evaluator',
     'UBR двухмесячной давности.', result(A, 'fail'), 'AT-14'),
    ('Записи каталога в состоянии draft в оценку SYS-003 не попадают: месяц вводит в действие только '
     'verifyWindowsReleaseMonth.', PATCH, 'evaluator', 'Импорт CVRF за месяц без сверки при наступившем сроке.',
     result(A, 'unknown', 'release_catalog_stale'), 'AT-14'),
    ('Ввод месяца каталога в действие не меняет ruleVersion SYS-003 и ставит пересчёт; отставшие устройства '
     'получают opened с source_change.', PATCH, 'worker', 'Сверка ноябрьского месяца при graceDays, уже истёкшем.',
     event('opened', 'source_change'), 'AT-14'),
    ('importWindowsReleases и verifyWindowsReleaseMonth выполняет только Admin.', PATCH, 'portal_api',
     'Technician вызывает verifyWindowsReleaseMonth.', http(403, 'forbidden'), 'AT-14'),
    ('Устройство без check-in дольше 14 суток (dormant) не входит в знаменатель coverageAt, а устройство без дня '
     'в device_presence за период — в знаменатель coveragePeriod; оба показываются отдельно.', REPORT, 'evaluator',
     'Ноутбук три недели в отпуске.', effect('none'), 'AT-07'),
    ('Устройство без check-in дольше 90 суток выводится из учёта вместе с томами; следующий check-in его '
     'возвращает.', SUBJECTS, 'worker', 'ПК списан без отзыва.', event('subject_retired', 'source_change'),
     'AT-06'),
    ('SYS-002 и SYS-003 берут WIN-011 только из пакетов, которые могли менять проекцию.', CURRENT, 'evaluator',
     'WIN-011 из перенумерованного старого пакета после восстановления ПК из checkpoint.', effect('none'), 'AT-13'),
    ('SYS-001 всегда informational и finding не создаёт.', WINDOWS, 'evaluator',
     'Политика с SYS-001 assessed.', result(I, None), 'AT-14'),
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
