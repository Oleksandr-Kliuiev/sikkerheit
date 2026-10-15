# Ревью Development Package 0.3.0: Microsoft 365 и Entra, безопасность, данные и API

> Происхождение. Отчёт написал субагент Claude, запущенный в сессии разработки 2026-10-15: с чистым контекстом, без доступа к рассуждениям автора правок, только чтение пакета. Это не внешнее и не человеческое ревью, поэтому слепые пятна модели у автора и рецензента могут совпадать. Отчёт описывает пакет до внесения правок, номера строк — по тому снимку. Как закрыто каждое замечание — [0.3.0-decisions.md](../reviews/0.3.0-decisions.md).

Дата: 2026-10-15. Независимый технический рецензент. Работа только на чтение: ни один файл репозитория не изменён.

## Объём и метод

Прочитано: `README.md`, `01`, `02` (разделы «Сбор данных Microsoft 365», «Фоновые задания», «Разделение клиентов»), `03` («Семантика результата», «Проверки Microsoft 365» с подразделами правил, «Возможности подключения»), `04` и `05` целиком, `06` («Резервное копирование и восстановление»), `07` (P0, приёмочные сценарии, runbooks), `08`, `10` (раздел M365). Из скриптов прочитаны `contract_catalog.py`, `contract_schemas.py`, `contract_paths.py` и `invariants_data.py`, а также `examples/m365-collection.json`. `specs/openapi.json` проверялся выборкой через `jq`.

Что проверено:

- `python3 -I scripts/validate_package.py` проходит; `standardValidation=false`, сторонние валидаторы не установлены.
- По `openapi.json` 29 операций P1 и 12 P2, как в `05`. У `startTenantConsent` нет `requestBody`.
- Пример покрытия из `05` пересчитан, итог — в разделе «Пересчёт примера покрытия».
- Внешние факты сверены с learn.microsoft.com, таблица с URL — в конце.

Что не проверялось: поведение реальных tenant (это задача SP-01), агент Windows (P2) вне вопросов изоляции и данных, расходы.

Нумерация F-xx — собственная нумерация ревью; R-xx, Q-xx и AT-xx пакета не используются.

## Сводка

| ID | Серьёзность | Тип | Кратко |
| --- | --- | --- | --- |
| F-01 | major | defect | Подключение M365 не привязано к ожидаемому tenant. Consent может уйти в tenant компании или к чужому клиенту, путь через GDAP не работает |
| F-02 | major | defect | Consent, выданный администратором клиента, нельзя завершить: state привязан к сессии сотрудника |
| F-03 | major | defect | M365-003, шаг 2: ложный pass. Evidence не учитывает условия политики CA, оператор OR, исключённые приложения, `requirementsSatisfied` у authentication strength и размер исключённых групп |
| F-04 | major | defect | Нет таблицы «проверка → модули». Сбой модуля CA или Security Defaults даёт ложный fail critical M365-003, а на следующий день — ложное «исправлено» |
| F-05 | major | defect | M365-002: методы не читаются у исключённых и гостевых администраторов, поэтому каждая учётная запись аварийного доступа получает fail critical |
| F-06 | major | defect | Finding M365-002 не закрывается после снятия роли; активации PIM дают флаппинг M365-002 и M365-005 |
| F-07 | major | defect | Модель области RLS не покрывает межорганизационные чтения: поиск state consent, проверку tenant, планировщик, сводку, выбор организаций к удалению |
| F-08 | major | defect | M365-003 не учитывает per-user MFA в tenant с P1; `02` и `03` расходятся в том, когда читать per-user MFA |
| F-09 | minor | defect | Состояния запуска сбора: статус `skipped` не учтён, исходы при таймауте и отмене не заданы |
| F-10 | minor | defect + question | M365-006: `05` указывает другой default; политика `…-recommended` разрешает приложения непроверенных издателей |
| F-11 | minor | defect | Пример покрытия (fixture AT-07) противоречит правилу проекции и семантике informational |
| F-12 | minor | defect | Запуск, который ещё идёт во время `disconnectTenant` или `disable`, может записать данные после отключения |
| F-13 | minor | defect | M365-007: ложный pass для учётных записей, созданных до июня 2018 года (`createdDateTime=null`) |
| F-14 | minor | defect | M365-005 считает отключённых глобальных администраторов |
| F-15 | minor | defect | RLS: «политика записи (WITH CHECK)» не ограничивает DELETE и выбор строк для UPDATE в области all |
| F-16 | minor | gap | В модели данных нет хранилища `idempotencyKey` портала |
| F-17 | minor | gap | Автомат подключения: откат из `consent_pending`, повторный consent на `active`, смена tenant, вывод tenant-субъекта |
| F-18 | minor | gap | Не задано, что происходит при отказе схемы для одного наблюдения M365 (`userType=null`, больше 50 политик, SAFE_TEXT) |
| F-19 | minor | defect | Причины unknown: у сборщика M365 нет источника для `unsupported`; правило выставляет `partial_data`; конфликт с `permission_missing` модуля roles |
| F-20 | minor | risk | Список привилегированных ролей v1 не содержит часть ролей, которые Microsoft помечает как Privileged; назначения в области AU не определены |
| F-21 | minor | defect | Сверка подписей Key Vault с запусками сбора даёт ложную тревогу на каждом `completeTenantConsent` |
| F-22 | minor | question | Вход сотрудников: `amr` в ID-токене v2 не документирован, `wiaormfa` не исключён, нет выхода и смены идентификатора сессии |
| F-23 | minor | gap | `staff_user.roles` устаревают, поэтому ответственным можно назначить уволенного сотрудника |
| F-24 | minor | nit | `policy_inputs_missing` для M365-002 недостижим: схема требует непустой список |
| F-25 | minor | nit | `04` «Минимизация данных» не упоминает `createdAt` пользователя |
| F-26 | minor | risk | Учётная запись синхронизации Entra Connect даёт постоянный fail по M365-001 |
| F-27 | minor | risk | Таймаут запуска 30 минут ограничивает tenant примерно 850–900 пользователями; условие пересмотра в `08` указывает на другую границу |

Риски из внешних фактов (RX-1…RX-5) и вопросы владельцу (QX-1…QX-4) — в конце документа.

---

## Подтверждённые дефекты — major

### F-01. Подключение M365 не привязано к ожидаемому tenant

- **Серьёзность и тип:** major, defect.
- **Где:**
  - `04` «Подключение и отзыв» (стр. 61–65) и стр. 57: компания выдаёт consent через GDAP;
  - `05` «Подключение M365 и сбор» (стр. 124–133);
  - `scripts/contract_paths.py:224–233`: у `startTenantConsent` нет тела, в `openapi.json` `requestBody=null`;
  - `ConsentStart` (`contract_schemas.py:482`);
  - AT-03 (`07`, стр. 131).
- **Сценарий отказа.** `startTenantConsent` не принимает ни tenant ID, ни домен, поэтому ссылка admin consent не может указывать на конкретный tenant (сегмент `organizations` или `common`, в пакете не определено). Документация Microsoft прямо говорит, что `organizations` выдаёт consent в домашнем tenant того, кто входит ([Grant tenant-wide admin consent](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/grant-admin-consent)). Последствия по шагам:
  1. Admin компании (обычно Global Administrator в tenant MSP) нажимает «Подключить» и выдаёт consent в tenant компании. Ответ содержит tenant компании.
  2. Шаги 3–4 `completeTenantConsent` проходят: этот tenant не подключён к другой организации, токен выдаётся, `/organization` совпадает.
  3. Организация клиента A подключена к tenant MSP.
  4. Технику с ролью через GDAP нужно войти именно в tenant клиента, а без tenant-специфичного URL это невозможно. Путь «компания выдаёт consent сама» из `04:57` не работает.
  5. По той же причине организация A может быть по ошибке подключена к ранее не подключённому tenant клиента B.
- **Последствие.** Очередь, история и недельный отчёт клиента A содержат UPN и состояние MFA другого клиента или самой компании — это утечка между клиентами (R-03 пакета). Сверка `tenant` через токен и `/organization` доказывает только, что consent есть, но не то, что tenant тот самый.
- **Исправление.**
  1. `startTenantConsent` принимает обязательный `tenantHint` (tenant ID или проверенный домен). Сервис переводит домен в tenant ID через OIDC discovery и хранит `expectedTenantId` в `consent_request`.
  2. Ссылка строится как `https://login.microsoftonline.com/{expectedTenantId}/v2.0/adminconsent?client_id=…&scope=https://graph.microsoft.com/.default&redirect_uri=…&state=…`.
  3. В `completeTenantConsent` добавляется шаг «`tenant` ≠ `expectedTenantId` → 409» (`tenant_conflict` или отдельный код). Токен и `/organization` запрашиваются для `expectedTenantId`.
  4. Перед активацией портал показывает `tenantDisplayName` и основной домен. Tenant компании подключается только явным флагом.
  5. Добавить инвариант и негативный сценарий в AT-03: «consent выдан в другом tenant, чем указан».
- **Проверка.** В `openapi.json` у `startTenantConsent` есть тело с `tenantHint`. AT-03: consent в tenant компании при ожидаемом tenant клиента даёт 409, подключение не создаётся. В `consent_request` есть `expectedTenantId`.

### F-02. Consent, выданный администратором клиента, нельзя завершить

- **Серьёзность и тип:** major, defect.
- **Где:**
  - `04:57`: «иначе — администратор клиента»;
  - `05:124–133`: state связан с сессией сотрудника и действует 30 минут, `completeTenantConsent` выполняет Admin;
  - `contract_paths.py:229–233`: `portal_mutation`, то есть PortalSession, CsrfToken и ADMIN_ROLES;
  - инвариант `invariants_data.py:98` («только от сессии, которая его создала»);
  - вопрос 2 в `08`: GDAP-роли у компании может не быть.
- **Сценарий отказа.**
  1. У компании нет GA или PRA в tenant клиента. Admin пересылает ссылку администратору клиента.
  2. Тот выдаёт consent, и Microsoft возвращает его браузер на redirect URI портала.
  3. Сессии сотрудника там нет (клиентского входа нет до P3), и SPA не может вызвать `completeTenantConsent`.
  4. Через 30 минут state истекает, статус возвращается к прежнему.
  5. Consent в tenant клиента есть, а подключения нет. Admin компании повторить consent не может — у него нет роли.
- **Последствие.** FR-04 недостижим для клиентов без GDAP-роли у компании, обходной путь в пакете не описан. 30 минут на пересылку ссылки клиенту тоже мало.
- **Исправление.** Отдельный режим «ссылка для администратора клиента»:
  - state не привязан к сессии, но привязан к организации и `expectedTenantId` (F-01), срок около 7 суток;
  - публичная страница результата без данных, только «consent получен»;
  - активацию выполняет операция Admin «проверить подключение»: токен client credentials для `expectedTenantId` плюс `/organization`, коды `422 consent_not_granted` и `409 tenant_conflict`.

  Проще вариант без redirect: Admin вводит tenant, и успешное получение токена само доказывает consent.
- **Проверка.** Новый сценарий AT-03: consent из браузера без сессии сотрудника, затем проверка подключения, подключение становится `active`. Негатив: проверка до consent даёт 422.

### F-03. M365-003, шаг 2: ложный pass

- **Серьёзность и тип:** major, defect.
- **Где:** `03` «Правило M365-003» (стр. 126 и 134), `contract_schemas.py:149–154` (`_ca_policy`). В AT-05 (`07:133`) и в `examples/m365-collection.json` для M365-003 есть только один отрицательный случай — report-only.
- **Что упускает evidence.** `_ca_policy` хранит только `allUsers`, `allApplications`, `allClientAppTypes`, счётчики исключений и `control` (`mfa` или `authentication_strength`). Не хранятся:
  - условия политики: `userRiskLevels`, `signInRiskLevels`, `locations`, `platforms`, `devices` (фильтр), `authenticationFlows`, `insiderRiskLevels`, `clientApplications`;
  - `grantControls.operator` (OR) и другие встроенные контроли, например `compliantDevice` и `domainJoinedDevice`;
  - `excludeApplications`;
  - `authenticationStrength.requirementsSatisfied`. По документации strength «may or may not fulfill the requirements to grant an MFA claim», значения `none` или `mfa` ([authenticationStrengthPolicy](https://learn.microsoft.com/en-us/graph/api/resources/authenticationstrengthpolicy?view=graph-rest-1.0));
  - размер исключённых групп.
- **Сценарий отказа.** Пример политики «CA008» из [документации List policies](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies?view=graph-rest-1.0): `includeUsers: All`, `includeApplications: All`, `clientAppTypes: all`, authentication strength MFA, но `userRiskLevels: [high]`. По evidence пакета это политика «все пользователи, все приложения, все клиенты, enabled», то есть шаг 2 и pass. Та же ошибка возникает, если:
  - MFA не требуется из доверенных расположений (частая настройка SMB);
  - grant «MFA OR compliant device»;
  - охвачены все приложения, кроме Exchange или SharePoint;
  - исключена группа, где большинство пользователей;
  - используется собственная strength с `requirementsSatisfied=none`.
- **Последствие.** Pass по критической проверке, хотя MFA не обязательна. Это противоречит «консервативному правилу» (`01:93`) и критерию «0 ложных pass» (`01:127`), риск R-02 пакета.
- **Исправление.**
  1. Расширить evidence (новая `ruleVersion`): `scopedByConditions` (или список заданных условий), `grantOperator`, `otherGrantControls`, `excludedApplications`, `authStrengthRequirementsSatisfied`, флаг «все исключённые id входят в `excludedUserIds` или в разрешённый список групп».
  2. Шаг 2 срабатывает, только когда политика ничем не ограничена; иначе — шаг 3, unknown/`enforcement_unconfirmed`.
  3. Допуски, например «MFA или устройство» и доверенные расположения, — только явным параметром политики (QX-1).
  4. То же для `_legacy_policy` M365-004 (`contract_schemas.py:157–161`): нет `allApplications` и условий.
- **Проверка.** Добавить в AT-05 и в пример эталонные отрицательные fixtures для каждого из шести случаев выше; ожидание — не pass. Добавить инварианты; validate проверяет их наличие, как сейчас проверяет report-only.

### F-04. Нет таблицы «проверка → модули»: сбой модуля даёт ложный fail critical

- **Серьёзность и тип:** major, defect.
- **Где:**
  - `03:125`: `conditionalAccessAvailable` — есть P1 «и модуль Conditional Access прочитан»;
  - `03:136–139`: шаги 4–7;
  - `03:206–212`: «Перенос статуса в наблюдения» без указания, каких наблюдений;
  - `02:55`: per-user MFA читается, «если ... Conditional Access недоступен»;
  - `contract_schemas.py:168–176`: `securityDefaultsEnabled` и `conditionalAccessAvailable` — обязательные булевы поля, состояния «неизвестно» нет;
  - инвариант `invariants_data.py:137` («проверка, зависящая от модуля без лицензии, даёт license_missing») расходится с шагами 4–6 M365-003, которым нужно collected-наблюдение при отсутствии CA.
- **Сценарий отказа.**
  1. Tenant с P1, включённая политика MFA на всех, Security Defaults выключены.
  2. Модуль `conditional_access` получает 429 подряд. Лимит — 1 запрос в секунду на tenant для всех приложений, без Retry-After ([Throttling limits](https://learn.microsoft.com/en-us/graph/throttling-limits)), так что его делят и другие инструменты MSP. Модуль получает `temporary_error`.
  3. `conditionalAccessAvailable=false`, по `02:55` выполняется `per_user_mfa`.
  4. У пользователей под CA per-user MFA в состоянии «disabled», как и рекомендует Microsoft ([Security defaults](https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults): «Disabled is the appropriate status for users who are using … Conditional Access based MFA»).
  5. Шаг 5 даёт fail critical, finding открывается с `source_change`.
  6. Следующей ночью CA читается: pass, `resolved` с `source_change`, то есть «исправлено».

  Сбой `security_defaults` у tenant с Security Defaults аналогичен: булево поле приходится заполнить `false`, без P1 per-user MFA везде «disabled», шаг 5 даёт fail critical.

  Ещё один конфликт: 403 на членов группы с ролью даёт модулю `roles` статус `permission_missing` (`03:188`). По `03:211` это `permission_denied` для всех наблюдений модуля, а инвариант `invariants_data.py:134` ждёт `partial_data` от правила M365-005.
- **Последствие.** Ложный critical в очереди и в сводке Teams, затем ложное «исправлено» в отчёте. Это искажает и критерий ценности пилота «≥1 resolved с `source_change` за 2 недели» (`01:128`). Реализация зависит от догадки разработчика.
- **Исправление.**
  1. Добавить в `03` таблицу «проверка → обязательные модули (сбой — наблюдение `unavailable` с перенесённой причиной) → условные модули (`license_missing` — признак в evidence) → необязательные».
  2. Поля evidence сделать трёхзначными, например `conditionalAccess: available|license_missing|unavailable`.
  3. M365-003: при P1 и сбое CA — `unavailable`/`temporary_error` (или `permission_denied`), `per_user_mfa` не запускается.
  4. Для `roles` при 403 на часть групп выбрать один путь: модуль `partial` и M365-005 с `unknown`/`partial_data` по правилу.
- **Проверка.** Инварианты:
  - «CA `temporary_error` в tenant с P1 → M365-003 unknown/`temporary_error`»;
  - «`security_defaults` `temporary_error` → unknown/`temporary_error`»;
  - «403 на `transitiveMembers` → `roles=partial`, прямые администраторы M365-002 оцениваются».

  Сценарии в AT-04.

### F-05. M365-002: методы не читаются у исключённых и гостевых администраторов

- **Серьёзность и тип:** major, defect.
- **Где — противоречие между:**
  - `03:90` («методы для них не запрашиваются») и `05:150` («только для включённых member-пользователей вне `excludedUserIds`; у остальных `methodKinds` пуст»);
  - `03:98` и `05:44`: M365-002 игнорирует `excludedUserIds`, учётные записи аварийного доступа тоже проверяются;
  - инвариант `invariants_data.py:149`: ожидает `methodKinds=[password]` у исключённого администратора, то есть методы прочитаны;
  - `02:53`: методы — «для каждого включённого member», без исключения.

  Схема M365-002 (`contract_schemas.py:166–167`) требует `methodKinds` и не отличает «не запрашивались» от «нет методов». Применимость M365-002 — только `accountEnabled=true`, поэтому гости-администраторы входят в выборку (`03:98`).
- **Сценарий отказа.** У каждого клиента две учётные записи аварийного доступа с FIDO2, внесённые в `excludedUserIds`, — ровно то назначение поля, ради которого оно существует. Их `methodKinds=[]`, и M365-002 ежедневно даёт fail critical «нет метода MFA». Гость с ролью Global Administrator (типичный техник MSP до GDAP; гостевые GA есть и в примере [List roleAssignments](https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignments?view=graph-rest-1.0)) получает то же.
- **Последствие.** Около 80 ложных critical на 40 клиентов, каждый придётся оформлять как `suppressed` с пересмотром не реже раза в год, а explanation при этом неверен. Ложные срабатывания по метрике «≤10% ложных fail» почти наверняка превысят порог.
- **Исправление.**
  1. Методы запрашиваются для объединения: включённые member вне исключений плюс все пользователи с ролью из `privilegedRoleTemplateIds`. Для этого модуль `roles` идёт до `auth_methods`, порядок в `02:53–54` меняется.
  2. В evidence добавить `methodsCollected` или сделать `methodKinds` nullable.
  3. Для гостей-администраторов — отдельное решение (QX-4).
- **Проверка.** AT-05:
  - исключённый администратор с FIDO2 — pass, только с паролем — fail critical;
  - гость-администратор — по решению QX-4;
  - инвариант «методы не прочитаны ≠ методов нет».

### F-06. Finding M365-002 не закрывается после снятия роли; PIM даёт флаппинг

- **Серьёзность и тип:** major, defect.
- **Где:**
  - `05:151`: наблюдения M365-002 только для пользователей с ролью;
  - `05:233`: проекция — последний запуск, «в котором есть этот субъект»;
  - `05:236` и инвариант `invariants_data.py:171`: нет наблюдения у известного субъекта — unknown/`missing_observation`;
  - `05:174–178`: при unknown или stale finding остаётся `open`;
  - `05:84`: из учёта выводит только исчезновение из `/users`;
  - `05:492`: пары M365-002 — «только пользователи с привилегированной ролью».
- **Сценарий отказа.**
  1. Администратор без MFA, M365-002 даёт fail critical.
  2. Техник снимает лишнюю роль — нормальное исправление.
  3. В следующих запусках у пользователя нет наблюдения M365-002. Текущая оценка становится unknown/`missing_observation` либо прежний fail уходит в stale.
  4. Finding остаётся `open` навсегда и в отчёте числится среди «критических сейчас».
  5. Текущая оценка пары не not_applicable, поэтому пара остаётся в знаменателе покрытия, и `coverageAt` и `coveragePeriod` снижены навсегда. Цель NFR-03 (90%) у небольших tenant может стать недостижимой.

  PIM: активированные назначения видны в `roleAssignments`. Активация в момент ночного сбора создаёт пару M365-002 на один день и меняет число GA в M365-005: fail и pass с `source_change` дают ложные «новые» и «исправленные» события.
- **Исправление.**
  1. При `roles=available` ожидаемые пары M365-002 = текущие администраторы плюс пары с существующей оценкой. Пользователь без роли получает not_applicable/`policy_not_applicable`, finding закрывается (`applicability_change` или `source_change` — решение QX-2). При недоступном `roles` — unknown с причиной модуля.
  2. Для M365-002 и M365-005 решить, как учитывать временные активации. Нужные данные есть в [roleAssignmentScheduleInstances](https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignmentscheduleinstances?view=graph-rest-1.0) (`assignmentType: Assigned|Activated`, `endDateTime`), доступно с уже запрашиваемым `RoleManagement.Read.Directory`.
- **Проверка.** Новая последовательность AT-06 «роль снята»: событие с выбранной причиной, пара уходит из знаменателя покрытия. Инвариант для M365-005: «временная активация не меняет счёт» (или иное принятое решение).

### F-07. Модель области не покрывает межорганизационные чтения

- **Серьёзность и тип:** major, defect (противоречие между потоками и правилом изоляции).
- **Где:**
  - `02:116–129`: область чтения всех организаций «только для `listOrganizations` и `listFindingsAcrossOrganizations`», `completeTenantConsent` — «в области организации из state»; без области 0 строк;
  - `04:153`; ADR-12 в `08`;
  - `05:13`: `consent_request` содержит `organizationId`, то есть это клиентская таблица под RLS, а платформенных таблиц по `02:129` три.
- **Сценарий отказа.** Следующие потоки невозможно выполнить ни в одной из двух разрешённых областей:
  1. `completeTenantConsent` ищет `consent_request` по `stateHash`, ещё не зная организацию, — нужна область all.
  2. Шаг 3 (`05:129`) проверяет «tenant подключён к другой организации». В области организации чужие строки не видны, проверка молча проходит, и глобальный уникальный индекс (`05:12`) падает с ошибкой БД вместо `409 tenant_conflict`.
  3. Планировщик (`02:107`) перебирает организации, их `timezone` и `collectionHourLocal` из `policy_revision`.
  4. `teams_digest` (`02:102`, `06:95`) читает данные всех клиентов.
  5. `organization_delete` (`02:99`) ищет организации с `deletionDueAt ≤ now`.
  6. Оповещение «больше 2% подключений без сбора» (`06:81`).
  7. P2: `enrollAgent` ищет ключ по хэшу, `createAgentSession` — устройство по `deviceId`.

  Отдельно: `05:19–20` объявляет `agent_challenge` и `agent_session` платформенными, а перечень `02:129` их не содержит. Где хранится tombstone, не определено.
- **Последствие.** Разработчик будет вводить ad hoc область all (и правило «только две операции» перестанет быть правдой) либо получит неработающий consent и планировщик. AT-01 не проверяет, что область all используется только там, где разрешено.
- **Исправление.** Перечислить в `02` внутренние «системные чтения» и способ каждого:
  - **Bootstrap-поиски по секрету** — `SECURITY DEFINER`-функции, возвращающие только `organizationId` (state consent, ключ регистрации, устройство).
  - **Планировщик, сводка, выбор к удалению, оповещения** — область all в транзакции `READ ONLY` или платформенная проекция (`organization_schedule`).

  Проверку уникальности tenant делать через индекс с отображением ошибки в 409. Дополнить список платформенных таблиц, добавить инварианты и AT-01 (запись в области all невозможна; область all только у перечисленных компонентов).
- **Проверка.** Инварианты `db_rls` для каждого компонента. Интеграционный тест: `completeTenantConsent` в чистой транзакции без области находит state; для tenant другой организации отвечает 409, а не 500.

### F-08. M365-003 не учитывает per-user MFA в tenant с P1

- **Серьёзность и тип:** major, defect (с решением владельца).
- **Где:**
  - `03:136–139`: шаги 4–6 только при `conditionalAccessAvailable=false`, шаг 7 — fail critical;
  - `03:143`: per-user MFA читается, «когда шаги 1–3 не решают»;
  - `02:55`: «только если Security Defaults выключены и Conditional Access недоступен»;
  - `examples/m365-collection.json`: при единственной report-only политике шаги 1–3 не решают, но `per_user_mfa=skipped` — пример следует `02`, а не `03`.
- **Сценарий отказа.** Клиент с Business Premium исторически использует per-user MFA (`enforced` у всех) без CA-политики MFA, или с управляемыми Microsoft политиками в report-only. Шаг 7 даёт fail critical «MFA не обязательна», хотя MFA обязательна.
- **Последствие.** Ложный critical. При переходе клиента на CA он превращается в ложное «исправлено».
- **Исправление.** Привести `02` и `03` к одному условию. Рекомендация:
  - `per_user_mfa` выполняется, когда Security Defaults выключены и ни одна включённая политика не покрывает всех;
  - шаги 4–6 применяются до шага 7 и при наличии CA.

  Если владелец считает per-user MFA устаревшим механизмом, лучше отдельный warning, чем critical.
- **Проверка.** Fixture AT-05 «P1, per-user `enforced` у всех, CA без MFA» с ожидаемым результатом по решению; пример приводится в соответствие с `03`.

---

## Подтверждённые дефекты и пробелы — minor

### F-09. Состояния запуска сбора

- **Где:**
  - `05:136–146`: `completed` — все модули `available` или `license_missing`; `partial` — хотя бы один `partial`, `permission_missing` или `temporary_error`; `failed` — данных нет;
  - `contract_catalog.py:58–60`: есть статус `skipped`;
  - `CollectionRun.failureCode` (`contract_schemas.py:493–494`).
- **Сценарий.** В `examples/m365-collection.json` девять модулей `available` и `per_user_mfa=skipped`. По тексту `05` это ни `completed`, ни `partial`; так будет в обычном запуске почти каждого tenant. Все модули с `temporary_error` подходят одновременно под `partial` и под `failed`. Исход для таймаута запуска (30 минут, `02:65`) и для отмены при `disconnectTenant` (`05:134`) или `disable` не задан, а в `failureCode` нет `cancelled` и `timeout`.
- **Исправление.**
  - `skipped` входит в `completed`.
  - `failed`, если не получены `tenant` или `users`; иначе `partial`.
  - Добавить `failureCode`: `cancelled` и `run_timeout` (или правило «таймаут → partial с незавершёнными модулями `temporary_error`»).
  - Определить статус выключенного модуля `per_user_mfa` (H-MFA1 провалилась): `skipped` либо отдельный `disabled`.
- **Проверка.** Инвариант на вывод состояния из набора статусов; в примере `graph-collection` есть итоговое `state`.

### F-10. M365-006: расхождение default и смысл `…-recommended`

- **Где.** `05:54`: default — только `…microsoft-user-default-low`. `03:173` и схема (`contract_schemas.py:306–308`): `-low` и `-recommended`. Инвариант `invariants_data.py:168` говорит о «известных Microsoft-политиках», а `03:174` даёт unknown для любой политики вне разрешённого списка; что делать с известной, но не разрешённой политикой, не ясно.
- **Факт.** Управляемая политика `microsoft-user-default-recommended` разрешает пользователю consent на любые user-consentable delegated permissions, кроме перечня. В перечне чтение файлов и сайтов, почты, календаря, чатов, задач, `People.Read`, общие и записываемые контакты, а также EAS, EWS, IMAP и POP. `Mail.Send` и `Contacts.Read` в перечень не входят. Условия о проверенном издателе нет, тогда как `-low` ограничивает consent проверенными издателями и разрешениями «low» ([Manage app consent policies](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-app-consent-policies)).
- **Последствие.** Документы противоречат друг другу. Pass для `-recommended` по умолчанию оставляет риск consent phishing на непроверенных приложениях — это решение владельца (QX-3).
- **Исправление.** Исправить `05:54`. Для известной Microsoft-политики вне разрешённого списка давать fail, для собственной политики клиента — unknown; синхронизировать с инвариантом.
- **Проверка.** Таблица `05` совпадает с default схемы (это можно добавить в `validate_docs.py`); fixtures AT-05 для `-low`, `-recommended` и собственной политики.

### F-11. Пример покрытия противоречит правилам

- **Где.** `05:505–520`; пример — fixture AT-07 (`07:135`).
- **Противоречие (а).** «M365-006 — pass, stale (50 часов)». По `05:233` текущая проекция — наблюдение последнего завершённого запуска, в котором есть субъект tenant. В последнем `partial` запуске M365-006 имеет `unavailable`/`temporary_error`, а если наблюдение не записано — `missing_observation` (`05:236`). Значит, текущая оценка — unknown, а не stale pass.
- **Противоречие (б).** «not_applicable — 2: M365-001 и M365-007 у G». M365-007 в примере informational, а informational-оценка всегда имеет `result=null`, и `policy_not_applicable` ей не присваивается (`03:49`, `Assessment.allOf` в `contract_schemas.py:507–510`). Правильно: informational — 6, not_applicable — 1.
- **Исправление.** Либо определить проекцию как «последний определённый результат плюс отдельная пометка о сбое» (это ближе к `01:30`), либо исправить пример: stale 0, unknown 2. Исправить счётчики.
- **Проверка.** Пересчёт fixture AT-07 даёт одинаковые числа по тексту и по реализации; итог — в разделе «Пересчёт примера покрытия».

### F-12. Запуск может записать данные после отключения

- **Где.** `05:134` («незавершённые запуски отменяются»), `05:154` и `02:57` (одна транзакция в конце запуска). Инварианта нет.
- **Сценарий.** `disconnectTenant` или `disable` выполняются, пока запуск в состоянии `running`. Финальная транзакция без повторной проверки пишет наблюдения и события, в том числе `resolved` с `source_change`, уже после отключения. Replay журнала безопасности это не исправит.
- **Исправление.** Финальная транзакция блокирует строку `tenant_connection` и организации и пишет данные, только если статусы `active`, `entraTenantId` прежний, а запуск в состоянии `running`. Иначе — отмена.
- **Проверка.** Инвариант и сценарий AT-03: disconnect во время запуска не создаёт наблюдений и событий.

### F-13. M365-007: ложный pass для старых учётных записей

- **Где.** `03:180`: fail при `null`, если `createdAt` старше `inactiveDays`; иначе pass. Схема — `contract_schemas.py:182–183`.
- **Факт.** `createdDateTime` «is null for some users created before June 2018 and on-premises users that were synced … before June 2018» ([user](https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0)). `lastSuccessfulSignInDateTime` заполняется с 2023-12-01 ([signInActivity](https://learn.microsoft.com/en-us/graph/api/resources/signinactivity?view=graph-rest-1.0)).
- **Сценарий.** Учётная запись 2016 года без входа с 2023 года: `createdAt=null`, `lastSuccessfulSignInAt=null`, в режиме assessed — pass. Именно самые старые заброшенные учётные записи и проходят.
- **Исправление.** `createdAt=null` считать датой не позже 2018-06-01: при `lastSuccessfulSignInAt=null` — fail. Как вариант — unknown/`unmapped_state`.
- **Проверка.** Fixture AT-05 с `createdAt=null` и `lastSuccessfulSignInAt=null` в режиме assessed даёт fail.

### F-14. M365-005 считает отключённых глобальных администраторов

- **Где.** `03:159–165`, `contract_schemas.py:177–178`. Нет `accountEnabled`, и правило подсчёта отключённых не задано.
- **Сценарий.** Один включённый GA и один отключённый дают число 2, то есть pass, хотя фактически точка отказа одна.
- **Исправление.** Считать только `accountEnabled=true`, отключённых показывать в explanation. Учёт временных активаций — F-06.
- **Проверка.** Fixture AT-05 «1 включённый и 1 отключённый GA» даёт fail.

### F-15. RLS: «политика записи» не ограничивает DELETE

- **Где.** `02:123` (чтение: `org = scope_org() OR scope_all()`; запись: WITH CHECK `org = scope_org()`), инвариант `invariants_data.py:92` (проверяется только INSERT).
- **Факт PostgreSQL.** WITH CHECK применяется к INSERT и UPDATE. DELETE и выбор строк для UPDATE определяет только USING. Если реализовать одну политику `FOR ALL USING (чтение) WITH CHECK (запись)`, то в области all команда `DELETE` удалит строки всех организаций. Если же отдельную политику для DELETE не создать, DELETE будет запрещён везде, и `retention_purge` и `organization_delete` перестанут работать.
- **Исправление.** Политики по командам:
  - SELECT: USING по правилу чтения;
  - INSERT: WITH CHECK по правилу записи;
  - UPDATE: USING и WITH CHECK по правилу записи;
  - DELETE: USING по правилу записи.
- **Проверка.** AT-01: DELETE и UPDATE в области all и в чужой организации затрагивают 0 строк.

### F-16. Нет хранилища `idempotencyKey`

- **Где.** `05:443`, операции `changeOrganizationLifecycle`, `createOrganizationExport`, `requestCollection` и `requestDeviceScan` (`05:406–435`). В таблице сущностей (`05:7–31`) нет места для ключа, хэша запроса и ответа; для агента такое место есть — `enrollment`.
- **Исправление.** Сущность `idempotency_record`: `organizationId`, `operationId`, `key`, `requestHash`, `responseStatus`, `responseBody` или `resultId`, `createdAt`, `expiresAt`. Срок хранения и место в `retention_purge`.
- **Проверка.** Инварианты повтора уже есть, нужна строка в таблице сущностей и в сроках хранения.

### F-17. Пробелы автомата подключения M365

- **Где.** `05:122–124`, `contract_paths.py:227–228`, `05:129`, `05:84`, `05:115`, `05:493`.
- **Пробелы.**
  1. «По истечении state без завершения он возвращается к прежнему» — механизм не задан: задания нет, прежний статус нигде не хранится.
  2. По контракту в `consent_pending` переходят только `not_connected` и `disconnected`. В `05` повторный consent при новых правах выполняется тем же путём. Непонятно, что с `active`: остаётся ли сбор и какой код ответа.
  3. Можно ли из `disconnected` подключить другой tenant: формулировка «действующего подключения» в шаге 3 допускает оба толкования.
  4. Tenant-субъект никогда не выводится из учёта (`05:84`), а «Tenant — подключение active» (`05:493`) засчитывает пары прежнего tenant в знаменатель покрытия после смены tenant.
  5. `completeTenantConsent` для организации, отключённой после старта, — нет шага с 409.
  6. Повторная отправка того же state той же сессией (двойной вызов эффекта в SPA) даёт 400, хотя подключение уже создано.
- **Исправление.**
  - Хранить `previousStatus` или вычислять статус при чтении.
  - Повторный consent на `active`: статус не меняется, сбор продолжается.
  - Явно разрешить или запретить смену tenant; при смене выводить из учёта прежние субъекты с отдельной причиной.
  - Активный tenant-субъект — тот, чей `key` равен текущему `entraTenantId`.
  - Добавить шаг `lifecycle_transition_forbidden`.
  - Повтор той же сессии отдаёт прежний результат.
- **Проверка.** Таблица переходов `tenant_connection` в `05` и инварианты к ней.

### F-18. Отказ схемы для одного наблюдения M365 не определён

- **Где.** `05:154`; `contract_schemas.py:165` (`userType` — только Member или Guest), `:169` (не больше 50 MFA-политик), `:193` и `:478` (SAFE_TEXT для UPN и `tenantDisplayName`).
- **Факт.** `userType` поддерживает фильтр «`eq` on `null` values», то есть бывает null ([user](https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0)). Лимит CA-политик в tenant заметно больше 50.
- **Сценарий.** Одно наблюдение не проходит схему. Неизвестно, отбрасывается ли оно (`missing_observation`, модуль `partial`) или падает весь запуск. Если `tenantDisplayName` содержит `<`, ответ API нарушает собственную схему.
- **Исправление.**
  - Правило «наблюдение вне схемы → unavailable/`partial_data`, модуль `partial`».
  - `userType=null` считать Member, как это делает Microsoft, или давать unknown.
  - Недопустимые символы в строках из Graph нормализовать (замена на U+FFFD), а не отклонять.
- **Проверка.** Негативы в `_graph_negatives` и инвариант.

### F-19. Семантика причин unknown

- **Где.** `03:20–26`: сборщик M365 выставляет `unsupported`, но ни один статус модуля в него не переходит (`03:211`). `03:30–36`: только сервер выставляет 11 причин, а правило M365-005 выставляет `partial_data` (`03:161`, инвариант 134). Конфликт с `permission_missing` модуля `roles` — см. F-04.
- **Исправление.** Либо убрать `unsupported` из причин M365 (`contract_catalog.py:133`), либо задать его источник. Явно разрешить правилам использовать `partial_data` (или оформлять M365-005 как `unavailable`).

### F-20. Список привилегированных ролей и область назначений

- **Где.** `03:101–118`, `contract_schemas.py:76–91`.
- **Факт.** Все 14 template ID верны. Но Microsoft помечает как Privileged и роли, которых нет в списке v1: Hybrid Identity Administrator, Domain Name Administrator, Password Administrator, External Identity Provider Administrator, Partner Tier1 и Tier2 Support, Directory Writers, Cloud Device Administrator, Security Operator, Global Reader и другие ([Built-in roles](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference)). Первые четыре дают путь к повышению прав. В перечне ролей, для которых Security Defaults требуют MFA, есть Password Administrator и Authentication Policy Administrator. Как учитывать назначения с `directoryScopeId` ≠ `/` (AU), не определено.
- **Исправление.** Включить в v1 хотя бы роли с путём к повышению прав или брать признак `isPrivileged` из определений ролей (сверить доступность в v1.0 в SP-01). Явно сказать, считается ли назначение в области AU.

### F-21. Сверка подписей Key Vault даёт ложную тревогу при подключении

- **Где.** `04:75` и `06:82` (подпись вне запуска сбора — оповещение безопасности), `05:130` (`completeTenantConsent` получает токен для tenant).
- **Факт.** `aud` в client assertion зависит от tenant ([Certificate credentials](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials)), поэтому каждый токен нового tenant требует подписи.
- **Исправление.** Сверять подписи с запусками и с операциями consent и проверки подключения; записывать `correlationId` подписи.

### F-22. Вход сотрудников: `amr`, выход, фиксация сессии

- **Где.** `04:18–21`, инвариант `invariants_data.py:78`.
- **Факт.** В [справочнике claims ID-токена](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference) `amr` нет. В [справочнике access token](https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference) он есть, и среди значений есть `wiaormfa`, который MFA не доказывает.
- **Исправление.**
  - SP-02 проверяет именно тот токен, который валидирует сервис.
  - Принимать только `mfa` (и при необходимости `ngcmfa`).
  - Запасной вариант — authentication context CA (`acrs`).
  - Описать выход (инвалидация серверной сессии) и смену идентификатора сессии после входа. Операции выхода нет ни в `04`, ни в OpenAPI.

### F-23. Устаревшие роли сотрудников

- **Где.** `05:10` (роли берутся при входе и обновлении сессии), `05:201` (ответственный — сотрудник с ролью Admin или Technician из `listStaff`).
- **Сценарий.** Уволенный техник больше не входит, его `roles` не обновляются, и ему можно назначать проблемы.
- **Исправление.** Признак активности (например, вход за последние N дней) или сброс ролей, когда обновление сессии отклонено.

### F-24. `policy_inputs_missing` для M365-002 недостижим

`05:51` и `05:69` против `contract_schemas.py:302`: `minItems=1`, поэтому пустой список даёт `schema_violation`, а не `policy_inputs_missing`. Нужно согласовать текст и схему.

### F-25. Минимизация данных: `createdAt` не указан

`04:188` перечисляет сохраняемые поля M365 без даты создания пользователя, а M365-007 хранит `createdAt` (`contract_schemas.py:183`).

### F-26. Учётная запись синхронизации даёт постоянный fail M365-001

Включённый member On-Premises Directory Synchronization Service Account (роль Directory Synchronization Accounts, `d29b2b05-…`) не может иметь MFA, и Security Defaults его исключают. M365-001 будет давать fail warning у каждого гибридного клиента. Рекомендация: автоматически исключать пользователей с этой ролью или подсказывать Admin внести их в `excludedUserIds`.

### F-27. Граница tenant по таймауту запуска

При 5 запросах методов за 10 секунд на tenant ([Throttling limits](https://learn.microsoft.com/en-us/graph/throttling-limits)) и таймауте запуска 30 минут (`02:65`) запуск укладывается примерно в 850–900 включённых пользователей. Условие пересмотра в `08:73` говорит о «ночном окне» и 300 пользователях, а ограничивает фактически таймаут. Нужно назвать именно его и задать поведение (`partial` с ротацией пользователей или чтение `userRegistrationDetails`).

---

## Риски из внешних фактов (не дефекты текста)

- **RX-1. Security Defaults по отдельным защитам (preview).** Страница [Security defaults](https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults) обновлена 2026-10-14. Защиты «MFA для всех», «MFA для администраторов», «блокировка legacy» и «device code» включаются по отдельности (private preview для Free) и могут работать вместе с CA. Тогда `isEnabled=true` уже не означает, что все защиты включены — это ложный pass M365-003 (шаг 1) и M365-004. Кроме того, для обычных пользователей Security Defaults требуют MFA «when necessary», и explanation должен это говорить. Предлагается гипотеза для SP-01: как Graph отражает защиты по отдельности; если не отражает — pass только с оговоркой.
- **RX-2. Политика почтовых клиентов.** `microsoft-user-default-allow-consent-apps`, «enabled by default» ([Manage app consent policies](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-app-consent-policies)). Если она попадает в `permissionGrantPoliciesAssigned`, то по default-политике M365-006 у tenant с настройкой Microsoft получится unknown/`unmapped_state`. Проверить в SP-01.
- **RX-3. GDAP и DAP.** Доступ техников компании к tenant клиента через GDAP или DAP, по-видимому, не отражается в `roleAssignments` клиента. Тогда M365-002 и M365-005 не видят собственный привилегированный доступ MSP. Проверить в SP-01 и указать в explanation.
- **RX-4. State в журналах.** Redirect consent приходит GET-запросом с `state` и `tenant` в query. Журналы App Service и request telemetry Application Insights по умолчанию пишут URL целиком. Нужно исключить query этого маршрута из журналов (`04` запрещает писать nonce, а state по смыслу такой же секрет).
- **RX-5. Проверенный издатель.** Multi-tenant приложение без подтверждённого издателя показывает администратору клиента экран consent с пометкой «unverified». Для MSP-партнёра стоит подтвердить издателя через MPN ID, чтобы consent меньше пугал клиентов и не путался с фишингом.

## Вопросы владельцу и открытые решения

- **QX-1.** Считать ли принуждением к MFA «MFA или соответствующее или гибридное устройство» и исключение доверенных расположений? Предлагается: по умолчанию нет, unknown; параметром политики — да, с пометкой в explanation.
- **QX-2.** Снятие привилегированной роли у администратора без MFA — это исправление (`source_change`) или «стало неприменимым» (`applicability_change`)? Это влияет на критерий ценности пилота.
- **QX-3.** Оставлять ли `…-recommended` в разрешённых по умолчанию, если она допускает непроверенных издателей? CIS для M365 рекомендует запрещать согласие пользователей.
- **QX-4.** Гости с привилегированной ролью: оценивать методы в tenant ресурса, давать unknown или вынести в отдельный fail «гость с ролью»?

## Пересчёт примера покрытия (`05:505–520`)

Знаменатель — 8 пар: M365-001 у U1…U4 (G — not_applicable), M365-002 у U3, M365-003, M365-005 и M365-006 у tenant. Совпадает с примером.

| Метрика | Пакет | Пересчёт | Комментарий |
| --- | --- | --- | --- |
| `coverageAt` | 6/8 = 75,0% | 6/8 = 75,0% | U1 pass, U2 fail, U3 pass ×2, M365-003 fail, M365-005 fail |
| `coveragePeriod` | 7/8 = 87,5% | 7/8 = 87,5% | Плюс pass M365-006 в периоде; у U4 нет определённой оценки |
| Compliance | 3/6 = 50% | 3/6 = 50% | pass: U1, U3 (001), U3 (002); fail: U2, M365-003, M365-005 |
| informational | 5 | 6 | M365-007 у G — informational с `result=null` (`03:49`) |
| not_applicable | 2 | 1 | Только M365-001 у G |
| stale / unknown | 1 / 1 | 0 / 2 по `05:233` | M365-006 в последнем запуске `unavailable` (F-11) |

M365-005 fail согласуется с `minGlobalAdmins=2` (один GA — U3).

## Сверка внешних фактов

| Положение пакета | Итог | Источник |
| --- | --- | --- |
| `GroupMember.ReadBasic.All` — наименьшее право для `transitiveMembers` | Верно (application) | [List transitiveMembers](https://learn.microsoft.com/en-us/graph/api/group-list-transitivemembers?view=graph-rest-1.0) |
| `RoleManagement.Read.Directory` — наименьшее право для `roleAssignments` | Верно | [List roleAssignments](https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignments?view=graph-rest-1.0) |
| CA — `Policy.Read.All`, более узкого права нет | Верно | [List CA policies](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies?view=graph-rest-1.0) |
| Per-user MFA — beta `/users/{id}/authentication/requirements`, `Policy.Read.All` | Верно; beta «not supported» в production — учтено гипотезой H-MFA1 | [Get authentication states (beta)](https://learn.microsoft.com/en-us/graph/api/authentication-get?view=graph-rest-beta) |
| Лимиты: 5 за 10 с на tenant и 122 за 10 с на все tenant (identity and access reports, включая `authenticationMethod`); `signInActivity` — 10 в минуту; CA — 1 в секунду на tenant для всех приложений, без Retry-After | Верно | [Throttling limits](https://learn.microsoft.com/en-us/graph/throttling-limits) |
| Client assertion PS256 и `x5t#S256` | Верно; `aud` зависит от tenant (F-21) | [Certificate credentials](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials) |
| Consent на application permissions Graph — Privileged Role Administrator или GA | Верно; `organizations` выдаёт consent в домашнем tenant входящего (F-01) | [Grant admin consent](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/grant-admin-consent) |
| Параметрам ответа consent нельзя доверять | Верно; ответ с ошибкой тоже содержит `admin_consent=True`, и порядок проверок в `05` (сначала `error`) правильный | [Admin consent protocol](https://learn.microsoft.com/en-us/entra/identity-platform/v2-admin-consent) |
| `lastSuccessfulSignInDateTime` с 2023-12-01, без досчёта | Верно | [signInActivity](https://learn.microsoft.com/en-us/graph/api/resources/signinactivity?view=graph-rest-1.0) |
| 14 template ID ролей | Верно (F-20 — о полноте списка) | [Built-in roles](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference) |
| `…-recommended` — default для новых tenant | Верно; смысл политики — F-10 | [Manage app consent policies](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-app-consent-policies) |
| SMTP AUTH Basic: выключение по умолчанию в конце декабря 2026, окончательная дата — во второй половине 2027 | Верно (MC786329) | [heise](https://heise.de/-11156432) |
| Security Defaults: MFA для администраторов, для пользователей «when necessary», блокировка legacy | Верно; новый режим отдельных защит — RX-1 | [Security defaults](https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults) |
| Authentication strength может не давать MFA | Пакетом не учтено (F-03) | [authenticationStrengthPolicy](https://learn.microsoft.com/en-us/graph/api/resources/authenticationstrengthpolicy?view=graph-rest-1.0) |
| `createdDateTime` бывает null, `userType` бывает null | Пакетом не учтено (F-13, F-18) | [user](https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0) |
| `amr` в ID-токене | В справочнике ID-токена отсутствует (F-22) | [ID token claims](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference) |

Не сверено: видимость GDAP в `roleAssignments` клиента (RX-3); то, что каждый запрос в JSON batch учитывается отдельно (принято по `10-sources.md`); как политика почтовых клиентов отражается в `permissionGrantPoliciesAssigned` (RX-2).

## Что подтверждено без замечаний

- Набор прав Graph минимален для выбранных модулей. Право на `subscribedSkus` объяснено (`04:55`), `Directory.Read.All` не запрашивается.
- Порядок проверок `completeTenantConsent`: state, затем `error`, затем конфликт, затем собственный токен и `/organization`. Недоверие к параметру `tenant` соответствует документации Microsoft.
- Определение лицензии P1/P2 по service plan, а не по имени SKU; правило «403 не доказывает отсутствие лицензии».
- Журнал безопасности:
  - запись до commit с откатом при сбое;
  - replay с `T − 5 минут`;
  - `schedule_deletion` повторяется не раньше чем через 24 часа (`06:115`), поэтому отменённое удаление не исполняется мгновенно после restore;
  - срок неизменяемости журнала больше срока PITR.
- Выдача отчёта: заголовки и CSP sandbox, `nosniff`, `no-store`, вывод недоверенных строк только как текст, запрет `dangerouslySetInnerHTML`.
- Защита от SSRF в сборщике: фиксированные хосты, `@odata.nextLink` только того же хоста и пути.
- Cursor привязан к операции, организации и фильтру; сущность чужой организации даёт 404.

## Рекомендуемый порядок исправлений

1. До SP-01: F-01, F-02 (дизайн consent) и проверки RX-1…RX-3 включить в протокол SP-01.
2. До WP-04 (правила M365): F-03, F-04, F-05, F-06, F-08, затем F-13, F-14, F-10, F-19, F-20.
3. До WP-02 (каркас и изоляция): F-07, F-15, F-16.
4. Остальное — в 0.3.x вместе с инвариантами и fixtures AT-03, AT-04, AT-05, AT-06 и AT-07.
