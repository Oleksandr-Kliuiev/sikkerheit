# Каталог проверок и ограничений

Каталог определяет измеряемые факты, условия вывода и границы интерпретации. Пороговые значения ниже — параметры политики v1, которую сервер создаёт вместе с организацией; любое изменение даёт новую неизменяемую ревизию политики и запись в аудите. `checkId` хранится в наблюдении и совпадает с машинным каталогом `specs/check-catalog.json`.

Каталог содержит 21 проверку. Семь проверок Microsoft 365 (M365-*) относятся к P1; M365-007 отложена вместе с правом `AuditLog.Read.All` (правило M365-007 ниже), поэтому в P1 собираются шесть. Одиннадцать проверок агента Windows (WIN-*) и три серверные проверки (SYS-*) — в P2. Для каждой проверки каталог задаёт:

- `defaultAssessmentMode` — `assessed` или `informational`;
- `source` — `graph`, `agent` или `server`;
- `subjectType` — тип объекта.

Колонки «Объект» и «Режим по умолчанию» в таблицах ниже совпадают с этими полями каталога.

## Семантика результата

Сборщик возвращает для каждого наблюдения `collectionStatus` — `collected` либо `unavailable`. Evidence передаётся только при `collected` и только по закрытой схеме проверки:

- агента — `specs/observation.schema.json`;
- M365 — `specs/graph-observation.schema.json`;
- серверных проверок SYS-* — `evidenceSchema` в `specs/check-catalog.json`.

Причины недоступности описывают только сбор. Агент передаёт `permission_denied`, `unsupported`, `collector_timeout` или `temporary_error`. Сборщик M365 выставляет только четыре причины (`GRAPH_COLLECTOR_REASONS` каталога, перечисление `reasonCode` схемы `specs/graph-observation.schema.json`):

- `permission_denied` — 403 на запрос;
- `temporary_error` — сбой или исчерпаны повторы;
- `license_missing` — модулю нужна лицензия, которой нет по `subscribedSkus`;
- `partial_data` — неполные страницы, нет обязательного свойства или наблюдение не прошло схему.

`unsupported` и `collector_timeout` сборщик M365 не выставляет: функция, которой нет в tenant, проявляется как `license_missing` или 403, а таймаут запуска — как `temporary_error`.

Сборщик не решает, применима ли проверка: это делает сервер по действующей ревизии политики и фактам того же источника.

Сервер оценивает наблюдение как `pass`, `fail`, `unknown` либо `not_applicable`; успешное получение факта не означает pass. Причины unknown и not_applicable, которые выставляет только сервер:

- `missing_observation`, `clock_inconsistent`, `unmapped_state`;
- `applicability_input_missing`, `policy_not_applicable`, `evidence_time_invalid`;
- `os_version_unknown`, `os_inventory_missing`;
- `release_catalog_stale`, `build_not_in_catalog`;
- `enforcement_unconfirmed`.

Вместе с шестью причинами сбора они образуют закрытый перечень `Assessment.reasonCode` из 17 значений.

Оценка определяется по порядку, действует первое совпадение:

1. Признак часов пакета агента — unknown/`clock_inconsistent` (`05`, «Время и часы устройства»).
2. Применимость, если она зависит от другого наблюдения того же пакета или от атрибутов субъекта. Вход отсутствует или `unavailable` — unknown/`applicability_input_missing`; применимость известна и проверка не применима — not_applicable/`policy_not_applicable`.
3. Собственное наблюдение: отсутствует — unknown/`missing_observation`; `unavailable` — unknown с причиной наблюдения.
4. Правило проверки.

`assessmentMode` хранится в ревизии политики явно для каждой проверки; наличие входных настроек — необходимое, но не достаточное условие режима `assessed`.

Informational-оценка всегда имеет `result=null`, `severity=null`, не создаёт finding и не участвует в compliance. В неё переносятся только причины отсутствия данных — шесть причин сбора, `missing_observation`, `clock_inconsistent` и `applicability_input_missing`. Остальные причины правил informational-оценке не присваиваются: `result=null`, `reasonCode=null`.

`Finding.severity` — `critical` или `warning` по колонке «Severity при fail».

Отдельно хранится `freshness=fresh|stale`. Окно свежести `freshnessWindowHours` задаётся в политике для каждой проверки: 48 часов для M365 (сбор раз в сутки), 72 часа для Windows. Свежесть вычисляется при чтении на текущий момент и при формировании отчёта на `periodEnd`. Устаревший pass показывается как прошлый результат с датой. Метрики покрытия и пример — `05`, раздел «Отчёт и покрытие».

## Проверки Microsoft 365

| ID | Проверка и данные | Объект | Режим по умолчанию | Условие оценки | Severity при fail | Права и ограничения |
| --- | --- | --- | --- | --- | --- | --- |
| M365-001 | Регистрация MFA пользователя: `accountEnabled`, `userType`, признак учётной записи синхронизации, `methodKinds` | user | assessed | По правилу M365-001 ниже; входные настройки не нужны | warning | `User.Read.All`, `UserAuthenticationMethod.Read.All`; без лицензии P1. Регистрация метода не доказывает обязательность MFA |
| M365-002 | Регистрация MFA администратора: роли, способ назначения, временные активации PIM, `methodKinds` | user | assessed | По правилу M365-002 ниже; список ролей не пуст по схеме | critical; гость с ролью — warning | `RoleManagement.Read.Directory`, `GroupMember.Read.All`; активные назначения, включая временные активации PIM |
| M365-003 | Принуждение к MFA: Security Defaults, политики CA с MFA, per-user MFA | tenant | assessed | По правилу M365-003 ниже | critical | `Policy.Read.All`; Conditional Access требует Entra ID P1; per-user MFA — только Graph beta |
| M365-004 | Блокировка устаревшей аутентификации: Security Defaults и политики CA | tenant | informational | Инвентаризация; правило для assessed — ниже | warning | `Policy.Read.All` |
| M365-005 | Число включённых глобальных администраторов | tenant | assessed | fail вне [`minGlobalAdmins`, `maxGlobalAdmins`] (2…4) | warning | Активные назначения, прямые или через группу; отключённые учётные записи не считаются |
| M365-006 | Согласие пользователей на приложения: `permissionGrantPolicies` | tenant | assessed | По правилу M365-006 ниже | warning | `Policy.Read.All` |
| M365-007 | Неактивные учётные записи: последний успешный вход | user | informational | Инвентаризация; для assessed — `inactiveDays` (90) | warning | Отложена: `AuditLog.Read.All` не входит в первый consent. Требует Entra ID P1; лимит `signInActivity` — 10 запросов в минуту |

Все запросы — Graph v1.0, кроме модуля `per_user_mfa` (раздел «Возможности подключения»). Приложение имеет только права чтения и ничего не меняет в tenant. Объём сохраняемых данных ограничен allowlist-схемой: номера телефонов, адреса и названия методов не сохраняются. Наблюдение, не прошедшее схему, сохраняется как unavailable/`partial_data`, а его модуль получает `partial`. Строки из Graph с недопустимыми символами (управляющие, `<`, `>`) нормализуются заменой символа на U+FFFD, а не отклоняются.

Причина `partial_data` возникает тремя путями: модуль получил неполные данные, ответ неизвестной формы (правило M365-003 ниже), или правило M365-005 не смогло прочитать членов группы с ролью. Причины `permission_denied`, `temporary_error`, `license_missing` и `partial_data` переносятся в наблюдения из статусов модулей по таблице «Проверка → модули» ниже.

Чего проверки не видят:

- доступ сотрудников компании в tenant клиента через GDAP: он не отражается в назначениях ролей клиента (проверяет SP-01);
- назначения eligible в PIM до активации;
- регистрацию методов гостя в его домашнем tenant;
- администраторов ролей вне `privilegedRoleTemplateIds`: M365-002 их не оценивает, но шаблоны таких ролей перечисляет M365-005 (`uncoveredRoleTemplateIds`), чтобы Admin решил, добавить ли роль в политику.

Explanation называет эти ограничения там, где они влияют на вывод.

### Правило M365-001 и M365-002

Сборщик нормализует `@odata.type` методов аутентификации в `methodKinds`:

- `microsoftAuthenticatorAuthenticationMethod` → `microsoft_authenticator`;
- `fido2AuthenticationMethod` → `fido2`;
- `windowsHelloForBusinessAuthenticationMethod` → `windows_hello_for_business`;
- `platformCredentialAuthenticationMethod` → `platform_credential`;
- `softwareOathAuthenticationMethod` → `software_oath`;
- `phoneAuthenticationMethod` → `phone`;
- `externalAuthenticationMethod` → `external`;
- `emailAuthenticationMethod` → `email`;
- `temporaryAccessPassAuthenticationMethod` → `temporary_access_pass`;
- `passwordAuthenticationMethod` → `password`;
- `qrCodePinAuthenticationMethod` → `qr_code_pin`;
- остальные типы → `other`.

`methodKinds` равен null, если методы пользователя не запрашивались.

Метод MFA — `microsoft_authenticator`, `fido2`, `windows_hello_for_business`, `platform_credential`, `software_oath`, `hardware_oath`, `external`, а при `phoneMethodsAccepted=true` — также `phone`. Не считаются: `password`, `email` (используется только для сброса пароля), `temporary_access_pass` (временный), `qr_code_pin` (вход сотрудников с общими устройствами) и `other`. Аппаратные токены OATH Graph показывает только в beta. В P1 они не читаются: пользователь только с аппаратным токеном получит fail, а explanation назовёт эту причину. Гипотеза H-MFA2 в SP-01 решает, читать ли их в новой `ruleVersion`; до этого такой fail оформляется решением `suppressed`.

M365-001 — объект: каждый пользователь tenant.

- **Применимость.** Проверка применима к пользователю с `accountEnabled=true`, `userType=Member` (null считается Member), id вне `excludedUserIds` и без роли Directory Synchronization Accounts (`d29b2b05-8046-44ba-8758-1e26182fcf32`). Учётная запись синхронизации Entra Connect не может иметь MFA, и Security Defaults её тоже исключают. Остальные пользователи — not_applicable/`policy_not_applicable`; методы для них не запрашиваются.
- **Результат.** Pass — есть хотя бы один метод MFA. Fail warning — метода MFA нет. Отказ 403 на методы пользователя — unknown/`permission_denied`, сбой — unknown/`temporary_error`.
- **Границы вывода.** Explanation называет зарегистрированные виды методов и не утверждает, что MFA обязательна при входе: это оценивает M365-003.

M365-002 — объект: пользователь, у которого есть или была в предыдущем полном сборе активная роль из `privilegedRoleTemplateIds`.

- **Источник ролей.** Назначение прямое или через группу с назначаемыми ролями. Такие группы требуют Entra ID P1 и не бывают вложенными, поэтому члены читаются одним запросом `transitiveMembers`. Если членов группы прочитать не удалось, модуль `roles` получает `partial`: прямые администраторы оцениваются, M365-005 даёт unknown/`partial_data`.
- **Что учитывается.** Назначения с областью административной единицы считаются: MFA нужна и ограниченному администратору. Активные временные назначения PIM учитываются отдельным видом назначения: при Entra ID P2 сборщик сверяет назначения с `roleAssignmentScheduleInstances`, и роли, которые у пользователя действуют только как активация (`assignmentType=Activated`), перечисляются в `temporaryRoleTemplateIds`, а explanation называет активацию. Администратор, активировавший роль без метода MFA, получает fail, как и постоянный: именно в это время у него есть привилегии. Когда активация заканчивается, пара получает not_applicable и в отчёте попадает в «стали неприменимыми», а не в «исправлено». Назначения eligible до активации не видны.
- **Сбор методов.** Методы администраторов читаются всегда, даже если они в `excludedUserIds`: учётные записи аварийного доступа тоже должны иметь метод MFA, лучше FIDO2.
- **Результат** по порядку:
  1. Ролей больше нет (`roleTemplateIds` пуст) — not_applicable/`policy_not_applicable`; finding закрывается событием `resolved`/`applicability_change` и в отчёте попадает в «стали неприменимыми», а не в «исправлено».
  2. `accountEnabled=false` — not_applicable/`policy_not_applicable`.
  3. Гость (`userType=Guest`) — fail warning: методы гостя хранятся в его домашнем tenant и здесь не подтверждаются, а гость в привилегированной роли — отдельный риск. Explanation рекомендует выдавать такой доступ через GDAP или учётную запись в tenant.
  4. Есть метод MFA — pass.
  5. Иначе — fail critical.

Обязательная MFA Microsoft для порталов администрирования, введённая в 2024–2025 годах, не делает регистрацию лишней: без метода MFA администратор остаётся уязвим в остальных сценариях входа.

Роли политики v1 (`privilegedRoleTemplateIds`), идентификаторы шаблонов сверены со справочником встроенных ролей Microsoft Entra:

| Роль | Template ID |
| --- | --- |
| Global Administrator | 62e90394-69f5-4237-9190-012177145e10 |
| Privileged Role Administrator | e8611ab8-c189-46e8-94e1-60213ab1f814 |
| Privileged Authentication Administrator | 7be44c8a-adaf-4e2a-84d6-ab2649e08a13 |
| Security Administrator | 194ae4cb-b126-40b2-bd5b-6091b380977d |
| Conditional Access Administrator | b1be1c3e-b65d-4f19-8427-f6fa0d97feb9 |
| Exchange Administrator | 29232cdf-9323-42fd-ade2-1d097af3e4de |
| SharePoint Administrator | f28a1f50-f6e7-4571-818b-6a12f2af6b6c |
| User Administrator | fe930be7-5e62-47db-91af-98c3a49a38b1 |
| Authentication Administrator | c4e39bd9-1100-46d3-8c65-fb160da0071f |
| Authentication Policy Administrator | 0526716b-113d-4c15-b2c8-68e3c22b9f80 |
| Password Administrator | 966707d0-3269-4727-9be2-8c3a10f19b9d |
| Application Administrator | 9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3 |
| Cloud Application Administrator | 158c047a-c907-4556-b7ef-446551a6b5f7 |
| Intune Administrator | 3a2c62db-5318-420d-8d74-23affee5d9d5 |
| Helpdesk Administrator | 729827e3-9c14-49f7-bb1b-9608f156bbb8 |
| Billing Administrator | b0f54661-2d74-4c50-afa3-1ec803f12efe |
| Directory Writers | 9360feb5-f418-4baa-8175-e2a00bac4301 |
| Partner Tier2 Support | e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8 |

Microsoft помечает привилегированными и другие роли, например Hybrid Identity Administrator и Domain Name Administrator. Гипотеза H-ROLES в SP-01: доступен ли признак `isPrivileged` определений ролей в Graph v1.0. Если доступен, следующая версия правила дополняет список ролями с этим признаком; до этого Admin может добавить их в политику.

### Правило M365-003

Evidence:

- `securityDefaults` — `enabled` или `disabled`;
- `conditionalAccess` — `available` или `license_missing` (нет Entra ID P1 или P2 по `subscribedSkus`);
- `mfaPolicies` — сводка политик CA с grant control `mfa` или authentication strength в любом state. По каждой политике хранятся:
  - охват: все пользователи, все приложения и число исключённых приложений, все типы клиентов;
  - заданные условия: риск пользователя и входа, внутренний риск, расположения с отдельным признаком «исключены только доверенные», платформы, фильтр устройств, потоки аутентификации, клиентские приложения;
  - оператор grant (`AND` или `OR`) и набор grant controls;
  - даёт ли authentication strength требование MFA (`requirementsSatisfied = mfa`);
  - число исключённых пользователей вне `excludedUserIds` (прямо, через группы и роли) и число исключений, членов которых прочитать не удалось;
- `perUserMfa` — счётчики состояния per-user MFA включённых member-пользователей вне `excludedUserIds` и без роли синхронизации: `required` — enforced, `notRequired` — disabled, `enabled` — enabled, `unknown` — отсутствующее или нераспознанное состояние. Счётчик `enabled` необязателен: если его нет, состояние enabled учтено в `unknown`. null — модуль `per_user_mfa` не выполнялся.

**Безусловная политика** — политика, у которой выполнено всё перечисленное:

- state `enabled`;
- все пользователи, все приложения без исключённых приложений, все типы клиентов;
- нет условий. Исключение только доверенных расположений допускается, если `trustedLocationsExclusionAccepted=true`;
- MFA требуется всегда: grant содержит `mfa` или authentication strength с `requirementsSatisfied = mfa`, и при операторе `OR` других grant controls нет. Grant «MFA или соответствующее либо гибридное устройство» допускается, если `deviceAlternativeAccepted=true`;
- `excludedUsersOutsidePolicy` = 0 и `unresolvedExclusions` = 0. Исключения учётных записей аварийного доступа допустимы, если они внесены в `excludedUserIds`.

Исключение гостей и внешних пользователей не мешает: M365-001 их не оценивает.

Правило применяется по порядку, действует первое совпадение:

| № | Условие | Результат |
| --- | --- | --- |
| 1 | `securityDefaults=enabled` | pass; explanation: Security Defaults требуют MFA «при необходимости», а не при каждом входе |
| 2 | `conditionalAccess=available` и есть безусловная политика | pass; explanation называет политику и исключения |
| 3 | `perUserMfa` не null, у всех пользователей per-user MFA в состоянии enforced (`notRequired` = 0, `unknown` = 0, `enabled` = 0 или нет) | pass |
| 4 | `perUserMfa` не null, `notRequired` = 0, `enabled` + `unknown` > 0: у части пользователей состояние enabled или не распознано | unknown/`enforcement_unconfirmed`: enabled до подтверждения в SP-01 принуждением не считается |
| 5 | `conditionalAccess=available` и есть политики в state `enabled`, требующие MFA, но ни одна не безусловна | unknown/`enforcement_unconfirmed`: охват объединением или условиями политик не доказывается |
| 6 | `perUserMfa` null — модуль `per_user_mfa` выключен по итогам H-MFA1 | unknown/`enforcement_unconfirmed`; рекомендация — включить Security Defaults или политику CA |
| 7 | Иначе: Security Defaults выключены, безусловной политики нет, а per-user MFA у части пользователей disabled | fail critical |

Политики в состоянии report-only (`enabledForReportingButNotEnforced`) и disabled MFA не требуют. Поэтому единственная report-only политика при выключенных Security Defaults и per-user MFA даёт fail, а не pass — это эталонный отрицательный случай (пример `examples/m365-collection.json`, AT-05).

Модули `security_defaults` и, при Entra ID P1, `conditional_access` обязательны: их сбой (`temporary_error`, `permission_missing`) делает наблюдение M365-003 unavailable с той же причиной. Сбой не превращается в `disabled` и не даёт ложный fail.

Неизвестная форма ответа даёт unknown, а не pass. Неизвестной формой считаются:

- ответ Security Defaults без логического свойства `isEnabled`;
- политика CA с grant control `mfa`, authentication strength или block, у которой state не `enabled`, `enabledForReportingButNotEnforced` или `disabled`;
- такая же политика с заданным условием вне перечня `CA_CONDITIONS`, в том числе `servicePrincipalRiskLevels`, `times` и `deviceStates`.

Такой ответ не нормализуется с потерей смысла: модуль получает `partial`, наблюдения M365-003 и M365-004 — unavailable/`partial_data`, и M365-003 даёт unknown/`partial_data`. Положительная ветвь правила включается только для проверенной формы ответа; новое условие или новая защита попадают в перечень новой версией правила.

Per-user MFA читается только в Graph beta (`/beta/users/{id}/authentication/requirements`, право `Policy.Read.All`) и только когда шаги 1–2 не дают pass. Состояния `enabled` и `enforced` хранятся раздельно: pass даёт только enforced. В состоянии enabled MFA требуется лишь после регистрации метода, и обход в отдельных сценариях не исключён, поэтому до проверки в SP-01 оно даёт unknown/`enforcement_unconfirmed` (шаг 4). Гипотеза H-MFA1 в SP-01: endpoint работает стабильно на трёх tenant, а ответ различает disabled, enabled до регистрации метода и enforced при контролируемых входах. Если SP-01 подтвердит, что enabled означает принуждение, новая версия правила засчитывает его; если endpoint нестабилен, модуль `per_user_mfa` выключается (статус `skipped`), и шаг 6 даёт unknown.

Гипотеза H-SD1 в SP-01: Microsoft вводит отдельное включение защит Security Defaults (preview). Нужно выяснить, как Graph это показывает. Пока форма ответа не проверена, ответ с отдельными защитами вместо логического `isEnabled` даёт unknown/`partial_data`; если `isEnabled=true` перестанет означать включённую MFA для всех, шаг 1 в новой версии правила проверяет конкретную защиту.

### Правило M365-004

Informational по умолчанию: показывает, блокирует ли tenant устаревшую аутентификацию. Блокировку дают включённые Security Defaults либо политика CA с grant control block, которая отвечает всем условиям:

- state `enabled`;
- все пользователи и все приложения без исключённых приложений;
- без условий;
- типы клиентов Exchange ActiveSync и «другие клиенты»;
- без исключений вне `excludedUserIds`.

Если политика переводит проверку в `assessed`:

- блокировка есть — pass;
- Conditional Access доступен, Security Defaults выключены, такой политики нет — fail warning;
- Conditional Access недоступен и Security Defaults выключены — unknown/`enforcement_unconfirmed`.

Exchange Online выключает Basic-аутентификацию SMTP AUTH по умолчанию в конце декабря 2026 года, но администратор может включить её обратно, а окончательная дата отключения ещё не объявлена; поэтому инвентаризация остаётся полезной.

### Правило M365-005

Evidence:

- `globalAdminUserIds` — включённые пользователи с активным назначением Global Administrator, прямым или через группу, без временных активаций PIM;
- `disabledGlobalAdminUserIds` — отключённые учётные записи с этой ролью;
- `unresolvedGroupAssignments` — группы с ролью, членов которых прочитать не удалось;
- `uncoveredRoleTemplateIds` — необязательное поле: шаблоны ролей каталога вне `privilegedRoleTemplateIds` политики, назначенные включённым пользователям. На результат оно не влияет, explanation перечисляет такие роли и предлагает Admin проверить, не добавить ли их в политику M365-002.

Сервисные principal в число не входят.

- `unresolvedGroupAssignments` > 0 — unknown/`partial_data`.
- Число включённых администраторов вне [`minGlobalAdmins`, `maxGlobalAdmins`] — fail warning.
- Иначе — pass.

Explanation называет число и UPN администраторов и отдельно — отключённые учётные записи с ролью, у которых роль лучше снять. Рекомендация: два–четыре включённых глобальных администратора, включая учётную запись аварийного доступа. Один администратор — единая точка отказа, больше четырёх — лишняя поверхность атаки.

### Правило M365-006

Evidence — записи `ManagePermissionGrantsForSelf.*` из `defaultUserRolePermissions.permissionGrantPoliciesAssigned`. Префикс сравнивается без учёта регистра и сохраняется в каноническом написании; записи `ManagePermissionGrantsForOwnedResource.*` к согласию пользователей не относятся и не сохраняются.

Известные политики Microsoft — данные правила:

| Политика | Смысл | По умолчанию |
| --- | --- | --- |
| `…microsoft-user-default-legacy` | Пользователи согласуют любые приложения | fail |
| `…microsoft-user-default-recommended` | Управляемая Microsoft политика, по умолчанию для новых tenant; допускает приложения непроверенных издателей для многих разрешений | fail, пока не разрешена политикой клиента |
| `…microsoft-user-default-low` | Только проверенные издатели и разрешения низкого влияния | Разрешена (`allowedPermissionGrantPolicies` v1) |
| Политика почтовых клиентов Microsoft (`…microsoft-user-default-allow-consent-apps`, в документации встречается и другое написание) | Согласие только для одобренных Microsoft почтовых приложений | Не влияет на результат; фактическое написание подтверждает SP-01 |

Правило по порядку:

1. Есть `…-legacy` — fail warning.
2. Список пуст — согласие пользователей выключено — pass.
3. Каждая запись входит в `allowedPermissionGrantPolicies` или является политикой почтовых клиентов — pass.
4. Есть известная политика Microsoft вне разрешённых — fail warning.
5. Иначе (собственная политика клиента) — unknown/`unmapped_state`; Admin может разрешить её после проверки.

### Правило M365-007

M365-007 отложена: право `AuditLog.Read.All` в первый consent не входит, модуль `sign_in_activity` всегда получает `skipped`, и наблюдений M365-007 сборщик не пишет. В режиме informational (по умолчанию) оценок M365-007 нет, а перевод в assessed даёт каждому пользователю unknown/`missing_observation`. Проверка вводится новой версией правил с повторным consent всех клиентов (`04`, «Права Graph»; RB-03); правило ниже действует с этой версии.

Informational по умолчанию: число дней с последнего успешного входа (`lastSuccessfulSignInAt` из `signInActivity`). Поле заполняется Microsoft с 1 декабря 2023 года; null означает, что успешного входа с этой даты не было. Применимость — как у M365-001. Без Entra ID P1 модуль получает `license_missing`, и оценка — `result=null` с этой причиной.

Если политика переводит проверку в `assessed`, fail warning даёт любое из условий:

- `lastSuccessfulSignInAt` старше `inactiveDays`;
- `lastSuccessfulSignInAt` null при `createdAt` старше `inactiveDays`;
- `lastSuccessfulSignInAt` null при `createdAt` null — учётная запись создана до июня 2018 года.

Иначе — pass.

## Возможности подключения

Каждый модуль запуска сбора получает статус:

- `available` — данные получены полностью;
- `skipped` — модуль в этом запуске не нужен или выключен;
- `permission_missing` — 403 Authorization_RequestDenied на основной запрос модуля;
- `license_missing` — по `subscribedSkus` нет нужного плана, запрос не выполнялся;
- `partial` — не все страницы, нет обязательного свойства, наблюдение вне схемы, отклонён `@odata.nextLink` или 403 на часть вложенных запросов (члены отдельных групп);
- `temporary_error` — 5xx, таймаут или исчерпаны повторы.

| Модуль | Endpoints | Права | Лицензия |
| --- | --- | --- | --- |
| tenant | `/organization` | `Organization.Read.All` | — |
| licenses | `/subscribedSkus` | `Organization.Read.All` | — |
| users | `/users` со списком полей | `User.Read.All` | — |
| auth_methods | `/users/{id}/authentication/methods` в JSON batch | `UserAuthenticationMethod.Read.All` | — |
| roles | `/roleManagement/directory/roleAssignments`, `/groups/{id}/transitiveMembers`; при Entra ID P2 — `roleAssignmentScheduleInstances` | `RoleManagement.Read.Directory`, `GroupMember.Read.All` | — |
| security_defaults | `/policies/identitySecurityDefaultsEnforcementPolicy` | `Policy.Read.All` | — |
| conditional_access | `/identity/conditionalAccess/policies`; члены исключённых групп — `transitiveMembers` | `Policy.Read.All`, `GroupMember.Read.All` | Entra ID P1 |
| authorization_policy | `/policies/authorizationPolicy` | `Policy.Read.All` | — |
| sign_in_activity | `/users` с `signInActivity`; отложен вместе с M365-007, в P1 всегда `skipped` | `User.Read.All`, `AuditLog.Read.All` | Entra ID P1 |
| per_user_mfa | `/beta/users/{id}/authentication/requirements` | `Policy.Read.All` | — |

Проверка → модули. Сбой обязательного модуля делает наблюдение проверки `unavailable` с причиной, перенесённой из статуса модуля. Условный модуль со статусом `license_missing` отражается в evidence, а не в причине.

| Проверка | Обязательные модули | Условные модули |
| --- | --- | --- |
| M365-001 | users, roles; auth_methods — для пользователя, к которому проверка применима | — |
| M365-002 | users, roles; auth_methods — для каждого администратора | — |
| M365-003 | licenses, security_defaults; conditional_access — при Entra ID P1; per_user_mfa — когда он нужен по правилу | conditional_access без P1 (`conditionalAccess=license_missing`) |
| M365-004 | licenses, security_defaults; conditional_access — при Entra ID P1 | conditional_access без P1 |
| M365-005 | roles | — |
| M365-006 | authorization_policy | — |
| M365-007 | users, roles | sign_in_activity — после ввода проверки; без P1 — `license_missing` в оценке |

Как модули влияют на сбор и оценку:

- **Лицензия P1 или P2.** Определяется только по планам `AAD_PREMIUM` (servicePlanId `41781fb2-bc02-4b7c-bd55-b576c07bb09d`) и `AAD_PREMIUM_P2` (`eec0eb4f-6444-4f95-aba0-50c24d67f998`) во включённых подписках, а не по имени SKU: например, `O365_BUSINESS_PREMIUM` — это Business Standard без P1.
- **403 и лицензия.** Ответ 403 не считается доказательством отсутствия лицензии.
- **Неполный ответ.** Ответ 200 без обязательного свойства не считается полным наблюдением.
- **Перенос статуса в наблюдения.** `permission_missing` → `permission_denied`, `license_missing` → `license_missing`, `partial` → `partial_data`, `temporary_error` → `temporary_error`.
- **Частичный доступ.** Tenant с частично доступными модулями остаётся подключённым с явным перечнем недоступных проверок; запуск получает `partial`.
- **Ограничения запросов.** Запросы идут только к `graph.microsoft.com` по фиксированным путям; следующая страница — только по `@odata.nextLink` того же host и пути. Произвольные URL не выполняются.

Фактическую достаточность прав, ответы без лицензии (в том числе Conditional Access в tenant без P1, поведение которого не документировано), стабильность модуля `per_user_mfa`, отражение Security Defaults по отдельным защитам (H-SD1), признак `isPrivileged` ролей (H-ROLES), написание политики почтовых клиентов и видимость доступа GDAP проверяет SP-01 на трёх tenant.

## Проверки Windows

| ID | Проверка и данные | Объект | Режим по умолчанию | Условие оценки | Severity при fail | Права и ограничения |
| --- | --- | --- | --- | --- | --- | --- |
| WIN-001 | Свободное место на томе ОС: `totalBytes`, `freeBytes` | volume | assessed | fail warning при менее 10% или 10 GiB; fail critical при менее 5% или 2 GiB | по порогу | Объект — том ОС (`volumeId`, `role=os`); эксплуатационный показатель, не доказательство защиты |
| WIN-002 | BitLocker тома ОС: `volumeStatus`, `protectionStatus`, `encryptionPercentage` | volume | assessed | По таблице правила WIN-002 ниже: pass только при завершённом шифровании и включённой защите, приостановленная защита — fail (эталонный отрицательный тест). Редакции из `notApplicableEditionIds` по `editionId` WIN-011 — not_applicable | critical | Recovery password никогда не извлекается и не передаётся |
| WIN-003 | Антивирусы: `products[]` до 10 элементов и объект `defender` | device | informational | По таблице решений WIN-003; для assessed нужен непустой `approvedProviders` или `defenderApproved=true` | critical | Сторонний продукт — только статус, который он сообщает Windows Security Center |
| WIN-004 | Давность сигнатур Defender: `signatureLastUpdatedAt` | device | assessed | fail warning старше `warnDays` (3) суток, critical — старше `criticalDays` (7); время позже `observedAt` — unknown/`evidence_time_invalid`. Применима только при `defenderApproved=true` и `amRunningMode=normal` по WIN-003 того же пакета | по порогу | Без пригодного WIN-003 — unknown/`applicability_input_missing`. Плановый сбор начинается не раньше чем через 60 минут после загрузки ОС, чтобы после отпуска Defender успел обновить сигнатуры |
| WIN-005 | Брандмауэр: `domainEnabled`, `privateEnabled`, `publicEnabled`, `firewallProducts[]` | device | assessed | Включены все профили из `requiredProfiles` либо активен одобренный сторонний firewall (правило WIN-005 ниже) | critical | Сторонний firewall — по статусу, который он сообщает Windows Security Center |
| WIN-006 | Служба обновлений: `lastSearchSuccessAt`, `lastInstallSuccessAt`, `wsusConfigured` | device | informational | По правилу WIN-006 ниже | warning | Уровень установленных исправлений оценивает SYS-003 |
| WIN-007 | Требование перезагрузки: `rebootRequired`, `lastBootAt` | device | assessed | Эпизод по правилу WIN-007 длится не меньше `warnDays` (3) суток — fail warning | warning | Снятие требования внутри одного сеанса между сборами не обнаруживается |
| WIN-008 | Прямые члены группы локальных администраторов: `members[]` до 100 — SID, класс и RID | device | informational | По правилу WIN-008 ниже | warning | Вложенные группы AD и Entra не раскрываются |
| WIN-009 | Secure Boot: `enabled`, `platform` | device | assessed | При `secureBootRequired=true` выключенный Secure Boot или `legacy_bios` — fail | critical | Нет доступа — unknown/`permission_denied` |
| WIN-010 | Присоединение устройства: `joinType`, `tenantId`, `entraDeviceId` | device | informational | По правилу WIN-010 ниже; для assessed нужен `expectedTenantId` | warning | Регистрация уровня пользователя (workplace join) не наблюдается |
| WIN-011 | OS-инвентарь: `editionId`, `displayVersion` (у старых сборок — `ReleaseId`), `build`, `ubr`, `architecture` | device | informational | Всегда informational; вход SYS-002, SYS-003 и применимости WIN-002 | — | Обязательна в `activeCheckIds` |
| SYS-001 | Свежий полный сбор: `lastFullScanAt`, `lastSeenAt` | device | informational | Всегда informational: истинно, если последний полный сбор не старше окна свежести SYS-001 | — | Вычисляется сервером; выключенный ПК не получает fail |
| SYS-002 | Версия ОС на обслуживании Microsoft | device | assessed | По подразделу «Жизненный цикл ОС» | critical | Вычисляется сервером по последнему collected WIN-011 в окне свежести; ОС вне матрицы агента даёт unknown, а не fail |
| SYS-003 | Уровень установленных исправлений ОС | device | assessed | По подразделу «Правило SYS-003 и каталог выпусков» | по отставанию | Вычисляется сервером по WIN-011 и сверенным месяцам каталога выпусков |

### Политика по умолчанию и входные настройки

Разрешённые члены группы администраторов (например, SID ролей Entra на присоединённых к Entra ПК), одобренные антивирусы и firewall, ожидаемый tenant согласуются с клиентом и записываются в параметры политики. Политика v1 включает в `activeCheckIds` все проверки M365 и WIN; режимы равны `defaultAssessmentMode` каталога; стартовые параметры — `05`, подраздел «Политика клиента». Без входных настроек проверка остаётся informational и не создаёт ложных отклонений.

Применимость проверки может зависеть от наблюдения другой проверки того же пакета:

- WIN-002 — от `editionId` из WIN-011 (`notApplicableEditionIds`; в политике v1 — Core, CoreN, CoreSingleLanguage, CoreCountrySpecific);
- WIN-004 — от объекта `defender` из WIN-003.

Если такого наблюдения в пакете нет или оно `unavailable`, зависимая проверка получает unknown/`applicability_input_missing`, а не not_applicable.

### Правило WIN-003

**Одобренный продукт** — элемент `products[]`, у которого `provider` начинается с записи из `approvedProviders` (без учёта регистра, поэтому смена версии в названии продукта не ломает сопоставление), а также Defender при `defenderApproved=true`. SP-04 проверяет, стабилен ли GUID продукта в Windows Security Center и не надёжнее ли сопоставлять по нему. Defender опознаётся по элементу со `statusSource=defender`. Он активен только при `amRunningMode=normal` и `realTimeProtectionEnabled=true`; режимы `passive`, `edr_block`, `sxs_passive`, `not_running` и `other` активным антивирусом не считаются. **Активный продукт** — продукт с `productState=on`, Defender — по правилу выше.

| № | Условие | Результат |
| --- | --- | --- |
| 1 | Хотя бы один одобренный продукт активен | pass |
| 2 | Активного одобренного нет, а хотя бы у одного одобренного `productState=unknown` | unknown/`unmapped_state` |
| 3 | Одобренные продукты есть, все в `off`, `snoozed` или `expired` либо Defender не активен | fail |
| 4 | Ни одного одобренного продукта (включая пустой `products[]`) | fail |

Лабораторная матрица SP-04 состоит из пяти конфигураций:

1. только Defender;
2. активен сторонний антивирус;
3. сторонний антивирус вместе с MDE или Smart App Control;
4. у стороннего антивируса истекла лицензия;
5. snoozed.

При политике «одобрен только Defender» ожидаются pass/fail/fail/fail/fail, при политике «Defender + VendorX» — pass/pass/pass/fail/fail.

### Правило WIN-002

При `encryptionRequired=false` проверка даёт not_applicable/`policy_not_applicable`. При `encryptionRequired=true`:

| volumeStatus | protectionStatus | Результат |
| --- | --- | --- |
| fully_encrypted | on | pass |
| fully_encrypted | off | fail: защита приостановлена (эталонный отрицательный тест ниже) |
| fully_encrypted | unknown | unknown/`unmapped_state` |
| encrypting | любой | unknown/`unmapped_state`: идёт первичное шифрование, итог покажет следующий сбор |
| encryption_paused, decrypting, decryption_paused, fully_decrypted | любой | fail |

Значение `Win32_EncryptableVolume` вне этих перечней агент передаёт как unavailable/`unsupported` (`02`, «Выполнение локальной проверки»).

### Правило WIN-005

1. Включены все профили из `requiredProfiles` — pass.
2. Иначе среди `firewallProducts[]` есть продукт, у которого `provider` начинается с записи из `approvedFirewallProviders` (без учёта регистра), в `productState=on` — pass.
3. Иначе одобренный продукт есть, но его состояние `unknown` — unknown/`unmapped_state`.
4. Иначе — fail.

### Правило WIN-008

Агент передаёт для каждого прямого члена группы SID, класс и RID относительно SID машины или домена присоединения. Класс определяется через LSA.

| kind | Член группы |
| --- | --- |
| builtin_administrator | Встроенная учётная запись Administrator (RID 500 SID машины); убрать её из группы нельзя |
| local_account | Другая локальная учётная запись или группа ПК, в том числе учётная запись Windows LAPS или RMM |
| domain | Учётная запись или группа домена, к которому присоединён ПК |
| entra | SID Entra (`S-1-12-1-…`): пользователь, группа или роль каталога |
| well_known | Известный SID Windows |
| unknown | SID другого домена или SID, который не удалось разрешить |

Член группы разрешён, если это `builtin_administrator` при `allowBuiltinAdministrator=true`, `domain` с RID из `allowedDomainRids` (512 — Domain Admins) или SID из `allowedSids`. Локальных учётных записей вне `allowedSids` допускается не больше `maxOtherLocalAccounts` (например, 1 для учётной записи LAPS). Все члены разрешены и лимит соблюдён — pass, иначе fail warning с перечнем лишних членов. Windows добавляет в группу ПК, присоединённого к Entra, SID ролей «Global Administrator» и «Microsoft Entra Joined Device Local Administrator» и по умолчанию — пользователя, выполнившего присоединение. Поэтому перед переводом в assessed SID ролей этого tenant вносятся в `allowedSids`, а пользователь с правами администратора остаётся отклонением.

### Правило WIN-010

Без `expectedTenantId` проверка informational и только показывает присоединение. При заданном `expectedTenantId`:

| joinType | tenantId | Результат |
| --- | --- | --- |
| entra_joined, hybrid_joined | равен `expectedTenantId` | pass |
| entra_joined, hybrid_joined | другой | fail |
| entra_joined, hybrid_joined | null | unknown/`unmapped_state` |
| domain_joined, not_joined | — | fail |

### Правило WIN-006

Evidence — время последнего успешного поиска и последней успешной установки службы автоматического обновления (`LastSearchSuccessDate`, `LastInstallationSuccessDate`) и признак политики WSUS. Это показатель работоспособности службы обновлений, а не уровня исправлений: уровень оценивает SYS-003.

По умолчанию проверка informational, потому что поиск может управляться WSUS или RMM. Если политика переводит её в `assessed`:

1. `lastSearchSuccessAt` позже `observedAt` — unknown/`evidence_time_invalid`.
2. `lastSearchSuccessAt` null или старше `maxSearchAgeDays` (7) до `observedAt` — fail warning.
3. Иначе — pass.

### Правило WIN-007

Эпизод требования перезагрузки — последовательность принятых по `sequence` сборов текущего сеанса загрузки, в каждом из которых `rebootRequired=true`. Сбор относится к тому же сеансу, если его `lastBootAt` отличается от начала сеанса (`device.rebootEpisodeBootAt`) не больше чем на 2 минуты: `LastBootUpTime` — расчётное значение и сдвигается при коррекции часов и гибернации.

- **Начало эпизода** — `observedAt` первого такого сбора (`device.rebootEpisodeSince`).
- **Сброс.** Значение `false` или `lastBootAt`, отличающийся больше чем на 2 минуты, эпизод прерывают; следующий `true` начинает новый.
- **Пропуски.** Сбор без наблюдения WIN-007 или с `unavailable` эпизод не прерывает. Пакеты с признаком часов в эпизод не входят.
- **Результат.** Fail warning — `observedAt` текущего сбора минус начало эпизода не меньше `warnDays`.

Вывод формулируется только как наблюдение: «требование перезагрузки зафиксировано во всех сборах с T; последний запуск ПК — B». Непрерывность требования между сборами не утверждается: оно могло исчезнуть и возникнуть снова, и такое снятие внутри сеанса не обнаруживается.

Поведение `LastBootUpTime` при Fast Startup, после синхронизации времени и после гибернации проверяет SP-04. Если источник окажется ненадёжным, WIN-007 переводится в informational «требование перезагрузки обнаружено» без длительности.

### Эталонный отрицательный тест BitLocker

В синтетическом примере `examples/scan-batch.json` у WIN-002 записаны `volumeStatus=fully_encrypted`, `protectionStatus=off` и `encryptionPercentage=100`. При `encryptionRequired=true` ожидается fail, а не pass: защита приостановлена, хотя том полностью зашифрован. Случай закреплён в domain-тесте AT-14, в записи реестра инвариантов с ожидаемым результатом fail и в сборочной проверке, что пример его содержит.

### Сбор данных и источники

Сборщики обращаются к WMI/CIM, COM и Win32 API напрямую из .NET. Запуск `powershell.exe`, `cmd.exe` и любых дочерних процессов запрещён (`02`, «Выполнение локальной проверки»). Evidence передаётся только по закрытой схеме проверки. Кандидаты API, которые подтверждает SP-04:

| Проверка | Источник |
| --- | --- |
| Свободное место, том ОС | `GetVolumeNameForVolumeMountPoint` для `volumeId` тома ОС, `Win32_Volume` |
| BitLocker | `Win32_EncryptableVolume` |
| Defender | `MSFT_MpComputerStatus` |
| Антивирусы и сторонний firewall | Windows Security Center (`IWSCProductList`) |
| Брандмауэр | `INetFwPolicy2` |
| Служба обновлений | `IAutomaticUpdatesResults` (`LastSearchSuccessDate`, `LastInstallationSuccessDate`), политика `WUServer` и `UseWUServer` |
| Перезагрузка | `ISystemInformation.RebootRequired`, `Win32_OperatingSystem.LastBootUpTime` |
| Локальные администраторы | `NetLocalGroupGetMembers` по известному SID группы, класс и RID — через LSA |
| Secure Boot | `GetFirmwareEnvironmentVariable` либо реестр `SecureBoot\State` |
| Присоединение к Entra | `NetGetAadJoinInformation` и сведения о домене |
| OS-инвентарь | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` (`EditionID`, `DisplayVersion`, у старых сборок `ReleaseId`, `CurrentBuild`, `UBR`); архитектура — `IsWow64Process2` |

Учётная запись LocalSystem, права и время каждого вызова на поддерживаемых редакциях фиксирует протокол SP-04. Каждый сборщик ограничен 30 секундами, сессия — 120 секундами; при исчерпании бюджета оставшиеся проверки получают `unavailable/collector_timeout`. Изоляция зависшего вызова — `02`, «Выполнение локальной проверки».

## Поддержка ОС и уровень патчей

SYS-001…SYS-003 вычисляет сервер; их наблюдения имеют `source=server`, а evidence — закрытые структуры `evidenceSchema` в `specs/check-catalog.json`: SYS-001 — `lastFullScanAt` и `lastSeenAt`; SYS-002 — продукт, семейство, версия, build, архитектура и `servicingEndsAt`; SYS-003 — ветка, UBR, уровень устройства, ожидаемый месяц, отставание, KB недостающего выпуска и `verifiedThroughMonth`. Вход SYS-002 и SYS-003 — последнее collected наблюдение WIN-011 в окне свежести WIN-011 из пакетов, которые могли менять проекцию, а время оценки — время сервера (`05`, «Выбор текущего состояния» и «Время и часы устройства»).

### Матрица совместимости агента

| Продукт | Версии | Семейства | Архитектура |
| --- | --- | --- | --- |
| Windows 11 | 21H2 (22000) и новее | home_pro, enterprise_education, ltsc, iot_ltsc | x64 |
| Windows 10 | LTSC 2019 (1809, 17763) и новее | home_pro, enterprise_education, ltsc, iot_ltsc | x64 |

MSI устанавливается только на клиентскую ОС (`MsiNTProductType=1`) с нативной архитектурой x64 (`06`, «Распространение агента через RMM»). ARM64 и серверы — P3: если агент всё же работает на такой ОС, WIN-011 сообщает фактическую архитектуру и редакцию, а SYS-002 даёт unknown/`os_version_unknown`, а не fail, потому что Microsoft такую ОС может поддерживать. Windows 10 22H2 и старые версии Windows 11 включены, чтобы клиент видел устаревшую ОС: SYS-002 даёт для них fail. Оплаченный ESU (только 22H2) оформляется решением `risk_accepted` по SYS-002 со сроком пересмотра не позже окончания оплаченного года ESU. Windows 11 26H1 выпускается для новых устройств на отдельных новых процессорах, обновление на неё с других версий не предлагается. В лаборатории SP-04 испытываются версии с действующим обслуживанием и Windows 10 22H2, а LTSC, IoT LTSC и Education — если они есть у клиентов (вопрос 3 в `08`).

### Жизненный цикл ОС

Семейство определяется по `editionId` из WIN-011:

| Семейство | editionId |
| --- | --- |
| home_pro | Core, CoreN, CoreSingleLanguage, CoreCountrySpecific, Professional, ProfessionalN, ProfessionalEducation, ProfessionalEducationN, ProfessionalWorkstation, ProfessionalWorkstationN |
| enterprise_education | Enterprise, EnterpriseN, Education, EducationN, IoTEnterprise, ServerRdsh |
| ltsc | EnterpriseS, EnterpriseSN |
| iot_ltsc | IoTEnterpriseS |

Продукт определяется по `build`: ниже 22000 — Windows 10, от 22000 — Windows 11. Версия — `DisplayVersion`, а у сборок без него (2004 и старше) — `ReleaseId`. Строка таблицы выбирается по семейству и `build`, поэтому отсутствие версии в реестре старой сборки результат не меняет.

Конвенция времени. «Последний день обслуживания» — дата окончания обновлений со страниц Windows release information и Microsoft Lifecycle. `servicingEndsAt` — исключающая граница: начало следующего календарного дня в America/Los_Angeles, переведённое в UTC по действующему в этот момент смещению (−07:00 летом, −08:00 зимой). Данные правила хранят только `servicingEndsAt`.

Таблица — данные правила SYS-002, а не параметр клиентской политики; её изменение выпускается новой версией сервиса и даёт `rule_change`. Значения сверены 2026-10-15.

| Продукт | Семейство | displayVersion | build | Последний день обслуживания | servicingEndsAt |
| --- | --- | --- | --- | --- | --- |
| Windows 10 | ltsc | 1809 | 17763 | 2029-01-09 | 2029-01-10T08:00:00Z |
| Windows 10 | iot_ltsc | 1809 | 17763 | 2029-01-09 | 2029-01-10T08:00:00Z |
| Windows 10 | ltsc | 21H2 | 19044 | 2027-01-12 | 2027-01-13T08:00:00Z |
| Windows 10 | iot_ltsc | 21H2 | 19044 | 2032-01-13 | 2032-01-14T08:00:00Z |
| Windows 10 | home_pro | 22H2 | 19045 | 2025-10-14 | 2025-10-15T07:00:00Z |
| Windows 10 | enterprise_education | 22H2 | 19045 | 2025-10-14 | 2025-10-15T07:00:00Z |
| Windows 11 | home_pro | 21H2 | 22000 | 2023-10-10 | 2023-10-11T07:00:00Z |
| Windows 11 | enterprise_education | 21H2 | 22000 | 2024-10-08 | 2024-10-09T07:00:00Z |
| Windows 11 | home_pro | 22H2 | 22621 | 2024-10-08 | 2024-10-09T07:00:00Z |
| Windows 11 | enterprise_education | 22H2 | 22621 | 2025-10-14 | 2025-10-15T07:00:00Z |
| Windows 11 | home_pro | 23H2 | 22631 | 2025-11-11 | 2025-11-12T08:00:00Z |
| Windows 11 | enterprise_education | 23H2 | 22631 | 2026-11-10 | 2026-11-11T08:00:00Z |
| Windows 11 | home_pro | 24H2 | 26100 | 2026-10-13 | 2026-10-14T07:00:00Z |
| Windows 11 | enterprise_education | 24H2 | 26100 | 2027-10-12 | 2027-10-13T07:00:00Z |
| Windows 11 | ltsc | 24H2 | 26100 | 2029-10-09 | 2029-10-10T07:00:00Z |
| Windows 11 | iot_ltsc | 24H2 | 26100 | 2034-10-10 | 2034-10-11T07:00:00Z |
| Windows 11 | home_pro | 25H2 | 26200 | 2027-10-12 | 2027-10-13T07:00:00Z |
| Windows 11 | enterprise_education | 25H2 | 26200 | 2028-10-10 | 2028-10-11T07:00:00Z |
| Windows 11 | home_pro | 26H1 | 28000 | 2028-03-14 | 2028-03-15T07:00:00Z |
| Windows 11 | enterprise_education | 26H1 | 28000 | 2029-03-13 | 2029-03-14T07:00:00Z |
| Windows 11 | home_pro | 26H2 | 26300 | 2028-10-10 | 2028-10-11T07:00:00Z |
| Windows 11 | enterprise_education | 26H2 | 26300 | 2029-10-09 | 2029-10-10T07:00:00Z |

Правило SYS-002 на время оценки t:

1. Нет collected WIN-011 в окне свежести — unknown/`os_inventory_missing`.
2. Архитектура не x64 или `editionId` вне таблицы семейств (например, серверная редакция) — unknown/`os_version_unknown`: ОС вне матрицы агента.
3. Есть строка с тем же семейством и `build`: t ≥ `servicingEndsAt` — fail, иначе — pass.
4. Строки нет:
   - `build` ниже 19045 у home_pro и enterprise_education или ниже наименьшего `build` своего семейства у ltsc и iot_ltsc — fail: обслуживание всех таких версий закончено;
   - иначе (новая версия до обновления таблицы, Insider) — unknown/`os_version_unknown`.

Explanation называет дату окончания обслуживания и, для Windows 10 22H2, возможность ESU.

### Правило SYS-003 и каталог выпусков

SYS-003 сравнивает установленный уровень исправлений (`build`.`ubr` из WIN-011) с каталогом выпусков Windows и считает отставание в месяцах безопасности, а не в числе выпусков.

Каталог — платформенная таблица `windows_release` с ключом (продукт, ветка `build`, `ubr`). Продукт в P2 один — `client`: серверные выпуски общей ветки 26100 (Windows Server 2025) не импортируются. Каждая запись содержит KB, `releaseAt`, вид и `securityMonth` — месяц, исправления безопасности которого включены в выпуск:

- `security_monthly` — ежемесячный выпуск безопасности второго вторника;
- `security_oob` — внеочередной выпуск с исправлениями безопасности;
- `nonsecurity_oob` и `preview` — без новых исправлений безопасности; `securityMonth` — месяц выпуска безопасности, на котором они построены;
- `hotpatch` — выпуск hotpatch: меняет UBR без перезагрузки, и его UBR может быть ниже UBR обычного выпуска того же месяца (май 2026: hotpatch 26100.8390 и обычный выпуск 26100.8457).

`autoOffered` отмечает, предлагает ли Windows Update выпуск автоматически; в P2 он только дополняет пояснение. Ветки 24H2 (26100), 25H2 (26200) и 26H2 (26300) хранятся отдельно, потому что часть внеочередных выпусков выходит не для всех веток.

Записи импортируются черновиком (`importWindowsReleases`) и участвуют в оценке только после сверки месяца Admin (`verifyWindowsReleaseMonth`). Месяц без новых записей подтверждается флагом `noNewReleases`. `verifiedThroughMonth` — последний месяц, до которого сверены все месяцы подряд. Пополнение каталога не меняет `ruleVersion`: `verifiedThroughMonth` пишется в `basisSnapshot`, а сверка месяца ставит `patch_level_sweep`, и отставшие устройства получают события с `source_change`. Ошибочная сверенная запись исправляется новой версией сервиса с новой `ruleVersion` SYS-003 и пересчётом с `rule_change`.

Обозначения для устройства с веткой B и UBR u в момент оценки t:

- **Уровень устройства** — `securityMonth` сверенной записи ветки B с точным совпадением UBR; без точного совпадения — наибольший `securityMonth` сверенных записей ветки, кроме `hotpatch`, с UBR не выше u.
- **Ожидаемый месяц** E(t) — последний месяц M, у которого дата второго вторника + `graceDays` (14) ≤ дата t в UTC.
- **Отставание** — число месяцев с записью `security_monthly` ветки B после уровня устройства и не позже E(t). Ветка, обслуживание которой закончилось, новых месяцев не получает, поэтому отставание не растёт: устаревшую ОС оценивает SYS-002.

Правило:

1. Нет collected WIN-011 в окне свежести — unknown/`os_inventory_missing`.
2. Ветки нет в каталоге (например, Insider) — unknown/`build_not_in_catalog`.
3. `verifiedThroughMonth` раньше E(t) — unknown/`release_catalog_stale`: месяц, срок grace которого наступил, ещё не сверен.
4. Отставание 0 — pass; от 1 до `criticalBehindMonths` − 1 — fail warning; не меньше `criticalBehindMonths` (2) — fail critical. UBR ниже самой ранней записи ветки даёт отставание не меньше `criticalBehindMonths`.

Внеочередные выпуски отставание не увеличивают: месяц считается один раз, и hotpatch даёт тот же уровень, что обычный выпуск своего месяца. Explanation называет build и UBR, уровень устройства, ожидаемый месяц, KB недостающего выпуска безопасности ветки и число пропущенных месяцев, а при доступном внеочередном выпуске безопасности с `autoOffered` — и его KB. Обновление, которое установлено, но ждёт перезагрузки, UBR ещё не меняет и даёт отставание вместе с WIN-007. SYS-003 не оценивает обновления Office, драйверов и стороннего ПО.

Месяц сверяется по RB-13 в течение 7 суток после второго вторника, а внеочередные выпуски безопасности — по мере выхода. Предпочтительный источник — API MSRC CVRF (`api.msrc.microsoft.com/cvrf/v3.0`): без аутентификации, с KB и `FixedBuild` по продуктам. Документы CVRF меняются и после выпуска, а данные бывают неточными, поэтому записи месяца до использования сверяются Admin со страницей Windows release information. Альтернатива — Graph Windows Updates API: он только в beta и требует лицензий Autopatch. Окончательный источник и формат импорта выбирает SP-04. Задание `release_catalog_check` поднимает оповещение, если месяц не сверен через 7 суток после второго вторника; при `graceDays` 14 это неделя запаса до unknown. Сверка через 1–13 суток после выпуска не даёт ни одного unknown по календарю 2026–2027, в том числе в месяцы с интервалом 35 суток между выпусками. При `graceDays` меньше 7 сверка должна идти быстрее, иначе SYS-003 этой организации временно даёт unknown.

## Следующие модули

Модули P3 оцениваются отдельно, после пилотов:

- **Microsoft 365:**
  - сопоставление устройств Intune по подтверждённому `entraDeviceId` (без сопоставления по имени и UPN);
  - соответствие Intune;
  - инциденты и состояние Defender;
  - Secure Score — как индикатор внедрения контролей, а не вероятности взлома;
  - назначения eligible в PIM;
  - журналы входов.
- **Windows:**
  - каталог приложений vendor/version и сторонние обновления; WinGet — дополнительный источник, неизвестная версия хранится явно;
  - блокировка экрана и Windows Hello — нужен пользовательский контекст измерения;
  - резервное копирование — нужна интеграция с поставщиком и подтверждение восстановления;
  - ARM64 и серверы;
  - сертификаты Secure Boot 2023: сертификаты Microsoft 2011 для Secure Boot истекают в 2026 году, а WIN-009 видит только, включён ли Secure Boot.
