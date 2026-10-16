# RB-06. Инцидент безопасности

## Назначение

Ограничить ущерб, оценить и задокументировать возможную утечку данных или захват учётной записи сотрудника, сервиса, Key Vault или регистрации приложения, уведомить затронутых и восстановить работу. Сервис хранит конфигурацию безопасности Microsoft 365 клиентов и сведения о пользователях — object id, UPN, виды методов аутентификации, роли (`04`, «Минимизация данных»). Захват сервиса или ключа Graph даёт чтение каталога всех подключённых tenant, но не запись (R-04 в `08`).

## Владелец роли и этап

Security Owner (по умолчанию владелец), этап P1. Operations выполняет команды Azure, Service Manager держит связь с клиентами, Product Owner принимает решения об уведомлениях.

## Признак запуска

- RB-02, раздел В: подпись ключом Graph чужой identity или необъяснённые подписи.
- `tenant_mismatch` при сборе (RB-01).
- В журнале аудита организации действия, которых сотрудник не делал: выдача отчётов и экспорта, подключение или отключение tenant, изменение политики.
- Вход в портал неизвестной учётной записи или с неожиданной ролью: записи `Staff sign-in …` в журнале сервиса, страница «Ansatte» (столбцы «Roller» и «Sist innlogget»).
- Изменения регистраций «Sikkerheit Graph Reader» и «Sikkerheit Portal (prod)», ролей Azure или настроек приложения, которых никто не делал.
- Сообщение клиента, сотрудника, Microsoft или третьего лица; утечка секрета, файла отчёта или экспорта; фишинг под видом экрана consent.

## Предусловия и доступы

- Контакты: [ЗАПОЛНИТЬ: владелец, Product Owner, юрист или ответственный за защиту данных, контакты клиентов].
- `az login` с Owner на подписке; Application Administrator в Entra; чтение журналов Entra (Security Reader или выше); роль Admin в портале.
- `<site>`, `<kv>`, `<graph-app-id>` — README, «Имена ресурсов».

## Шаги

### 1. Зафиксировать

Открыть протокол (README, «Протокол») и сразу записать время, когда об инциденте стало известно (UTC): от него отсчитываются 72 часа (шаг 4). Записать источник и что известно. Ничего не удалять: журналы — доказательства. Результаты запросов шага 3 сохранять файлами: журналы сервиса хранятся 90 дней, журнал безопасности удаляется через 45 суток, журнал действий Azure — 90 дней.

### 2. Локализовать

По масштабу — одно или несколько действий:

- **Одна или несколько организаций.** `changeOrganizationLifecycle`: «Innstillinger» → «Livssyklus» → «Begrunnelse» → «Deaktiver» — сбор прекращается. `disconnectTenant`: «Oversikt» → «Koble fra». Если подозревается доступ через токены приложения, попросить администратора клиента удалить корпоративное приложение «Sikkerheit Graph Reader» в своём tenant (RB-03, «Отключение»).
- **Ключ Graph, сервис или регистрация приложения** — RB-02, раздел Г: выдача токенов прекращается во всех tenant сразу.
- **Учётная запись сотрудника.** Заблокировать вход в Entra и снять назначение роли: Entra admin center → Enterprise applications → «Sikkerheit Portal (prod)» → Users and groups. Сессия портала заканчивается не позже чем через час (AT-02); если ждать нельзя — закрыть доступ к сервису целиком.
- **Сервис целиком.** Закрыть входящий доступ и выключить задания — три команды RB-05, шаг 1. Подозрение на подмену кода — выпустить проверенную версию (README, «Откат версии»).

### 3. Оценить

Цель — что произошло, когда, какие организации и данные затронуты, продолжается ли.

- **Журнал аудита организации** — `listAuditEvents`: «Innstillinger» → «Revisjonslogg» → «Detaljer», «Vis flere» для следующих страниц. По столбцам «Tidspunkt», «Utført av», «Handling», «Objekt» искать `report.download`, `organization_export.create`, `organization_export.download`, `m365.consent_start`, `m365.connect`, `m365.disconnect`, `organization.lifecycle_change`, `policy.revision_create`, `audit_events.read`. Каждое открытие журнала само пишет `audit_events.read`.
- **Входы сотрудников и выдача файлов** (Application Insights → «Logs»):

  ```kusto
  traces
  | where timestamp > ago(30d)
  | where message startswith "Staff sign-in" or message startswith "Staff session" or message startswith "Staff token refresh"
  | project timestamp, severityLevel, message
  | order by timestamp desc
  ```

  ```kusto
  requests
  | where timestamp > ago(30d)
  | where name contains "download" or name contains "audit-events"
  | project timestamp, name, url, resultCode
  | order by timestamp desc
  ```

- **Key Vault** (Log Analytics → «Logs»): кто подписывал ключом Graph, читал секреты, менял ключи и сертификаты. Ожидаются только identity слотов: production подписывает и читает секреты, `staging` только читает секреты. Столбец `identity_claim_oid_g` — допущение (RB-02, В1).

  ```kusto
  AzureDiagnostics
  | where TimeGenerated > ago(30d)
  | where ResourceProvider == "MICROSOFT.KEYVAULT" and Category == "AuditEvent"
  | extend caller = tostring(column_ifexists("identity_claim_oid_g", ""))
  | summarize calls = count(), first = min(TimeGenerated), last = max(TimeGenerated) by OperationName, caller, CallerIPAddress, ResultSignature
  | order by last desc
  ```

- **Azure и Entra.** Журнал действий группы ресурсов — изменения настроек, ролей, слотов, ограничений доступа:

  ```bash
  az monitor activity-log list --resource-group rg-sikkerheit-prod --offset 7d --query "[].{time:eventTimestamp, caller:caller, operation:operationName.value, status:status.value}" -o table
  ```

  Журнал аудита Entra tenant компании (Entra admin center → Monitoring & health → Audit logs): изменения регистраций «Sikkerheit Graph Reader» и «Sikkerheit Portal (prod)», назначения ролей. Credentials и владельцы приложения Graph — RB-02, Г2.
- **Tenant клиента.** При Entra ID P1 у клиента его администратор выгружает журнал входов service principal «Sikkerheit Graph Reader»; адреса должны входить в исходящие адреса сервиса:

  ```bash
  az webapp show --resource-group rg-sikkerheit-prod --name <site> --query possibleOutboundIpAddresses -o tsv
  ```

- **Итог оценки** — в протокол: организации, категории данных, число затронутых пользователей, окно времени, путь доступа, продолжается ли.

### 4. Уведомить

Напоминание, а не юридическая консультация: решение принимает Product Owner вместе с [ЗАПОЛНИТЬ: юрист или ответственный за защиту данных] по договорам обработки данных.

- GDPR, статья 33: о нарушении безопасности персональных данных контролёр уведомляет надзорный орган — в Норвегии Datatilsynet — без неоправданной задержки и, где возможно, не позже 72 часов с момента, когда о нём стало известно; обработчик уведомляет контролёра без неоправданной задержки. Статья 34 — уведомление самих субъектов данных при высоком риске для них.
- Для данных клиентов роли сторон и срок сообщения клиенту определяет договор обработки данных (вопрос 6 в `08`). Затронутым клиентам сообщить как можно раньше, чтобы у них оставалось время на собственные решения: [ЗАПОЛНИТЬ: канал и шаблон письма].
- Учётные записи сотрудников в портале — данные самой компании.
- Каждое уведомление — в протокол: кому, когда, что сообщено.

### 5. Восстановить

После устранения причины:

- ключ Graph — RB-02, Г5; повторный consent клиентам не нужен;
- версия сервиса — выпуск проверенного тега (README, «Откат версии»);
- данные повреждены — RB-05;
- секрет `cursor-key` — новое значение, затем `az webapp restart` (открытые списки в портале придётся загрузить заново):

  ```bash
  az keyvault secret set --vault-name <kv> --name cursor-key --value "$(openssl rand -base64 32)"
  ```

- `teams-webhook` — новый поток Workflows и новый адрес (`infra/README.md`, «После установки»);
- организации — «Aktiver», затем «Lag samtykkelenke» и «Kontroller tilkobling» (RB-03);
- доступ к сервису — `Jobs__Enabled=true` (RB-05, шаг 6) и `--default-action Allow` на обоих слотах (RB-05, шаг 8).

### 6. Разбор

В течение [ЗАПОЛНИТЬ: срок] после закрытия: причина, что сработало и что нет, задачи (оповещения, права, код), правки runbooks.

## Проверка результата

- Доступ злоумышленника прекращён: чужих credentials, ролей и сессий нет, запросы шага 3 после локализации не показывают новых действий.
- Затронутые организации и данные перечислены, уведомления отправлены и записаны со временем.
- Сервис восстановлен: вход, сбор и отчёты работают.

## Запись в протокол

Шаблон — [README](README.md), раздел «Протокол». Дополнительно: хронология (обнаружение, локализация, оценка, уведомления, восстановление), сохранённые выгрузки журналов, решение об уведомлениях и его основание, ссылки на протоколы RB-02 и RB-05, если они выполнялись.

## Связанные документы

- [04-security-and-privacy.md](../../development-package/04-security-and-privacy.md) — «Ключ приложения», «Журнал безопасности», «Минимизация данных», «Угрозы и проверяемые меры».
- [08-risks-and-decisions.md](../../development-package/08-risks-and-decisions.md) — R-04, вопрос 6.
- [06-azure-and-operations.md](../../development-package/06-azure-and-operations.md) — «Наблюдаемость и оповещения».
- [RB-02](RB-02-graph-key.md), [RB-03](RB-03-client-onboarding.md), [RB-05](RB-05-database-restore.md).
