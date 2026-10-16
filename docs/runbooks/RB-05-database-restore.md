# RB-05. Восстановление базы из PITR

## Назначение

Восстановить базу PostgreSQL на точку T (PITR, 14 суток) в новый сервер и вернуть сервис в согласованное состояние без произвольного SQL: повторить журнал безопасности, защитить удаления, сдвинуть версии политики, разобрать файлы и задания, составить перечень потерянных изменений и открыть доступ. Цели — RPO до 15 минут и RTO до 4 часов (NFR-07). Восемь шагов повторяют `06`, «Резервное копирование и восстановление»; шаги 3–6 выполняет команда `restore-replay` образа сервиса. Отдельный раздел — учебное восстановление.

## Владелец роли и этап

Operations выполняет; Security Owner принимает решение о восстановлении и точке T и проверяет шаги 3, 6 и 8; Admin (Service Manager) повторяет потерянные изменения. Этап P1.

## Признак запуска

- Потеря или порча данных базы, которую нельзя исправить операциями портала: ошибочный выпуск или миграция, массовое ошибочное изменение, повреждение данных при инциденте (RB-06).
- Сервер базы недоступен, и Azure его не восстанавливает (Azure Service Health, ошибки подключения к базе в журнале сервиса).
- Учебное восстановление: до пилота M365 и затем раз в квартал — раздел «Учебное восстановление»; даты: [ЗАПОЛНИТЬ: календарь].

Ошибку одного сотрудника в одной организации исправляют операциями портала, а не восстановлением.

## Предусловия и доступы

- `az login`; Owner или Contributor на подписке. Рабочая станция с `jq`; роль Admin в портале. Owner (или User Access Administrator) нужен для временной роли на шаге 5, Owner и Application Administrator в Entra — для `setup.sh` после восстановления: он назначает роли и меняет регистрации приложений. Для учения хватает Contributor; ещё нужны `unzip`, `openssl` и сборка сервиса (Node, .NET SDK), если не передан готовый архив.
- `<site>`, `<server>`, `<storage>`, `<prod-host>` — README, «Имена ресурсов».
- Точка T (UTC, ISO 8601, раньше начала повреждения) утверждена Security Owner и записана в протокол. Самая ранняя доступная точка:

  ```bash
  az postgres flexible-server show --resource-group rg-sikkerheit-prod --name <server> --query backup.earliestRestoreDate -o tsv
  ```

- Причина — выпуск: сначала откат версии (README, «Откат версии»), чтобы код совпадал со схемой на момент T. Если после T выпускалась версия с новыми миграциями и её оставляют, после шага 2 выпустить её заново (`infra/scripts/deploy-app.sh prod`, на время выпуска разрешив адрес рабочей станции на обоих слотах правилом шага 6): миграции применит слот `staging`. Проверить этот путь при первом учебном восстановлении.
- Сотрудники предупреждены, что портал недоступен: [ЗАПОЛНИТЬ: канал Teams]. Время начала шага 1 записано — от него считается RTO.

## Шаги

### 1. Закрыть доступ

Запретить входящие запросы на production и `staging`: в P1 это стандартные hostname слотов, а правило слота действует на все его hostname. Сайт SCM не закрывать — через него идёт SSH шага 3.

```bash
az webapp config access-restriction set --resource-group rg-sikkerheit-prod --name <site> --default-action Deny
```

```bash
az webapp config access-restriction set --resource-group rg-sikkerheit-prod --name <site> --slot staging --default-action Deny
```

Выключить задания настройкой слота (режим обслуживания); приложение перезапустится:

```bash
az webapp config appsettings set --resource-group rg-sikkerheit-prod --name <site> --slot-settings Jobs__Enabled=false
```

Проверить: `https://<prod-host>/` отвечает 403; `Jobs__Enabled` — `false` (команда RB-04, шаг 2); слот `staging` — `Stopped`:

```bash
az webapp show --resource-group rg-sikkerheit-prod --name <site> --slot staging --query state -o tsv
```

Срабатывает ли при закрытом доступе `alert-sikkerheit-prod-health`, подтвердить при первом учебном восстановлении; если да — отметить в протоколе как ожидаемое.

### 2. Восстановить базу

Новый сервер — в той же делегированной подсети и зоне Private DNS, приватный доступ сохраняется. `<new-server>` — например `psql-sikkerheit-prod-<5>-r<yyyymmdd>` (строчные буквы, цифры, дефис).

```bash
az postgres flexible-server restore --resource-group rg-sikkerheit-prod --name <new-server> --source-server <server> --restore-time <T> --vnet vnet-sikkerheit-prod --subnet database --private-dns-zone sikkerheit-prod.private.postgres.database.azure.com
```

Проверить: `state` — `Ready`, публичный доступ выключен, вход Entra включён, пароли выключены; `fqdn` — это `<new-fqdn>`.

```bash
az postgres flexible-server show --resource-group rg-sikkerheit-prod --name <new-server> --query "{state:state, fqdn:fullyQualifiedDomainName, network:network, auth:authConfig}" -o json
```

Администратор Entra — `id-sikkerheit-prod-migrations`:

```bash
az postgres flexible-server microsoft-entra-admin list --resource-group rg-sikkerheit-prod --server-name <new-server> -o table
```

Если вход Entra или администратор не перенеслись (подтвердить при первом учебном восстановлении) — вернуть их; первая команда даёт `<migrations-principal-id>`:

```bash
az identity show --resource-group rg-sikkerheit-prod --name id-sikkerheit-prod-migrations --query principalId -o tsv
```

```bash
az postgres flexible-server update --resource-group rg-sikkerheit-prod --name <new-server> --microsoft-entra-auth Enabled --password-auth Disabled
```

```bash
az postgres flexible-server microsoft-entra-admin create --resource-group rg-sikkerheit-prod --server-name <new-server> --display-name id-sikkerheit-prod-migrations --object-id <migrations-principal-id> --type ServicePrincipal
```

Переключить оба слота на новый сервер. Строки — как в `infra/bicep/modules/app.bicep`, меняется только `Host`; это настройки слота:

```bash
az webapp config appsettings set --resource-group rg-sikkerheit-prod --name <site> --slot-settings "ConnectionStrings__Sikkerheit=Host=<new-fqdn>;Database=sikkerheit;Username=sikkerheit-app;Ssl Mode=VerifyFull;Maximum Pool Size=20"
```

```bash
az webapp config appsettings set --resource-group rg-sikkerheit-prod --name <site> --slot staging --slot-settings "ConnectionStrings__Sikkerheit=Host=<new-fqdn>;Database=sikkerheit;Username=sikkerheit-staging;Ssl Mode=VerifyFull;Maximum Pool Size=10" "ConnectionStrings__SikkerheitOwner=Host=<new-fqdn>;Database=sikkerheit;Username=id-sikkerheit-prod-migrations;Ssl Mode=VerifyFull"
```

Старый сервер не удалять: он нужен для разбора (раздел «После восстановления»).

### 3. Повторить журнал безопасности

Команда запускается в контейнере production-слота. Журнал безопасности она читает identity восстановления `id-sikkerheit-prod-restore`: у неё только Storage Blob Data Reader на `security-log`, `reports` и `exports`, как требует `04` для команды восстановления, а её client id лежит в настройке слота `Restore__ManagedIdentityClientId`. Файлы отчётов и экспорта без строк команда переносит в карантин, а файлы удалённых организаций удаляет identity production-слота (Storage Blob Data Contributor): шагу 5 и повтору `organization.delete` нужна запись в Blob. С `--drill` и файлы читаются identity восстановления, поэтому учение перенести их не может. Сессия SSH (если CLI её не открывает — Azure portal → `<site>` → SSH):

```bash
az webapp ssh --resource-group rg-sikkerheit-prod --name <site>
```

В сессии проверить только эти переменные (README, «Общие правила»). Ожидается `false`:

```bash
printenv Jobs__Enabled
```

Ожидается `Host=<new-fqdn>…`:

```bash
printenv ConnectionStrings__Sikkerheit
```

Иначе контейнер ещё старый: выйти из сессии, перезапустить приложение и войти снова:

```bash
az webapp restart --resource-group rg-sikkerheit-prod --name <site>
```

Ожидается client id `id-sikkerheit-prod-restore`; без него команда завершится с кодом 2:

```bash
printenv Restore__ManagedIdentityClientId
```

Если переменная пуста, identity восстановления не назначена слоту: шаблон применён не полностью. Назначить её вручную (`setup.sh` во время восстановления не запускать: он включает задания), затем, когда приложение перезапустится, войти в сессию снова. Первая команда даёт `<restore-identity-id>`, `<restore-client-id>` и `<restore-principal-id>`; если identity нет, передать разработчику.

```bash
az identity show --resource-group rg-sikkerheit-prod --name id-sikkerheit-prod-restore --query "{id:id, clientId:clientId, principalId:principalId}" -o json
```

Ожидается Storage Blob Data Reader на контейнерах `security-log`, `reports` и `exports`; без этих ролей команда завершится с кодом 1 и ошибкой 403 — передать разработчику (роли назначает Owner):

```bash
az role assignment list --assignee <restore-principal-id> --all --query "[].{role:roleDefinitionName, scope:scope}" -o table
```

```bash
az webapp identity assign --resource-group rg-sikkerheit-prod --name <site> --identities <restore-identity-id>
```

```bash
az webapp config appsettings set --resource-group rg-sikkerheit-prod --name <site> --slot-settings Restore__ManagedIdentityClientId=<restore-client-id>
```

Endpoint managed identity доступен в сессии:

```bash
test -n "$IDENTITY_ENDPOINT" && echo managed-identity-ok
```

Запуск (`<T>` — например `2026-11-03T14:20:00Z`, обязательно с `Z` или смещением):

```bash
cd /home/site/wwwroot && dotnet Sikkerheit.Host.dll restore-replay --since <T> --report /home/LogFiles/restore-replay-<yyyymmdd>.json
```

```bash
echo $?
```

Код 0 — выполнено и проверено; 1 — сбой или проверка не прошла (причина — в stderr и `verification.problems`); 2 — неверные аргументы, задания включены или нет `Restore__ManagedIdentityClientId`. Команда идемпотентна: после устранения причины её повторяют с тем же `--since`.

Команда читает журнал с T − 5 минут по времени и применяет `organization.disable`, `organization.schedule_deletion` (срок не раньше now + 7 суток), `organization.cancel_deletion`, `organization.delete` (состоявшееся удаление повторяется сразу, находка F11) и `m365.disconnect`; каждая применённая запись пишет аудит `restore.replay_applied`. Записи P2 (`device.revoke`, `enrollment_key.revoke`) в P1 пропускаются с причиной `p2_not_implemented`.

Скачать отчёт на рабочую станцию: команда выгружает архив `/home/LogFiles`, отчёт `restore-replay-<yyyymmdd>.json` — внутри (тот же JSON напечатан в сессии):

```bash
az webapp log download --resource-group rg-sikkerheit-prod --name <site> --log-file restore-logs-<yyyymmdd>.zip
```

Сводка (имена полей — по текущей реализации команды):

```bash
jq '{passed: .verification.passed, problems: .verification.problems, recordsRead, applied: ([.records[] | select(.outcome == "applied")] | length), deletionsPostponed, policyEpochs, orphanFiles: (.orphanFiles | length), leasesReset, steps}' restore-replay-<yyyymmdd>.json
```

### 4. Защитить удаление

`deletionsPostponed` — организации в `deletion_scheduled`, чей срок сдвинут не раньше now + 7 суток (`from` → `to`). Передать перечень Admin: для каждой подтвердить, что удаление ещё нужно; не нужно — «Avbryt sletting» после шага 8.

### 5. Сверить счётчики, файлы и задания

- `policyEpochs`: следующая версия политики каждой организации — наименьшее кратное 10 000, большее максимальной сохранённой версии и восстановленного счётчика (`nextVersion`; решение F10, `06` шаг 5 и INV-195). Номера ревизий, потерянных после T, не повторятся и при повторном восстановлении.
- `orphanFiles`: файлы отчётов и экспорта без строк в базе перенесены в `reports/restore-orphans/` и `exports/restore-orphans/`; правило жизненного цикла `restore-orphans-30-days` удаляет их через 30 суток. Отчёт, уже переданный клиенту, остаётся для сверки. Чтобы скачать файл, своей учётной записи на время даётся роль Storage Blob Data Reader на контейнере (`<container>` — `reports` или `exports` из записи отчёта); первые две команды дают `<my-object-id>` и `<storage-id>`:

  ```bash
  az ad signed-in-user show --query id -o tsv
  ```

  ```bash
  az storage account show --resource-group rg-sikkerheit-prod --name <storage> --query id -o tsv
  ```

  ```bash
  az role assignment create --assignee-object-id <my-object-id> --assignee-principal-type User --role "Storage Blob Data Reader" --scope <storage-id>/blobServices/default/containers/<container>
  ```

  ```bash
  az storage blob download --account-name <storage> --container-name <container> --name <quarantineKey> --file <local-file> --auth-mode login
  ```

  ```bash
  az role assignment delete --assignee-object-id <my-object-id> --role "Storage Blob Data Reader" --scope <storage-id>/blobServices/default/containers/<container>
  ```

- `digestPeriodsMarked` — сводки Teams за сутки после T отмечены отправленными; `weeklyReportsMarked` — недели, чей отчёт нашёлся в карантине, отмечены выполненными. `m365_collect` и `retention_purge` идут обычным порядком.

### 6. Проверить

- `verification.passed` — `true`, `problems` пуст: каждый объект из журнала не мягче записи. `leasesReset` — сколько lease сброшено.
- Включить задания — для проверки ключа Graph они нужны раньше открытия доступа:

  ```bash
  az webapp config appsettings set --resource-group rg-sikkerheit-prod --name <site> --slot-settings Jobs__Enabled=true
  ```

- Открыть портал только своему внешнему IPv4-адресу:

  ```bash
  az webapp config access-restriction add --resource-group rg-sikkerheit-prod --name <site> --rule-name restore-check --action Allow --ip-address <your-ip>/32 --priority 100
  ```

- В портале: «Kunder» открывается; организации из `records` с `applied` — в ожидаемом статусе, в их «Revisjonslogg» — `restore.replay_applied` (а также `restore.deletion_postponed` и `restore.policy_epoch`, где сдвинуты срок и версия); у организаций из `deletionsPostponed` — «Slettes …» не раньше now + 7 суток; в одной организации «Tilkoblet» — «Samle inn nå» → «Fullført» или «Delvis»: ключ Graph работает.
- P2: у каждой организации с устройствами есть активный ключ регистрации.

### 7. Отчёт для ручного повтора

Изменения после T, которые восстановление потеряло, — из журнала запросов (Application Insights → «Logs»). Формат `name` («МЕТОД /маршрут») — допущение. Журнал запросов P1 не содержит `entraUserId` (отступление от `05`, «API портала»): исполнителя устанавливают по времени и опросу сотрудников.

```kusto
requests
| where timestamp >= datetime(<T>)
| where url contains "/api/v1/" and (name startswith "POST" or name startswith "PATCH")
| where success == true
| extend organizationId = extract(@"/organizations/([0-9a-f-]{36})", 1, url)
| project timestamp, name, organizationId, resultCode
| order by timestamp asc
```

| Маршрут | Операция | Что делает Admin |
| --- | --- | --- |
| `POST /api/v1/organizations` | `createOrganization` | Завести клиента заново (RB-03) |
| `PATCH …/organizations/{organizationId}` | `updateOrganization` | Повторить «Kundeopplysninger» |
| `POST …/lifecycle` | `changeOrganizationLifecycle` | Ограничивающие переходы уже применены (`records`); запрос без записи в `records` — вероятно «Aktiver»: сверить статус и повторить |
| `POST …/policy-revisions` | `createPolicyRevision` | Повторить во вкладке «Policy»; номер версии — новая эпоха |
| `POST …/m365-connection/consent`, `…/verify` | `startTenantConsent`, `verifyTenantConnection` | Подключение восстановить на шаге 8 |
| `POST …/m365-connection/disconnect` | `disconnectTenant` | Уже применено из журнала |
| `PATCH …/findings/{findingId}`, `POST …/risk-decisions` | `patchFinding`, `decideFindingRisk` | Повторить работу по проблеме и решение о риске |
| `POST …/reports`, `POST …/exports` | `createReport`, `createOrganizationExport` | Создать заново при необходимости; отчёт, отправленный клиенту, сверить с карантином |
| `POST …/collection-runs` | `requestCollection` | Не повторять: сбор идёт по расписанию |

### 8. Открыть доступ

```bash
az webapp config access-restriction remove --resource-group rg-sikkerheit-prod --name <site> --rule-name restore-check
```

```bash
az webapp config access-restriction set --resource-group rg-sikkerheit-prod --name <site> --default-action Allow
```

```bash
az webapp config access-restriction set --resource-group rg-sikkerheit-prod --name <site> --slot staging --default-action Allow
```

- `https://<prod-host>/health` отвечает 200, вход в портал работает.
- Admin повторяет перечень шага 7. Подключение M365, созданное после T: «Lag samtykkelenke» и сразу «Kontroller tilkobling» — consent в tenant клиента уже есть, ссылку клиенту не пересылать (`06`, шаг 8).
- Сообщить сотрудникам, что сервис работает и что было потеряно.
- RTO = окончание шага 8 − начало шага 1; цель — не больше 4 часов.

## После восстановления

- Старый сервер остановить; Azure сам запускает остановленный сервер через 7 суток — повторить остановку или удалить его по решению владельца после разбора:

  ```bash
  az postgres flexible-server stop --resource-group rg-sikkerheit-prod --name <server>
  ```

- В тот же день после шага 8 привести Bicep к новому серверу. Шаблон заново применит к нему свои настройки: PITR 14 суток, вход только Entra, администратор Entra, база `sikkerheit`. `infra/.state/prod.json` получит новые `databaseServerName` и `databaseHost`. Раньше шага 8 `setup.sh` не запускать: он возвращает настройки `main.bicep`, в том числе `Jobs__Enabled=true`. `<alert-email>` — адрес оповещений, заданный при установке.

  ```bash
  SIKKERHEIT_ALERT_EMAIL=<alert-email> SIKKERHEIT_DATABASE_SERVER=<new-server> infra/scripts/setup.sh prod
  ```

  Скрипт проверяет, что `<new-server>` есть в группе и что на нём уже работает production-слот (шаг 2), и передаёт его в параметр `databaseServerName` шаблона. Строки подключения обоих слотов остаются на `<new-fqdn>`. Без переменной `setup.sh` берёт сервер из строки подключения production-слота, поэтому и запуск с другой машины, где `infra/.state` старый, не вернёт сервис на старый сервер. Имя, которого нет в группе или которое расходится со строкой подключения (например, старый сервер), и сбой `az` останавливают скрипт до развёртывания. Выпуск кода (`deploy-app.sh`) строк подключения не меняет; test на время выпуска берёт адрес базы из строки подключения приложения.

  Диск: Azure не уменьшает диск, а восстановленный сервер или автоувеличение могли дать больше 32 GiB. `setup.sh` читает текущий `storage.storageSizeGb` сервера и передаёт шаблону параметр `databaseStorageGb` не меньше него (на первой установке 32 GiB); шаблон диск не уменьшает. Если `az` не вернул размер, скрипт останавливается до развёртывания. Так же останавливает его сбой проверки блокировки неизменяемости `security-log`: политику не считают ни заблокированной, ни незаблокированной, пока её состояние не прочитано.
- P2: агенты, зарегистрированные после T, получают `device_unknown` и регистрируются заново; новый ключ регистрации раздаётся через RMM (RB-10).

## Проверка результата

- `verification.passed` — `true`, отчёт приложен к протоколу.
- Все ограничивающие действия после T применены; отменённое удаление не исполнено; ни одна организация не удаляется раньше 7 суток после восстановления.
- Номера ревизий политики не повторяются (`policyEpochs`).
- Ключ Graph работает; подключения после T восстановлены; перечень шага 7 повторён.
- RTO измерен и не больше 4 часов.

## Учебное восстановление

До пилота M365 и затем раз в квартал (`06`). Резервная копия production восстанавливается в изолированную группу `rg-sikkerheit-drill` без входящего доступа и без сбора M365; сценарий выполняет `infra/scripts/drill.sh`, в `rg-sikkerheit-prod` он только читает. Журнал безопасности и файлы production учебный экземпляр читает identity восстановления `id-sikkerheit-prod-restore` (только Storage Blob Data Reader), поэтому файлы только перечисляются (`--drill`), а ролей на хранилище production учение не назначает. После измерения RTO группа удаляется: в ней копия данных клиентов. Что подтверждается впервые — README, «Что подтвердить в реальном окружении». Перенос файлов в карантин проверяется на test (AT-11): шаги 1–8 в `rg-sikkerheit-test` без `--drill`, у test нет слота и одна строка подключения.

RTO учения — от запуска PITR (Д3) до прохождения проверки отчёта (Д6). Группа, сеть и учебный экземпляр готовятся до PITR и в RTO не входят. Скрипт печатает время UTC каждого шага для протокола.

Д1–Д4. Checkout тега версии, которая работает в production: скрипт собирает её так же, как `infra/scripts/deploy-app.sh`, или берёт готовый архив этой версии (`--package <архив>`). `<T>` — в UTC с `Z`, не раньше `earliestRestoreDate` (раздел «Предусловия и доступы»).

```bash
infra/scripts/drill.sh start --since <T>
```

- Д1 — группа `rg-sikkerheit-drill` с тегом `environment=drill` и сеть из того же `infra/bicep/modules/network.bicep`, что в production: `vnet-sikkerheit-drill` с подсетями `app` и `database`, зона `sikkerheit-drill.private.postgres.database.azure.com`.
- Д2 — учебный экземпляр `app-sikkerheit-drill-<yyyymmddhhmm>-<4>` на B1. Доступ закрывается сразу после создания; включены Always On и журнал контейнера в файловой системе.
  - Identity: системная; identity миграций production — она создаёт роль `sikkerheit-drill` в восстановленной копии, как слот `staging` в production; identity восстановления.
  - Настройки: окружение `Drill`, задания выключены, без `M365__*` и входа Entra (процесс стартует без производственных ключей Key Vault), хранилище и журнал безопасности production, `Restore__ManagedIdentityClientId`. Application Insights не подключается.
- Д3 — PITR сервера, на котором сейчас работает production (он берётся из строки подключения production-слота), в `psql-sikkerheit-drill-<yyyymmddhhmm>`. Затем проверки шага 2: `Ready`, без публичного доступа, вход только Entra, администратор Entra — identity миграций. Если вход Entra или администратор не перенеслись, скрипт их возвращает.
- Д4 — строки подключения к восстановленному серверу и выпуск. Миграции при старте создают роль `sikkerheit-drill`; `az webapp deploy` ждёт запуска.

Д5. Команда восстановления — шаг 3 с `--drill`, вручную в SSH. `start` печатает точные команды: `az webapp ssh`, проверку `Jobs__Enabled` и `Restore__ManagedIdentityClientId`, запуск с `--report /home/LogFiles/restore-drill-<yyyymmddhhmm>.json` и `echo $?`.

Д6. Проверка отчёта и RTO:

```bash
infra/scripts/drill.sh check
```

Скрипт скачивает журнал экземпляра (`az webapp log download`), сохраняет отчёт в `infra/.state/drill/` и печатает сводку шага 3. Учение не прошло, если:

- отчёт не учебный (`drill` — не `true`) или точка в нём не `<T>`;
- `verification.passed` — не `true`;
- хотя бы один файл перенесён (`moved` — `true`);
- RTO больше 4 часов.

Остальное сверить с AT-11, часть P1: все ограничивающие действия после T применены; отменённое удаление не исполнено; ни одна организация не удаляется раньше 7 суток; номера ревизий не повторяются.

Д7. Удаление группы, в том числе после неудачного `start`:

```bash
infra/scripts/drill.sh cleanup
```

Скрипт удаляет только группу с тегом `environment=drill` и ждёт окончания удаления. Отчёт из `infra/.state/drill/` приложить к протоколу, затем удалить с рабочей станции.

## Запись в протокол

Шаблон — [README](README.md), раздел «Протокол». Записать T и основание выбора; время начала и конца каждого из восьми шагов (для учения — Д1–Д7, время печатает `drill.sh`); имена старого и нового серверов; отчёт команды файлом и его сводку (`recordsRead`, применённые записи, `deletionsPostponed`, `policyEpochs`, `orphanFiles`, `verification`); перечень шага 7 и кто что повторил; RTO. Для учения — также удаление группы (`drill.sh cleanup`).

## Связанные документы

- [06-azure-and-operations.md](../../development-package/06-azure-and-operations.md) — «Резервное копирование и восстановление», «Окружения и развёртывание».
- [04-security-and-privacy.md](../../development-package/04-security-and-privacy.md) — «Журнал безопасности», «Сроки хранения».
- [05-data-and-api.md](../../development-package/05-data-and-api.md) — «Жизненный цикл организации», «Фоновые задания и планировщик».
- [07-delivery-plan-and-acceptance.md](../../development-package/07-delivery-plan-and-acceptance.md) — AT-09, AT-11.
- [0.3.0-decisions.md](../reviews/0.3.0-decisions.md) — находки F10, F11; [dev/README.md](../dev/README.md) — «Восстановление после PITR» (устройство команды).
- [infra/README.md](../../infra/README.md) — «Восстановление базы», «Учебное восстановление»; [RB-04](RB-04-jobs-and-scheduler.md), [RB-06](RB-06-security-incident.md).
