# Runbooks Sikkerheit

Эксплуатационные процедуры этапа P1 по `07`, раздел «Runbooks»: признак запуска, шаги с операциями портала или командами Azure, проверка результата и запись в протокол. Runbooks агента Windows этапа P2: RB-08…RB-12; RB-13 (каталог выпусков Windows) ещё не написан.

## Перечень

| RB | Название | Владелец роли | Когда запускать | Файл |
| --- | --- | --- | --- | --- |
| RB-01 | Сбой подключения Microsoft 365 | Service Manager | Запуск сбора «Mislyktes» с `consent_missing`, `tenant_mismatch` или `credential_error`; модуль «Mangler tillatelse»; отказ «Kontroller tilkobling» | [RB-01-m365-connection-failure.md](RB-01-m365-connection-failure.md) |
| RB-02 | Ключ приложения Graph | Security Owner | За 30 дней до конца срока сертификата; `credential_error` у всех организаций; подпись вне сбора; подозрение на компрометацию | [RB-02-graph-key.md](RB-02-graph-key.md) |
| RB-03 | Подключение и отключение клиента | Service Manager | Новый клиент; новые права приложения Graph; клиент отключает Microsoft 365 | [RB-03-client-onboarding.md](RB-03-client-onboarding.md) |
| RB-04 | Сбой заданий и планировщика | Operations | Ошибки заданий в журнале сервиса; health check; «Siste innsamling» старше 26 часов; 503 при записи журнала безопасности | [RB-04-jobs-and-scheduler.md](RB-04-jobs-and-scheduler.md) |
| RB-05 | Восстановление базы из PITR | Operations (+ Security Owner) | Потеря или порча данных базы; учебное восстановление до пилота M365 и затем раз в квартал | [RB-05-database-restore.md](RB-05-database-restore.md) |
| RB-06 | Инцидент безопасности | Security Owner | Подозрение на утечку данных, захват учётной записи сотрудника, сервиса, Key Vault или регистрации приложения | [RB-06-security-incident.md](RB-06-security-incident.md) |
| RB-07 | Уход клиента | Service Manager | Клиент прекращает обслуживание или просит удалить данные | [RB-07-client-offboarding.md](RB-07-client-offboarding.md) |
| RB-08 | Выпуск агента через RMM | Operations | Новая утверждённая версия; ежемесячная проверка .NET; «Alert RB-08»; откат после остановки раскатки | [RB-08-agent-release.md](RB-08-agent-release.md) |
| RB-09 | Аварийный отзыв опасной версии агента | Security Owner | Критическая уязвимость агента или .NET; компрометация подписи кода | [RB-09-agent-emergency-revocation.md](RB-09-agent-emergency-revocation.md) |
| RB-10 | Ключ регистрации организации | Security Owner | Плановая ротация; «Alert RB-10»; подозрение на утечку ключа; кража ПК | [RB-10-enrollment-key.md](RB-10-enrollment-key.md) |
| RB-11 | Конфликт идентичности устройства | Service Manager | «Alert RB-11»; «Konflikt» в «Enheter»; частый `device.sequence_resync` | [RB-11-device-identity.md](RB-11-device-identity.md) |
| RB-12 | Агент не выходит на связь | Service Manager | «Alert RB-12»; «Sist sett» старше 72 часов; отказы 422; часы; буфер | [RB-12-agent-offline.md](RB-12-agent-offline.md) |
| RB-14 | Бюджет Azure и дневной лимит журналов | Product Owner (+ Operations) | Письмо бюджета на 80% и 100%; достигнут дневной лимит Log Analytics | [RB-14-azure-budget-and-log-cap.md](RB-14-azure-budget-and-log-cap.md) |

## Роли

| Роль | Кто исполняет | Основание |
| --- | --- | --- |
| Product Owner | Владелец компании или назначенный им руководитель: [ЗАПОЛНИТЬ: имя] | `07`, «Правила этапов и гейты» |
| Service Manager | Ведущий техник с ролью Admin в портале: [ЗАПОЛНИТЬ: имя] | `07` |
| Security Owner | По умолчанию владелец; ему же уходят оповещения безопасности | Ответы владельца 2026-10-15 в [0.3.0-decisions.md](../reviews/0.3.0-decisions.md) |
| Operations | Разработчик | `06`, `07` |
| Замещение на время отсутствия | [ЗАПОЛНИТЬ] | — |

## Общие правила

- **Кто выполняет.** Владелец роли или его замещающий. Операции портала в runbooks требуют роли Admin в «Sikkerheit Portal (prod)» и входа с MFA; Technician может читать, нажимать «Samle inn nå», работать с проблемами и создавать отчёты. Команды Azure выполняются после `az login` в tenant компании с правами, перечисленными в runbook.
- **Без произвольного SQL.** К базе не подключаться (psql, pgAdmin и т. п.): она доступна только из VNet и только по входу Entra. Данные меняются операциями портала (operationId из `07`) или режимом обслуживания образа сервиса (`restore-replay`, RB-05). «—» в колонке операций `07` означает шаги в Azure.
- **Окно работ.** Плановые работы — ротация ключа, выпуск, изменение настроек, учебное восстановление — выполняются вне окна ночного сбора 01:00–05:00 по времени Europe/Oslo (`06`). Аварийные шаги RB-05, RB-06 и аварийный отзыв RB-02 выполняются сразу.
- **Время.** В командах и протоколе — UTC в ISO 8601 (`2026-11-03T14:20:00Z`); портал показывает местное время.
- **Секреты.** Секреты и токены не попадают в чат, заявки и протокол. В SSH-сессии контейнера не выполнять `printenv` без имени переменной: значения ссылок Key Vault там уже раскрыты.
- **Окружение.** Команды даны для production (`rg-sikkerheit-prod`). Для test заменить `prod` на `test`: у test нет слота `staging`, приложение Graph — «Sikkerheit Graph Reader (test)», к нему подключаются только тестовые tenant.
- **Отступления.** Если шаг не совпадает с тем, что видно в портале или Azure, остановиться в безопасном состоянии, записать расхождение в протокол и передать разработчику для правки runbook.

## Имена ресурсов

Имена создаёт `infra/bicep/main.bicep`; `<5>` — пять символов от id группы ресурсов.

| Ресурс | Имя | Обозначение в runbooks |
| --- | --- | --- |
| Группа ресурсов | `rg-sikkerheit-prod` | — |
| Web App и слот | `app-sikkerheit-prod-<5>`, слот `staging` | `<site>`; hostname `<prod-host>` и `<staging-host>` |
| PostgreSQL Flexible Server | `psql-sikkerheit-prod-<5>`, после RB-05 — восстановленный сервер (параметр `databaseServerName`); база `sikkerheit` | `<server>` |
| VNet и Private DNS | `vnet-sikkerheit-prod` (подсети `app`, `database`), зона `sikkerheit-prod.private.postgres.database.azure.com` | — |
| Storage | `stsikkerheitprod<5>`: контейнеры `reports`, `exports`, `agent-releases`, `dataprotection`, `security-log` | `<storage>` |
| Key Vault | `kv-sikkerheit-prod-<5>`: сертификат `graph-reader`, ключ `dataprotection`, секреты `cursor-key`, `teams-webhook` | `<kv>` |
| Log Analytics и Application Insights | `log-sikkerheit-prod`, `appi-sikkerheit-prod` | — |
| Оповещения и бюджет | `alert-sikkerheit-prod-5xx`, `-health`, `-errors`; группа действий `ag-sikkerheit-prod`; бюджет `budget-sikkerheit-prod` | — |
| Identity миграций, восстановления и выпуска | `id-sikkerheit-prod-migrations` (назначена только слоту `staging`); `id-sikkerheit-prod-restore` — только чтение `security-log`, `reports`, `exports` для команды восстановления (назначена production-слоту, RB-05); `id-sikkerheit-prod-deploy` — вход GitHub Actions по OIDC, если при установке задан `SIKKERHEIT_GITHUB_REPO` | — |
| Приложения Entra | «Sikkerheit Portal (prod)»; «Sikkerheit Graph Reader» | `<graph-app-id>` — Application (client) ID |

На рабочей станции, где запускался `setup.sh`, имена лежат в `infra/.state/prod.json` (`siteName`, `productionHost`, `stagingHost`, `vaultName`, `storageAccountName`, `databaseServerName`, `databaseHost`) и `infra/.state/prod.graph`. Иначе:

```bash
az resource list --resource-group rg-sikkerheit-prod --query "[].{name:name, type:type}" -o table
```

```bash
az ad app list --display-name "Sikkerheit Graph Reader" --query "[0].appId" -o tsv
```

## Оповещения и признаки

Письма приходят на адрес `SIKKERHEIT_ALERT_EMAIL`, заданный при установке (группа действий `ag-sikkerheit-prod`). Сигналы `06`, «Наблюдаемость и оповещения», которых в Azure ещё нет, проверяются вручную по runbook.

| Сигнал `06` | Как обнаруживается сейчас | Runbook |
| --- | --- | --- |
| Сбор M365 `failed` с `consent_missing`, `tenant_mismatch`, `credential_error` | `alert-sikkerheit-prod-errors` (любая запись уровня Error за 15 минут), сводка Teams в 07:30 | RB-01 |
| Задания `failed`, отчёт `failed`, сбой экспорта | `alert-sikkerheit-prod-errors`, сводка Teams | RB-04 |
| Запись журнала безопасности не создаётся (503) | `alert-sikkerheit-prod-5xx` (больше 5 ответов 5xx за 15 минут), отказ операции в портале | RB-04 |
| Сервис не отвечает | `alert-sikkerheit-prod-health` | RB-04 |
| Tenant без завершённого сбора 26 часов | Не реализовано: ежедневно «Kunder» → столбец «Siste innsamling» | RB-04 |
| Последний такт планировщика | Не реализовано: косвенные признаки | RB-04 |
| Подпись ключом Graph вне запуска сбора, рост числа подписей | Не реализовано: еженедельный запрос к журналу Key Vault | RB-02 |
| Срок сертификата Graph меньше 30 дней | Письмо Key Vault контактам сертификатов за 30 дней (адрес оповещений задаёт `setup.sh`); ежемесячная проверка | RB-02 |
| Бюджет 80% и 100% | Письмо бюджета `budget-sikkerheit-prod` (200 USD; у test — 50 USD) | RB-14 |
| Дневной лимит Log Analytics достигнут | Не реализовано: проверка состояния рабочей области | RB-14 |

Запросы KQL:

- Application Insights `appi-sikkerheit-prod` → «Logs»: таблицы `traces`, `requests`, `exceptions`;
- Log Analytics `log-sikkerheit-prod` → «Logs»: `AzureDiagnostics` (журнал Key Vault, категория `AuditEvent`), `Usage`, `_LogOperation` и те же данные Application Insights в таблицах `AppTraces`, `AppRequests`.

Имена столбцов, которые не подтверждены на реальных данных, отмечены в runbooks: сверить при первом запуске в SP-02.

## Откат версии

После переключения слотов в `staging` лежит прежняя версия, слот остановлен. Схема совместима с прежней версией (`06`, «Окружения и развёртывание»). Откат — вне окна 01:00–05:00, если ситуация позволяет.

```bash
az webapp start --resource-group rg-sikkerheit-prod --name <site> --slot staging
```

Дождаться ответа 200 от `https://<staging-host>/health`, затем:

```bash
az webapp deployment slot swap --resource-group rg-sikkerheit-prod --name <site> --slot staging --target-slot production
```

```bash
az webapp stop --resource-group rg-sikkerheit-prod --name <site> --slot staging
```

Проверить `https://<prod-host>/health` (200) и вход в портал. Нужна версия старше предыдущей — выпустить её тег: `infra/scripts/deploy-app.sh prod` из checkout тега или workflow `deploy.yml` в GitHub Actions («Run workflow», тег в «Use workflow from», environment `prod`). Прерванный выпуск оставляет слот `staging` запущенным: `infra/scripts/deploy-app.sh prod --cleanup` останавливает его.

## Протокол

Каждый запуск runbook — одна запись в [ЗАПОЛНИТЬ: система заявок или защищённая папка компании]. В репозиторий протоколы не кладутся: в них имена клиентов и сотрудников. Отчёт команды восстановления (RB-05) прикладывается к записи файлом.

```markdown
# <RB-nn> <краткое название> — <дата UTC>

- Начало / окончание (UTC):
- Исполнитель и роль; кто ещё участвовал:
- Признак запуска (оповещение, письмо, наблюдение в портале, обращение клиента; ссылка):
- Окружение: prod / test / учебное (rg-…)
- Затронутые организации и tenant:

## Шаги
| Время UTC | Шаг runbook | Действие (операция портала или команда) | Результат |
| --- | --- | --- | --- |

## Проверка результата
- Что проверено и чем (запрос, экран портала, код возврата):
- Отчёт восстановления: файл, `verification.passed`, RTO (только RB-05):

## Уведомления
- Кому, когда, каким каналом (клиенты, Datatilsynet, сотрудники):

## Отступления от runbook и последующие действия
- Что сделано иначе и почему:
- Задачи: что, владелец, срок:
```

## Известные отступления

Runbooks учитывают расхождения текущей реализации с пакетом; после исправления — убрать обходы из runbooks:

- на подключении «Tilkoblet» портал не показывает «Lag samtykkelenke» и «Kontroller tilkobling», хотя API их допускает: повторный consent — по ссылке, составленной вручную (RB-03);
- сервис не записывает `correlationId` подписи Key Vault вместе с запуском сбора (`04`, «Ключ приложения»): подписи сверяются запросами RB-02, раздел В;
- оповещений о подписи вне сбора, tenant без сбора 26 часов, такте планировщика и дневном лимите журналов нет (таблица выше); о сроке сертификата пишет Key Vault контактам сертификатов;
- журнал запросов не содержит `entraUserId` (`05`, «API портала»): перечень RB-05, шаг 7, — без исполнителя;
- журнал безопасности команда восстановления читает identity только для чтения, но в реальном восстановлении переносит и удаляет файлы identity production-слота, у которой Storage Blob Data Contributor на всё хранилище, включая `security-log` (`04`, «Журнал безопасности», и `06`, шаг 5, этого не различают); код пишет только в `reports` и `exports`.

## Что подтвердить в реальном окружении

Эти места runbooks проверены только по документации и справке Azure CLI; подтвердить в SP-02 или при первом учебном восстановлении и исправить runbook:

- `az webapp ssh` открывает сессию в production-контейнере при запрете входящих запросов на основной сайт (туннель идёт через сайт SCM), а в сессии видны настройки приложения (`Jobs__Enabled`, `ConnectionStrings__Sikkerheit`) и endpoint managed identity;
- health check при запрете входящих запросов: срабатывает ли `alert-sikkerheit-prod-health`;
- `az postgres flexible-server restore` с `--vnet`, `--subnet` и `--private-dns-zone` в ту же делегированную подсеть; перенос администратора Entra и `authConfig` на новый сервер; вход роли `sikkerheit-app`;
- повторный выпуск версии с миграциями при закрытом доступе (RB-05, «Предусловия и доступы»);
- `az webapp log download` содержит отчёт из `/home/LogFiles`;
- столбцы `id_s` и `identity_claim_oid_g` в `AzureDiagnostics` Key Vault, формат `name` в `requests` («МЕТОД /маршрут»), ключи `customDimensions` в `traces`, вызовы Graph в `dependencies`, запись `OverQuota` в `_LogOperation`;
- учебное восстановление (`infra/scripts/drill.sh`):
  - identity миграций и восстановления production назначаются экземпляру в другой группе;
  - роль `sikkerheit-drill` создаётся мигратором под identity миграций;
  - процесс стартует с `ASPNETCORE_ENVIRONMENT=Drill`;
  - `az webapp create` принимает `--runtime "DOTNETCORE:10.0"`;
  - `az webapp deploy` дожидается запуска с миграциями;
  - экземпляр из VNet учения доходит до хранилища production;
  - `microsoft-entra-admin list` отдаёт `objectId`;
  - в архиве `az webapp log download` есть отчёт;
- identity восстановления: команда в production-контейнере получает её токен по `Restore__ManagedIdentityClientId` и читает журнал, а запись этой identity в Blob отклоняется (403);
- `setup.sh` после восстановления: Bicep принимает восстановленный сервер (повторный PUT с теми же `network`, `version` и `storageSizeGB`, база `sikkerheit` уже есть). Если автоувеличение подняло диск исходного сервера выше 32 GiB, шаблон с 32 GiB будет отклонён — тогда, как и при любом повторном запуске `setup.sh`, поднять `storageSizeGB` в `postgres.bicep`;
- отключение старой версии сертификата отключает и её ключ (RB-02);
- аварийный отзыв ключа Graph (находка F05) — на тестовой регистрации.

## Связанные документы

- [06-azure-and-operations.md](../../development-package/06-azure-and-operations.md) — ресурсы, развёртывание, оповещения, восстановление, удаление, расходы.
- [07-delivery-plan-and-acceptance.md](../../development-package/07-delivery-plan-and-acceptance.md) — таблица «Runbooks», роли, AT-03, AT-09, AT-11.
- [infra/README.md](../../infra/README.md) — установка и выпуск.
- [0.3.0-decisions.md](../reviews/0.3.0-decisions.md) — решения владельца и отступления реализации P1.
