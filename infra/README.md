# Развёртывание Sikkerheit в Azure

Ресурсы — `bicep/main.bicep` (модули в `bicep/modules`), установка — `scripts/setup.sh`, выпуск версии — `scripts/deploy-app.sh` (с рабочей машины или из `.github/workflows/deploy.yml`), учебное восстановление — `scripts/drill.sh`, IaC-тест — `tools/iac/check_arm.py`. Требования к ресурсам — `development-package/06-azure-and-operations.md`.

## Что создаётся

| Ресурс | Настройка |
| --- | --- |
| Группа `rg-sikkerheit-<env>` | Norway East по умолчанию (`SIKKERHEIT_LOCATION=swedencentral`, если PostgreSQL в Norway East недоступен) |
| App Service, Linux, .NET 10 | prod — P0v3 со слотом `staging`, который работает только во время развёртывания; test — B1 без слота (у планов Basic слотов нет). Always On, health check `/health`, HTTPS only, VNet |
| PostgreSQL 17 Flexible Server B1ms | Только приватный доступ, только вход Entra (паролей нет), PITR 14 суток. Имя — параметр `databaseServerName`: по умолчанию `psql-sikkerheit-<env>-<5>`, после восстановления — восстановленный сервер (раздел «Восстановление базы») |
| Managed identity `id-sikkerheit-<env>-migrations` | Администратор Entra сервера и владелец схемы. В prod назначена только слоту `staging`; в test шаблон её не назначает никому, `deploy-app.sh` даёт её приложению только на время развёртывания |
| Managed identity `id-sikkerheit-<env>-restore` | Только чтение: Storage Blob Data Reader на контейнеры `security-log`, `reports`, `exports`. Назначена production-слоту (в test — приложению); её client id — в настройке `Restore__ManagedIdentityClientId`, в prod это настройка слота. Ею команда восстановления читает журнал безопасности, а в учении и файлы; сервис ею не пользуется |
| Storage (ZRS) | Без ключей доступа, контейнеры `reports`, `exports`, `agent-releases`, `dataprotection`, `security-log` (неизменяемость 30 суток, удаление через 45); файлы, перенесённые восстановлением в `reports/restore-orphans/` и `exports/restore-orphans/`, удаляются через 30 суток |
| Key Vault Premium | RBAC, purge protection; ключ Data Protection (RSA-HSM 3072), сертификат Graph (RSA-HSM 3072, неэкспортируемый), секреты `cursor-key`, `teams-webhook` |
| Log Analytics, Application Insights | 90 дней, дневной лимит; оповещения на почту: 5xx, health check, ошибки в журнале |
| Бюджет | prod — 200 USD в месяц, test — 50 USD (NFR-09), письма на 80% и 100% |
| Приложения Entra | «Sikkerheit Portal (<env>)» — вход сотрудников, роли Admin/Technician/Reader, без секретов (federated credential от managed identity приложения и, в prod, слота `staging`); «Sikkerheit Graph Reader» — multi-tenant, только чтение, сертификат из Key Vault |
| Managed identity `id-sikkerheit-<env>-deploy` (если задан `SIKKERHEIT_GITHUB_REPO`) | Вход GitHub Actions по OIDC, без секретов: Website Contributor на группу ресурсов, в test ещё Managed Identity Operator на identity миграций. Доступа к базе, Key Vault и данным хранилища нет |

Ориентир стоимости production — около 110–125 USD в месяц, test — около 45 (`06`, «Модель расходов»).

## Первая установка

Нужны права Owner на подписку и Application Administrator (или Global Administrator) в tenant компании. Вход — в своём терминале:

```bash
az login
```

```bash
SIKKERHEIT_ALERT_EMAIL=drift@firma.no infra/scripts/setup.sh prod
```

Окружение test — та же команда с `test`. Скрипт идемпотентен и выполняет:

1. Группу ресурсов и первый проход Bicep. Сервер базы — тот, что в строке подключения приложения; при первой установке — `psql-sikkerheit-<env>-<5>`. `SIKKERHEIT_DATABASE_SERVER` должен назвать тот же сервер, а нужен, только если приложения или адреса базы в его строке подключения нет. Скрипт останавливается до развёртывания, если сервера нет в группе, имя расходится со строкой подключения или вызов `az` не удался: иначе Bicep вернул бы сервис на другой сервер или создал бы новый пустой.
2. Регистрацию «Sikkerheit Portal»: redirect URI приложения и слота `staging` (в test слота нет), app roles, собственный API со scope `access_as_user` и токенами v1 (в них есть `amr`), назначение ролей только через Enterprise application, federated credentials managed identity приложения и слота, роль Admin запустившему скрипт.
3. Регистрацию «Sikkerheit Graph Reader»: multi-tenant, application permissions только на чтение (`Organization.Read.All`, `User.Read.All`, `UserAuthenticationMethod.Read.All`, `RoleManagement.Read.Directory`, `GroupMember.Read.All`, `Policy.Read.All`), redirect URI страницы возврата consent.
4. Сертификат Graph в Key Vault, его публичную часть — в регистрацию; право sign — только production-слоту; секрет `cursor-key`; `teams-webhook`, если задан `SIKKERHEIT_TEAMS_WEBHOOK`.
5. Блокировку неизменяемости журнала безопасности, если `SIKKERHEIT_LOCK_SECURITY_LOG=yes` (отменить нельзя; сделать до пилота). Заблокированная политика допускает только продление срока, поэтому следующие проходы Bicep её не передают (параметр `securityLogLocked` скрипт определяет сам).
6. Второй проход Bicep с идентификаторами приложений; в prod слот `staging` затем останавливается.
7. Identity развёртывания из GitHub, если задан `SIKKERHEIT_GITHUB_REPO` (раздел «Развёртывание из GitHub»).

Затем выпуск кода:

```bash
infra/scripts/deploy-app.sh prod
```

Сборка портала и сервиса, затем:

- prod: слот `staging` (миграции при старте под identity миграций) → smoke-тесты на hostname слота (health, страница портала, 401 API, переход на вход Entra, CSP) → переключение слотов → остановка `staging`. При ошибке слот `staging` тоже останавливается; если переключение уже было, скрипт печатает команды отката.
- test: приложению на время развёртывания назначаются identity миграций и настройки `Database__MigrateOnStart=true`, `ConnectionStrings__SikkerheitOwner`, `Database__OwnerIdentityClientId`, `Database__AppPrincipals__0__*` → публикация → те же smoke-тесты на hostname приложения → настройки и identity снимаются, приложение перезапускается. Снимает их trap, в том числе при ошибке любого шага; после прерванного запуска — `infra/scripts/deploy-app.sh test --cleanup`.

Без `infra/.state/<env>.json` (другая машина, CI) скрипт находит приложение, hostname, identity миграций и адрес базы через `az`.

## Развёртывание из GitHub

Workflow `.github/workflows/deploy.yml` запускается вручную (Actions → deploy → Run workflow, окружение test или prod): IaC-тест, затем тот же `deploy-app.sh`. Вход в Azure — OIDC через federated credential, секретов нет; к базе конвейер не подключается, инфраструктуру не меняет — это делает `setup.sh` с правами владельца.

Настройка, один раз на окружение:

1. `SIKKERHEIT_ALERT_EMAIL=drift@firma.no SIKKERHEIT_GITHUB_REPO=owner/repo infra/scripts/setup.sh test` — создаёт `id-sikkerheit-test-deploy` с federated credential для `repo:owner/repo:environment:test` и печатает три переменные. Имя репозитория — точно как на GitHub.
2. GitHub → Settings → Environments: окружения `test` и `prod`, в каждом — Environment variables `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID` из вывода скрипта. У каждого окружения своя identity, поэтому это переменные окружения, а не репозитория.
3. Для `prod` — Required reviewers и Deployment branches and tags: только `main` и теги версий.

Права identity: Website Contributor на группу ресурсов (приложение и слоты) и, только в test, Managed Identity Operator на identity миграций — чтобы назначать её приложению на время развёртывания. В prod это право не нужно: identity миграций слоту `staging` назначает шаблон.

Отменённый запуск завершается шагом `deploy-app.sh <env> --cleanup`: остановка `staging` в prod, снятие временного доступа в test. Если раннер пропал и шаг не выполнился, ту же команду запускают с рабочей машины.

## Восстановление базы

Восстановление по [RB-05](../docs/runbooks/RB-05-database-restore.md) создаёт новый сервер, и сервис переключается на него строками подключения. После шага 8 RB-05 `setup.sh` приводит Bicep к этому серверу:

```bash
SIKKERHEIT_ALERT_EMAIL=drift@firma.no SIKKERHEIT_DATABASE_SERVER=<new-server> infra/scripts/setup.sh prod
```

Имя попадает в параметр `databaseServerName`, и шаблон применяет к восстановленному серверу свои настройки: PITR 14 суток, вход только Entra, администратор Entra, база `sikkerheit`. `infra/.state/prod.json` получает новые `databaseServerName` и `databaseHost`.

- Без переменной сервер берётся из строки подключения приложения, поэтому повторный запуск — в том числе с другой машины — не вернёт сервис на старый сервер. Переменная, которая расходится со строкой подключения (например, старый сервер), останавливает скрипт: переключение строк подключения — шаг 2 RB-05, а не `setup.sh`.
- Раньше шага 8 скрипт не запускать: шаблон возвращает `Jobs__Enabled=true`.
- `deploy-app.sh test` берёт адрес базы из строки подключения приложения, а не из `infra/.state`.
- Старый сервер шаблон не трогает: его останавливают или удаляют по RB-05.

Команда восстановления читает журнал безопасности identity `id-sikkerheit-<env>-restore` (`04`: только чтение). Файлы реального восстановления — перенос без строк в карантин и удаление файлов удалённых организаций — пишет identity слота: без записи в Blob эти шаги невозможны.

## Учебное восстановление

```bash
infra/scripts/drill.sh start --since <T>
```

```bash
infra/scripts/drill.sh check
```

```bash
infra/scripts/drill.sh cleanup
```

- `start` восстанавливает production на точку `<T>` (UTC с `Z`) в группу `rg-sikkerheit-drill`. Сеть строится тем же `modules/network.bicep`; учебный экземпляр работает без входящего доступа и без сбора M365, с identity миграций и восстановления production. Выпускается версия текущего checkout или архив из `--package <архив>`.
- Команду восстановления с `--drill` оператор запускает в SSH (RB-05, Д5).
- `check` разбирает отчёт команды и считает RTO.
- `cleanup` удаляет группу; его запускают и после неудачного `start`.

В `rg-sikkerheit-prod` скрипт только читает и ролей не назначает, поэтому достаточно Contributor на подписке. Порядок и критерии — RB-05, «Учебное восстановление».

## Проверка IaC

```bash
python3 -I tools/iac/check_arm.py
```

Скрипт собирает `main.bicep` (`az bicep build`, вход в Azure не нужен) и для `prod` и `test` проверяет итоговый ARM-шаблон: хранилище без ключей и публичного доступа, ровно пять приватных контейнеров, soft delete 7 дней; неизменяемость `security-log` 30 суток без append writes и удаление через 45 суток (INV-083); удаление `restore-orphans/` через 30 суток (INV-081); PostgreSQL без публичного доступа и firewall rules, только вход Entra, PITR 14 суток; identity миграций в prod только у слота `staging`, в test — ни у одного ресурса; `Jobs__Enabled` и `Database__MigrateOnStart` по слотам и как настройки слота (INV-085); в настройках нет секретов, `Cursors__Key` и `Teams__WebhookUrl` — ссылки на Key Vault.

Проверки восстановления (`tools/iac/restore_checks.py`):

- identity восстановления есть только у production-слота, и её называет настройка слота `Restore__ManagedIdentityClientId`;
- у неё только Storage Blob Data Reader и только на `security-log`, `reports`, `exports` (INV-081);
- сервер базы по умолчанию — `psql-<unique>`. С заданным `databaseServerName` шаблон вычисляется ещё раз, и вслед за параметром на другой сервер переходят и сам сервер, и все строки подключения.

По тексту скриптов проверяются блокировка политики (`setup.sh`) и остановка слота после переключения (`deploy-app.sh`) — в ARM они не выражаются. Кроме того:

- `setup.sh` передаёт сервер шаблону и проверяет, что он существует;
- `drill.sh` меняет только `rg-sikkerheit-drill`, запускает команду только с `--drill` и удаляет группу (INV-081).

Выражения ARM вычисляет небольшой интерпретатор `tools/iac/arm_eval.py`; общие помощники проверок — `iac_common.py`. Значение, известное только при развёртывании, или неподдерживаемая функция дают FAIL («cannot evaluate»), а не догадку. `--self-test` проверяет, что каждая проверка падает на намеренно испорченной копии шаблона; `--template <arm.json>` проверяет готовый шаблон. `deploy.yml` запускает проверку перед развёртыванием, CI — на каждое изменение.

## Офлайн-тесты скриптов

```bash
python3 -I -m unittest discover -s tools/iac/tests
```

Тесты запускают `drill.sh`, `setup.sh` и `deploy-app.sh test` в копии дерева; первыми в `PATH` стоят заглушки из `tools/iac/tests/stubs`: `az` пишет каждый вызов в журнал и отвечает JSON из правил сценария (сопоставление по аргументам; настоящий `jq`), `npm`, `dotnet`, `curl` и `sleep` ничего не делают. Azure, сеть и вход не нужны. Проверяется:

- `drill.sh`: в `rg-sikkerheit-prod` только чтения (`show`/`list`), нет назначений ролей; отказы `start` (прошлое учение не убрано, время вне окна PITR, нет identity восстановления) ничего не создают; `check` падает на отчёте, перенёсшем файлы; `cleanup` удаляет только группу с тегом `environment=drill`;
- `setup.sh`: первая установка (сервер создаёт Bicep), повтор с сервером из строки подключения приложения, `SIKKERHEIT_DATABASE_SERVER` (совпадает, единственный источник, расходится), сервера нет в группе, сбой `az` внутри `$(...)` — при любом отказе развёртывания не было;
- `deploy-app.sh test`: адрес базы берётся из строки подключения приложения, а не из `infra/.state`; доступ миграций снимается и после сбоя.

Новый сценарий — новый метод в `test_*.py`; правила `az` строит `rule(...)` из `script_harness.py`. CI запускает тесты в job `infra`.

## После установки

- Роли сотрудников: Entra admin center → Enterprise applications → «Sikkerheit Portal (prod)» → Users and groups.
- Conditional Access tenant компании требует MFA для «Sikkerheit Portal (prod)»; без MFA вход отклоняется (`signin=failed&reason=mfa_required`).
- Сводка Teams: поток Workflows «Post to a channel when a webhook request is received», адрес — секрет `teams-webhook` (`az keyvault secret set --vault-name <kv> --name teams-webhook --value <url>`), затем перезапуск приложения.
- Подтверждение издателя «Sikkerheit Graph Reader» (Microsoft AI Cloud Partner Program) до пилота.
- Подключение клиента: портал → клиент → «Lag samtykkelenke» → ссылка глобальному администратору клиента → «Kontroller tilkobling».

## Отступления от `06`

- Identity миграций — администратор Entra сервера PostgreSQL: при старте с `Database__MigrateOnStart` она создаёт роли managed identity приложения (в prod — обоих слотов) и включает их в группу `sikkerheit_app`. Так установка не требует SQL с машины вне VNet. В prod identity назначена только слоту `staging`, который работает лишь во время развёртывания; в test — приложению на время развёртывания.
- Служебная identity пишет журнал безопасности с ролью Storage Blob Data Contributor; запрет изменения и удаления записей даёт заблокированная политика неизменяемости контейнера.
- Шаг 5 восстановления (`06`): файлы без строк переносит в карантин identity слота (Storage Blob Data Contributor на всё хранилище) — identity восстановления только читает.
- Smoke-тесты не вызывают `createAgentChallenge`: API агента появится в P2.
