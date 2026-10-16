# Развёртывание Sikkerheit в Azure

Ресурсы — `bicep/main.bicep` (модули в `bicep/modules`), установка — `scripts/setup.sh`, выпуск версии — `scripts/deploy-app.sh` (с рабочей машины или из `.github/workflows/deploy.yml`), IaC-тест — `tools/iac/check_arm.py`. Требования к ресурсам — `development-package/06-azure-and-operations.md`.

## Что создаётся

| Ресурс | Настройка |
| --- | --- |
| Группа `rg-sikkerheit-<env>` | Norway East по умолчанию (`SIKKERHEIT_LOCATION=swedencentral`, если PostgreSQL в Norway East недоступен) |
| App Service, Linux, .NET 10 | prod — P0v3 со слотом `staging`, который работает только во время развёртывания; test — B1 без слота (у планов Basic слотов нет). Always On, health check `/health`, HTTPS only, VNet |
| PostgreSQL 17 Flexible Server B1ms | Только приватный доступ, только вход Entra (паролей нет), PITR 14 суток |
| Managed identity `id-sikkerheit-<env>-migrations` | Администратор Entra сервера и владелец схемы. В prod назначена только слоту `staging`; в test шаблон её не назначает никому, `deploy-app.sh` даёт её приложению только на время развёртывания |
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

1. Группу ресурсов и первый проход Bicep.
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

## Проверка IaC

```bash
python3 -I tools/iac/check_arm.py
```

Скрипт собирает `main.bicep` (`az bicep build`, вход в Azure не нужен) и для `prod` и `test` проверяет итоговый ARM-шаблон: хранилище без ключей и публичного доступа, ровно пять приватных контейнеров, soft delete 7 дней; неизменяемость `security-log` 30 суток без append writes и удаление через 45 суток (INV-083); удаление `restore-orphans/` через 30 суток (INV-081); PostgreSQL без публичного доступа и firewall rules, только вход Entra, PITR 14 суток; identity миграций в prod только у слота `staging`, в test — ни у одного ресурса; `Jobs__Enabled` и `Database__MigrateOnStart` по слотам и как настройки слота (INV-085); в настройках нет секретов, `Cursors__Key` и `Teams__WebhookUrl` — ссылки на Key Vault. Блокировку политики и остановку слота после переключения скрипт проверяет по тексту `setup.sh` и `deploy-app.sh`: в ARM они не выражаются.

Выражения ARM вычисляет небольшой интерпретатор `tools/iac/arm_eval.py`. Значение, известное только при развёртывании, или неподдерживаемая функция дают FAIL («cannot evaluate»), а не догадку. `--self-test` проверяет, что каждая проверка падает на намеренно испорченной копии шаблона; `--template <arm.json>` проверяет готовый шаблон. `deploy.yml` запускает проверку перед развёртыванием, CI — на каждое изменение.

## После установки

- Роли сотрудников: Entra admin center → Enterprise applications → «Sikkerheit Portal (prod)» → Users and groups.
- Conditional Access tenant компании требует MFA для «Sikkerheit Portal (prod)»; без MFA вход отклоняется (`signin=failed&reason=mfa_required`).
- Сводка Teams: поток Workflows «Post to a channel when a webhook request is received», адрес — секрет `teams-webhook` (`az keyvault secret set --vault-name <kv> --name teams-webhook --value <url>`), затем перезапуск приложения.
- Подтверждение издателя «Sikkerheit Graph Reader» (Microsoft AI Cloud Partner Program) до пилота.
- Подключение клиента: портал → клиент → «Lag samtykkelenke» → ссылка глобальному администратору клиента → «Kontroller tilkobling».

## Отступления от `06`

- Identity миграций — администратор Entra сервера PostgreSQL: при старте с `Database__MigrateOnStart` она создаёт роли managed identity приложения (в prod — обоих слотов) и включает их в группу `sikkerheit_app`. Так установка не требует SQL с машины вне VNet. В prod identity назначена только слоту `staging`, который работает лишь во время развёртывания; в test — приложению на время развёртывания.
- Служебная identity пишет журнал безопасности с ролью Storage Blob Data Contributor; запрет изменения и удаления записей даёт заблокированная политика неизменяемости контейнера.
- Smoke-тесты не вызывают `createAgentChallenge`: API агента появится в P2.
