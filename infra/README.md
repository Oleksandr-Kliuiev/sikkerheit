# Развёртывание Sikkerheit в Azure

Ресурсы — `bicep/main.bicep` (модули в `bicep/modules`), установка — `scripts/setup.sh`, выпуск версии — `scripts/deploy-app.sh`. Требования к ресурсам — `development-package/06-azure-and-operations.md`.

## Что создаётся

| Ресурс | Настройка |
| --- | --- |
| Группа `rg-sikkerheit-<env>` | Norway East по умолчанию (`SIKKERHEIT_LOCATION=swedencentral`, если PostgreSQL в Norway East недоступен) |
| App Service P0v3 (prod) или B1 (test), Linux, .NET 10 | Always On, health check `/health`, HTTPS only, VNet, слот `staging` |
| PostgreSQL 17 Flexible Server B1ms | Только приватный доступ, только вход Entra (паролей нет), PITR 14 суток |
| Managed identity `id-sikkerheit-<env>-migrations` | Администратор Entra сервера и владелец схемы; назначена только слоту `staging` |
| Storage (ZRS) | Без ключей доступа, контейнеры `reports`, `exports`, `agent-releases`, `dataprotection`, `security-log` (неизменяемость 30 суток, удаление через 45) |
| Key Vault Premium | RBAC, purge protection; ключ Data Protection (RSA-HSM 3072), сертификат Graph (RSA-HSM 3072, неэкспортируемый), секреты `cursor-key`, `teams-webhook` |
| Log Analytics, Application Insights | 90 дней, дневной лимит; оповещения на почту: 5xx, health check, ошибки в журнале |
| Бюджет | 200 USD в месяц, письма на 80% и 100% |
| Приложения Entra | «Sikkerheit Portal (<env>)» — вход сотрудников, роли Admin/Technician/Reader, без секретов (federated credential от managed identity слотов); «Sikkerheit Graph Reader» — multi-tenant, только чтение, сертификат из Key Vault |

Ориентир стоимости production — около 110–125 USD в месяц (`06`, «Модель расходов»).

## Первая установка

Нужны права Owner на подписку и Application Administrator (или Global Administrator) в tenant компании. Вход — в своём терминале:

```bash
az login
```

```bash
SIKKERHEIT_ALERT_EMAIL=drift@firma.no infra/scripts/setup.sh prod
```

Скрипт идемпотентен и выполняет:

1. Группу ресурсов и первый проход Bicep.
2. Регистрацию «Sikkerheit Portal»: redirect URI обоих слотов, app roles, собственный API со scope `access_as_user` и токенами v1 (в них есть `amr`), назначение ролей только через Enterprise application, federated credentials слотов, роль Admin запустившему скрипт.
3. Регистрацию «Sikkerheit Graph Reader»: multi-tenant, application permissions только на чтение (`Organization.Read.All`, `User.Read.All`, `UserAuthenticationMethod.Read.All`, `RoleManagement.Read.Directory`, `GroupMember.Read.All`, `Policy.Read.All`), redirect URI страницы возврата consent.
4. Сертификат Graph в Key Vault, его публичную часть — в регистрацию; право sign — только production-слоту; секрет `cursor-key`; `teams-webhook`, если задан `SIKKERHEIT_TEAMS_WEBHOOK`.
5. Блокировку неизменяемости журнала безопасности, если `SIKKERHEIT_LOCK_SECURITY_LOG=yes` (отменить нельзя; сделать до пилота).
6. Второй проход Bicep с идентификаторами приложений.

Затем выпуск кода:

```bash
infra/scripts/deploy-app.sh prod
```

Сборка портала и сервиса → слот `staging` (миграции при старте под identity миграций) → smoke-тесты (health, страница портала, 401 API, переход на вход Entra, CSP) → переключение слотов → остановка `staging`.

## После установки

- Роли сотрудников: Entra admin center → Enterprise applications → «Sikkerheit Portal (prod)» → Users and groups.
- Conditional Access tenant компании требует MFA для «Sikkerheit Portal (prod)»; без MFA вход отклоняется (`signin=failed&reason=mfa_required`).
- Сводка Teams: поток Workflows «Post to a channel when a webhook request is received», адрес — секрет `teams-webhook` (`az keyvault secret set --vault-name <kv> --name teams-webhook --value <url>`), затем перезапуск приложения.
- Подтверждение издателя «Sikkerheit Graph Reader» (Microsoft AI Cloud Partner Program) до пилота.
- Подключение клиента: портал → клиент → «Lag samtykkelenke» → ссылка глобальному администратору клиента → «Kontroller tilkobling».

## Отступления от `06`

- Identity миграций — администратор Entra сервера PostgreSQL: при старте слота `staging` она создаёт роли managed identity обоих слотов и включает их в группу `sikkerheit_app`. Так установка не требует SQL с машины вне VNet. Identity назначена только слоту `staging`, который работает лишь во время развёртывания.
- Служебная identity пишет журнал безопасности с ролью Storage Blob Data Contributor; запрет изменения и удаления записей даёт заблокированная политика неизменяемости контейнера.
- Окружение test на плане B1 без слота пока не автоматизировано: `deploy-app.sh` рассчитан на слот `staging`.
