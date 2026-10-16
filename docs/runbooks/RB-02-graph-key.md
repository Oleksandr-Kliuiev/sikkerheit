# RB-02. Ключ приложения Graph

## Назначение

Сертификат `graph-reader` в Key Vault (RSA-HSM 3072, неэкспортируемый, 12 месяцев) — единственный credential приложения «Sikkerheit Graph Reader»: им сервис подписывает client assertion для токенов всех подключённых tenant (`04`, «Ключ приложения»). Runbook описывает плановую ротацию (А), разбор сбоя подписи (Б), проверку подписей вне запуска сбора (В) и аварийный отзыв (Г). Повторный consent клиентов не нужен ни в одном случае: меняется только credential регистрации в tenant компании (`06`, «Резервное копирование и восстановление»).

## Владелец роли и этап

Security Owner (по умолчанию владелец), этап P1. Команды Azure выполняет Operations.

## Признак запуска

| Признак | Как обнаруживается сейчас | Раздел |
| --- | --- | --- |
| Срок сертификата меньше 30 дней | Письмо Key Vault контактам сертификатов за 30 дней (шаг А0); ежемесячная проверка (шаг А1) | А |
| `credential_error` у всех подключённых организаций | `alert-sikkerheit-prod-errors`, сводка Teams, «Feil i applikasjonens legitimasjon» в «Innsamlinger» (RB-01) | Б |
| Подпись ключом Graph вне запуска сбора, резкий рост числа подписей | Оповещения нет, и сервис пока не записывает `correlationId` подписи вместе с запуском (`04`): еженедельно запросы раздела В | В |
| Чужая identity подписывает ключом, подозрение на захват сервиса, Key Vault или регистрации приложения | Раздел В, RB-06 | Г |

## Предусловия и доступы

- `az login` в tenant компании; Contributor на `rg-sikkerheit-prod`.
- Роль Key Vault Certificates Officer на `<kv>` (`setup.sh` выдаёт её тому, кто запускал установку).
- Владелец регистрации «Sikkerheit Graph Reader» или Application Administrator в Entra.
- Чтение `log-sikkerheit-prod`: журнал Key Vault — таблица `AzureDiagnostics`.
- `<kv>`, `<site>`, `<graph-app-id>` — README, «Имена ресурсов». Плановая ротация — вне 01:00–05:00.

Идентификаторы, которые нужны в нескольких разделах:

```bash
az webapp identity show --resource-group rg-sikkerheit-prod --name <site> --query principalId -o tsv
```

```bash
az keyvault show --name <kv> --query id -o tsv
```

Первое — `<prod-principal-id>`, единственная identity с правом sign; второе — `<vault-id>`.

## А. Плановая ротация

А0. Контакты сертификатов: Key Vault присылает им письмо за 30 дней до конца срока (политика сертификата). `setup.sh` добавляет адрес оповещений `SIKKERHEIT_ALERT_EMAIL`; проверить, что он есть:

```bash
az keyvault certificate contact list --vault-name <kv> -o table
```

Если письма должен получать и Security Owner, добавить его адрес (команда отказывает, если адрес уже есть):

```bash
az keyvault certificate contact add --vault-name <kv> --email [ЗАПОЛНИТЬ: почта Security Owner]
```

А1. Срок и отпечаток текущей версии (раз в месяц и перед ротацией):

```bash
az keyvault certificate show --vault-name <kv> --name graph-reader --query "{expires:attributes.expires, enabled:attributes.enabled, thumbprint:x509ThumbprintHex, kid:kid}" -o table
```

Начинать ротацию не позже чем за 30 дней до `expires`. Записать `thumbprint` — это отпечаток старого сертификата.

А2. Файл `graph-reader-policy.json` — та же политика, что в `infra/scripts/setup.sh` (шаг 4/7):

```json
{
  "issuerParameters": { "name": "Self" },
  "keyProperties": { "exportable": false, "keyType": "RSA-HSM", "keySize": 3072, "reuseKey": false },
  "secretProperties": { "contentType": "application/x-pem-file" },
  "x509CertificateProperties": { "subject": "CN=Sikkerheit Graph Reader", "validityInMonths": 12, "keyUsage": ["digitalSignature"] },
  "lifetimeActions": [ { "trigger": { "daysBeforeExpiry": 30 }, "action": { "actionType": "EmailContacts" } } ]
}
```

Шаги А3–А6 выполнить подряд, за несколько минут: сервис перечитывает текущую версию сертификата раз в 6 часов, и если возьмёт новую до её загрузки в регистрацию, сбор получит `credential_error`.

А3. Новая версия сертификата с новым ключом:

```bash
az keyvault certificate create --vault-name <kv> --name graph-reader --policy @graph-reader-policy.json
```

А4. Публичная часть новой версии:

```bash
az keyvault certificate download --vault-name <kv> --name graph-reader --file graph-reader-new.pem --encoding PEM
```

А5. Добавить её в регистрацию, не трогая старую. Без `--append` команда удаляет все прежние credentials — это аварийный отзыв, а не ротация:

```bash
az ad app credential reset --id <graph-app-id> --cert @graph-reader-new.pem --append
```

А6. Через 5 минут перезапустить сервис, чтобы он сразу взял новую версию:

```bash
az webapp restart --resource-group rg-sikkerheit-prod --name <site>
```

А7. Проверить: в одной организации «Samle inn nå» → «Fullført» или «Delvis»; запрос В1 показывает подписи production-identity с результатом `OK`.

А8. После следующей ночи, когда у всех организаций «Tilkoblet» обновилась «Siste innsamling» и нет `credential_error`, удалить старый сертификат из регистрации. Старый `keyId` — строка с отпечатком из А1:

```bash
az ad app credential list --id <graph-app-id> --cert --query "[].{keyId:keyId, thumbprint:customKeyIdentifier, end:endDateTime}" -o table
```

```bash
az ad app credential delete --id <graph-app-id> --key-id <old-key-id> --cert
```

А9. Отключить старую версию в Key Vault (`<old-version>` — последний сегмент `id` версии с отпечатком из А1; то, что вместе с сертификатом отключается его ключ, подтвердить в SP-02):

```bash
az keyvault certificate list-versions --vault-name <kv> --name graph-reader --query "[].{id:id, thumbprint:x509ThumbprintHex, enabled:attributes.enabled}" -o table
```

```bash
az keyvault certificate set-attributes --vault-name <kv> --name graph-reader --version <old-version> --enabled false
```

Удалить локальный `graph-reader-new.pem` (в нём только публичный сертификат).

## Б. Сбой подписи: `credential_error` у всех организаций

Б1. Срок не истёк, сертификат включён — команда А1.

Б2. Отпечаток текущей версии есть в регистрации — команда списка из А8.

Б3. Права production-identity на ключ и сертификат:

```bash
az role assignment list --assignee-object-id <prod-principal-id> --scope <vault-id>/keys/graph-reader --query "[].roleDefinitionName" -o tsv
```

```bash
az role assignment list --assignee-object-id <prod-principal-id> --scope <vault-id>/certificates/graph-reader --query "[].roleDefinitionName" -o tsv
```

Ожидается `Key Vault Crypto User` и `Key Vault Certificate User`.

Б4. Результаты обращений сервиса к Key Vault (Log Analytics → «Logs»):

```kusto
AzureDiagnostics
| where TimeGenerated > ago(1d)
| where ResourceProvider == "MICROSOFT.KEYVAULT" and Category == "AuditEvent"
| where OperationName in ("KeySign", "CertificateGet")
| summarize calls = count(), last = max(TimeGenerated) by OperationName, ResultSignature
```

Б5. Исправить по найденному:

- срок истёк или сертификат отключён — ротация А2–А7 сразу, старый сертификат удаляется после первого успешного сбора;
- отпечатка нет в регистрации — А4–А6;
- нет роли — вернуть ту, которой нет (команды те же, что в `setup.sh`):

  ```bash
  az role assignment create --assignee-object-id <prod-principal-id> --assignee-principal-type ServicePrincipal --role "Key Vault Crypto User" --scope <vault-id>/keys/graph-reader
  ```

  ```bash
  az role assignment create --assignee-object-id <prod-principal-id> --assignee-principal-type ServicePrincipal --role "Key Vault Certificate User" --scope <vault-id>/certificates/graph-reader
  ```

- `KeySign` с отказом при наличии ролей — подождать до 10 минут распространения прав, проверить доступность Key Vault (Azure Service Health).

Затем А6 и проверочный сбор (RB-01, шаг 5).

## В. Подпись вне запуска сбора, рост числа подписей

Сервис держит токен tenant около часа, поэтому подписей в сутки — примерно по одной на подключённую организацию плюс ручные «Samle inn nå» и «Kontroller tilkobling». Сбор идёт в «Innsamlingstidspunkt (lokal time)» организации (по умолчанию 03:00) с задержкой до 30 минут.

В1. Кто и сколько подписывает (Log Analytics → «Logs»; еженедельно и при любом подозрении):

```kusto
AzureDiagnostics
| where TimeGenerated > ago(7d)
| where ResourceProvider == "MICROSOFT.KEYVAULT" and Category == "AuditEvent" and OperationName == "KeySign"
| where tostring(column_ifexists("id_s", "")) has "/keys/graph-reader/"
| extend caller = tostring(column_ifexists("identity_claim_oid_g", ""))
| summarize signs = count() by day = bin(TimeGenerated, 1d), caller, CallerIPAddress, ResultSignature
| order by day desc
```

Ожидается только `caller` = `<prod-principal-id>`. Любой другой `caller` — сразу раздел Г и RB-06. Число подписей за сутки вдвое больше обычного без объяснения (новые клиенты, ротация, повторы после сбоя) — разбор по В2. Столбцы `id_s` и `identity_claim_oid_g` — допущение, сверить на первых данных.

В2. Подписи вне ночного окна без действий сотрудников:

```kusto
let signs = AzureDiagnostics
    | where TimeGenerated > ago(7d)
    | where ResourceProvider == "MICROSOFT.KEYVAULT" and Category == "AuditEvent" and OperationName == "KeySign"
    | where tostring(column_ifexists("id_s", "")) has "/keys/graph-reader/"
    | summarize signs = count() by hour = bin(TimeGenerated, 1h);
let staff = AppRequests
    | where TimeGenerated > ago(7d)
    | where Name startswith "POST" and (Name contains "collection-runs" or Name contains "m365-connection")
    | summarize staffRequests = count() by hour = bin(TimeGenerated, 1h);
signs
| join kind=leftouter staff on hour
| extend osloHour = datetime_part("hour", datetime_utc_to_local(hour, "Europe/Oslo"))
| where isnull(staffRequests) and not(osloHour between (1 .. 5))
| project hour, osloHour, signs
| order by hour desc
```

Каждую строку объяснить: другое «Innsamlingstidspunkt» организации, догоняющий сбор после перезапуска или простоя, ротация. Необъяснённая подпись — раздел Г и RB-06.

## Г. Аварийный отзыв

Когда: чужая identity в В1, необъяснённые подписи, подозрение на захват сервиса, production-identity, Key Vault или регистрации приложения. Записать время и открыть протокол RB-06.

Г1. Удалить все сертификаты из регистрации: новые токены перестают выдаваться во всех tenant сразу; уже выданные действуют до своего срока, обычно около часа (`04`). Повторить удаление для каждого `keyId`:

```bash
az ad app credential list --id <graph-app-id> --cert --query "[].{keyId:keyId, thumbprint:customKeyIdentifier}" -o table
```

```bash
az ad app credential delete --id <graph-app-id> --key-id <key-id> --cert
```

Г2. Проверить, что злоумышленник не добавил свои credentials: секретов и federated credentials у приложения быть не должно, владельцы — только ожидаемые [ЗАПОЛНИТЬ: кто владелец регистрации].

```bash
az ad app credential list --id <graph-app-id>
```

```bash
az ad app federated-credential list --id <graph-app-id>
```

```bash
az ad app owner list --id <graph-app-id> --query "[].userPrincipalName" -o tsv
```

Найденный секрет (`keyId` из первого списка) или federated credential (`id` из второго) удалить:

```bash
az ad app credential delete --id <graph-app-id> --key-id <key-id>
```

```bash
az ad app federated-credential delete --id <graph-app-id> --federated-credential-id <credential-id>
```

Г3. Пока причина не устранена, снять право sign с production-identity:

```bash
az role assignment delete --assignee-object-id <prod-principal-id> --role "Key Vault Crypto User" --scope <vault-id>/keys/graph-reader
```

Г4. Перезапустить сервис (А6), чтобы сбросить токены в его памяти. Сборы получают `credential_error` — это ожидаемо, записать в протокол.

Г5. Восстановление — после устранения причины по RB-06: вернуть роль (команда из Б5), выпустить новую версию сертификата (А2–А6), проверить сбор (А7). Клиентам повторный consent не нужен (`06`). Проверка этого раздела на тестовой регистрации — часть SP-02 (находка F05).

## Проверка результата

- А: в регистрации только новый отпечаток; сборы всех организаций проходят после ночи; подписывает только production-identity; старая версия отключена.
- Б: проверочный сбор «Fullført» или «Delvis», новых `credential_error` нет.
- В: каждая подпись за период объяснена.
- Г: до восстановления сборы падают с `credential_error`; после восстановления проходят без повторного consent.

## Запись в протокол

Шаблон — [README](README.md), раздел «Протокол». Записать раздел runbook, старый и новый отпечатки, время каждого шага, результаты запросов В1 и В2 (число подписей и вызывающие identity), удалённые credentials; для раздела Г — ссылку на протокол RB-06.

## Связанные документы

- [04-security-and-privacy.md](../../development-package/04-security-and-privacy.md) — «Ключ приложения», «Права Graph».
- [06-azure-and-operations.md](../../development-package/06-azure-and-operations.md) — «Ресурсы», «Наблюдаемость и оповещения».
- [infra/README.md](../../infra/README.md) и `infra/scripts/setup.sh` — создание сертификата и прав.
- [RB-01](RB-01-m365-connection-failure.md), [RB-06](RB-06-security-incident.md).
