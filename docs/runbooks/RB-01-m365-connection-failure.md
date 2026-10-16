# RB-01. Сбой подключения Microsoft 365

## Назначение

Вернуть сбор Microsoft 365 организации, когда запуск сбора завершился `failed` из-за подключения (`consent_missing`, `tenant_mismatch`, `credential_error`), когда модулю сбора не хватает прав или когда проверка подключения отвечает отказом. Подключение нового клиента и повторный consent при новых правах приложения — RB-03; запуски `run_timeout`, `temporary_error` и пропуски сбора у многих организаций — RB-04.

## Владелец роли и этап

Service Manager, этап P1. `credential_error` у всех подключённых организаций передаётся Security Owner (RB-02, раздел Б), `tenant_mismatch` — Security Owner для оценки (RB-06).

## Признак запуска

- Письмо `alert-sikkerheit-prod-errors`: в журнале сервиса запись уровня Error `Microsoft 365 collection of organization <id> failed: <failureCode> (RB-01)`.
- Сводка Teams в 07:30: неудачный сбор организации.
- Портал, вкладка «Oversikt», карточка «Innsamlinger»: запуск «Mislyktes» с причиной из таблицы.
- Карточка «Microsoft 365-tilkobling» → «Datakilder ved siste innsamling»: модуль «Mangler tillatelse» (запуск «Delvis»).
- «Kontroller tilkobling» отвечает «Samtykket er ikke gitt ennå, eller appen mangler tillatelser.» (422 `consent_not_granted`) или «Denne tenanten er allerede koblet til en annen kunde.» (409 `tenant_conflict`).

| `failureCode` | В портале | Причина (`05`, «Подключение M365 и сбор») |
| --- | --- | --- |
| `consent_missing` | «Samtykke mangler» | Токен не выдан: consent отозван или приложение удалено в tenant клиента |
| `tenant_mismatch` | «Feil tenant» | `/organization` вернул другой tenant |
| `credential_error` | «Feil i applikasjonens legitimasjon» | Сбой подписи Key Vault или сертификата приложения |

Запуск `failed` наблюдений не пишет: проблемы организации не закрываются и со временем становятся «Utdatert».

## Предусловия и доступы

- Роль Admin в «Sikkerheit Portal (prod)», вход с MFA.
- Контакт администратора клиента: [ЗАПОЛНИТЬ: где хранится — CRM или система заявок].
- Чтение `appi-sikkerheit-prod` (Azure portal → Application Insights → «Logs») для шага 3.

## Шаги

1. **Подключение** — `getTenantConnection`: «Kunder» → клиент → вкладка «Oversikt» → карточка «Microsoft 365-tilkobling». Записать статус («Tilkoblet», «Venter på samtykke», «Frakoblet»), «Tenant», «Tenant ID», «Siste innsamling».
2. **Запуски** — `listCollectionRuns`: карточка «Innsamlinger» на той же вкладке. Записать время первого неудачного запуска, «Utløser» и причину.
3. **Охват.** Сколько организаций затронуто и с какого времени (Application Insights → «Logs»):

   ```kusto
   traces
   | where timestamp > ago(7d)
   | where message has "Microsoft 365 collection of organization"
   | extend organizationId = coalesce(tostring(customDimensions.OrganizationId), extract(@"organization ([0-9a-f-]{36})", 1, message)),
            failureCode = coalesce(tostring(customDimensions.FailureCode), extract(@"failed: (\w+)", 1, message))
   | summarize runs = count(), first = min(timestamp), last = max(timestamp) by organizationId, failureCode, severityLevel
   | order by last desc
   ```

   Уровень Error — причины этого runbook, Warning — `cancelled`, `run_timeout`, `temporary_error` (RB-04). `credential_error` сразу у всех подключённых организаций — сбой ключа приложения: перейти к RB-02, раздел Б, этот runbook не продолжать. Ключи `customDimensions` — допущение: если они пусты, значения берутся из текста сообщения.
4. **Действие по причине.**
   - `consent_missing`. Спросить администратора клиента, удаляли ли приложение «Sikkerheit Graph Reader» или отзывали согласие. Клиент уходит — RB-07. Иначе — повторный consent для того же tenant по RB-03, раздел «Повторный consent»: подключение остаётся «Tilkoblet», ссылку открывает глобальный администратор клиента.
   - Модуль «Mangler tillatelse». Администратор клиента снял часть прав приложения — тот же повторный consent.
   - `tenant_mismatch`. Сразу отключить — `disconnectTenant`: «Koble fra», в диалоге снова «Koble fra». Сообщить Security Owner: сервис получил токен одного tenant, а Graph ответил данными другого (оценка — RB-06). Сверить tenant ID с администратором клиента и подключить заново по RB-03 с верным «Tenant-ID eller verifisert domene».
   - `credential_error` у одной организации при успешных остальных — повторить сбор (шаг 5); повторяется — RB-02, раздел Б.
   - 409 `tenant_conflict` на «Lag samtykkelenke» или «Kontroller tilkobling». Tenant уже подключён к другой организации портала: найти её в «Kunder» (столбец «Microsoft 365»), вместе с Service Manager решить, какая запись верна, лишнюю отключить «Koble fra».
   - 422 `consent_not_granted` на «Kontroller tilkobling». Consent ещё не выдан или выдан в другом tenant. Подождать 5–10 минут после consent и повторить; затем выяснить, в какой tenant входил администратор клиента. Ссылка действует 7 суток («Lenken gjelder til …»); истекла — «Lag samtykkelenke» заново.
5. **Проверочный сбор** — `requestCollection`: «Samle inn nå» → «Innsamlingen er satt i kø.». В «Innsamlinger» появляется строка «Manuell»; дождаться «Fullført» или «Delvis».

## Проверка результата

- Последний запуск «Fullført» или «Delvis» без «Mangler tillatelse»; «Siste innsamling» обновилась.
- Запрос шага 3 за последний час не показывает новых ошибок организации.
- Во вкладке «Problemer» проблемы организации снова свежие: отметка «Utdatert» уходит после сбора.
- Для `tenant_mismatch`: решение Security Owner записано, подключение к верному tenant проверено «Kontroller tilkobling».

## Запись в протокол

Шаблон — [README](README.md), раздел «Протокол». Записать организацию и tenant ID, `failureCode` и время первого сбоя, ответ клиента, кто и когда выдал consent, результат проверочного сбора; для `tenant_mismatch` — решение Security Owner и ссылку на протокол RB-06, если он открыт.

## Связанные документы

- [05-data-and-api.md](../../development-package/05-data-and-api.md) — «Подключение M365 и сбор», таблица кодов Problem.
- [04-security-and-privacy.md](../../development-package/04-security-and-privacy.md) — «Права Graph», «Подключение и отзыв».
- [06-azure-and-operations.md](../../development-package/06-azure-and-operations.md) — «Наблюдаемость и оповещения».
- [RB-02](RB-02-graph-key.md), [RB-03](RB-03-client-onboarding.md), [RB-04](RB-04-jobs-and-scheduler.md), [RB-06](RB-06-security-incident.md).
