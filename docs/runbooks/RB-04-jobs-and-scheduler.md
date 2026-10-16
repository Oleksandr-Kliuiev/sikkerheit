# RB-04. Сбой заданий и планировщика, tenant без сбора дольше 26 часов

## Назначение

Фоновые задания выполняет только production-слот (`Jobs__Enabled=true`): сбор Microsoft 365, отчёты, экспорт, удаление организаций, сроки хранения, пересчёты и сводка Teams (`02`, «Фоновые задания»). Ошибка задания повторяется через 1, 5, 15 и 60 минут, затем раз в час; после 10 попыток задание становится `failed`. Runbook находит причину, возвращает задания в работу и догоняет пропущенные сборы. Отказы подключения (`consent_missing`, `tenant_mismatch`, `credential_error`) — RB-01.

## Владелец роли и этап

Operations, этап P1. Повторный сбор и отчёты в портале выполняет Service Manager или Technician.

## Признак запуска

- `alert-sikkerheit-prod-errors`: `Job <id> of type <type> failed`, `Scheduler tick failed`, `Job runner iteration failed`, `Report <id> failed with …`, `Export <id> failed`. Каждая неудачная попытка пишет запись, поэтому письмо приходит раньше, чем задание станет `failed`.
- `alert-sikkerheit-prod-health` или `alert-sikkerheit-prod-5xx`: сервис не отвечает или отвечает ошибками.
- Tenant без завершённого сбора дольше 26 часов: порог `06` — больше 2% активных подключений, при 40 клиентах это уже одна организация. Оповещения нет: ежедневно смотреть «Kunder» → столбец «Siste innsamling» у организаций «Tilkoblet» (время последнего запуска «Fullført» или «Delvis»).
- Последний такт планировщика старше двух периодов (10 минут). Метрики нет; косвенно: за сутки у подключённых организаций нет запусков «Planlagt» в «Innsamlinger», сводка Teams не пришла в 07:30, в понедельник после 06:00 нет новых недельных отчётов.
- Отчёт «Mislyktes» во вкладке «Rapporter» («Oversettelse mangler» или «Feil ved generering»), «Eksporten mislyktes.» во вкладке «Innstillinger».
- Ограничивающая операция в портале отвечает «Tjenesten er midlertidig utilgjengelig. Prøv igjen.» (503) — раздел «Журнал безопасности недоступен». Тот же текст портал показывает при любой ошибке без кода Problem, поэтому причину сверить с журналом сервиса.

## Предусловия и доступы

- `az login`, Contributor на `rg-sikkerheit-prod`; чтение `appi-sikkerheit-prod`.
- Роль Admin или Technician в портале для повторного сбора и отчётов.
- `<site>`, `<storage>`, `<prod-host>` — README, «Имена ресурсов».

## Шаги

1. **Сервис работает.** Ожидается `Running`, а `https://<prod-host>/health` отвечает 200.

   ```bash
   az webapp show --resource-group rg-sikkerheit-prod --name <site> --query state -o tsv
   ```

   Не отвечает — журнал контейнера; сбой начался после выпуска — откат (README, «Откат версии»).

   ```bash
   az webapp log tail --resource-group rg-sikkerheit-prod --name <site>
   ```

2. **Задания включены** на production-слоте; ожидается `true`:

   ```bash
   az webapp config appsettings list --resource-group rg-sikkerheit-prod --name <site> --query "[?name=='Jobs__Enabled'].value" -o tsv
   ```

   `false` вне RB-05 — забытый режим обслуживания. Вернуть (приложение перезапустится):

   ```bash
   az webapp config appsettings set --resource-group rg-sikkerheit-prod --name <site> --slot-settings Jobs__Enabled=true
   ```

3. **Какие задания падают** (Application Insights → «Logs»). Ключ `customDimensions.Type` — допущение; если он пуст, тип берётся из текста:

   ```kusto
   traces
   | where timestamp > ago(24h) and severityLevel >= 3
   | extend jobType = coalesce(tostring(customDimensions.Type), extract(@"of type (\w+) failed", 1, message))
   | extend kind = iff(isnotempty(jobType), strcat("job: ", jobType), substring(message, 0, 60))
   | summarize errors = count(), first = min(timestamp), last = max(timestamp) by kind
   | order by last desc
   ```

   Текст исключений:

   ```kusto
   exceptions
   | where timestamp > ago(24h)
   | summarize count(), last = max(timestamp) by type, outerMessage
   | order by last desc
   ```

4. **Действие по типу задания.**

   | Задание | Действие |
   | --- | --- |
   | `m365_collect` | «Innsamlinger» организации: причина подключения — RB-01; «Tidsavbrudd» или «Midlertidig feil» — «Samle inn nå». Сбой сразу у многих организаций — Graph или Entra: Azure Service Health и шаг 6; ночной сбор повторится сам |
   | `report_generate`, `weekly_report` | «Rapporter» → «Uke» → «Lag rapport»: отчёт «Mislyktes» создаётся заново. «Oversettelse mangler» — нет текста на языке отчёта: Admin восполняет перевод (выпуск версии), затем «Lag rapport» |
   | `organization_export` | «Innstillinger» → «Lag eksport» заново |
   | `organization_delete` | Организация живёт дольше срока удаления — срочно. Чаще всего недоступен журнал безопасности (раздел ниже); после исправления задание повторяется само в течение часа |
   | `retention_purge` | Повторяется ежедневно; ошибка несколько дней подряд нарушает сроки хранения (`04`, «Сроки хранения») — разбор разработчиком |
   | `teams_digest` | Секрет `teams-webhook` и поток Workflows (`infra/README.md`, «После установки»); сводку за пропущенный день не повторять |
   | `recalculate_policy`, `freshness_sweep`, `review_expiry` | Создаются заново каждый час или с новой политикой; ошибка повторяется — разбор разработчиком |
   | `Scheduler tick failed`, `Job runner iteration failed` | Сбой базы или настроек: шаг 5; началось после выпуска — откат (README) |

5. **Перезапуск**, если исполнитель или планировщик не восстановились сами (по возможности вне 01:00–05:00). Lease занятых заданий истекают через 5 минут, задания захватываются заново.

   ```bash
   az webapp restart --resource-group rg-sikkerheit-prod --name <site>
   ```

6. **Ответы Graph 429** (сигнал `06` — рост вдвое за сутки): ограничитель запросов или лимиты Graph. Таблица `dependencies` с вызовами Graph — допущение, сверить на первых данных:

   ```kusto
   dependencies
   | where timestamp > ago(3d)
   | where target has "graph.microsoft.com"
   | summarize calls = count() by day = bin(timestamp, 1d), resultCode
   | order by day desc
   ```

7. **Tenant без сбора 26 часов.** Для каждой такой организации: «Oversikt» → «Innsamlinger» → причина → шаг 4; затем «Samle inn nå».

## Журнал безопасности недоступен

Ограничивающие действия («Deaktiver», «Planlegg sletting», «Avbryt sletting», «Koble fra», удаление организации заданием) сначала создают запись в контейнере `security-log`; без записи действие не выполняется, портал получает 503, задание повторяется (`04`, «Журнал безопасности»).

1. Причина — в журнале сервиса: `security log write failed: <статус хранилища>` (403 — права, 5xx — сбой хранилища).
2. Хранилище доступно: ожидается `available` и `Enabled`.

   ```bash
   az storage account show --resource-group rg-sikkerheit-prod --name <storage> --query "{status:statusOfPrimary, publicNetworkAccess:publicNetworkAccess, id:id}" -o json
   ```

3. Право записи production-identity (`<storage-id>` — `id` из шага 2, `<prod-principal-id>` — первая команда):

   ```bash
   az webapp identity show --resource-group rg-sikkerheit-prod --name <site> --query principalId -o tsv
   ```

   ```bash
   az role assignment list --assignee-object-id <prod-principal-id> --scope <storage-id> --query "[].roleDefinitionName" -o tsv
   ```

   Ожидается `Storage Blob Data Contributor`. Нет — вернуть:

   ```bash
   az role assignment create --assignee-object-id <prod-principal-id> --assignee-principal-type ServicePrincipal --role "Storage Blob Data Contributor" --scope <storage-id>
   ```

4. Политика контейнера: `Locked` и 30 суток (до пилота допустимо `Unlocked`):

   ```bash
   az storage container immutability-policy show --account-name <storage> --resource-group rg-sikkerheit-prod --container-name security-log --query "{state:state, days:immutabilityPeriodSinceCreationInDays}" -o table
   ```

5. После исправления сотрудник повторяет операцию в портале (операции идемпотентны), задания повторяются сами.

## Проверка результата

- Запрос шага 3 за последний час не показывает новых ошибок.
- У всех организаций «Tilkoblet» «Siste innsamling» моложе 26 часов.
- Сводка Teams пришла в 07:30 следующего дня; отчёты «Mislyktes» созданы заново и стали «Klar».
- Ограничивающие операции портала проходят без 503.

## Запись в протокол

Шаблон — [README](README.md), раздел «Протокол». Записать оповещение и время первой ошибки, типы заданий и организации, причину, действие (перезапуск, откат, права, повтор в портале), время восстановления и задания, которые остались `failed` и повторены вручную.

## Связанные документы

- [02-architecture-and-stack.md](../../development-package/02-architecture-and-stack.md) — «Фоновые задания».
- [05-data-and-api.md](../../development-package/05-data-and-api.md) — «Фоновые задания и планировщик», «Подключение M365 и сбор».
- [06-azure-and-operations.md](../../development-package/06-azure-and-operations.md) — «Наблюдаемость и оповещения».
- [04-security-and-privacy.md](../../development-package/04-security-and-privacy.md) — «Журнал безопасности».
- [RB-01](RB-01-m365-connection-failure.md), [RB-05](RB-05-database-restore.md).
