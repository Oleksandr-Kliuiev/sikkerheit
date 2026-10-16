# RB-14. Бюджет Azure и дневной лимит журналов

## Назначение

Удержать расходы Azure в ориентире NFR-09 — production до 200 USD в месяц, test до 50 USD; расчёт P1 — около 110–125 USD (`06`, «Модель расходов») — и не потерять наблюдаемость, когда Log Analytics достигает дневного лимита приёма (production 2 ГБ, test 1 ГБ). После лимита данные до сброса не принимаются, и оповещение по журналу `alert-sikkerheit-prod-errors` молчит.

## Владелец роли и этап

Product Owner принимает решения о расходах и лимитах; Operations разбирает причину и выполняет команды. Этап P1.

## Признак запуска

- Письмо бюджета `budget-sikkerheit-prod`: фактические расходы месяца достигли 80% или 100% от 200 USD. Бюджет только уведомляет, Azure ничего не останавливает.
- Дневной лимит Log Analytics достигнут. Оповещения нет: в журнале сервиса пропали записи за последние часы, `dataIngestionStatus` рабочей области — `OverQuota` (шаг 5). Проверять при подозрении и раз в неделю.
- Счёт за месяц выше ориентира `06`.
- У test бюджет 50 USD (`monthlyBudget` в `main.bicep` по умолчанию зависит от окружения): письмо test на 80% — уже 40 USD при расчёте около 45.

## Предусловия и доступы

- `az login`; Cost Management Reader (или выше) на подписке; Contributor на `rg-sikkerheit-prod` для изменения лимита.
- Чтение `log-sikkerheit-prod` (Log Analytics → «Logs»).

## Шаги: бюджет

1. **Текущие расходы** — Azure portal → Cost Management → Cost analysis, область `rg-sikkerheit-prod`, группировка по ресурсу и по службе; сравнить с таблицей `06`, «Модель расходов». Состояние бюджета (группа команд `consumption` в CLI — preview):

   ```bash
   az consumption budget show --budget-name budget-sikkerheit-prod --resource-group rg-sikkerheit-prod
   ```

2. **Забытые ресурсы** — частая причина:
   - серверы PostgreSQL, оставшиеся после RB-05; остановленный сервер Azure сам запускает через 7 суток:

     ```bash
     az postgres flexible-server list --resource-group rg-sikkerheit-prod --query "[].{name:name, state:state, sku:sku.name}" -o table
     ```

   - группы учебного восстановления (`rg-sikkerheit-drill`) и прочие группы проекта:

     ```bash
     az group list --query "[?starts_with(name, 'rg-sikkerheit')].{name:name, location:location}" -o table
     ```

   - уровень плана App Service или SKU PostgreSQL изменён вручную: по `06` — P0v3 и B1ms, B2s — только по итогам AT-17.
3. **Рост по службам**: Log Analytics — шаги 5–6; Key Vault — число операций (резкий рост подписей — RB-02, раздел В); Storage — объём экспорта и отчётов.
4. **Решение Product Owner**: принять (записать причину), устранить причину или пересмотреть ориентир. Бюджет и лимит меняются через Bicep, иначе следующее развёртывание вернёт прежние значения: `monthlyBudget` и `dailyCapGb` модуля `monitoring` в `main.bicep` (`setup.sh` передаёт параметры без файла `main.prod.bicepparam`). Перевод production на план B2 без слота — вариант `06`, «Модель расходов».

## Шаги: дневной лимит журналов

5. **Состояние приёма**: `dataIngestionStatus` (`RespectQuota` — норма, `OverQuota` — лимит достигнут), `dailyQuotaGb`, `quotaNextResetTime`:

   ```bash
   az monitor log-analytics workspace show --resource-group rg-sikkerheit-prod --name log-sikkerheit-prod --query workspaceCapping -o json
   ```

   Срабатывание лимита в журнале операций рабочей области (запрос по документации Microsoft; сверить в SP-02):

   ```kusto
   _LogOperation
   | where TimeGenerated > ago(7d)
   | where Category =~ "Ingestion" and Detail has "OverQuota"
   | project TimeGenerated, Operation, Detail
   ```

6. **Что занимает объём**:

   ```kusto
   Usage
   | where TimeGenerated > ago(7d)
   | where IsBillable == true
   | summarize GB = round(sum(Quantity) / 1024, 2) by day = bin(TimeGenerated, 1d), DataType
   | order by day desc, GB desc
   ```

   Если больше всего — записи сервиса, то какие:

   ```kusto
   AppTraces
   | where TimeGenerated > ago(1d)
   | summarize records = count(), MB = round(sum(_BilledSize) / 1048576, 1) by SeverityLevel, head = substring(Message, 0, 60)
   | top 20 by MB
   ```

   Всплеск ошибок или отказов входа может быть атакой — RB-06; массовые ошибки заданий — RB-04.
7. **Пока лимит действует**, оповещения по журналу не работают: до сброса (`quotaNextResetTime`) вручную проверять `https://<prod-host>/health`, «Kunder» → «Siste innsamling» и сводку Teams.
8. **Временное повышение лимита** — только по решению Product Owner; следующее развёртывание Bicep вернёт 2 ГБ:

   ```bash
   az monitor log-analytics workspace update --resource-group rg-sikkerheit-prod --workspace-name log-sikkerheit-prod --quota 3
   ```

   Постоянное изменение — значение `dailyCapGb` в `main.bicep` (задача разработчику).

## Проверка результата

- Причина роста расходов найдена и записана; забытые ресурсы удалены или их сохранение утверждено; прогноз месяца в ориентире, или ориентир пересмотрен решением Product Owner.
- `dataIngestionStatus` — `RespectQuota`, записи сервиса снова поступают; источник объёма устранён или лимит изменён через Bicep.

## Запись в протокол

Шаблон — [README](README.md), раздел «Протокол». Записать письмо бюджета или признак лимита, расходы по службам, найденную причину, удалённые ресурсы, решение Product Owner, изменения лимита (временное значение и когда его вернёт Bicep).

## Связанные документы

- [06-azure-and-operations.md](../../development-package/06-azure-and-operations.md) — «Модель расходов», «Наблюдаемость и оповещения».
- [01-product-and-scope.md](../../development-package/01-product-and-scope.md) — NFR-09.
- [infra/README.md](../../infra/README.md); бюджет — `infra/bicep/modules/alerts.bicep`, лимит — `infra/bicep/modules/monitoring.bicep`.
- [RB-02](RB-02-graph-key.md), [RB-04](RB-04-jobs-and-scheduler.md), [RB-05](RB-05-database-restore.md), [RB-06](RB-06-security-incident.md).
