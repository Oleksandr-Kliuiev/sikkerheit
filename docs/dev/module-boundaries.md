# Границы модулей сервиса

Правило `02`, «Структура репозитория»: модуль не обращается к таблицам другого модуля напрямую, только через его интерфейс. Модули — папки `src/Sikkerheit.Host` (`docs/dev/README.md`, «Отличия от структуры `02`»).

## Как проверяется

`tests/Sikkerheit.UnitTests/Architecture/ModuleBoundaryTests.cs` разбирает исходники сервиса синтаксическими деревьями Roslyn и находит обращения к таблицам трёх видов:

- DbSet контекста: `scope.Db.Findings`, `all.Db.Organizations`, поле `db` автомата проблем; `Set<T>()` и `Entries<T>()`;
- SQL в строковых литералах и интерполированных строках: таблица после `from`, `join`, `update`, `into`, `table`;
- литеральные списки имён таблиц для динамического SQL (`["audit_event", …]`, `[("organization", "id"), …]`).

Обращение модуля к таблице, у которой другой владелец, — нарушение. Нарушения, найденные при вводе теста, перечислены в `Known` (модуль → таблица : файл). Новое нарушение роняет тест с подсказкой, через интерфейс какого модуля идти; устранённое тоже роняет тест, пока его не уберут из `Known`, — список только сокращается. Ещё два теста проверяют, что у каждой таблицы миграций есть владелец и что сканер видит все три вида обращений (иначе правило ничего бы не доказывало).

Сканер не видит SQL, собранный не из литералов, обращения через функции и представления PostgreSQL и передачу сущностей между модулями — это не нарушения по определению теста, но и не разрешение.

Модуль `Data` (схема, `DbScopes`, контекст EF) и `Program.cs` (композиция) не принадлежат модулям и из проверки исключены.

## Владельцы таблиц

| Модуль | Таблицы |
| --- | --- |
| `Access` | `staff_user`, `staff_session`, `staff_login` |
| `Organizations` | `organization`, `policy_revision` |
| `M365` | `tenant_connection`, `collection_run` |
| `Assessment` | `subject`, `observation`, `assessment`, `finding`, `finding_event`, `risk_decision` |
| `Reports` | `report`, `teams_digest` |
| `Exports` | `organization_export` |
| `Jobs` | `job`, `organization_tombstone` |
| `Operations` | `audit_event`, `idempotency_record` |

`job` раньше меняли два модуля: очередь (`JobQueue`) лежала в `Operations`, исполнитель — в `Jobs`. 2026-10-16 `JobQueue` перенесена в `Jobs`, и у таблицы один владелец. Код восстановления (`Operations/RestoreReplay.cs`) с самого начала меняет данные других модулей только через их интерфейсы: `OrganizationLifecycle`, `TenantConnections`, `OrganizationDeletion`, `JobQueue`, `TeamsDigestJob.MarkSentAsync`, `ReportService.KnownFileKeysAsync`, `OrganizationExports.KnownFileKeysAsync`.

## Нарушения на 2026-10-16

67 записей `Known`. По смыслу они сводятся к восьми группам.

| Группа | Где | Записей |
| --- | --- | --- |
| 1. Организация и текущая политика читаются напрямую | `M365CollectionJob`, `RecalculatePolicyJob`, `SweepJobs`, `Scheduler`, `ReportService`, `TeamsDigest`, `Coverage`, `ReportBuilder`, `FindingEndpoints` | 12 |
| 2. Состояние подключения и запуски M365 читаются напрямую | `OrganizationEndpoints` (список, создание строки подключения), `RecalculatePolicyJob` (блокировка `tenant_connection`), `M365Evaluator` (соединение с `collection_run`), `Coverage`, `ReportBuilder`, `TeamsDigest`, `Scheduler` | 8 |
| 3. Проблемы, события и субъекты меняются вне `Assessment` | `SweepJobs` (свежесть и истечение решений), `ConnectionEndpoints.RetireTenantSubjectsAsync` (смена tenant) | 4 |
| 4. Чтение проблем, оценок и решений для отчётов и сводок | `ReportBuilder`, `Coverage`, `TeamsDigest`, счётчики в `OrganizationEndpoints` | 10 |
| 5. Сотрудники читаются вне `Access` | `FindingEndpoints.CanBeAssignedAsync`, имена в `ReportBuilder` | 2 |
| 6. Уборка платформенных строк чужих модулей | `Scheduler.PurgePlatformAsync`: `staff_session`, `staff_login`, `teams_digest` | 3 |
| 7. Аудит и экспорт читаются вне своих модулей | журнал аудита в `OrganizationEndpoints.ListAudit`, проверка экспорта после отключения в `OrganizationEndpoints` | 2 |
| 8. Сквозные операции над всеми данными организации | удаление (`OrganizationDeletion`), сроки хранения (`RetentionPurgeJob`), экспорт (`OrganizationExports.Tables`) | 26 |

Точный перечень — массив `Known` в тесте.

## Как устранить, не ломая тесты

Каждый шаг отдельным изменением: перенос кода или новый метод модуля-владельца, вызов вместо прямого обращения, удаление строк из `Known`; модульные, интеграционные и контрактные тесты остаются зелёными на каждом шаге, потому что поведение не меняется.

1. **Перенести код к владельцу (механически).** `FreshnessSweepJob` и `ReviewExpiryJob` — из `Jobs/SweepJobs.cs` в `Assessment`: это логика проблем, `Jobs` только запускает задания. `RetireTenantSubjectsAsync` — в `Assessment` (`SubjectRetirement.RetireTenantAsync(scope, actorId, now)`), `ConnectionEndpoints` вызывает его. Закрывает группу 3.
2. **Интерфейс `Organizations` для чтения.** `OrganizationLifecycle.FindAsync(scope, forUpdate)` вместо `scope.Db.Organizations` и `select … from organization … for update` в заданиях; `Policies.CurrentAsync(scope)` и `Policies.InPeriodAsync(scope, start, end)` вместо `PolicyRevisions` и CTE `latest` в SQL. Запросы, которым политика нужна внутри SQL (`FindingEndpoints`, `Coverage`), получают конфигурацию параметром: её читают интерфейсом до запроса. Закрывает группу 1.
3. **Интерфейс `M365` для состояния.** `TenantConnections.LockAsync(scope)` — точка сериализации пересчёта политики со сбором (сейчас `RecalculatePolicyJob` блокирует строку сам); `TenantConnections.StatesAsync(all)` для списка организаций и планировщика; `CollectionRuns.ProjectionRunsAsync(scope)` для пересчёта; `TenantConnections.CreateAsync(scope)` для новой организации. Закрывает группу 2.
4. **Интерфейсы чтения `Assessment` для отчётов.** `FindingHistory.EventsAsync(scope, start, end)`, `FindingHistory.OpenAtAsync(scope, end)`, `RiskDecisions.InPeriodAsync`, `Assessments.LatestAsync(scope, at)` возвращают записи, которые сейчас собирают `ReportBuilder` и `Coverage`; `Findings.OpenCountsAsync(all)` — для сводки клиентов. `ReportBuilder` и `Coverage` строят снимок из этих записей. Это самая большая часть: шаг делается по одному запросу, сверяя снимок отчёта на фикстурах `ReportApiTests` и `CoverageTests` побайтно. Закрывает группу 4.
5. **Мелкие интерфейсы `Access`, `Operations`, `Exports`.** `StaffDirectory.CanBeAssignedAsync(scope, id, now)` и `StaffDirectory.NamesAsync(ids)`; `AuditLog.ListAsync(scope, cursor, size)`; `OrganizationExports.HasExportSinceAsync(scope, since)`. Закрывает группы 5 и 7.
6. **Уборка платформы у владельцев.** `StaffSessions.PurgeExpiredAsync(platform, now)`, `TeamsDigestJob.PurgeMarksAsync(platform, now)`; `Scheduler` вызывает их. Закрывает группу 6.
7. **Сквозные операции.** Каждый модуль-владелец даёт `DeleteOrganizationDataAsync(scope)`, `PurgeAsync(scope, cutoffs)` с числом удалённых строк и `ExportAsync(scope, writer)`; `OrganizationDeletion`, `RetentionPurgeJob` и `OrganizationExports` вызывают их в порядке внешних ключей (`Catalog.RetentionPurgeOrder` для сроков хранения). Порядок и полноту уже проверяют контрактные тесты INV-071 и тесты удаления и экспорта (AT-09). Если владелец решит оставить эти три операции сквозными намеренно — записать решение в `docs/reviews` и оставить в `Known` только их, с комментарием. Закрывает группу 8.

Шаги 1, 5 и 6 — по часу работы; шаги 2 и 3 — по полдня; шаги 4 и 7 — по дню с проверкой отчётов на фикстурах.
