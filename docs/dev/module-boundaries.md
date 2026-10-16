# Границы модулей сервиса

Правило `02`, «Структура репозитория»: модуль не обращается к таблицам другого модуля напрямую, только через его интерфейс. Модули — папки `src/Sikkerheit.Host` (`docs/dev/README.md`, «Отличия от структуры `02`»).

## Как проверяется

`tests/Sikkerheit.UnitTests/Architecture/ModuleBoundaryTests.cs` разбирает исходники сервиса синтаксическими деревьями Roslyn и находит обращения к таблицам трёх видов:

- DbSet контекста: `scope.Db.Findings`, `all.Db.Organizations`, поле `db` автомата проблем; `Set<T>()` и `Entries<T>()`;
- SQL в строковых литералах и интерполированных строках: таблица после `from`, `join`, `update`, `into`, `table`;
- литеральные списки имён таблиц для динамического SQL (`["audit_event", …]`, `[("organization", "id"), …]`).

Обращение модуля к таблице, у которой другой владелец, — нарушение: тест падает с подсказкой, через интерфейс какого модуля идти. Исключение возможно, только если его принял владелец: запись в `Known` (модуль → таблица : файл) с причиной. Сейчас `Known` пуст. Запись, которой больше не соответствует ни одно обращение, тоже роняет тест.

Ещё два теста проверяют, что у каждой таблицы миграций есть владелец и что сканер видит все три вида обращений. Второй считает и обращения модулей к своим таблицам, поэтому не зависит от того, остались ли нарушения: без него правило ничего бы не доказывало.

Сканер не видит SQL, собранный не из литералов, обращения через функции и представления PostgreSQL и передачу сущностей между модулями. По определению теста это не нарушения, но и не разрешение. Интерфейсы возвращают сущности EF (`Organization`, `PolicyRevision`, `TenantConnection`, `CollectionRun`, `Report`) только для чтения; меняет их только модуль-владелец.

Модуль `Data` (схема, `DbScopes`, контекст EF) и `Program.cs` (композиция) не принадлежат модулям и из проверки исключены. В `Data` лежит и `OrganizationRows` — удаление и выгрузка всех строк организации из таблиц, которые называет модуль. Модуль передаёт только свои таблицы. Список чужих таблиц в модуле — нарушение вида «список таблиц».

## Владельцы таблиц

| Модуль | Таблицы |
| --- | --- |
| `Access` | `staff_user`, `staff_session`, `staff_login` |
| `Organizations` | `organization`, `policy_revision` |
| `M365` | `tenant_connection`, `collection_run` |
| `Assessment` | `subject`, `observation`, `assessment`, `finding`, `finding_event`, `risk_decision`, `windows_release`, `windows_release_month` |
| `Agents` | `enrollment_key`, `enrollment`, `device`, `device_presence`, `revoked_installation`, `scan_batch`, `scan_request`, `agent_challenge`, `agent_session` |
| `Reports` | `report`, `teams_digest` |
| `Exports` | `organization_export` |
| `Jobs` | `job`, `organization_tombstone` |
| `Operations` | `audit_event`, `idempotency_record` |

`job` раньше меняли два модуля: очередь (`JobQueue`) лежала в `Operations`, исполнитель — в `Jobs`. 2026-10-16 `JobQueue` перенесена в `Jobs`, и у таблицы остался один владелец. Код восстановления (`Operations/RestoreReplay.cs`) с самого начала меняет данные других модулей только через их интерфейсы: `OrganizationLifecycle`, `TenantConnections`, `OrganizationDeletion`, `JobQueue`, `TeamsDigestJob.MarkSentAsync`, `ReportService.KnownFileKeysAsync`, `OrganizationExports.KnownFileKeysAsync`.

## Интерфейсы модулей

Что модуль даёт другим. Методы принимают область (`DbScope`) вызывающего; методы с параметром `all` — только для компонентов с областью чтения всех клиентов (`02` «Разделение клиентов»).

| Модуль | Интерфейс | Кто вызывает |
| --- | --- | --- |
| `Organizations` | `OrganizationLifecycle.FindAsync(scope, forUpdate)` — организация области, с блокировкой строки по требованию; `OrganizationDirectory.ListAsync(all)` — все организации по имени в порядке сортировки базы | задания сбора, пересчёта, отчётов, экспорта, удаления и сроков хранения; планировщик, сводка Teams |
| | `Policies.CurrentAsync`, `CurrentByOrganizationAsync`, `AtAsync`, `VersionsInPeriodAsync` — ревизии политики | сбор, пересчёт, проверка свежести, `FindingEndpoints`, планировщик, покрытие, отчёт |
| `M365` | `TenantConnections.Create`, `LockAsync`, `FindAsync`, `StatesAsync`, `ActiveTenantAtAsync` | создание организации, пересчёт (точка сериализации со сбором), отчёт, покрытие, список организаций, планировщик |
| | `CollectionRuns.ProjectionRunsAsync`, `LastCollectedBeforeAsync`, `LastFinishedBeforeAsync`, `CountsAsync`, `FailedAsync` | пересчёт политики, отчёт, сводка Teams |
| `Assessment` | `FindingHistory.StateEventsAsync`, `OpenAtAsync`, `NewCriticalAsync`, `OpenCountsAsync`; `RiskDecisions.LatestBeforeAsync`; `Assessments.LatestAsync`, `DeterminedAsync`; `Subjects.InPeriodAsync` | отчёт, покрытие, сводка Teams, список организаций |
| | `SubjectRetirement.RetireTenantAsync` | смена tenant в `ConnectionEndpoints` |
| | `DeviceSubjects.EnsureAsync`, `RenameAsync`, `SeenAsync`, `RetireAsync` — субъекты устройства и его томов; `WindowsEvaluator.IngestAsync`, `RecalculateAsync` — оценка пакета и пересчёт; `ReleaseCatalogStore.ViewAsync`, `RecentlyVerifiedAsync`; `AssessmentData.ObservedBatchesAsync` — пакеты, на которые ссылаются наблюдения | `Agents` (регистрация, check-in, отзыв, приём пакета), `RecalculatePolicyJob`, планировщик |
| `Agents` | `Devices.FindAsync`, `LockAsync` (блокировка строки устройства — точка сериализации пакетов и заданий), `ActiveAsync`, `UnseenSinceAsync`, `ProjectionBatchAsync`, `ProjectionBatchesAsync`, `BatchPolicyVersionAsync`, `PresenceDaysAsync`, `RecoverIdentitiesAsync` | `Assessment` (пакет, пересчёт, `patch_level_sweep`, `freshness_sweep`), покрытие, задание истечения запросов |
| | `AgentData.DeleteOrganizationDataAsync`, `ExportAsync`, `PurgeBatchesAsync`, `PurgeRequestsAsync`, `PurgePresenceAsync`, `PurgeDevicesAsync`, `PurgeInstallationsAsync`, `PurgeCredentialsAsync`, `PurgePlatformAsync`; `AgentReplay.RevokeDeviceAsync`, `RevokeKeyAsync` | удаление организации, `RetentionPurgeJob`, экспорт, планировщик, `RestoreReplay` |
| `Access` | `StaffDirectory.CanBeAssignedAsync`, `NamesAsync` | назначение проблемы, решения в отчёте |
| `Operations` | `AuditLog.ListAsync` | журнал аудита организации |
| `Exports` | `OrganizationExports.HasExportSinceAsync` | планирование удаления организации |
| Уборка платформы | `StaffSessions.PurgeExpiredAsync` (`Access`), `TeamsDigestJob.PurgeMarksAsync` (`Reports`) | планировщик |

Задания `freshness_sweep` и `review_expiry` меняют проблемы, поэтому лежат в `Assessment` (`Assessment/SweepJobs.cs`). `Jobs` только ставит их в очередь.

## Сквозные операции

Удаление организации, сроки хранения и экспорт затрагивают все данные организации. Каждая выполняется через методы модулей-владельцев; оркестратор не знает чужих таблиц.

- **Удаление** (`OrganizationDeletion.DeleteAsync`, `Jobs`). Сначала файлы под префиксом организации, затем `DeleteOrganizationDataAsync` владельцев в порядке внешних ключей: `AuditLog`, `ReportService`, `OrganizationExports`, `AssessmentData`, `AgentData` (наблюдения ссылаются на пакеты, поэтому после `AssessmentData`), `TenantConnections`, `Idempotency`, `OrganizationLifecycle`. В конце `Jobs` удаляет задания и пишет надгробие.
- **Сроки хранения** (`RetentionPurgeJob`, `Jobs`). Сначала `AssessmentData.ExpireEvidenceAsync` заменяет старые доказательства базовым снимком. Затем удаление идёт по таблице за шаг в порядке `Catalog.RetentionPurgeOrder`: `AssessmentData.Purge…Async`, `CollectionRuns.PurgeAsync` и `AgentData.Purge…Async` (пакеты, запросы, присутствие, устройства, отозванные установки; ключи, сессии и регистрации — после реестра). Запуски и пакеты, на которые ещё ссылаются наблюдения, `Assessment` сообщает через `ObservedRunsAsync` и `ObservedBatchesAsync`. В конце `Idempotency.PurgeAsync`, `AuditLog.PurgeAsync`, `ReportService.PurgeAsync` (файлы и строки) и `OrganizationExports.ExpireAsync`. Шаги в задании записаны словарём таблица → шаг, и контрактный тест INV-071 проверяет, что ключи идут в порядке реестра.
- **Экспорт** (`OrganizationExports.BuildAsync`, `Exports`). `OrganizationLifecycle`, `TenantConnections`, `AssessmentData`, `AgentData`, `ReportService` и `AuditLog` пишут свои таблицы через `TableRowsWriter`; порядок файлов архива прежний. HTML готовых отчётов даёт `ReportService.ReadyAsync`.

## Как устранены 67 обращений (2026-10-16)

При вводе теста в `Known` было 67 записей. Каждый шаг — отдельное изменение: новый метод владельца или перенос кода к нему, вызов вместо прямого обращения, удаление строк из `Known`. После каждого шага модульные, интеграционные и контрактные тесты зелёные.

| Шаг | Что сделано | Записей |
| --- | --- | --- |
| 1 | Задания проверки свежести и истечения решений перенесены из `Jobs` в `Assessment`, смена tenant — `SubjectRetirement` | 5 |
| 2 | Интерфейс `Organizations`: `FindAsync`, `OrganizationDirectory`, `Policies` | 11 |
| 3 | Интерфейс `M365`: `TenantConnections`, `CollectionRuns` | 8 |
| 4 | Интерфейсы чтения `Assessment` для отчёта, покрытия, сводки Teams и списка организаций | 11 |
| 5 | `StaffDirectory.CanBeAssignedAsync`, `AuditLog.ListAsync`, `OrganizationExports.HasExportSinceAsync` | 3 |
| 6 | Уборка платформенных строк у владельцев | 3 |
| 7 | Удаление, сроки хранения и экспорт через методы владельцев | 26 |

Отступления от исходного плана:

- **Шаг 1.** Перенесённое задание свежести сразу читает политику через `Policies.CurrentAsync`; это часть шага 2. Иначе перенос создал бы новое нарушение `Assessment → policy_revision`.
- **Шаг 2.** Запросам `FindingEndpoints` политика нужна внутри SQL. Они получают параметром jsonb `@windows` только `freshnessWindowHours` каждой проверки, а не всю конфигурацию. Сводка Teams берёт порядок организаций из `OrganizationDirectory.ListAsync`, то есть из сортировки базы, как прежний `order by o.name`. Сортировка в C# дала бы другой порядок в рабочей базе с сортировкой `en_US.utf8`.
- **Шаг 3.** Пересчёт политики соединяет наблюдения с завершёнными запусками через `unnest` массивов из `CollectionRuns.ProjectionRunsAsync`, а не через `join collection_run`.
- **Шаг 4.** В тот же шаг вошла запись группы 5 `Reports → staff_user`: запросу решений нужны имена сотрудников, их даёт `StaffDirectory.NamesAsync`.
- **Шаг 7.** Порядок удаления `idempotency_record` и `tenant_connection` поменялся местами. Обе таблицы ссылаются только на `organization`, поэтому результат в одной транзакции прежний. Замена доказательств снимком идёт первой, а не между `finding_event` и `assessment`: ни одно удаление между ними не меняет оценок и наблюдений, на которые смотрит замена, поэтому строки и счётчики сводки те же. Статическая часть теста INV-071 читает шаги задания, а не `delete from` в его тексте — операторы переехали к владельцам.

## Как проверено

После каждого шага прошли `dotnet test` по `tests/Sikkerheit.UnitTests`, `IntegrationTests` и `ContractTests`. Дополнительно временный тест сверки (в репозиторий не вошёл) на одной базе сравнил новые чтения с SQL коммита `25e05cd` побайтно:

- снимки отчёта за две недели и для организации без подключения;
- покрытие в разные моменты в обеих областях и за неделю;
- сводку Teams;
- список организаций;
- списки проблем и оценок со свежестью;
- входы планировщика;
- уборку платформенных строк;
- архив экспорта (имена файлов и SHA-256);
- два дня сроков хранения: оставшиеся строки и счётчики сводки;
- удаление организации.

Чувствительность сверки проверена намеренными поломками: подменённое поле снимка, пропущенная уборка сессий, переставленные шаги сроков хранения — тест на них падал. Подмену порядка организаций в сводке Teams тестовая база не различает: образ `postgres:17-alpine` сортирует имена побайтно. Поэтому порядок берётся из базы, а не сортируется в коде.
