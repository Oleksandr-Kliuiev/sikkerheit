# Карта контекста Sikkerheit

Типовые задачи и минимальный набор файлов для каждой. Состояние на 2026-10-16, пакет 0.3.1 (собран, тег `package-v0.3.1`). Пути даны от `development-package/`, если не указано иное. Правила работы — в [AGENTS.md](../AGENTS.md); стадии, гейты и статус — в [WORKFLOW.md](WORKFLOW.md).

## Файлы пакета

| Файл | Содержание |
| --- | --- |
| `README.md` | Состав пакета, приоритет документов, «Изменения в 0.3.1» и «Изменения в 0.3.0» |
| `01-product-and-scope.md` | Роли, сценарии P1 (M365) и P2 (агент), этапы P0–P3, FR-01…13 с колонкой «Контракт», язык портала и отчёта, границы обещаний, NFR-01…09, экономика пилотов |
| `02-architecture-and-stack.md` | Один сервис и компоненты, развёртывание, сбор Microsoft 365 и лимиты Graph, агент под LocalSystem, фоновые задания, разделение клиентов и RLS, структура репозитория и владельцы таблиц по модулям |
| `03-check-catalog.md` | Семантика результата, проверки M365-001…007 и их правила, модули и статусы Graph, проверки WIN-001…011 с правилами WIN-002, WIN-003, WIN-005…WIN-008, WIN-010 и SYS-001…003, матрица ОС, семейства и жизненный цикл, правило SYS-003 и каталог выпусков |
| `04-security-and-privacy.md` | Вход сотрудников и роли Admin/Technician/Reader, права Graph и ключ приложения в Key Vault, ключ регистрации организации, ключ устройства и сессия, журнал безопасности, минимизация и сроки хранения, угрозы |
| `05-data-and-api.md` | Сущности, политика клиента, субъекты и идентичность устройства (канонизация признака, тестовый вектор, разбор конфликта), жизненный цикл организации, подключение M365 и сбор, состояния проблем, задания, API агента (версии конфигурации, регистрация, приём, часы, ошибки, автомат), API портала, отчёт и покрытие |
| `06-azure-and-operations.md` | Ресурсы Azure, развёртывание через слот staging с миграциями при старте слота, распространение агента через RMM (файл ключа, подпись, кольца по телеметрии), оповещения, восстановление с повтором журнала безопасности, удаление, расходы |
| `07-delivery-plan-and-acceptance.md` | Гейты, эксперименты SP-01…05, backlog WP-01…12, план приёмки и календарь (часы приёмки человеком), AT-01…17 с частями P1/P2, пилоты, допуск, RB-01…14 с операциями |
| `08-risks-and-decisions.md` | ADR-01…16, R-01…17, 18 вопросов владельцу с рубежами (закрытые помечены), условия пересмотра |
| `09-independent-review-prompt.md` | Запрос независимой оценки, если владелец решит её провести |
| `10-sources.md` | Первичные источники с датами сверки (основные — 2026-10-15) |
| `specs/check-catalog.json` | 21 проверка: M365-* (P1, graph), WIN-* (P2, agent), SYS-* (P2, server) с закрытым `evidenceSchema` |
| `specs/observation.schema.json`, `specs/scan-batch.schema.json` | Наблюдение и пакет агента (schemaVersion 2.0) |
| `specs/graph-observation.schema.json`, `specs/graph-collection.schema.json` | Allowlist наблюдений M365 и запуск сбора |
| `specs/openapi.json` | 45 операций: P1 — 29, P2 — 16; этап — `x-phase` |
| `specs/invariants.json` | 201 инвариант вне JSON Schema (P1 — 105, P2 — 96) |
| `examples/scan-batch.json`, `examples/scan-batch-unavailable.json` | Пакеты агента; основной — с эталонным случаем BitLocker |
| `examples/m365-collection.json` | Запуск сбора M365; эталонный случай report-only для M365-003 |
| `scripts/contract_catalog.py`, `contract_schemas.py`, `contract_paths.py`, `invariants_data.py` | Источники контракта (см. AGENTS.md → «Сгенерированные файлы») |
| `scripts/generate_contracts.py` | Пишет `specs/` и `examples/` |
| `scripts/validate_package.py` и `validate_*.py`, `schema_check.py`, `doc_tables.py` | Проверка пакета без записи файлов |
| `scripts/build_package.py` | validate → `VALIDATION.md`, `REVIEW-BUNDLE.md`, `manifest.json`, ZIP |

Вне пакета лежит `../sikkerheit-app-chat-transcript.md` — первоисточник идеи. `source/boss-chat.md` — его копия, её создаёт сборка.

## Задачи

### Продукт, этапы, объём

`README.md` → «Изменения в 0.3.1» и «Изменения в 0.3.0», затем `01`. Решения и риски — `08`. Почему архитектура такая и что стало с замечаниями G0 — `../docs/reviews/0.3.0-decisions.md`.

### Проверки Microsoft 365 и права Graph

- Читать: `03` → «Проверки Microsoft 365», правила M365-001…007, «Возможности подключения»; `04` → «Доступ к Microsoft 365»; `02` → «Сбор данных Microsoft 365»; `05` → «Подключение M365 и сбор».
- Машинные источники: `contract_catalog.py` (`CHECKS`, `GRAPH_PERMISSIONS` — 6 прав, `PRIVILEGED_ROLE_TEMPLATES`, `DEFERRED_IDS`, `METHOD_KINDS`, `GRAPH_MODULES`, `CAPABILITY_STATUSES`), `contract_schemas.py` (`GRAPH_EVIDENCE`, параметры M365 в `policy_configuration`), `generate_contracts.py` (`SYNTHETIC_GRAPH`).
- Обновить вместе: таблицу прав в `04` (сверяется с `GRAPH_PERMISSIONS`), `10-sources.md`, `08` (ADR-05, R-04, R-06), `07` (SP-01, AT-03…AT-05), записи P1 в `invariants_data.py`.

### Изменить или добавить Windows-проверку

- Читать: `03` → «Семантика результата», «Проверки Windows», «Поддержка ОС и уровень патчей»; `contract_catalog.py` (`CHECKS`), `contract_schemas.py` (`EVIDENCE`, параметры WIN и SYS), `generate_contracts.py` (`SYNTHETIC_EVIDENCE`).
- Обновить вместе: строку таблицы Windows в `03` (колонки «Объект» и «Режим по умолчанию» сверяются с каталогом); параметры — `05` → «Политика клиента»; приёмку — `07` (AT-14); инварианты — `invariants_data.py`; отрицательные варианты — `validate_contracts.py` (`_negatives`).
- Число WIN-проверок вычисляется (`maxItems = len(AGENT_IDS)`), литералов нет.

### Каталог выпусков, жизненный цикл ОС и SYS-*

- Читать: `03` → «Поддержка ОС и уровень патчей» (матрица, семейства, таблица жизненного цикла, правила SYS-002 и SYS-003); `05` → «Сущности и ограничения» (`windows_release`, `windows_release_month`, `observation.source=server`), «Выбор текущего состояния» (п. 7), строки каталога в «API портала»; `02` → `patch_level_sweep` и `release_catalog_check`.
- Машинные источники: `contract_catalog.py` (`RELEASE_KINDS`, `OS_FAMILIES`), `contract_schemas.py` (`SERVER_EVIDENCE`, `WindowsRelease*`, параметры SYS-003), `contract_paths.py` (`_release_paths`).
- Обновить вместе: `07` (AT-14, RB-13), `06` (оповещение каталога), `08` (ADR-10, R-14, вопрос 14), записи `PATCH` и `LIFECYCLE_OS` в `invariants_data.py`. Таблица жизненного цикла — данные правила: её изменение выпускается новой версией сервиса.

### Регистрация и аутентификация агента, приём пакетов

`04` → «Регистрация и аутентификация агента»; `05` → «Субъекты и идентичность устройства», «API агента» (регистрация и сессия, порядок приёма, часы, ошибки, автомат); `02` → «Выполнение локальной проверки»; `07` → SP-04, SP-05, AT-12, AT-13; `08` → ADR-06…ADR-09.

### HTTP API агента или портала

- Читать: `05` → «API агента», «API портала»; `contract_paths.py` (операции, `x-phase`, security, наборы ответов, заголовки); роли, `CROSS_ORG_OPERATIONS` и `AUDIT_READS` — `contract_catalog.py`.
- Обновить вместе: таблицы операций в `05` (каждый operationId в колонке `operationId`); таблицу Problem в `05`; роли — `04` → «Вход сотрудников и роли»; FR — колонка «Контракт» в `01` (каждая операция ровно в одном FR своего этапа); проверки — `validate_contracts.check_openapi`.
- Сам `openapi.json` смотреть через `jq` (команды в конце).

### Состояния проблем, история, отчёт, покрытие

`05` → «Состояния проблем» (таблица переходов, workflowState, eventType × cause, выбор текущего состояния), «Отчёт и покрытие»; `03` → «Семантика результата»; `01` → «Язык портала и отчёта»; `07` → AT-06…AT-08.

### Изоляция клиентов, роли, RLS, аудит

`02` → «Разделение клиентов»; `04` → «Вход сотрудников и роли», «Изоляция клиентов», «Угрозы и проверяемые меры»; `05` → «Сущности и ограничения»; `07` → SP-02, AT-01, AT-02.

### Персональные данные, сроки хранения, удаление, восстановление

`04` → «Минимизация данных» (таблица сроков), «Журнал безопасности»; `05` → «Жизненный цикл организации»; `06` → «Резервное копирование и восстановление», «Удаление данных клиента»; `07` → AT-09, AT-11, RB-05, RB-07. Команда восстановления в коде — `dev/README.md` → «Восстановление после PITR» (путь от `docs/`).

### Azure, распространение агента, эксплуатация, расходы

`06`; `08` → ADR-02…ADR-04, ADR-09; `07` → SP-02, SP-05, WP-07, WP-11, «Runbooks»; runbooks P1 — `runbooks/` (путь от `docs/`).

### План, трудоёмкость, приёмка

`07`. Связь FR → AT и операции — таблица в `01` → «Функциональные требования».

### Независимое ревью

Стадии и гейты — [WORKFLOW.md](WORKFLOW.md). Текст запроса к независимому рецензенту — `09` → «Текст запроса»; `REVIEW-BUNDLE.md` и ZIP самим читать не нужно.

### Выпуск новой версии пакета

- Версия: `build_package.py` (`VERSION`, `DATE`), `contract_catalog.py` (`CATALOG_VERSION`), `README.md` (строка 3), `09` (строка 3); validate сверяет их совпадение. Имя ZIP строится из `VERSION`; старые архивы остаются в корне.
- `10-sources.md`: колонка «Сверено» — по каждой строке отдельно.
- Журнал принятых и отклонённых замечаний — вне пакета, `docs/reviews/`.
- Нейтральность: перед выпуском поиск по пакету имён рецензентов и моделей, ID замечаний и ссылок на `docs/`.

### Код сервиса, портала и инфраструктуры

Обзор и команды — `dev/README.md` (путь от `docs/`); развёртывание — `../infra/README.md`; эксплуатация — `runbooks/`. Модули сервиса — папки проекта `src/Sikkerheit.Host`; модуль обращается только к своим таблицам (владельцы — `02`, «Структура репозитория»; план устранения нарушений — `dev/module-boundaries.md`):

| Задача | Код | Тесты |
| --- | --- | --- |
| Контракт, схемы, каталог | `src/Sikkerheit.Contracts` (`ContractSchemas`, `Catalog.g.cs` из `tools/contracts/gen_csharp_catalog.py`) | `tests/Sikkerheit.UnitTests/Contracts` |
| Схема БД, RLS, области | `Data/Migrations/0001_p1_core.sql` (P1), `0002_p2_agents.sql` (P2: устройства, ключи, сессии, пакеты, каталог выпусков), `Data/DbScopes.cs`, `Data/SchemaMigrator.cs`, `Data/DatabaseConnections.cs` (вход Entra) | `RowLevelSecurityTests` |
| Организации, политика, жизненный цикл | `Organizations/` (`OrganizationEndpoints`, `OrganizationLifecycle` — переходы и эпоха версий политики, `Policies` — ревизии для других модулей, `OrganizationDirectory`) | `OrganizationApiTests` |
| Вход сотрудников, сессии, CSRF | `Access/` (`LoginEndpoints`, `StaffIdentity`, `StaffSessions`, `StaffDirectory`) | `StaffSignInTests` |
| Сбор Microsoft 365 | `M365/` (`GraphClient`, `M365Collector` — в том числе активации PIM, `M365CollectionJob`, `ConnectionEndpoints`, `TenantConnections`, `CollectionRuns`) | `M365CollectionTests`, `Infrastructure/FakeGraph.cs` |
| Правила, оценки, проблемы, пересчёт политики и `ruleVersion` | `Assessment/` (`Rules`, `FindingMachine`, `M365Evaluator`, `RecalculatePolicyJob`, `SweepJobs`, `FindingEndpoints`, `Texts`, `RoleNames`; чтения для отчётов — `AssessmentReads`) | `M365RulesTests`, `FindingApiTests` |
| Регистрация и сессия агента, check-in, приём пакета (P2) | `Agents/` (`AgentEnrollment` — challenge, регистрация, сессия; `AgentRequests` — токен, check-in, конфигурация; `ScanIntake` — `submitScan` по порядку из `05`; `AgentCrypto` — подписи, nonce; `AgentLimits` — частота; `AgentMetrics` — метрики) | `AgentApiTests`, `AgentApiInvariantTests`, `Infrastructure/FakeAgent.cs`, `AgentHost.cs` |
| Устройства, ключи регистрации, разбор идентичности (P2) | `Agents/` (`Devices`, `DeviceEndpoints`, `EnrollmentKeys`, `AgentData` — удаление, экспорт, сроки хранения, `AgentReplay` — повтор журнала безопасности после восстановления, `AgentHealthJob` — оповещения по парку) | `AgentLifecycleTests`, `AgentPortalInvariantTests`, `AgentInfraInvariantTests` |
| Правила Windows и серверные проверки (P2) | `Assessment/` (`WindowsRules` — WIN-001…011; `WindowsEvaluator` — пакет в наблюдения, оценки и проблемы, эпизод WIN-007; `ServerRules` — таблица жизненного цикла ОС, SYS-002, SYS-003; `ServerChecks` — SYS-001…003 и задание `patch_level_sweep`; `DeviceSubjects`; тексты — `WindowsTexts`) | `WindowsRuleInvariantTests`, `WindowsPipelineInvariantTests`, `WindowsTextsTests` |
| Каталог выпусков Windows, RB-13 (P2) | `Assessment/` (`ReleaseCatalog` — API, `release_import`, `release_catalog_check`; `ReleaseCatalogStore` — чтение сверенных месяцев и `verifiedThroughMonth`); платформенные таблицы `windows_release`, `windows_release_month` | `AgentLifecycleTests`, `AgentWorkerInvariantTests` |
| Отчёт, покрытие, сводка Teams | `Reports/` (`Coverage`, `ReportBuilder`, `ReportHtml`, `ReportService`, `TeamsDigest`) | `Reports/*Tests`, `ReportApiTests`, `LifecycleJobTests` |
| Экспорт, удаление, сроки хранения | `Exports/`, `Jobs/DataLifecycleJobs.cs`; строки модулей — их методы `DeleteOrganizationDataAsync`, `Purge…Async`, `ExportAsync` (`Assessment/AssessmentData.cs` и др.), общий `Data/OrganizationRows.cs` | `LifecycleJobTests`, `WorkerInvariantTests` (INV-071) |
| Задания и планировщик | `Jobs/` (`JobQueue`, `JobRunner`, `Scheduler`) | `ReportPeriodTests`, интеграционные тесты заданий |
| Журнал безопасности, аудит, файлы, идемпотентность | `Operations/` | через API-тесты, `InfraInvariantTests` |
| Восстановление после PITR (RB-05) | `Operations/RestoreReplay.cs`, `RestoreReplayCommand.cs` (`dotnet Sikkerheit.Host.dll restore-replay --since <T>`) | `RestoreReplayTests`, `InfraInvariantTests`, `Operations/RestoreReplayCommandTests` |
| Агент Windows (WP-09): служба, сборщики WIN-001…011, буфер, регистрация, сессия, check-in, автомат | `src/Agent/Sikkerheit.Agent` (`Runtime/AgentEngine*.cs`, `AgentStateMachine.cs`, `Storage/BatchBuffer.cs`, `Api/`, `Scan/`, `Protocol/`, `Windows/WindowsKeys.cs`), `src/Agent/Sikkerheit.Agent.Collectors` (`Collectors.cs`, `Mapping/`, `Windows/`, `Runtime/CollectorRunner.cs`) | `tests/Sikkerheit.Agent.Tests` (`AgentInvariantTests`, `StateMachineTests`, `CollectorInvariantTests`, `Support/FakeServer.cs`); проверка на Windows — `dev/agent-windows-verification.md` |
| Негативные тесты реестра инвариантов (WP-01, WP-10) | `tests/Sikkerheit.ContractTests`: классы по `enforcement` (для P2 — `AgentApiInvariantTests`, `Windows*InvariantTests`, `AgentWorkerInvariantTests`, `AgentPortalInvariantTests`, `AgentSchemaInvariantTests`, `AgentInfraInvariantTests`), `Invariants/` (атрибуты, реестр, проверка покрытия), `Support/ContractHost.cs` | `RegistryCoverageTests` |
| Границы модулей | Владельцы таблиц и принятые владельцем исключения (сейчас нет) — `tests/Sikkerheit.UnitTests/Architecture/ModuleBoundaryTests.cs`; интерфейсы модулей и сквозные операции — `dev/module-boundaries.md` | `ModuleBoundaryTests` |
| Problem, курсоры, заголовки, телеметрия | `Platform/` | `PortalHostingTests` |
| Портал | `src/Portal/src` (`pages/`, `components/`, `api/schema.d.ts` из OpenAPI, строки `i18n/*.json`); P2 — `pages/organization/DevicesTab.tsx` (устройства и ключи регистрации), `pages/WindowsReleases.tsx` (каталог выпусков), `lib/devices.ts`, `lib/releases.ts` | `src/Portal/src/**/*.test.ts(x)` |
| Azure | `infra/bicep/main.bicep` и `modules/`, `infra/scripts/setup.sh`, `deploy-app.sh`, учебное восстановление — `drill.sh`; развёртывание из GitHub по OIDC — `.github/workflows/deploy.yml` | `tools/iac/check_arm.py` (и `--self-test`; проверки восстановления — `restore_checks.py`, помощники — `iac_common.py`, выражения ARM — `arm_eval.py`; тесты скриптов на заглушке `az` — `tools/iac/tests`) |
| Runbooks P1 (RB-01…RB-07, RB-14) | `runbooks/` (путь от `docs/`): указатель и шаблон протокола — `README.md` | — |
| Локальная разработка | `tools/dev/` (база в Docker, демо-данные), `.claude/launch.json` | — |

Отступления реализации от пакета и вопросы к 0.3.1 — `reviews/0.3.0-decisions.md`, разделы «Реализация P1» и «Реализация P2».

### Журналы и отчёты (вне пакета)

`reviews/0.3.0-decisions.md` (путь от `docs/`) — решения D-01…D-41 версии 0.3.0, итоги двух ревью 0.3.0 субагентами Claude (F-xx и RV-xx; это не внешние рецензенты) и судьба каждого замечания четвёртого раунда G0. Читать первым, если вопрос «почему так, а не как в 0.2.0».

`reviews/G0-summary.md` — итог гейта G0 по версии 0.2.0: ход раундов и реестр условий.

`reviews/G0-r1-journal.md` — журнал решений по ревью G0 v0.1.0: сводная таблица кластеров в начале, решения — `### C-NN · …`. Нужный кластер искать через `rg -n '^### C-15'`.

`reports/2026-10-13-readiness-audit.md` — аудит готовности пакета v0.1.0: 94 замечания с доказательствами. Заголовки замечаний `### <ID> · <severity>`.

`reports/2026-10-15-review-m365-security.md`, `reports/2026-10-15-review-agent-ops-plan.md`, `reports/2026-10-15-audit-review-fixes.md` — отчёты субагентов Claude по 0.3.0 (находки F-xx, RV-xx и аудит их внесения); номера строк — по снимку до правок, судьба находок — в `reviews/0.3.0-decisions.md`.

## Форматы, которые читает validate

Менять заголовки и первые ячейки только вместе с `validate_docs.py` и `doc_tables.py`.

| Файл | Что ищется |
| --- | --- |
| `01` | Таблица `| ID | Требование | Этап | Приёмка | Контракт |`, ровно FR-01…13, этап P1 или P2; каждая операция OpenAPI — в «Контракт» ровно одного FR своего этапа |
| `03` | Таблицы с колонками `ID`, `Объект`, `Режим по умолчанию`: строка на каждую проверку каталога (M365, WIN, SYS), значения без обратных кавычек; таблица `| Семейство | editionId |` — ровно `OS_FAMILIES` по порядку; таблица `| Продукт | Семейство | displayVersion | build | Последний день обслуживания | servicingEndsAt |` с правилом America/Los_Angeles и семействами из `OS_FAMILIES` |
| `04` | Таблица `| Роль | Область | Разрешения |` ровно с ролями Admin, Technician, Reader; таблица `| Право | Endpoints | Проверки |` — права в порядке `GRAPH_PERMISSIONS`; цепочка `retention_purge` (начинается с `risk_decision`) |
| `05` | Таблицы операций с колонкой `operationId` (все 45); `| code | HTTP | Операции | Когда | Действие агента |`; `| eventType | Допустимые cause | assessmentId |`; `| Состояние | Что делает агент | Выход |` — ровно `AGENT_STATES` по порядку; цепочка `retention_purge` |
| `07` | `| ID | Этап | Сценарий | Ожидаемый результат | Ответственный WP |` — ровно AT-01…17, этап P1, P2 или «P1, P2»; FR, записи реестра и строки `| Шаг | Условия |` ссылаются только на сценарии со своим этапом (диапазон «AT-01…AT-11» раскрывается); `| RB-nn | Название | Владелец роли | Этап | Операции |` — ровно 14, операции существуют и не позже этапа runbook; `| SP-nn |` с колонкой «Лимит», `| WP-nn |`; `| Параметр | Значение |` со строкой «Часы приёмки человеком в неделю» (целое число); план `| Работа | Этап | Часы приёмки |` с итогами `**Итого P1**` и `**Итого P2**`; календарь `| Отрезок | Состав | Часы приёмки | Минимум, недель | Календарные недели |` — сумма работ отрезка, недели = max(минимум, часы / часы в неделю с округлением половины вверх), каждая работа ровно в одном отрезке |
| `08` | Строки `| ADR-nn |`, `| R-nn |` |
| Все `.md` | Каждый упомянутый FR/AT/RB/SP/WP/ADR/R/INV определён в своём файле; локальные ссылки разрешаются; заголовки, на которые ссылается `invariants.json` (`sourceDoc`), существуют |

## Не читать целиком

| Файл | Размер | Вместо этого |
| --- | --- | --- |
| `REVIEW-BUNDLE.md` | Повторяет весь пакет | Исходные файлы пакета |
| `specs/openapi.json` | ~13 600 строк | `contract_paths.py`, `contract_schemas.py` или `jq` |
| `specs/invariants.json` | ~2 800 строк | `invariants_data.py` или `jq` |
| `specs/observation.schema.json`, `specs/graph-observation.schema.json` | ~1 100 и ~1 000 строк | `EVIDENCE` и `GRAPH_EVIDENCE` в `contract_schemas.py` |
| `05-data-and-api.md` | ~100 КБ | Раздел по заголовку `##` |
| `../docs/reports/2026-10-13-readiness-audit.md` | ~190 КБ | `rg` по ID замечания |
| `../docs/reviews/G0-r1-journal.md` | ~360 КБ | Сводная таблица в начале, `rg` по ID кластера |
| `manifest.json`, ZIP в корне | — | Нужны только для проверки целостности |

Выборки из контрактов (запускать из корня проекта):

```bash
jq -r '.paths | to_entries[] | .key as $p | .value | to_entries[] | "\(.value["x-phase"]) \(.key|ascii_upcase) \($p) \(.value.operationId)"' development-package/specs/openapi.json
```

```bash
jq '.components.schemas.Finding' development-package/specs/openapi.json
```

```bash
jq -c '.allOf[] | select(.then.properties.evidence) | {check: .if.properties.checkId.const, fields: (.then.properties.evidence.properties | keys)}' development-package/specs/graph-observation.schema.json
```

```bash
jq -r '.invariants[] | "\(.id) \(.phase) \(.rule)"' development-package/specs/invariants.json
```
