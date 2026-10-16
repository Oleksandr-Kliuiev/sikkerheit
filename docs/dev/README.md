# Разработка Sikkerheit

Код сервиса — в `src/`, тесты — в `tests/`, портал — в `src/Portal`, инфраструктура — в `infra/`, контракт — в `development-package/specs` (файлы встроены в сборку `Sikkerheit.Contracts`, типы портала генерируются из `openapi.json`).

## Инструменты

- .NET SDK 10.0.402 (`global.json`); на машине разработки — в `~/.dotnet`.
- Node 24 LTS для портала; на машине разработки — в `~/.local/opt/node24`.
- Docker Desktop: интеграционные тесты и локальная база поднимают PostgreSQL 17.
- Azure CLI с Bicep (`az bicep install`) — для `infra/`.
- Python 3 для валидатора пакета и генератора каталога.

```bash
export PATH="$HOME/.dotnet:$HOME/.local/opt/node24/bin:$PATH" DOTNET_ROOT="$HOME/.dotnet"
```

## Проверки

```bash
dotnet test --project tests/Sikkerheit.UnitTests
```

```bash
dotnet test --project tests/Sikkerheit.IntegrationTests
```

```bash
dotnet test --project tests/Sikkerheit.ContractTests
```

```bash
dotnet test --project tests/Sikkerheit.Agent.Tests
```

Агент (`src/Agent`) собирается и тестируется на macOS и Linux; тесты Windows-слоя (`WindowsSmokeTests`) там пропускаются и работают в CI на `windows-latest`. Что проверяется только на Windows — [agent-windows-verification.md](agent-windows-verification.md).

```bash
cd src/Portal && npm ci && npm run lint && npm run typecheck && npm test
```

```bash
python3 -I tools/contracts/gen_csharp_catalog.py --check
```

```bash
python3 -I tools/lint/check_source_text.py
```

```bash
python3 -I tools/iac/check_arm.py
```

Интеграционные и контрактные тесты поднимают PostgreSQL 17 в Docker; IaC-проверка собирает ARM JSON командой `az bicep build` (нужен Azure CLI с Bicep, вход в Azure не нужен).

После изменения `development-package/scripts/contract_catalog.py` перегенерировать `src/Sikkerheit.Contracts/Catalog.g.cs` командой без `--check`; после изменения OpenAPI — `npm run gen:api` в `src/Portal`. CI (`.github/workflows/ci.yml`) проверяет и то и другое.

Интеграционные тесты: каждый экземпляр сервиса получает свою базу из мигрированного шаблона (`PostgresFixture.CreateDatabaseAsync`), поэтому исполнители заданий параллельных тестов не мешают друг другу. Время сервиса двигает `TestClock` (смещённое «сейчас», таймеры идут в реальном времени); Graph, Entra и webhook Teams заменены поддельными (`FakeGraph`, `FakeStaffIdentity`, `CapturingHandler`).

## Контрактные тесты реестра инвариантов

`tests/Sikkerheit.ContractTests` — проект `tests/Contract` из `02` (WP-01): на каждую запись этапа P1 из `development-package/specs/invariants.json` — автоматический негативный тест, который воспроизводит `negativeExample` и ожидает `expectedError` на уровне, указанном в `enforcement`.

- Тест помечается `[Invariant("INV-nnn")]`, класс — `[Enforcement("<enforcement>")]`; классы разложены по уровням: `PortalApiInvariantTests` (HTTP), `DatabaseInvariantTests` (RLS и области), `SchemaInvariantTests`, `CollectorInvariantTests` (поддельный Graph), `EvaluatorRuleInvariantTests` (правила и автомат проблем без базы) и `EvaluatorPipelineInvariantTests` (через запуск сбора), `WorkerInvariantTests` (задания и lease), `InfraInvariantTests` (восстановление, журнал безопасности, задания слотов). Для P2 (WP-10) добавлены классы по тем же уровням: `AgentApiInvariantTests` (`agent_api`: регистрация, сессия, приём пакета по HTTP с тестовым агентом), `WindowsRuleInvariantTests` (правила WIN и SYS без базы) и `WindowsPipelineInvariantTests` (пакет через сервис), `AgentWorkerInvariantTests`, `AgentPortalInvariantTests`, `AgentSchemaInvariantTests`, `AgentInfraInvariantTests` (повтор журнала после восстановления).
- `Invariants/RegistryCoverageTests` роняет сборку, если у записи P1 или у серверной записи P2 нет теста на её `enforcement`, если тест ссылается на неизвестную запись, запись агента или запись другого уровня, а классы серверных уровней не работают с PostgreSQL. Запись `infra` может закрыть и IaC-проверка: её кортеж `INVARIANTS` в `tools/iac/check_arm.py` читается тестом.
- Записи P2: 83 из 96 закрыты в этом проекте (WP-10 и INV-201 из WP-11). 13 записей уровня `agent` проверены в `tests/Sikkerheit.Agent.Tests` (своя отметка `[Invariant]`, `RegistryCoverageTests` читает её из исходников); INV-201 (скрипт RMM) проверяет `RmmScriptInvariantTests` — запускает `pwsh` с `tools/rmm/tests/Run-RmmTests.ps1` (без `pwsh` локально тест пропускается, в CI без него падает). Тестовый агент — `tests/Sikkerheit.IntegrationTests/Infrastructure/FakeAgent.cs`: свой ключ P-256, отпечаток машины и подписи по `05`, пакеты по примеру пакета; `AgentHost.cs` поднимает сервис с организацией и ключом регистрации.
- Реестр в пакете 0.3.0 местами старше решений, уже внесённых в код (F01, F03, F04, F10, F11, access token v1): такие тесты проверяют поведение по решению, а `Decision` атрибута называет его. Тексты 0.3.1 совпадают с этим поведением; новые записи 0.3.1 потребуют своих тестов — проверка покрытия перечислит их.
- Чтобы добавить запись: тест в класс её уровня с атрибутом `[Invariant]`; общий сценарий — `Support/ContractHost.cs`. Инфраструктура интеграционных тестов (`ApiFactory`, `PostgresFixture`, поддельный Graph, `LogCapture`) подключена в проект ссылками на файлы.

## Восстановление после PITR

Команда восстановления — режим обслуживания образа сервиса (`06`, «Резервное копирование и восстановление», шаги 3–6; RB-05):

```bash
dotnet Sikkerheit.Host.dll restore-replay --since 2026-11-03T14:20:00Z --report /home/LogFiles/restore-replay.json
```

Она работает только при `Jobs__Enabled=false`, читает журнал безопасности с T − 5 минут в порядке времени и идемпотентно повторяет `organization.disable`, `organization.schedule_deletion` (срок не раньше now + 7 суток), `organization.cancel_deletion`, `organization.delete` (состоявшееся удаление — сразу) и `m365.disconnect`; каждая применённая запись пишет аудит `restore.replay_applied` с correlationId `restore:<T>:<действие>:<id записи>`, по нему повторный запуск узнаёт уже применённое. Затем: сдвиг `deletionDueAt` всех запланированных удалений, следующая версия политики — следующая эпоха, кратная 10 000 (решение F10; отсчёт от большего из максимальной сохранённой версии и восстановленного счётчика, чтобы и повторное восстановление не выдало потерянные номера), перенос файлов отчётов и экспорта без строк в `restore-orphans/` (с `--drill` — только перечень), отметка выполненными `teams_digest` после T и `weekly_report` за недели из карантина, сброс lease заданий, проверка. Отчёт JSON — в stdout, журнал — в stderr; код выхода 0 — проверено, 1 — сбой или проверка не прошла, 2 — неверные аргументы, включённые задания или нет identity восстановления. Код — `Operations/RestoreReplay.cs`, `RestoreReplayCommand.cs`; тесты — `RestoreReplayTests` (копия базы в точке T вместо PITR), `InfraInvariantTests` и `Operations/RestoreReplayCommandTests`.

Identity: в Azure (задан `SecurityLog:ContainerUri`) журнал безопасности команда читает только identity восстановления, client id которой — в `Restore:ManagedIdentityClientId` (`id-sikkerheit-<env>-restore`, Storage Blob Data Reader; `04` — «Identity команды восстановления — только читать»); без этой настройки — код 2. С `--drill` ею же читаются файлы, поэтому учение перенести их не может. Реальное восстановление переносит и удаляет файлы хранилищем сервиса, то есть identity слота: записи в Blob требуют шаг 5 и повтор `organization.delete`. Вне Azure (разработка, тесты) — локальные журнал и файлы. Учение целиком — `infra/scripts/drill.sh` (RB-05, «Учебное восстановление»).

## Локальный запуск

1. База: `tools/dev/start-db.sh` (контейнер `sikkerheit-dev-pg`, порт 55432, роли как в production).
2. Сервис: конфигурация `api` в `.claude/launch.json` или `dotnet run` в `src/Sikkerheit.Host` с `ASPNETCORE_ENVIRONMENT=Development` и `--urls http://localhost:5080`. Миграции применяются при старте; задания выполняются, планировщик выключен (`Jobs:SchedulerEnabled=false`).
3. Портал: конфигурация `portal` или `npm run dev` в `src/Portal` — http://localhost:5173, прокси `/api` и `/auth` на сервис. Вход — кнопки «Utviklerinnlogging» (только Development).
4. Демо-данные: `tools/dev/seed-demo.sh` — три клиента с синтетическими tenant, наблюдениями, проблемами и решением о риске. Пересоздать базу: `docker exec sikkerheit-dev-pg psql -U postgres -c "drop database sikkerheit with (force)"`, затем шаги 1–2 и 4.

Сборка портала (`npm run build`) кладёт файлы в `src/Sikkerheit.Host/wwwroot`, откуда их раздаёт сервис; каталог не хранится в git.

## Устройство сервиса

- `src/Sikkerheit.Contracts` — встроенный контракт, валидатор схем и заголовков ответов (`ContractSchemas`), сгенерированный каталог (`Catalog.g.cs`).
- `src/Sikkerheit.Host` — модульный монолит; модули — папки и пространства имён одного проекта:
  - `Data` — SQL-миграции (`Data/Migrations/*.sql`, применяются ролью-владельцем; в Azure она же создаёт роли managed identity слотов), `DbScopes` — единственное место установки области RLS, EF Core только читает и пишет по готовой схеме; `OrganizationRows` — удаление и выгрузка строк организации из таблиц, которые называет модуль-владелец;
  - `Platform` — Problem, проверка тела по схеме, курсоры, роли, маршрутизация по hostname, заголовки безопасности, раздача портала, телеметрия без query-строк;
  - `Access` — вход Entra (code flow с PKCE на сервере, `amr=mfa` в access token v1), серверные сессии с ежечасным обновлением, CSRF, вход для разработки;
  - `Operations` — аудит, журнал безопасности (файлы в разработке, неизменяемый Blob в Azure), файлы отчётов и экспорта, идемпотентность, команда восстановления `restore-replay`;
  - `Organizations` — организации, жизненный цикл, политика, журнал аудита;
  - `M365` — подключение, клиент Graph с ограничителем и повторами, сборщик, задание сбора;
  - `Assessment` — правила, автомат проблем, оценки, пересчёт по новой политике, задания проверки свежести и истечения решений;
  - `Reports` — покрытие (одна функция для портала и отчёта), неизменяемый снимок и HTML-отчёт, задания отчётов, сводка Teams;
  - `Exports` — ZIP-экспорт с манифестом и SHA-256;
  - `Jobs` — очередь заданий (`JobQueue`, единственный владелец таблицы `job`), исполнитель с lease, планировщик; удаление организации и сроки хранения вызывают методы модулей-владельцев;
  - `Agents` (P2) — ключи регистрации, устройства и их идентичность, challenge, регистрация и сессия агента, check-in с конфигурацией, синхронный приём пакета `submitScan`, запросы повторной проверки, повтор журнала безопасности для устройств, метрики и оповещения по парку. Агент Windows (`src/Agent`) — отдельный проект, с сервером его связывают только OpenAPI и схемы пакета. `Assessment` дополнен правилами WIN и SYS, оценкой пакета, каталогом выпусков Windows и заданиями `patch_level_sweep`, `release_import`, `release_catalog_check`.
- Каждый ответ API в интеграционных тестах сверяется со схемой OpenAPI, заголовки выдачи файлов — со схемами заголовков операции.

## Устройство агента (P2, WP-09)

Агент — отдельные проекты `src/Agent/Sikkerheit.Agent` (служба) и `src/Agent/Sikkerheit.Agent.Collectors` (сборщики); сервис их не использует, а они — только `Sikkerheit.Contracts` (схемы и каталог). Всё, что не зависит от Windows, проверяется тестами `tests/Sikkerheit.Agent.Tests`; Windows-слой лежит в папках `Windows/` и только компилируется на других ОС (`EnableWindowsTargeting`, защита `OperatingSystem.IsWindows()`).

- `Sikkerheit.Agent.Collectors`: `ICollector` и `CollectorOutcome` (факт или причина недоступности), `Readers.cs` — интерфейсы читателей фактов Windows, `Collectors.cs` — сборщики WIN-001…011 и фиксированный набор `CollectorSet`, `Mapping/` — чистое отображение сырых значений в перечисления контракта (состояния WSC и Defender, классы членов группы администраторов), `Runtime/CollectorRunner` — один поток на сборщик (STA для COM), 30 с на сборщик и 120 с на сессию, счётчик оставленных потоков; `Windows/` — реализации читателей (реестр, WMI, COM, Win32, LSA) и `WindowsReaderFactory`.
- `Sikkerheit.Agent`: `Protocol/` — base64url, отпечаток JWK по RFC 7638, подписываемые строки, признак машины; `Keys/` — интерфейсы ключа устройства и защиты секрета; `Windows/WindowsKeys.cs` — CNG (TPM, затем MSKSP), DPAPI, права каталога данных; `Storage/` — SQLite (`AgentDatabase`, `AgentStateStore`, `BatchBuffer`: лимиты по размеру и дням, перенумерация очереди); `Api/` — клиент HTTP и таблица действий по ответам (`ProblemPolicy` из каталога); `Config/` — строгий разбор конфигурации по схеме; `Scan/ScanBatchBuilder` — пакет и проверка каждого наблюдения схемой; `Runtime/AgentStateMachine` — таблица автомата как чистая функция, `AgentEngine` — шаги по состоянию (регистрация, сессия, check-in, отправка, сбор), `AgentWorker` — цикл службы; `Program.cs` — сборка службы.
- Тесты: `Support/FakeServer` — сервер API агента в памяти (настоящие nonce с HMAC, проверка подписей, схемы OpenAPI, порядок отказов по `05`), программный ключ ECDSA P-256 вместо CNG, ручные часы, заглушки сборщиков с evidence из `examples/scan-batch.json`.
- Настройки службы: раздел `Agent` (`appsettings.json` рядом с файлом службы или переменные `SIKKERHEIT_Agent__ServerUrl`, `…DataDirectory`, `…Proxy`); `ServerUrl` — только https. Ключ регистрации не настройка: его кладёт скрипт RMM файлом `enrollment.key` в каталог данных (`04`).

## Отличия от структуры `02`

Модули — не отдельные проекты, а папки одного проекта `Sikkerheit.Host` (с P2 — и папка `Agents`): так проще сборка и общий `DbContext` для транзакций, затрагивающих несколько модулей. Правило «модуль не обращается к таблицам другого модуля напрямую» проверяет архитектурный тест `tests/Sikkerheit.UnitTests/Architecture/ModuleBoundaryTests.cs`: у каждой таблицы есть модуль-владелец, обращение к чужой таблице роняет тест. 67 обращений, существовавших до теста, устранены 2026-10-16; интерфейсы модулей и сквозные операции — в [module-boundaries.md](module-boundaries.md). Тесты — `tests/Sikkerheit.UnitTests`, `tests/Sikkerheit.IntegrationTests` и `tests/Sikkerheit.ContractTests` вместо `tests/Unit`, `tests/Integration` и `tests/Contract`; тесты портала лежат рядом с кодом (`*.test.ts`).

## Распространение агента (WP-11)

- `tools/rmm/Sikkerheit-Rmm.ps1` — скрипт RMM (Windows PowerShell 5.1 и 7): `-Action Install | SetEnrollmentKey | Uninstall`. Устанавливает только MSI, закреплённый заданием (версия, SHA-256, CN и O издателя), и пишет файл ключа регистрации из переменной окружения, не печатая ключ. Коды выхода — в заголовке скрипта и в [rmm-windows-verification.md](rmm-windows-verification.md).
- `tools/rmm/tests/Run-RmmTests.ps1` — тесты скрипта без Windows (подмена фактов машины и действий); `pwsh -NoProfile -File tools/rmm/tests/Run-RmmTests.ps1`. Нужен PowerShell 7 (`brew install powershell`, на этой машине стоит). Pester и PSScriptAnalyzer не нужны; синтаксис — `tools/rmm/Test-Syntax.ps1`.
- `src/Agent/Installer/Package.wxs`, `build.ps1` — описание MSI (WiX); сборка только на Windows. Статическая проверка: `python3 -I tools/rmm/check_installer.py`, её тесты — `python3 -I -m unittest discover -s tools/rmm/tests -p 'test_*.py'`.
- Метрики `agent.*` для колец и остановки — `Agents/AgentMetrics.cs`; процедура — RB-08…RB-12 в `docs/runbooks/`.
- CI: задание `rmm` (ubuntu) и `rmm-windows` (windows-latest, не блокирует: те же тесты в Windows PowerShell 5.1).
