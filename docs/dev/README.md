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
cd src/Portal && npm ci && npm run lint && npm run typecheck && npm test
```

```bash
python3 -I tools/contracts/gen_csharp_catalog.py --check
```

```bash
python3 -I tools/lint/check_source_text.py
```

После изменения `development-package/scripts/contract_catalog.py` перегенерировать `src/Sikkerheit.Contracts/Catalog.g.cs` командой без `--check`; после изменения OpenAPI — `npm run gen:api` в `src/Portal`. CI (`.github/workflows/ci.yml`) проверяет и то и другое.

Интеграционные тесты: каждый экземпляр сервиса получает свою базу из мигрированного шаблона (`PostgresFixture.CreateDatabaseAsync`), поэтому исполнители заданий параллельных тестов не мешают друг другу. Время сервиса двигает `TestClock` (смещённое «сейчас», таймеры идут в реальном времени); Graph, Entra и webhook Teams заменены поддельными (`FakeGraph`, `FakeStaffIdentity`, `CapturingHandler`).

## Локальный запуск

1. База: `tools/dev/start-db.sh` (контейнер `sikkerheit-dev-pg`, порт 55432, роли как в production).
2. Сервис: конфигурация `api` в `.claude/launch.json` или `dotnet run` в `src/Sikkerheit.Host` с `ASPNETCORE_ENVIRONMENT=Development` и `--urls http://localhost:5080`. Миграции применяются при старте; задания выполняются, планировщик выключен (`Jobs:SchedulerEnabled=false`).
3. Портал: конфигурация `portal` или `npm run dev` в `src/Portal` — http://localhost:5173, прокси `/api` и `/auth` на сервис. Вход — кнопки «Utviklerinnlogging» (только Development).
4. Демо-данные: `tools/dev/seed-demo.sh` — три клиента с синтетическими tenant, наблюдениями, проблемами и решением о риске. Пересоздать базу: `docker exec sikkerheit-dev-pg psql -U postgres -c "drop database sikkerheit with (force)"`, затем шаги 1–2 и 4.

Сборка портала (`npm run build`) кладёт файлы в `src/Sikkerheit.Host/wwwroot`, откуда их раздаёт сервис; каталог не хранится в git.

## Устройство сервиса

- `src/Sikkerheit.Contracts` — встроенный контракт, валидатор схем и заголовков ответов (`ContractSchemas`), сгенерированный каталог (`Catalog.g.cs`).
- `src/Sikkerheit.Host` — модульный монолит; модули — папки и пространства имён одного проекта:
  - `Data` — SQL-миграции (`Data/Migrations/*.sql`, применяются ролью-владельцем; в Azure она же создаёт роли managed identity слотов), `DbScopes` — единственное место установки области RLS, EF Core только читает и пишет по готовой схеме;
  - `Platform` — Problem, проверка тела по схеме, курсоры, роли, маршрутизация по hostname, заголовки безопасности, раздача портала, телеметрия без query-строк;
  - `Access` — вход Entra (code flow с PKCE на сервере, `amr=mfa` в access token v1), серверные сессии с ежечасным обновлением, CSRF, вход для разработки;
  - `Operations` — аудит, журнал безопасности (файлы в разработке, неизменяемый Blob в Azure), файлы отчётов и экспорта, идемпотентность, очередь заданий;
  - `Organizations` — организации, жизненный цикл, политика, журнал аудита;
  - `M365` — подключение, клиент Graph с ограничителем и повторами, сборщик, задание сбора;
  - `Assessment` — правила, автомат проблем, оценки, пересчёт по новой политике;
  - `Reports` — покрытие (одна функция для портала и отчёта), неизменяемый снимок и HTML-отчёт, задания отчётов, сводка Teams;
  - `Exports` — ZIP-экспорт с манифестом и SHA-256;
  - `Jobs` — исполнитель заданий с lease, планировщик, удаление организации и сроки хранения.
- Каждый ответ API в интеграционных тестах сверяется со схемой OpenAPI, заголовки выдачи файлов — со схемами заголовков операции.

## Отличия от структуры `02`

Модули — не отдельные проекты, а папки одного проекта `Sikkerheit.Host`: так проще сборка и общий `DbContext` для транзакций, затрагивающих несколько модулей. Границы модулей держатся пространствами имён; правило «модуль не читает таблицы другого модуля напрямую» будет проверять архитектурный тест. Тесты — `tests/Sikkerheit.UnitTests` и `tests/Sikkerheit.IntegrationTests` вместо `tests/Unit` и `tests/Integration`; тесты портала лежат рядом с кодом (`*.test.ts`).
