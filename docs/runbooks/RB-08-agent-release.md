# RB-08. Выпуск агента через RMM

## Назначение

Выкатить новую утверждённую версию агента Windows на ПК клиентов кольцами, останавливать раскатку по телеметрии check-in, откатывать на предыдущую утверждённую версию и раз в месяц обслуживать .NET (`06`, «Распространение агента через RMM», «Обновление и откат»). Скрипт RMM — `tools/rmm/Sikkerheit-Rmm.ps1`; проверка скрипта и MSI на Windows — [rmm-windows-verification.md](../dev/rmm-windows-verification.md) (SP-05).

## Владелец роли и этап

Operations (разработчик), этап P2. Решение «пускать в следующее кольцо» принимает Operations вместе с Service Manager; остановка раскатки по критериям ниже не требует согласования.

## Признак запуска

- Новая версия агента (исправление или функция) собрана, подписана и записана в release notes как утверждённая: версия и SHA-256 MSI.
- Ежемесячная проверка выпусков .NET (раз в месяц, в день после «вторника патчей» Microsoft) нашла исправление безопасности runtime: новая версия агента выходит этими же кольцами не позже 14 суток (критическое исправление — RB-09).
- Оповещение «Alert RB-08» в журнале сервиса (`agent_health_check`): агенты ниже `minimumAgentVersion`, отклонённая конфигурация, частые перезапуски службы.
- Откат после остановки раскатки (шаг 6).

## Предусловия и доступы

- Доступ Admin к RMM компании и права выпускать задания на группы ПК; роль Admin или Technician в портале (чтение «Enheter»).
- Release notes версии: версия, SHA-256 MSI, subject издателя (CN и O), результат `signtool verify /pa` из CI. Без этих трёх значений задание не создаётся.
- Группы ПК в RMM под кольца: **K0** лаборатория, **K1** ПК компании, **K2** один клиент, **K3** остальные пилотные клиенты, **K4** все клиенты. Состав групп: [ЗАПОЛНИТЬ].
- Доступ к Application Insights `appi-sikkerheit-prod` (запросы ниже).
- Если RMM требует URL: user delegation SAS на контейнер `agent-releases` (шаг 2).

## Шаги

1. **Подготовить утверждённую версию.** Загрузить MSI в библиотеку ПО RMM (или в контейнер `agent-releases`, шаг 2). Проверить на рабочей станции: `Get-FileHash .\Sikkerheit.Agent.msi -Algorithm SHA256` равен SHA-256 из release notes; `Get-AuthenticodeSignature` — `Valid`, subject совпадает. Записать версию и SHA-256 как **утверждённые** в release notes (список утверждённых версий ведёт Operations; в сервисе его нет).
2. **Ссылка SAS (только если RMM требует URL).** Доступ по ключу учётной записи выключен, ссылка — user delegation SAS не дольше 7 суток, и только на время кольца. Выпуск (подставить имя `<storage>` и файл):

   ```bash
   az storage blob generate-sas --account-name <storage> --container-name agent-releases --name Sikkerheit.Agent-0.3.1.msi --permissions r --expiry "$(date -u -v+3d '+%Y-%m-%dT%H:%MZ')" --auth-mode login --as-user --https-only --full-uri -o tsv
   ```

   (`date -v+3d` — macOS; в Linux `date -u -d '+3 days' '+%Y-%m-%dT%H:%MZ'`.) Ссылка — секрет: передаётся в секретную переменную RMM и в параметр `-MsiUrl` скрипта, который её не печатает; в чат и протокол не вставляется. Истёкшую ссылку выпускать заново, не продлевать.
3. **Создать задание RMM для кольца.** Запуск от SYSTEM, тот же скрипт для установки и обновления:

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File Sikkerheit-Rmm.ps1 -Action Install -MsiPath .\Sikkerheit.Agent.msi -ApprovedVersion <версия> -ApprovedSha256 <sha256> -PublisherCommonName "<CN>" -PublisherOrganization "<O>"
   ```

   Ключ регистрации в задание **не** включается (он нужен только новым ПК — RB-10; обновление идёт без него). Кольца запускаются последовательно K0 → K1 → K2 → K3 → K4; следующее кольцо — только после выдержки и проверки (шаг 4).
4. **Выдержка и проверка кольца.** Минимум 24 часа и один полный check-in всех ПК кольца (агент проверяет связь каждые 4 часа в `VersionBlocked`, при штатной работе — по расписанию из `PolicyConfiguration`). Рабочие пороги критериев `06` (уточняются по итогам SP-04 и SP-05):

   | Критерий | Остановить кольцо, если |
   | --- | --- |
   | Ошибки check-in (`requests`, `POST /api/v1/agent/check-ins`) | доля 4xx (кроме 401 перед повторной сессией) и 5xx выше 2% за 24 часа или выше, чем у предыдущей версии |
   | Перезапуски: `agent.service_starts`, `agent.recent_crashes` | любое устройство с более чем 3 запусками службы за сутки или со свежим `lastCrashAt` (24 часа) |
   | Бюджет NFR-05: `agent.working_set_mb`, `agent.cpu_seconds` | память > 150 МБ или CPU заметно выше предыдущей версии на тех же ПК |
   | `agent.abandoned_collectors` | больше 0 |
   | `agent.rejected_batches`, `agent.batches` с `outcome` ≠ `accepted`/`duplicate` | два отказа подряд у устройства или > 5% пакетов за сутки |
   | `agent.config_rejected` | любое устройство |

   Запрос по версиям (период и счётчики за сутки; метрики сервиса идут в `customMetrics`, версия агента — в `customDimensions.agentVersion`):

   ```kusto
   customMetrics
   | where timestamp > ago(24h)
   | where name in ("agent.check_ins", "agent.service_starts", "agent.recent_crashes", "agent.abandoned_collectors", "agent.rejected_batches", "agent.config_rejected")
   | extend version = tostring(customDimensions.agentVersion)
   | summarize total = sum(valueSum) by name, version
   | order by name asc, version asc
   ```

   ```kusto
   customMetrics
   | where timestamp > ago(24h) and name in ("agent.working_set_mb", "agent.cpu_seconds")
   | extend version = tostring(customDimensions.agentVersion)
   | summarize average = sum(valueSum) / sum(valueCount), maximum = max(valueMax) by name, version
   ```

   ```kusto
   requests
   | where timestamp > ago(24h) and name has "/api/v1/agent/check-ins"
   | summarize total = count(), failed = countif(toint(resultCode) >= 400 and toint(resultCode) != 401) by bin(timestamp, 1h)
   | extend failedShare = todouble(failed) / total
   ```

   Устройства кольца в портале: «Kunder» → клиент → «Enheter», колонки «Agentversjon» и «Sist sett»; ПК без check-in дольше 4 часов после обновления — признак сбоя установки (RB-12, шаг 2).
5. **Остановить раскатку** при выполнении любого критерия: отменить задания следующих колец в RMM, не откатывая кольцо автоматически; зафиксировать метрику и список ПК. Если причина — дефект версии: откат (шаг 6) и RB-09, если дефект опасен.
6. **Откат на предыдущую утверждённую версию.** Тем же заданием шага 3 с `-ApprovedVersion` и `-ApprovedSha256` предыдущей **утверждённой** версии (MSI допускает понижение; каталог данных сохраняется: идентичность, ключ устройства, буфер, sequence). Откат на версию, которой нет в списке утверждённых, скрипт не выполнит (отказ по SHA-256), и не должен выполняться. Проверить: «Agentversjon» вернулась, «Sist sett» свежий, очередь пакетов цела (`queueDepth` в check-in).
7. **Ежемесячное обслуживание .NET.** (а) Открыть выпуски .NET на странице релизов и в [10-sources.md](../../development-package/10-sources.md) указанные источники, сверить версию runtime в сборке агента (`global.json`, `Directory.Packages.props`). (б) Есть исправление безопасности — собрать, подписать и утвердить новую версию агента, затем шаги 1–5; срок — не позже 14 суток от выхода исправления. (в) Нет исправлений — записать «без выпуска» в протокол. Критическая уязвимость runtime — RB-09.
8. **`minimumAgentVersion` не поднимать вместе с выпуском.** Он поднимается только RB-09 (опасная версия) и после того, как почти все ПК обновлены: старая версия получает 422 `agent_version_unsupported` и переходит в `VersionBlocked` (видна через check-in, буфер сохраняется), пока RMM не поставит новую.
9. **Закрыть кольцо K4.** SAS-ссылку не продлевать; после завершения раскатки истёкшая ссылка не заменяется. Release notes: версия и SHA-256 — в списке утверждённых; предыдущая утверждённая остаётся для отката, более старые — по решению Operations.

## Проверка результата

- Все ПК кольца показывают новую «Agentversjon» и свежий «Sist sett»; запросы шага 4 не превышают порогов.
- Отказы скрипта (`result=refused`) разобраны: код выхода и причина — в таблице кодов скрипта ([rmm-windows-verification.md](../dev/rmm-windows-verification.md), раздел 1). Отказ 31, 32, 33 или 34 на ПК кольца — не повторять: сверить файл и release notes, возможна подмена.
- Для отката: версия возвращена на всех ПК кольца, `VersionBlocked` нет.

## Запись в протокол

Шаблон — [README](README.md), раздел «Протокол». Записать версию и SHA-256, кольцо и состав группы, время начала и окончания выдержки, значения запросов шага 4, решение «пускать дальше» или «остановить» с основанием, срок ссылки SAS (без самой ссылки), для обслуживания .NET — версию runtime «было/стало» или «без выпуска».

## Связанные документы

- [06-azure-and-operations.md](../../development-package/06-azure-and-operations.md) — «Распространение агента через RMM», «Наблюдаемость и оповещения».
- [07-delivery-plan-and-acceptance.md](../../development-package/07-delivery-plan-and-acceptance.md) — SP-05, WP-11, AT-16.
- [rmm-windows-verification.md](../dev/rmm-windows-verification.md) — что проверяет SP-05.
- [RB-09](RB-09-agent-emergency-revocation.md), [RB-10](RB-10-enrollment-key.md), [RB-12](RB-12-agent-offline.md).
