# RB-12. Агент не выходит на связь, отказы 422, расхождение часов, буфер

## Назначение

Найти причину, по которой устройство давно не присылает данные или пакеты отклоняются, и вернуть его в работу: нет check-in, отказы 422, `clockStatus=inconsistent`, переполнение буфера и потеря пакетов (`06`, «Наблюдаемость и оповещения»; `05`, «Ошибки и действия агента»).

## Владелец роли и этап

Service Manager (роль Admin или Technician в портале; запуск задач на ПК — через RMM), этап P2.

## Признак запуска

- «Alert RB-12»: не меньше 3 устройств и больше 10% не dormant устройств организации без check-in дольше 72 часов; `droppedBatchCount` > 0; два отказа 422 подряд у устройства или больше 5% пакетов за сутки; `clockStatus=inconsistent` дольше суток; `queueDepth` > 3 пакетов дольше суток.
- В «Enheter»: «Sist sett» старше 72 часов; «Ikke sett på 14 dager» (dormant — не считается отказом, это выключенный ПК).
- Жалоба клиента: «Siste fullstendige innsamling» устарела, отчёт без Windows.

## Предусловия и доступы

- Портал: «Kunder» → клиент → «Enheter»; Application Insights для запросов; RMM для просмотра службы и запуска скрипта.
- Для запроса новой проверки — роль Admin или Technician (`requestDeviceScan`).

## Шаги

1. **Сузить область.** «Enheter» → фильтр «Status» «Aktiv», сортировка по «Sist sett». Одно устройство — идти по шагам 2–7. Много устройств сразу — общая причина: сервис (`/health`, оповещения, RB-04), сеть клиента или прокси, обновление агента (RB-08, остановить раскатку), смена `minimumAgentVersion` (RB-09).
2. **Устройство вообще не выходит на связь** («Sist sett» старый). Через RMM: ПК включён? служба `Sikkerheit.Agent` работает (`Get-Service Sikkerheit.Agent`); версия агента; исходящий HTTPS к hostname агента (прокси: свойство `PROXY` при установке); часы ПК (`w32tm /query /status`). Нет службы — установка: `-Action Install` (RB-08, шаг 3). Служба остановлена по ошибке — Event Log источника службы (без ключей и токенов).
3. **Ответ сервера у агента** (по check-in и журналу сервиса):

   | Ответ / состояние | Значение | Действие |
   | --- | --- | --- |
   | 401 `session_invalid`, `challenge_invalid` | сессия истекла | агент сам получает новую сессию; повторяется — часы ПК (шаг 4) или сервис (RB-04) |
   | 401 `device_unknown` | сервер не знает устройство (устройство удалено, база восстановлена) | агент регистрируется заново, если у него сохранён ключ регистрации; иначе — файл ключа через RMM (RB-10, А.2) |
   | 401 `enrollment_key_invalid` | ключ регистрации неизвестен или отозван, состояние `EnrollmentBlocked` | новый ключ и файл ключа (RB-10) |
   | 401 `device_revoked` | устройство отозвано, агент в `Revoked` и не работает до переустановки | сознательное решение; переустановка даёт новое устройство (RB-11) |
   | 403 `organization_inactive` | организация отключена или ожидает удаления | `Suspended`: ждать возврата в активное состояние (RB-07, RB-03) |
   | 409 `identity_conflict` | конфликт идентичности | RB-11 |
   | 409 `sequence_conflict` | sequence не больше принятого: агент сам делает resync | частые `device.sequence_resync` — RB-11, шаг 5 |
   | 422 `agent_version_unsupported` | агент ниже `minimumAgentVersion`, `VersionBlocked`, check-in раз в 4 часа | утверждённая версия через RMM (RB-08) |
   | 422 `unsupported_schema_version` | сервер не поддерживает схему пакета агента | обновить агент (RB-08) |
   | 422 `batch_too_old` | пакет старше `maxBatchAgeDays` (9 суток): буфер потерян, пакет отброшен | `droppedBatchCount`; запросить новую проверку (шаг 6) |
   | 422 `schema_violation`, `unknown_policy_version`, `unexpected_subject`, `duplicate_observation`, `batch_time_inconsistent` | пакет не принят, агент отбрасывает его и обновляет конфигурацию | два отказа подряд у устройства — сверить версию агента с сервером (RB-08), затем разработчику с кодом и версиями (без тела пакета) |
   | 429 `rate_limited` | лимит частоты (регистрации — 20 в час и 200 в сутки на ключ) | подождать `Retry-After`; массовую переустановку делать волнами |
   | 503 `temporarily_unavailable` | временный сбой сервиса | агент повторит; общий сбой — RB-04 |

   Коды и поведение агента: `05`, «Ошибки и действия агента». Для разбора 422 по устройствам:

   ```kusto
   customMetrics
   | where timestamp > ago(2d) and name == "agent.batches"
   | extend outcome = tostring(customDimensions.outcome), device = tostring(customDimensions.deviceId), version = tostring(customDimensions.agentVersion)
   | where outcome !in ("accepted", "duplicate")
   | summarize refused = sum(valueSum) by outcome, version, device
   | order by refused desc
   ```

4. **Расхождение часов** (`clockStatus=inconsistent`, «Klokke» в карточке): часы ПК отличаются от серверных больше допуска. Аутентификация от часов не зависит, но временные метки наблюдений недостоверны, поэтому пакеты принимаются с отметкой. Исправить время на ПК (синхронизация `w32tm /resync`, домен или NTP, батарея CMOS, ВМ), проверить через следующий check-in; статус вернётся в «ok».
5. **Переполнение буфера и потерянные пакеты** (`queueDepth` растёт, `droppedBatchCount` > 0): буфер агента хранит до 7 суток и 100 МБ; при длительном отсутствии связи пакеты вытесняются. Восстановить связь (шаги 2–4); потерянные пакеты не восстанавливаются — запросить новую полную проверку (шаг 6). Если `droppedBatchCount` растёт при нормальной связи — разработчику (диск, SQLite).
6. **Запросить новую проверку** — `requestDeviceScan`: «Enheter» → строка → «Be om ny innsamling»; запрос доставляется при следующем check-in и действует 24 часа (портал показывает «Forespørselen leveres ved neste innsjekk og gjelder til …»).
7. **Переустановка** как последний шаг, если служба не восстанавливается: `-Action Uninstall`, затем `-Action Install` с ключом регистрации; устройство получит новую идентичность (RB-11, шаг 4).

## Проверка результата

- «Sist sett» свежий, «Siste fullstendige innsamling» обновилась после запроса, `clockStatus=ok`.
- Оповещение «Alert RB-12» не повторилось на следующий день; для массовой причины — доля устройств без check-in ниже порога.
- В запросе шага 3 нет роста отказов у устройства.

## Запись в протокол

Шаблон — [README](README.md), раздел «Протокол». Записать устройство или область (число устройств, организации), найденную причину, ответ сервера и версию агента, действия в RMM, запрос проверки, потерянные данные (`droppedBatchCount`), результат.

## Связанные документы

- [05-data-and-api.md](../../development-package/05-data-and-api.md) — «API агента», «Ошибки и действия агента», автомат.
- [06-azure-and-operations.md](../../development-package/06-azure-and-operations.md) — «Наблюдаемость и оповещения».
- [07-delivery-plan-and-acceptance.md](../../development-package/07-delivery-plan-and-acceptance.md) — AT-13.
- [RB-04](RB-04-jobs-and-scheduler.md), [RB-08](RB-08-agent-release.md), [RB-10](RB-10-enrollment-key.md), [RB-11](RB-11-device-identity.md).
