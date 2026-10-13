# Модель данных и HTTP API

Организация, устройство и облачная идентичность имеют разные ключи. DeviceId создаётся сервером при регистрации; имя ПК и UPN не используются как уникальные ключи. Сопоставление Entra/Intune выполняется только по подтверждённым tenantId и device IDs, а при неоднозначности остаётся unresolved.

## Сущности и ограничения

| Сущность | Ключевые данные | Ограничение |
| --- | --- | --- |
| organization | id, name, timezone, policyVersion, lifecycle | Клиентский контекст |
| organization_member | organizationId, entraUserId, role | Уникальность назначения и серверная авторизация |
| device | organizationId, id, displayName, status, lastSeenAt, latestSequence | Составной ключ для ссылок клиента |
| device_certificate | organizationId, deviceId, sha256, validFrom, validTo, revokedAt | Hash сертификата уникален; не включает private key |
| enrollment | id, organizationId, tokenHash, expiresAt, consumedAt, registrationRequestId, csrHash | Атомарное одноразовое погашение |
| integration | organizationId, id, entraTenantId, clientId, credentialRef, capabilities | Ссылка на секрет, не сам credential |
| policy_revision | organizationId, version, effectiveFrom, configuration | Immutable; прошлые версии доступны для офлайн-пакетов |
| scan_batch | organizationId, deviceId, scanId, sequence, timestamps, payloadHash, payload | Unique(deviceId, scanId), unique(deviceId, sequence) |
| observation | organizationId, sourceId, checkId, subject, observedAt, collectionStatus, evidence | Типизированные evidence и allowlist |
| assessment | observationId, ruleId, ruleVersion, policyVersion, result, freshness, severity | Исходное измерение не переписывается пересчётом |
| finding | organizationId, subject, checkId, technicalState, workflowState, revision | Стабильная пара subject/checkId; политика в событиях |
| finding_event | findingId, eventType, assessmentId, timestamp, cause | События immutable; cause=device_change/rule_change/manual_action |
| job | organizationId, type, inputId, state, leaseUntil, attempts, nextAttemptAt | Дедупликация задания по назначению и inputId |
| report | organizationId, period, timezone, state, blobKey, policyVersions | Файл выдаётся только после авторизации |
| audit_event | actor, organizationId, action, target, timestamp, correlationId | Отредактированные данные, ограниченный доступ |

Ссылки между клиентскими сущностями используют OrganizationId вместе с ID цели, включая foreign keys. Индексы: устройства по organization/status/lastSeenAt; наблюдения по subject/checkId/observedAt; открытые проблемы по organization/severity; готовые задания по state/nextAttemptAt. Нагрузочные испытания определяют необходимость партиционирования.

## Состояния проблем

`technicalState=open|resolved`; `workflowState=new|in_progress|risk_accepted|suppressed`. `risk_accepted` и `suppressed` требуют причины, сотрудника и срока пересмотра. Они не превращают fail в pass и не повышают показатель соответствия.

Правила перехода:

1. Свежий fail открывает либо повторно открывает проблему.
2. Свежий pass той же проверки и того же объекта закрывает проблему и сохраняет основание.
3. Unknown, stale, отсутствие устройства и отзыв Graph-доступа сохраняют последний technicalState и добавляют событие о качестве данных.
4. Not applicable, удаление объекта и изменение политики требуют отдельного события; они не попадают в число исправлений устройством.
5. Изменение правила помечается `rule_change`; недельный отчёт отделяет его от реальных изменений.

Текущее состояние выбирается по валидной последовательности и времени источника, не по receivedAt. Поздний офлайн-пакет пополняет историю, но не отменяет более новое наблюдение. Более поздний sequence с регрессией source time помещается в проверку `clock_inconsistent`, а не становится новым зелёным состоянием.

## API агента

Контракт находится в [specs/openapi.json](specs/openapi.json). JSON Schema отдельно описывает пакет и observation. P1 принимает только Windows-наблюдения: Graph-данные создаются Worker и не принимаются из агента.

| Метод и путь | Доступ | Поведение |
| --- | --- | --- |
| POST `/api/v1/agent/enroll` | Одноразовый enrollment token | CSR и installationId; возвращает DeviceId и подписанный certificate |
| GET `/api/v1/agent/configuration` | mTLS | Версия политики, check IDs и разрешённые настройки расписания |
| POST `/api/v1/agent/heartbeat` | mTLS | Версия агента, состояние буфера и время клиента; время связи задаёт сервер |
| POST `/api/v1/agent/scans` | mTLS | Транзакционно сохраняет пакет и задание; 202 после записи |
| POST `/api/v1/agent/certificate/renew` | Действующий mTLS | CSR нового локального ключа и ограниченное перекрытие сертификатов |

Bootstrap расположен на Portal API, остальные пути на отдельном Agent API. Серверная связь сертификата определяет device и organization. Agent API отклоняет OrganizationId/DeviceId в теле пакета как неизвестные поля.

Пакет ограничен 256 KiB до JSON parsing и 200 наблюдениями. Сжатые запросы P1 не принимает. `Idempotency-Key` должен совпадать со scanId. Повтор идентичного тела возвращает первоначальный receipt; изменённое тело с тем же ключом — 409. Два scanId с одинаковым sequence одного device — конфликт. Отправитель сохраняет байты до подтверждения.

Timestamps — UTC RFC3339; completedAt не раньше startedAt, observation не позже completedAt. Допускается до 5 минут будущего времени; до 7 дней запаздывания сохраняются исторически. Более старые или неконсистентные пакеты отклоняются с явной причиной; heartbeat всё равно может обновить доступность устройства. Клиент использует устойчивый sequence из SQLite; ротация ключа его сохраняет. Потеря состояния установки требует новой регистрации.

Ожидаемые check IDs задаются policyVersion; неизвестный checkId либо версия схемы возвращает 422. Отсутствующая ожидаемая проверка даёт unknown, даже если присланный пакет в остальном валиден. Каждая evidence проходит проверку структуры конкретного checkId; schema observation задаёт только транспортный верхний уровень.

## API портала

Portal API использует серверную сессию, назначение клиента и CSRF для изменений. List endpoints возвращают cursor pagination, максимум 100 записей; cursor связан с клиентом и фильтром. Изменения finding выполняются с If-Match/revision и возвращают 412 при конфликте.

| Метод и путь | Роль |
| --- | --- |
| GET/POST `/api/v1/organizations` | Список по назначениям; создание PlatformAdmin |
| POST `/api/v1/organizations/{organizationId}/enrollment-tokens` | ServiceManager или PlatformAdmin |
| GET `/api/v1/organizations/{organizationId}/devices` | Доступ к назначенному клиенту |
| POST `/api/v1/organizations/{organizationId}/devices/{deviceId}/scan-requests` | Technician и выше для назначенного клиента |
| GET `/api/v1/organizations/{organizationId}/devices/{deviceId}/assessments` | Основания оценок назначенного клиента |
| GET/PATCH `/api/v1/organizations/{organizationId}/findings/{findingId}` | Просмотр и разрешённое изменение workflow |
| GET `/api/v1/organizations/{organizationId}/findings` | Назначенный клиент и фильтры |
| GET `/api/v1/organizations/{organizationId}/findings/{findingId}/events` | История назначенного клиента |
| GET/POST `/api/v1/organizations/{organizationId}/reports` | Просмотр; создание ServiceManager или PlatformAdmin |
| GET `/api/v1/organizations/{organizationId}/reports/{reportId}/download` | Проверка назначения и принадлежащего клиенту reportId |
| POST `/api/v1/organizations/{organizationId}/devices/{deviceId}/revoke` | ServiceManager или PlatformAdmin |

Запрос повторного сбора имеет idempotencyKey, срок 24 часа и только известное действие `verify_remediation`. Агент видит pendingScanRequestId в конфигурации, которую запрашивает при старте и не реже heartbeat. Результат включает scanRequestId; сервер проверяет принадлежность устройству и завершает запрос после сохранения пакета. Офлайн-устройство не обещает немедленную проверку: истёкшее задание отмечается expired. Один pending request на устройство объединяет повторные запросы; произвольные команды отсутствуют.

Операции интеграций P2 описываются отдельным расширением после P0. Контракт P1 не допускает секретов в браузере, shell command и прямого изменения системных политик. Загрузка отчёта идёт через авторизованный backend; Blob-контейнер приватный, постоянные публичные ссылки отсутствуют. Назначенный сотрудник должен иметь доступ к тому же клиенту; risk acceptance и suppression доступны ServiceManager/PlatformAdmin.

Ошибки используют `application/problem+json` с code и correlationId без stack trace. Коды: 400 некорректный JSON; 401 отсутствующая/невалидная идентичность; 403 недостаточные права; 404 недоступная в контексте клиента сущность; 409 конфликт повторной операции; 412 ревизия устарела; 413 размер; 422 семантика; 429 лимит с Retry-After; 503 временный отказ. Access denial не раскрывает существование чужих устройств.

## Отчёт и покрытие

Период отчёта определяется timezone клиента, по умолчанию Europe/Oslo, и хранится вместе с UTC-границами. Результаты: новые, действительно исправленные, продолжающиеся, принятые риски, изменения правил и недоступные данные. Числа сопровождаются количеством активных объектов и датой измерения.

Coverage = число свежих определённых обязательных оценок / число применимых обязательных оценок. Compliance = свежие pass / свежие pass плюс свежие fail. При нулевом знаменателе выводится «нет данных». Informational, not applicable и принятые риски не скрывают недостаток покрытия. Compliance не интерпретируется как вероятность безопасности и не сравнивается между разными версиями политик без пояснения.
