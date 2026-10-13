# Модель данных и HTTP API

Организация, устройство и облачная идентичность имеют разные ключи. DeviceId создаётся сервером при регистрации; имя ПК и UPN не используются как уникальные ключи. Сопоставление Entra/Intune выполняется только по подтверждённым tenantId и device IDs, а при неоднозначности остаётся unresolved. Контракт описывает 34 операции (агентских 5, портальных 29) в [specs/openapi.json](specs/openapi.json); правила, которые не выражаются JSON Schema, перечислены в разделе «Инварианты вне JSON Schema» и в реестре [specs/invariants.json](specs/invariants.json).

## Сущности и ограничения

| Сущность | Ключевые данные | Ограничение |
| --- | --- | --- |
| organization | id, name, timezone, reportLanguage (nb, nn, en), status (active, disabled, deletion_scheduled), deletionDueAt | Клиентский контекст. `timezone` (IANA) обязательна при создании; портал предлагает Europe/Oslo, но сервер значения по умолчанию не подставляет. `deletionDueAt` заполнено только в `deletion_scheduled`. Удалённая организация оставляет tombstone (id, deletedAt) и в API не отдаётся. Переходы — раздел «Жизненный цикл организации» |
| platform_role | entraUserId, role, grantedBy, grantedAt | Зеркало назначения app role `PlatformAdmin` в Entra tenant компании; сервер сверяет его при входе и не реже раза в час. Отдельно от organization_member, изменения пишутся в `platform_audit_event` |
| organization_member | organizationId, id, entraUserId, role (ServiceManager, Technician), displayName, grantedAt, grantedBy | Уникальность назначения и серверная авторизация. PlatformAdmin здесь не хранится; CustomerReader появится в P3. Изменения аудируются |
| device | organizationId, id, displayName, status (active, revoked), installationId, machineFingerprintHash, identityState (ok, identity_conflict), clockStatus (ok, inconsistent), enrollmentTokenId, lastSeenAt, lastFullScanAt, lastAcceptedSequence, reenrollAllowedUntil (timestamp, nullable) | Составной ключ для ссылок клиента. `installationId` уникален среди всех неудалённых устройств организации, включая отозванные. `machineFingerprintHash` фиксируется при регистрации. `lastFullScanAt` — `completedAt` последнего полного сбора (раздел «Отчёт и покрытие», «Определения»). `reenrollAllowedUntil` записывается при ответе 401 `certificate_expired` за `superseded`-сертификат после окончания перекрытия и обнуляется в транзакции выдачи нового сертификата при повторной регистрации (раздел «Канонический объект и идентичность устройства») |
| device_certificate | organizationId, deviceId, sha256, state (pending, active, superseded, revoked), validFrom, validTo, activatedAt, revokedAt, renewalRequestId, csrHash | Hash сертификата уникален; private key не хранится. Записи добавляет только роль БД Issuer. Не больше одного pending и не больше двух действующих сертификатов на устройство; действующий — принимаемый сервером: `active` или `pending` с `validTo` > now либо `superseded` в пределах перекрытия, без отзыва (`04`, «Профиль и продление сертификата») |
| enrollment_token | organizationId, id, tokenHash, mode (single_use, batch), label, expiresAt, maxUses, useCount, revokedAt, createdAt, createdBy | Хранится только SHA-256 секрета. `useCount` увеличивается в одной транзакции с выдачей сертификата — и при создании устройства, и при повторной регистрации существующего, поэтому по токену выполняется не больше `maxUses` регистраций |
| enrollment | organizationId, tokenId, installationId, registrationRequestId, csrHash, deviceId, createdAt | Создаётся в транзакции выдачи при каждой регистрации, в том числе повторной регистрации существующего устройства. Идентичный повтор (`registrationRequestId` + CSR) возвращает прежний сертификат и не увеличивает `useCount` |
| integration | organizationId, id, entraTenantId, clientId, credentialRef, capabilities | Ссылка на секрет, не сам credential. Контракт интеграций появится в P2-расширении |
| policy_revision | organizationId, version, effectiveFrom, createdAt, createdBy, configuration | Immutable; хранится, пока на ревизию есть ссылки, но не меньше 12 месяцев; прошлые версии доступны для офлайн-пакетов. Структура configuration — подраздел «Политика клиента» |
| scan_batch | organizationId, deviceId, scanId, sequence, policyVersion, startedAt, completedAt, receivedAt, payloadHash, payload, state | Unique(deviceId, scanId), unique(deviceId, sequence). Payload удаляется после успешной обработки, но не позже 7 суток после приёма; метаданные повтора хранятся 90 дней |
| observation | organizationId, deviceId, subjectType, localKey, checkId, observedAt, collectionStatus, evidence, reasonCode | Канонический объект и закрытые evidence по checkId; хранится 90 дней |
| assessment | organizationId, id, observationId (nullable), deviceId, subjectType, localKey, checkId, ruleId, ruleVersion, sourcePolicyVersion, evaluatedPolicyVersion, assessmentScope (historical, current), assessmentMode (assessed, informational), result, severity, reasonCode, late, evaluatedAt, basisSnapshot, evidenceAvailability (available, expired) | Исходное измерение не переписывается пересчётом. Свежесть вычисляется при чтении и при формировании отчёта. Хранится 12 месяцев от `evaluatedAt`, но не удаляется, пока на неё ссылается сохраняемое событие; через 90 дней остаётся `basisSnapshot` |
| finding | organizationId, id, deviceId, subjectType, localKey, checkId, technicalState, workflowState, severity, assigneeId, dueAt, workflowReason, reviewAt, workflowDecidedBy, revision | Unique(organizationId, deviceId, subjectType, localKey, checkId); политика фиксируется в событиях |
| finding_event | findingId, id, eventType, cause, assessmentId, actorId, fromWorkflowState, toWorkflowState, occurredAt | События immutable. `cause` ∈ device_change, rule_change, policy_change, applicability_change, data_quality, manual_action, review_expired; допустимые сочетания — подраздел «Допустимые сочетания eventType и cause». `actorId` не null тогда и только тогда, когда `cause=manual_action` |
| scan_request | organizationId, id, deviceId, requestedBy, createdAt, expiresAt, state (requested, delivered, completed, expired) | Запрос повторной проверки `requestDeviceScan`, только в варианте A; относится к устройству, а не к отдельной проблеме. Ключ `id` совпадает с `ScanRequest.id` в API; в конфигурации агента он передаётся как `pendingScanRequestId`, в пакете агента — как `scanRequestId`. Хранится 90 суток от `createdAt`. Правила — раздел «API портала» |
| job | organizationId, id, type, inputId, periodKey, state, leaseOwner, leaseToken, leaseUntil, attempts, nextAttemptAt | Unique(type, organizationId, coalesce(inputId, periodKey)); у платформенного `platform_audit_purge` `organizationId` = null и уникальность по (`type`, `periodKey`); завершение под fencing по `leaseToken`. Подраздел «Задания и планировщик» |
| report | organizationId, id, periodStart, periodEnd, timezone, language, format, state, failureCode, blobKey, policyVersions | Файл выдаётся только после авторизации; опубликованный отчёт не пересчитывается |
| organization_export | organizationId, id, state (queued, ready, failed, expired), blobKey, createdAt, expiresAt, requestedBy | Файл экспорта хранится 7 дней и выдаётся только через авторизованный backend |
| audit_event | organizationId, id, occurredAt, actorType (user, platform_admin, device, system), actorId, action, targetType, targetId, outcome (success, denied, failed), correlationId | Только клиентский аудит: `organizationId` обязателен, таблица под RLS. Отредактированные данные, ограниченный доступ; читает только PlatformAdmin через `listAuditEvents`. Доступ PlatformAdmin к данным организации пишется в её `audit_event` и виден в `listAuditEvents` |
| platform_audit_event | id, occurredAt, actorType (user, platform_admin, system), actorId, action, targetType, targetId, outcome (success, denied, failed), correlationId | Платформенный аудит без `organizationId` и без RLS: изменения `platform_role`, создание, отключение и удаление организаций. Чтение — отдельная роль базы для runbook (только SELECT) и Log Analytics; операции API в P1 нет; срок хранения — как у `audit_event`, строки старше срока удаляет ежедневное задание `platform_audit_purge` в 02:30 (`organizationId` = null), а не `retention_purge` организации; право DELETE есть только у роли этого задания |
| lifecycle_journal | id, organizationId, targetType, targetId, action, occurredAt, correlationId | Хранится вне PostgreSQL, append-only, без PII и без `actorId`: исполнитель находится через `correlationId` и `audit_event` или `platform_audit_event`. Описание — `06`, раздел «Журнал жизненного цикла и restore в карантине» |

Ссылки между клиентскими сущностями используют OrganizationId вместе с ID цели, включая foreign keys. Индексы: устройства по organization/status/lastSeenAt; наблюдения по subject/checkId/observedAt; открытые проблемы по organization/severity; готовые задания по state/nextAttemptAt. Нагрузочные испытания определяют необходимость партиционирования. Контекст организации устанавливается только SECURITY DEFINER-функцией `app.begin_org_context(organizationId, actor, purpose)`: она сначала проверяет `platform_role`, затем членство, и если у субъекта есть `platform_role`, в той же транзакции пишет `audit_event` (`actorType=platform_admin`, `action=platform.access`, target — operationId), даже при наличии членства. Политики RLS имеют вид `organization_id = app.current_org_id()`, на клиентских таблицах включён `FORCE ROW LEVEL SECURITY`, и без контекста запрос возвращает 0 строк; политик межклиентского обхода нет, а глобальное чтение PlatformAdmin означает право войти в контекст любой организации. Роли и аудит описаны в `04`, раздел «Вход в портал и роли».

Сроки хранения всей цепочки перечислены в `04`, раздел «Сроки хранения». Для модели данных важны следующие правила. `basisSnapshot` неизменяем и содержит checkId, ruleId, ruleVersion, evaluatedPolicyVersion, result, freshness, reasonCode, observedAt и минимальные allowlisted-поля для explanation; для WIN-008 сохраняются только неразрешённые SID. Через 90 дней evidence оценки удаляется, остаётся `basisSnapshot`, `evidenceAvailability=expired` и `observationId=NULL`. Сроки: `assessment` — 12 месяцев от `evaluatedAt`, `finding_event` — 12 месяцев от `occurredAt`; `finding` удаляется, когда удалено его последнее событие и он в `resolved`. Политика FK: `device.enrollmentTokenId` ON DELETE SET NULL; `finding_event → assessment` ON DELETE RESTRICT, поэтому оценка, на которую ссылается сохраняемое событие, не удаляется до удаления этого события; `assessment → observation` ON DELETE SET NULL (observation_id) — список колонок в этом действии требует PostgreSQL 15 или новее, мажорная версия выбирается до SP-04; organizationId при этом не обнуляется, каскада от observation к истории нет. Задание `retention_purge` выполняется ежедневно по каждой организации в контексте RLS, удаляет в порядке `finding_event` → `assessment` → `finding` → `observation` → `scan_batch` → `scan_request` → `device_certificate` → `enrollment` → `enrollment_token` → `device` (`policy_revision` не удаляется, пока на неё ссылаются сохраняемые записи) и пишет в аудит сводку: что удалено и что заменено снимком. Клиентская политика может сократить сроки хранения наблюдений, payload и снимков, но не отменяет неизменяемость событий; срок хранения оснований и порядок утверждения удаления — вопрос 6 в `08`.

### Политика клиента

`policy_revision.configuration` описывается закрытой схемой PolicyConfiguration. `activeCheckIds` содержит WIN-* проверки, WIN-011 обязательна. `schedule` задаёт `scanIntervalHours` 1…168 (по умолчанию 24), `heartbeatIntervalHours` 1…24 (4) и `scanJitterMinutes` 0…60 (10). `buffer` задаёт `maxBufferDays` 1…30 (7) и `maxBatchAgeDays` 2…32 (9); при сохранении проверяется `maxBatchAgeDays ≥ maxBufferDays + 1`, иначе 422 `schema_violation`. `checks` — объект по 13 P1 checkId: у каждого есть `assessmentMode`, `freshnessWindowHours` 1…720 (72), необязательный `notApplicableEditionIds[]` (по умолчанию `[]`, у WIN-002 — `[Core, CoreN, CoreSingleLanguage, CoreCountrySpecific]`) и `parameters`; у WIN-011 и SYS-001 `assessmentMode` — const `informational`. Все обязательные поля PolicyConfiguration имеют значение default; таблица ниже показывает стартовые значения всех параметров.

| checkId | parameters (стартовая политика) | Что нужно для assessed |
| --- | --- | --- |
| WIN-001 | `warnFreePercent` 10, `warnFreeBytes` 10737418240, `criticalFreePercent` 5, `criticalFreeBytes` 2147483648 | — |
| WIN-002 | `encryptionRequired` true; `notApplicableEditionIds` [Core, CoreN, CoreSingleLanguage, CoreCountrySpecific] | — |
| WIN-003 | `approvedProviders` [] (элементы SAFE_TEXT), `defenderApproved` true | Непустой `approvedProviders` или `defenderApproved=true` |
| WIN-004 | `warnDays` 3, `criticalDays` 7 | WIN-003 в `activeCheckIds`. Применима только при `defenderApproved=true` и `amRunningMode=normal` по WIN-003 того же пакета, иначе not_applicable (в том числе при `defender = null`) |
| WIN-005 | `requiredProfiles` [domain, private, public] | — |
| WIN-006 | `expectedSource` null (допустимо `windows_update`, `wsus`, `other_approved`), `maxSearchAgeHours` 72, `graceDaysBySeverity` {critical 7, important 14, moderate 30, low 30, unrated 14}, `referenceTimeBasis` `first_seen` (допустимо `deadline`, `first_seen`) | `expectedSource` не null |
| WIN-007 | `warnDays` 3 | — |
| WIN-008 | `allowedSids` [] | Не меньше одного SID |
| WIN-009 | `secureBootRequired` true | — |
| WIN-010 | `expectedTenantId` null | `expectedTenantId` не null |
| WIN-011, SYS-001, SYS-002 | `{}` | WIN-011 и SYS-001 — всегда informational |

`createPolicyRevision` возвращает 422 `policy_inputs_missing` в трёх случаях: режим `assessed` без входных настроек; `activeCheckIds` без WIN-011; активна WIN-004 без WIN-003. Режим проверки хранится в политике явно; наличие входных настроек — необходимое, но не достаточное условие `assessed`. Межпроверочная применимость берётся из наблюдения того же пакета: WIN-002 — по `editionId` из WIN-011 (`notApplicableEditionIds`), WIN-004 — по `defender` из WIN-003. Если такого наблюдения в пакете нет или оно `unavailable`, зависимая проверка получает unknown/`applicability_input_missing` (в режиме informational — `result=null` с тем же `reasonCode`), а не not_applicable; если применимость известна и проверка не применима — not_applicable/`policy_not_applicable` (в режиме informational — `result=null`, `reasonCode=null`). Это правило применяется, только если у пакета нет признака часов: при признаке все оценки пакета получают `clock_inconsistent` (подраздел «Время и часы устройства»).

Политика по умолчанию v1 создаётся вместе с организацией операцией `createOrganization`. В её `activeCheckIds` входят все 11 WIN. Режимы равны `defaultAssessmentMode` каталога `03`: WIN-003, WIN-006, WIN-008, WIN-010, WIN-011 и SYS-001 — informational, остальные P1-проверки — assessed. Стартовые параметры берутся из таблицы выше, в том числе `defenderApproved=true` и `approvedProviders=[]`, поэтому WIN-004 применима на устройствах с Defender в режиме normal. Новая версия создаётся только с `If-Match`, равным текущей версии, ревизии неизменяемы.

### Задания и планировщик

Типы заданий: `evaluate_batch`, `recalculate_policy`, `report_generate`, `organization_export`; раз в час — `freshness_sweep`, `scan_request_expiry` и `review_expiry`; `weekly_report` — в понедельник 06:00 по timezone организации, за прошедшую неделю и только для `active`; `retention_purge` — ежедневно в 02:00; `platform_audit_purge` — ежедневно, платформенное задание с `organizationId` = null и уникальностью по (`type`, `periodKey`), удаляет строки `platform_audit_event` старше срока хранения аудита; `organization_delete` — планировщик ежечасно ставит его для организаций с `deletionDueAt ≤ now`; в P2 добавляется `graph_collect`. Планировщик работает внутри каждой реплики worker и каждые 5 мин вставляет периодические задания через `INSERT … ON CONFLICT DO NOTHING`; пропуски догоняются не глубже 24 ч для часовых заданий и 4 недель для `weekly_report`. Захват выполняется через `FOR UPDATE SKIP LOCKED` с lease 5 мин и продлением, при каждом захвате `leaseToken` увеличивается. Завершение и бизнес-эффект выполняются в одной транзакции `WHERE id=? AND leaseToken=?`; если обновлено 0 строк, транзакция откатывается, а эффекты идемпотентны за счёт уникальных ограничений. Выбор и обработка разделены: выбор — SECURITY DEFINER-функция `claim_jobs` от роли без входа, которая видит только метаданные job; обработка — отдельная транзакция с контекстом организации из `job.organizationId` (`purpose=job` с проверкой lease); `platform_audit_purge` обрабатывается без контекста организации под собственной ролью базы, единственной с правом DELETE на `platform_audit_event`. Метрика «последний такт планировщика» поднимает оповещение, если периодические задания не создавались дольше двух периодов.

## Канонический объект и идентичность устройства

Серверный ключ объекта — `(organizationId, deviceId, subjectType, localKey)`. `deviceId` берётся только из сертификата: агент не передаёт его и не может адресовать объект другого устройства. `localKey` равен `'device'` для устройства и `volumeId` (`\\?\Volume{GUID}\`) для тома; буква диска — только атрибут отображения `mountPoint`. В API `subject` имеет вид `{type, key, displayName}`. Уникальность внутри пакета — `(checkId, subject.type, localKey)`, уникальность finding — `(organizationId, deviceId, subjectType, localKey, checkId)`. Поэтому два ПК с томом C:, смена буквы тома ОС и повторная регистрация того же устройства не смешивают историю.

`deviceId` создаёт сервер при enroll. `machineFingerprint` — HMAC-SHA256 в hex нижнего регистра: ключ — 16 байт `installationId` (UUID) в порядке байтов RFC 4122 (big-endian), сообщение — UTF-8 строка SMBIOS UUID в каноническом виде (нижний регистр, с дефисами), байт `0x00` и UTF-8 строка MachineGuid в том же виде. Сервер хранит `machineFingerprintHash` = SHA-256 от этого значения, сырые идентификаторы не передаются; стабильность обоих источников в контексте службы проверяет SP-01. Признак передаётся в enroll, heartbeat, scans и renew. Несовпадение даёт 409 `identity_conflict`. В heartbeat, scans и renew у устройства выставляется `identityState=identity_conflict`; отказ enroll с чужим признаком `identityState` не меняет (регистрацию подтверждает только токен) и пишется в аудит `device.enroll_identity_conflict`, а исходное устройство с совпадающим признаком продолжает работу. Сертификат при конфликте не отзывается: отзыв и перерегистрацию выполняет ServiceManager вручную по RB-03. `identityState` возвращается в `ok`, если 7 суток не было запросов с чужим признаком; возникновение и снятие конфликта пишутся в аудит (`device.identity_conflict`, `device.identity_conflict_cleared`). Клон регистрируется заново только после чистой переустановки: новый `installationId`, новый ключ и sequence с нуля; агент не входит в golden image.

`lastAcceptedSequence` — максимальный принятый sequence устройства; он возвращается в Configuration, пропуски sequence допустимы. Ресинхронизация после `sequence_conflict` при совпадающем признаке выполняется так: агент запрашивает GET configuration, перенумеровывает неподтверждённые пакеты начиная с `lastAcceptedSequence + 1` и даёт им новые `scanId` — это единственное исключение из правила неизменности байтов; сервер пишет `device.sequence_rollback`. Ресинхронизация допускается не чаще раза в 24 ч, повторный конфликт за 24 ч сервер возвращает как `identity_conflict`.

Повторная регистрация с тем же `installationId` сохраняет `deviceId` и историю, если устройство не отозвано, признак машины совпадает и выполнено одно из условий: у устройства нет `active` сертификата с `validTo` > now (например, сертификат истёк; неактивированный `pending` не учитывается) либо `device.reenrollAllowedUntil > now`. Право на повторную регистрацию при действующем сертификате сервер хранит явно. Когда агент предъявляет по mTLS зарегистрированный сертификат своего устройства в состоянии `superseded` после окончания перекрытия (например, восстановленный образ старше ротации), сервер отвечает 401 `certificate_expired` и в той же транзакции записывает `device.reenrollAllowedUntil = now + 7 суток` (аудит `device.reenroll_allowed`). Отозванный сертификат или отозванное устройство это поле не выставляют. Окно выставляется по состоянию `superseded` независимо от `validTo`, если запрос дошёл до приложения; при обрыве TLS на ingress оно не открывается (вариант устанавливает SP-02, `04`, «Профиль и продление сертификата»). При любой повторной регистрации существующий неактивированный `pending` переводится в `revoked` в транзакции выдачи (аудит `device.pending_revoked`), а `useCount` токена увеличивается и создаётся запись `enrollment`, как при создании устройства. При `reenrollAllowedUntil > now` новый сертификат выдаётся как `pending`; перекрытие прежних `superseded` заканчивается в момент выдачи; прежний `active` переходит в `superseded` при первом mTLS-запросе новым; `reenrollAllowedUntil` обнуляется в транзакции выдачи; `previousCertificateValidUntil = null`; пишется аудит `device.reenroll_over_active` и поднимается оповещение ServiceManager. Если `installationId` уже зарегистрирован, а признак машины не совпадает, enroll возвращает 409 `identity_conflict` (действие агента `identity_stop`). Для отозванного устройства enroll возвращает 409 `installation_already_enrolled`, и нужна чистая переустановка с новым `installationId`; тот же код получает устройство с `active` сертификатом, у которого `validTo` > now, если `reenrollAllowedUntil` не задан или истёк. Порядок проверок `enrollAgent` — раздел «API агента». Имя устройства: начальное значение — `EnrollmentRequest.displayName`; ServiceManager или PlatformAdmin меняет его через `updateDevice`; агент имя не перезаписывает.

## Жизненный цикл организации

Между `schedule_deletion` и удалением проходит 30 суток (платформенный параметр). Срок, согласованный с клиентом, и порядок утверждения удаления — вопрос 6 в `08`. Переходы выполняет PlatformAdmin операцией `changeOrganizationLifecycle` с `idempotencyKey` в теле; повтор с тем же ключом возвращает прежний результат. Обязательное поле `reason` — свободный текст до 1000 символов; это недоверенная строка, она выводится только в аудите с экранированием. Ограничивающие действия записываются сначала в журнал жизненного цикла, затем в БД; разрешающие — сначала в БД, затем в журнал, чтобы потеря записи давала более строгий итог.

| Из | Действие | В | Условие | Порядок записи и эффекты |
| --- | --- | --- | --- | --- |
| active | disable | disabled | — | Сначала журнал, затем БД. Все enrollment-токены организации отзываются |
| disabled | enable | active | — | Сначала БД, затем журнал. Отозванные токены остаются отозванными |
| disabled | schedule_deletion | deletion_scheduled | Есть экспорт, созданный после перехода в `disabled`, в состоянии `ready` или `expired`; либо `exportWaived=true` | Сначала журнал, затем БД. `deletionDueAt` = now + 30 сут |
| deletion_scheduled | cancel_deletion | disabled | До `deletionDueAt` | Сначала БД, затем журнал. `deletionDueAt` = null |
| deletion_scheduled | Задание `organization_delete` при `deletionDueAt ≤ now` | deleted | — | Сначала журнал (`delete`), затем БД: отзыв всех устройств и сертификатов, удаление данных и Blob, tombstone |

Остальные сочетания дают 409 `lifecycle_transition_forbidden`. `exportWaived` допустим только при `schedule_deletion`.

| Статус | Портал | Агент | Задания |
| --- | --- | --- | --- |
| active | Все операции по ролям | Все операции | Все |
| disabled, deletion_scheduled | Чтение по ролям. Из мутаций разрешены только `changeOrganizationLifecycle`, `createOrganizationExport` и `deleteOrganizationMember`; остальные — 409 `lifecycle_transition_forbidden` | mTLS-операции — 403 `organization_inactive`; `enrollAgent` — 401 `enrollment_token_invalid` | Только `organization_export`, `retention_purge` и `organization_delete` |
| deleted | 404 `not_found` | 401 `certificate_revoked`, пока хранится запись отзыва | — |

Hash и `revokedAt` сертификатов удалённой организации хранятся до `validTo` сертификата, tombstone — 12 месяцев. Отзыв назначения действует со следующего запроса, потому что членство проверяется на сервере. Создание, назначение, смена политики, экспорт, отключение и удаление выполняются только операциями контракта; произвольный SQL для этих действий запрещён (RB-10).

## Состояния проблем

`technicalState=open|resolved`; `workflowState=new|in_progress|risk_accepted|suppressed`. Finding создаётся только для режима `assessed`. Оценка в режиме `informational` всегда имеет `result=null` и finding не создаёт. В informational-оценку переносятся только причины, по которым данных нет: код недоступности наблюдения (код сборщика), `missing_observation`, `applicability_input_missing` и `clock_inconsistent` — `result=null` с той же причиной. Остальные причины правил (`unmapped_state`, `update_*`, `os_version_unknown`, `os_inventory_missing`, `evidence_time_invalid`, `policy_not_applicable`) informational-оценке не присваиваются: `result=null`, `reasonCode=null`. У assessed-оценки `reasonCode` допускается только при `result` unknown или not_applicable. Пороги warn и critical в правилах `03` дают `result=fail` и `Finding.severity` = `warning` или `critical`. `risk_accepted` означает, что риск реален и организация сознательно принимает его до `reviewAt`. `suppressed` означает, что срабатывание признано ложным или неприменимым для этой организации без изменения политики, до `reviewAt`. Оба решения требуют причины, сотрудника и срока пересмотра, права на них одинаковы. Они не превращают fail в pass и не повышают показатель соответствия. Очередь проблем по умолчанию — `technicalState=open&workflowState=new,in_progress`, то есть открытые проблемы без этих решений; фильтр `workflowState` принимает несколько значений через запятую и показывает в том числе решения о риске. Недельный отчёт показывает «принятые риски» и «подавленные срабатывания» раздельно.

Термины. «Правило» — глобальная логика проверки с `ruleId` и `ruleVersion`; таблица жизненного цикла ОС для SYS-002 относится к данным правила. «Политика» — параметры клиента в `policy_revision`. `rule_change` пишется только при смене `ruleVersion`, `policy_change` — только при смене `policy_revision`, в том числе при изменении окна свежести. `applicability_change` пишется только с eventType `resolved`, когда проверка стала not_applicable из-за фактов устройства в пакете (например, `editionId` из WIN-011 для WIN-002 или режим Defender для WIN-004) без смены `policy_revision`. Исправлением на устройстве считается только `resolved` с `cause=device_change`. Событий задним числом нет: поздний пакет и пакет с признаком часов не создают событий за прошлое. События уровня устройства пишутся в `audit_event` с `actorType=system`, а не в `finding_event`: `device.sequence_rollback`, `device.identity_conflict`, `device.identity_conflict_cleared`, `device.data_loss`, `device.reenroll_allowed`, `device.reenroll_over_active`, `device.enroll_identity_conflict`.

Свежесть задаётся `freshnessWindowHours` политики для каждой проверки, по умолчанию 72 ч от `observedAt`. Она вычисляется при чтении (на текущий момент) и при формировании отчёта (на `periodEnd`). Heartbeat обновляет `lastSeenAt`, но не свежесть оценок; устаревший pass показывается как прошлый результат с датой. Задание `freshness_sweep` раз в час пишет `quality_changed` только при переходе свежести открытого finding (идемпотентно) и записывает оценку SYS-001 при смене её значения. Сервер помечает оценку признаком `late`, если `receivedAt − completedAt` больше 24 ч; поздний пакет не отменяет более новое наблюдение.

Эпизоды WIN-007 вычисляются по истории наблюдений устройства: наблюдения с признаком часов в эпизод не входят, длительность записывается в explanation оценки как нижняя граница («наблюдается не менее N дней в текущем сеансе загрузки»), а снятие требования без перезагрузки внутри одного сеанса не обнаруживается. Правило эпизода записано в `03`.

### Таблица переходов finding

| Текущее | Свежий fail | Свежий pass | unknown или stale | not_applicable после смены ревизии политики | not_applicable после смены фактов устройства | Объект выведен |
| --- | --- | --- | --- | --- | --- | --- |
| Нет finding | Создать `open`, `new`, событие `opened` | Ничего | Ничего (видно на устройстве и в coverage) | Ничего | Ничего | Ничего |
| open | Без события; `quality_changed`, если раньше качество было не fresh | `resolved`; `workflowState` не меняется | Остаётся `open`; `quality_changed` только при смене качества | `resolved`, `policy_changed`/`policy_change` | `resolved`, `resolved`/`applicability_change` | `resolved`, `object_retired` |
| resolved | `reopened`; `workflowState=new`, если нет действующего решения (`reviewAt > now`) | Без события | Без события | Без события | Без события | Без события |

Результат not_applicable (`reasonCode=policy_not_applicable`) вычисляется по политике и фактам устройства вместе: например, WIN-002 — по `notApplicableEditionIds` политики и `editionId` из WIN-011. Поэтому колонки таблицы различают не результат, а то, что изменилось. Для открытой проблемы причина события зависит от изменившегося входа: новая ревизия политики — `policy_changed`/`policy_change`; новые факты устройства в пакете без смены `policy_revision` — `resolved`/`applicability_change`.

`cause` у `opened`, `resolved` и `reopened` соответствует триггеру: `device_change`, `rule_change` или `policy_change`; у `resolved` из-за неприменимости по фактам устройства — `applicability_change`. Если такая проверка снова применима и даёт fail, пишется `reopened` с `device_change`. Причины вывода объекта: отзыв устройства — `object_retired`/`manual_action`; исчезновение тома — `object_retired`/`device_change`; исключение проверки из `activeCheckIds` или перевод в informational — `policy_changed`/`policy_change`. Not applicable (после смены ревизии политики и после смены фактов устройства), удаление объекта, изменение политики и изменение правила не попадают в число исправлений устройством; недельный отчёт показывает их отдельными категориями.

### Автомат workflowState

| Переход | Кто | Как |
| --- | --- | --- |
| new ↔ in_progress | Technician, ServiceManager, PlatformAdmin | patchFinding |
| new или in_progress → risk_accepted или suppressed | ServiceManager, PlatformAdmin | decideFindingRisk |
| risk_accepted ↔ suppressed | ServiceManager, PlatformAdmin | decideFindingRisk |
| risk_accepted или suppressed → new | ServiceManager, PlatformAdmin | decideFindingRisk `withdrawn` |
| risk_accepted или suppressed → new | Система | Задание `review_expiry` при наступлении `reviewAt`, `workflow_changed`/`review_expired`, идемпотентно |
| Resolve | Система | `workflowState` не меняется |

`patchFinding` (Technician, ServiceManager, PlatformAdmin; `If-Match` обязателен) меняет независимые поля `workflowState` (`new` ↔ `in_progress`), `assigneeId` и `dueAt`; все поля необязательны, но нужно хотя бы одно. `assigneeId` должен быть членом организации с ролью ServiceManager или Technician, иначе 422 `validation_failed`. В состояниях `risk_accepted` и `suppressed` разрешено менять только `assigneeId` и `dueAt`, а передача `workflowState` даёт 409 `workflow_transition_forbidden`. Значения `risk_accepted` и `suppressed` в PATCH отклоняются схемой с 422 `schema_violation`. Изменения ответственного и срока пишутся в `audit_event`, а не в `finding_event`.

`decideFindingRisk` (ServiceManager, PlatformAdmin; `If-Match` обязателен) принимает `decision` (`risk_accepted`, `suppressed`, `withdrawn`), `reason` (1…1000) и `reviewAt`. `risk_accepted` и `suppressed` допускаются только при `technicalState=open` (иначе 409 `workflow_transition_forbidden`) и при `reviewAt` в диапазоне (now, now + 365 сут] (иначе 422 `validation_failed`). Переход между `risk_accepted` и `suppressed` выполняется новым решением. `withdrawn` возвращает `new` и допустим только из `risk_accepted` или `suppressed`, иначе 409 `workflow_transition_forbidden`; при нём `reason` необязателен, а `reviewAt` запрещён. Каждое решение пишет событие `workflow_changed`/`manual_action` с `actorId` и from/to и заполняет `Finding.workflowDecidedBy`; `RiskDecision.reason` сохраняется как `Finding.workflowReason`. Ответ обеих операций — Finding с новым ETag.

### Допустимые сочетания eventType и cause

| eventType | Допустимые cause | assessmentId |
| --- | --- | --- |
| opened | device_change, rule_change, policy_change | обязателен |
| resolved | device_change, rule_change, policy_change, applicability_change | обязателен |
| reopened | device_change, rule_change, policy_change | обязателен |
| quality_changed | data_quality | может быть null (переход в stale без новой оценки) |
| workflow_changed | manual_action, review_expired | null |
| policy_changed | policy_change | может быть null (без пересчёта) |
| object_retired | device_change, manual_action | null |

`fromWorkflowState` и `toWorkflowState` равны null, если workflow не менялся. Сочетание вне таблицы — дефект реализации, а не допустимое событие.

### Выбор текущего состояния

1. Историческая оценка выполняется по `policyVersion` пакета (`sourcePolicyVersion`); неизвестная или будущая версия даёт 422 `unknown_policy_version`.
2. Текущая проекция пары (объект, checkId) — последнее валидное наблюдение без признака часов, оценённое по действующей политике (`evaluatedPolicyVersion`, `assessmentScope=current`): факты от политики не зависят.
3. Проверка, которую требует новая политика, но которой нет в старом пакете, даёт unknown/`missing_observation`.
4. Изменение политики пересчитывает текущие проекции с `cause=policy_change`, смена `ruleVersion` — с `rule_change`; в исправления устройством эти события не входят.
5. Пакет заменяет проекцию, если его sequence больше и признака часов нет. При равном `observedAt` выигрывает больший sequence. Пакет с меньшим sequence пополняет только историю.

Текущее состояние не выбирается по `receivedAt`. Поздний офлайн-пакет пополняет историю, но не отменяет более новое наблюдение, а пакет с признаком часов сохраняется только исторически (подраздел «Время и часы устройства»).

## API агента

Контракт находится в [specs/openapi.json](specs/openapi.json). JSON Schema отдельно описывает пакет и observation. P1 принимает только Windows-наблюдения. Graph-данные создаёт отдельный Graph-компонент (P2), при варианте B факты импорта создаёт компонент импорта; из агента они не принимаются, Worker Graph-сертификатов не получает. API агента действует в варианте A; если gate SP-05 выбирает вариант B, Agent API, PKI и Issuer отпадают, а модель observation/assessment/finding остаётся той же (`07`).

| operationId | Метод и путь | Хост и доступ | Повтор и конкуренция | Успех |
| --- | --- | --- | --- | --- |
| enrollAgent | POST `/api/v1/agent/enroll` | Portal API; `Authorization: Enrollment <token>` | Идемпотентно по `registrationRequestId` + CSR: повтор возвращает исходный ответ, в том числе при исчерпанном токене | 201 DeviceCertificate |
| getAgentConfiguration | GET `/api/v1/agent/configuration` | Agent API; mTLS | Доступна агенту в `VersionBlocked`, `Suspended` и `TrustFailed` | 200 Configuration |
| submitHeartbeat | POST `/api/v1/agent/heartbeat` | Agent API; mTLS | — | 200 HeartbeatReceipt |
| submitScan | POST `/api/v1/agent/scans` | Agent API; mTLS | Заголовок `Idempotency-Key` = `scanId`; повтор по `payloadHash` | 202 ScanReceipt |
| renewDeviceCertificate | POST `/api/v1/agent/certificate/renew` | Agent API; действующий mTLS | Идемпотентно по `renewalRequestId` + CSR | 200 DeviceCertificate |

Bootstrap расположен на Portal API, остальные пути — на отдельном Agent API в собственном Container Apps environment; правила доверия XFCC описаны в `04`, раздел «Доверие ingress и XFCC». Серверная связь сертификата определяет device и organization. Agent API отклоняет OrganizationId/DeviceId в теле пакета как неизвестные поля (422 `schema_violation`). Выпуск и продление сертификата выполняет внутренний компонент Issuer: Portal API (enroll) и Agent API (renew) вызывают его, Issuer заново проверяет CSR, а сетевая схема выбирается по SP-02 (`04`, раздел «Граница ключа CA»).

`enrollAgent` принимает `registrationRequestId`, `installationId`, `displayName` (SAFE_TEXT, до 120), `csrPem` и `machineFingerprint` и возвращает `deviceId`, `certificatePem`, `notBefore`, `expiresAt`, `previousCertificateValidUntil` (при enroll null, в том числе при повторной регистрации) и `agentApiUrl`. Проверки выполняются в таком порядке; первая сработавшая определяет ответ.

1. Токен неизвестен, истёк или отозван либо организация не в статусе `active` — 401 `enrollment_token_invalid`.
2. Тот же `registrationRequestId` с тем же CSR — идемпотентный повтор: прежний ответ с прежним сертификатом, даже если токен уже исчерпан; `useCount` не увеличивается. Тот же `registrationRequestId` с другим CSR — 409 `idempotency_conflict`.
3. Токен исчерпан (`useCount` = `maxUses`) — 401 `enrollment_token_invalid`.
4. `installationId` не зарегистрирован — создаётся новое устройство.
5. Устройство с этим `installationId` отозвано — 409 `installation_already_enrolled`.
6. Признак машины не совпадает с зафиксированным для этого `installationId` — 409 `identity_conflict`; `identityState` существующего устройства не меняется, пишется аудит `device.enroll_identity_conflict`.
7. У устройства есть `active` сертификат с `validTo` > now (неактивированный `pending` не учитывается), а `reenrollAllowedUntil` не задан или истёк — 409 `installation_already_enrolled`.
8. Иначе тому же `deviceId` выдаётся новый сертификат, история сохраняется. С окном и без в транзакции выдачи увеличивается `useCount` токена, создаётся запись `enrollment`, как при создании устройства, а существующий неактивированный `pending` переводится в `revoked` (аудит `device.pending_revoked`). Если в случае (8) `reenrollAllowedUntil` > now, новый сертификат выдаётся как `pending`, перекрытие прежних `superseded` заканчивается в момент выдачи, прежний `active` переходит в `superseded` при первом mTLS-запросе новым, `reenrollAllowedUntil` обнуляется, пишется аудит `device.reenroll_over_active` и поднимается оповещение ServiceManager. Подробности — раздел «Канонический объект и идентичность устройства».

Агент сохраняет `registrationRequestId` и новый ключ до отправки `enroll`, так же как `renewalRequestId` при продлении, и после потери ответа повторяет запрос с тем же id.

Свойства токенов — `04`, раздел «Enrollment-токены».

`renewDeviceCertificate` принимает `renewalRequestId`, `csrPem` и `machineFingerprint`. `renewalRequestId` привязан к deviceId и csrHash: тот же id и CSR возвращают прежний сертификат, другой CSR — 409 `renewal_request_conflict`. Новый id при неактивированном pending отзывает этот pending. Pending-сертификат принимается сразу; первый успешный mTLS-запрос им переводит его в `active`, а предыдущий — в `superseded`. `previousCertificateValidUntil` при renew равен `validTo` предыдущего сертификата как верхней границе, а фактически предыдущий перестаёт приниматься через 24 ч после первого запроса новым. Агент сохраняет `renewalRequestId` и новый ключ до отправки запроса, так же как байты пакета. Профиль и сроки — `04`, раздел «Профиль и продление сертификата».

`getAgentConfiguration` возвращает `policyVersion`, `activeCheckIds` (WIN-*, уникальные, не больше числа WIN-* в каталоге), `scanIntervalHours`, `heartbeatIntervalHours`, `scanJitterMinutes`, `maxBatchBytes` (в P1 — 262144; сервер проверяет ту же границу), `maxBufferBytes`, `maxBufferDays`, `lastAcceptedSequence`, `minimumAgentVersion`, `pendingScanRequestId` и `renewBeforeExpiryHours` (production 1440, тестовый профиль 6). `submitHeartbeat` передаёт `observedAt`, `agentVersion`, `queueDepth`, `bufferBytes`, `droppedBatchCount` и `machineFingerprint`; время связи задаёт сервер. Heartbeat обрабатывается в таком порядке: идентичность, статус организации, признак машины, затем `lastSeenAt` = время сервера, расхождение часов и `clockStatus`; рост `droppedBatchCount` пишется в `device.data_loss`.

Пакет ограничен 262144 байтами (`maxBatchBytes`) до разбора JSON и 200 наблюдениями; прочие агентские запросы — 16 KiB. Сжатые запросы P1 не принимает (415). `Idempotency-Key` должен совпадать со `scanId`. Клиент использует устойчивый sequence из SQLite; ротация ключа его сохраняет. Отправитель сохраняет байты пакета до подтверждения; единственное исключение — перенумерация при ресинхронизации sequence. Потеря состояния установки требует чистой переустановки и новой регистрации.

Структура evidence каждой WIN-проверки задаётся только схемой `observation.schema.json`: она содержит закрытые объекты evidence и `subject` по checkId и является единственным источником структурных правил. Backend дополнительно проверяет межполевые и семантические инварианты из раздела «Инварианты вне JSON Schema». `collectionStatus` агента принимает только `collected` или `unavailable`; применимость вычисляет сервер по `policy_revision` и наблюдениям того же пакета, и наблюдение агента не может установить not_applicable. Сервер проверяет форматы uuid и date-time явно, не полагаясь на аннотацию `format` JSON Schema draft 2020-12.

### Порядок приёма пакета

`submitScan` проверяется в одном порядке; первая сработавшая проверка определяет ответ.

1. Транспорт, до разбора JSON: при `Content-Encoding` или чужом `Content-Type` — 415 `unsupported_media_type`; при размере больше 262144 байт (`maxBatchBytes`) — 413 `payload_too_large`.
2. Идентичность по правилам XFCC: 401 `certificate_expired`, `certificate_revoked` или `certificate_unknown`.
3. Статус организации: не `active` — 403 `organization_inactive`.
4. Повтор по (deviceId, `Idempotency-Key`) и SHA-256 сырых байтов. Совпадение возвращает исходный receipt (202, `duplicate=true`) независимо от возраста пакета и без повторной оценки. Другой hash — 409 `idempotency_conflict`. Метаданные повтора хранятся 90 дней.
5. Разбор: 400 `invalid_json`. Затем `agentVersion` — 422 `agent_version_unsupported`; `schemaVersion` — 422 `unsupported_schema_version`; полная схема (включая checkId вне каталога) и совпадение `scanId` с ключом — 422 `schema_violation`.
6. `machineFingerprint`: 409 `identity_conflict`.
7. Окно и время: 422 `batch_too_old` по `maxBatchAgeDays` действующей ревизии политики организации (не ревизии пакета) или 422 `batch_time_inconsistent` по `startedAt`, `completedAt` и `observations[].observedAt`; метки времени внутри evidence на этом шаге не проверяются.
8. Версия политики: 422 `unknown_policy_version`.
9. Sequence: тот же sequence с другим `scanId` — 409 `sequence_conflict`.
10. Семантика: `unknown_check_id` (checkId каталога вне `activeCheckIds` версии политики пакета), `duplicate_observation`, `unexpected_subject`, межполевые инварианты (`schema_violation`). Отказ атомарный, частичного сохранения нет.
11. В одной транзакции записываются `scan_batch` и задание `evaluate_batch`, затем отправляется ответ 202 `{duplicate: false, state: queued}`. Признак часов вычисляет worker при оценке; пакет из-за него не отклоняется.

### Уникальность и ожидаемые объекты

Канонический ключ наблюдения в пакете — `(checkId, subject.type, localKey)`. Повтор ключа даёт атомарный отказ 422 `duplicate_observation` независимо от порядка элементов. Ожидаемые пары задаёт `policyVersion` пакета. В P1 это `device` для каждой активной проверки из WIN-003…WIN-011 и ровно один `volume` с `role=os` для WIN-001 и для WIN-002. Лишний или другой объект даёт 422 `unexpected_subject`. Отсутствующая ожидаемая пара даёт unknown/`missing_observation` (в режиме informational — `result=null` с тем же `reasonCode`), даже если присланный пакет в остальном валиден. checkId вне каталога отклоняет схема (`schema_violation`), а checkId каталога вне `activeCheckIds` версии политики пакета — `unknown_check_id`.

### Время и часы устройства

Время в схемах агента — UTC RFC3339 с окончанием `Z` и секундами; в портальных схемах допускается смещение `±hh:mm`. `completedAt` не раньше `startedAt`, `observedAt` не позже `completedAt`, а `startedAt`, `completedAt` и `observations[].observedAt` не позже `receivedAt` + 5 мин; иначе 422 `batch_time_inconsistent`. Метки времени внутри evidence при приёме не проверяются: правила для них задаёт проверка в `03`, например у WIN-004 `signatureLastUpdatedAt` позже `observedAt` этого наблюдения даёт unknown/`evidence_time_invalid`, а пакет не отклоняется. Heartbeat обновляет доступность устройства, даже если пакеты отклоняются.

| Параметр | Значение | Правило |
| --- | --- | --- |
| `maxBufferDays` | По умолчанию 7, допустимо 1…30 | Агент удаляет пакеты старше окна; переполнение 100 МБ удаляет самые старые и увеличивает `droppedBatchCount` |
| `maxBatchAgeDays` | По умолчанию 9 (= `maxBufferDays` + 2), допустимо 2…32 | Параметр политики; при сохранении проверяется `≥ maxBufferDays + 1`, иначе 422 `schema_violation`. Окно берётся из действующей ревизии политики организации, а не из ревизии пакета. Возраст считается по `completedAt` относительно `receivedAt`; пакет старше окна получает 422 `batch_too_old` |
| Признак `late` | `receivedAt − completedAt` > 24 ч | Пишется в Assessment; поздний пакет не отменяет более новое наблюдение. Клиентского флага нет |
| Будущее время | Не больше `receivedAt` + 5 мин | Только `startedAt`, `completedAt` и `observations[].observedAt`, иначе `batch_time_inconsistent`; время в evidence — по правилу проверки в `03` |

Алгоритм часов единственный. Время источника пакета (`batchSourceTime`) равно `completedAt`. `maxAcceptedSourceTime` — максимум min(`completedAt`, `receivedAt` + 5 мин) по принятым пакетам без признака; ограничение сверху не даёт скачку часов вперёд заблокировать следующие пакеты. Пакет принимается с признаком `clock_inconsistent`, если выполнено одно из условий: а) `sequence > lastAcceptedSequence` и `completedAt < maxAcceptedSourceTime`; б) по последнему heartbeat расхождение `|observedAt − receivedAt|` больше 5 мин. Такой пакет сохраняется в истории, признак действует на все его оценки: assessed-оценки получают `result=unknown`, `reasonCode=clock_inconsistent`, informational-оценки — `result=null`, `reasonCode=clock_inconsistent`; все они получают `assessmentScope=historical`, текущая проекция не меняется. Правило зависимых проверок (`applicability_input_missing`) применяется, только если у пакета нет признака часов; если меняется качество открытого finding, пишется `quality_changed` с `cause=data_quality`, а прошлые записи не меняются. Признак вычисляется для каждого пакета и не хранится как режим устройства.

Восстановление после ошибки часов не требует ручной правки БД. `Device.clockStatus` становится `inconsistent` после пакета с признаком или heartbeat с расхождением и сам возвращается в `ok` после heartbeat с расхождением не больше 5 мин и пакета с `completedAt ≥ maxAcceptedSourceTime`.

### Ошибки и действия агента

Ошибки используют `application/problem+json`. Обязательные поля Problem: `type`, `title`, `status`, `code` и `correlationId`; необязательные — `detail` (до 1000 символов, без чувствительных данных), `instance` (до 500) и `minimumAgentVersion`; лишние поля запрещены, stack trace не передаётся. `title` и `detail` не локализуются: SPA показывает сообщение по `Problem.code` из своих ресурсов. Отказ в доступе не раскрывает существование чужих устройств.

Классификация 422. `schema_violation` — тело нарушает JSON Schema (включая if/then и зависимости полей) либо межполевой инвариант тела, который не зависит от состояния сервера и времени: `freeBytes` ≤ `totalBytes`, `maxBatchAgeDays ≥ maxBufferDays + 1`, `periodStart < periodEnd`. `validation_failed` — проверка зависит от состояния сервера или текущего времени. Специальные коды (`policy_inputs_missing`, `batch_time_inconsistent`, `duplicate_observation`, `unexpected_subject`, `unknown_check_id` и другие) имеют приоритет над общими.

Действия агента образуют закрытый перечень; каждое ведёт в состояние подраздела «Конечный автомат агента».

| Действие | Состояние | Что делает агент |
| --- | --- | --- |
| retry_after | Backoff | Повтор по `Retry-After`, не дольше 6 ч |
| retry_backoff | Backoff | Экспоненциальный backoff: база 30 с, множитель 2, потолок 60 мин, full jitter |
| drop_batch | Active | Удаляет пакет из SQLite и увеличивает `droppedBatchCount` в следующем heartbeat |
| refresh_configuration | Active | Запрашивает GET configuration перед следующей отправкой |
| resync_sequence | Active | Ресинхронизация sequence (раздел «Канонический объект и идентичность устройства») |
| restart_renewal | Active | Новый ключ и новый `renewalRequestId` |
| skip_request | Текущее (Active или Unenrolled) | Запрос отбрасывается, пишется локальная диагностика. Heartbeat — следующий по расписанию; renew и enroll повторяются не чаще раза в 24 ч |
| stop_until_upgrade | VersionBlocked | См. «Конечный автомат агента» |
| suspend_until_active | Suspended | См. «Конечный автомат агента» |
| reenroll_required | ReenrollRequired | См. «Конечный автомат агента» |
| await_new_token | Unenrolled | Ждёт новый токен из канала установки |
| trust_failure | TrustFailed | См. «Конечный автомат агента» |
| stop_until_reinstall | ReinstallRequired | См. «Конечный автомат агента» |
| identity_stop | IdentityConflict | См. «Конечный автомат агента» |

Каталог `Problem.code` закрыт: 36 кодов. `—` в колонке «Действие агента» означает код портала, который агент не получает.

| code | HTTP | Операции | Когда | Действие агента |
| --- | --- | --- | --- | --- |
| invalid_json | 400 | Все с телом | Тело не разбирается как JSON | submitScan: drop_batch; прочие агентские: skip_request |
| unsupported_media_type | 415 | Все с телом | Есть `Content-Encoding` или `Content-Type` не `application/json` | submitScan: drop_batch; прочие агентские: skip_request |
| payload_too_large | 413 | Все с телом | Больше лимита до разбора: scans 262144 байт (`maxBatchBytes`), прочие агентские 16 KiB, портал 64 KiB | submitScan: drop_batch; прочие агентские: skip_request |
| schema_violation | 422 | Все с телом (агент и портал) | Нарушение схемы или межполевого инварианта тела (классификация выше); `scanId` ≠ `Idempotency-Key`; checkId вне каталога | submitScan: drop_batch + refresh_configuration; прочие агентские: skip_request |
| unsupported_schema_version | 422 | submitScan | Неподдерживаемый `schemaVersion` | drop_batch + refresh_configuration |
| unknown_check_id | 422 | submitScan | checkId из каталога, но вне `activeCheckIds` версии политики пакета | drop_batch + refresh_configuration |
| unexpected_subject | 422 | submitScan | Объект не ожидается политикой | drop_batch + refresh_configuration |
| duplicate_observation | 422 | submitScan | Повтор канонического ключа | drop_batch |
| unknown_policy_version | 422 | submitScan | `policyVersion` неизвестна или из будущего | drop_batch + refresh_configuration |
| batch_too_old | 422 | submitScan | `completedAt` < `receivedAt − maxBatchAgeDays` по действующей ревизии политики организации | drop_batch |
| batch_time_inconsistent | 422 | submitScan | `completedAt < startedAt`, `observedAt > completedAt` или `startedAt`, `completedAt` либо `observedAt` позже `receivedAt` + 5 мин | drop_batch |
| agent_version_unsupported | 422 | submitScan | `agentVersion < minimumAgentVersion`; поле `minimumAgentVersion` заполнено | stop_until_upgrade |
| idempotency_conflict | 409 | enrollAgent; submitScan; портальные операции с `idempotencyKey` | Тот же ключ, другое тело (для enrollAgent — тот же `registrationRequestId` с другим CSR) | enrollAgent: reenroll_required; submitScan: drop_batch |
| sequence_conflict | 409 | submitScan | Тот же `sequence` с другим `scanId`; ресинхронизация не чаще раза в 24 ч | resync_sequence |
| identity_conflict | 409 | enrollAgent, submitScan, submitHeartbeat, renewDeviceCertificate | `machineFingerprint` не совпадает с зафиксированным (при enroll — для уже зарегистрированного неотозванного `installationId`) либо второй `sequence_conflict` за 24 ч | identity_stop |
| organization_inactive | 403 | getAgentConfiguration, submitHeartbeat, submitScan, renewDeviceCertificate | Организация устройства в статусе `disabled` или `deletion_scheduled` | suspend_until_active |
| certificate_expired | 401 | Агентские mTLS-операции | Сертификат истёк (если запрос дошёл до приложения) либо зарегистрированный сертификат устройства в состоянии `superseded` после окончания перекрытия, например у восстановленного образа старше ротации; во втором случае (в том числе если наступил и `validTo`) сервер в той же транзакции записывает `device.reenrollAllowedUntil` = now + 7 суток | reenroll_required |
| certificate_revoked | 401 | Агентские mTLS-операции | Отозван сертификат или устройство, в том числе при удалении организации | stop_until_reinstall |
| certificate_unknown | 401 | Агентские mTLS-операции | Нет XFCC, XFCC продублирован, не совпадает Hash, чужой CA или hash не зарегистрирован | trust_failure |
| renewal_request_conflict | 409 | renewDeviceCertificate | Тот же `renewalRequestId` с другим CSR | restart_renewal |
| enrollment_token_invalid | 401 | enrollAgent | Токен неизвестен, истёк, отозван или исчерпан, либо организация не `active` | await_new_token |
| installation_already_enrolled | 409 | enrollAgent | `installationId` принадлежит отозванному устройству, либо у устройства есть `active` сертификат с `validTo` > now, а `reenrollAllowedUntil` не задан или истёк; идентичный повтор проверяется раньше; для случая с действующим сертификатом раньше проверяется и несовпадающий признак машины (порядок — раздел «API агента») | stop_until_reinstall |
| rate_limited | 429 | Все | Лимит запросов | retry_after |
| temporarily_unavailable | 503 | Все | Временный отказ | retry_after; без Retry-After: retry_backoff |
| session_required | 401 | Портал | Нет сессии или она недействительна | — |
| csrf_failed | 403 | Мутации портала | Нет CSRF-токена или он неверен | — |
| forbidden | 403 | Портал | Роли недостаточно для действия в доступной организации | — |
| not_found | 404 | Портал | Сущность отсутствует, принадлежит недоступной организации или организация удалена | — |
| invalid_cursor | 400 | list-операции | Cursor не связан с этой организацией и фильтром либо повреждён | — |
| revision_mismatch | 412 | patchFinding, decideFindingRisk, createPolicyRevision | Устаревший `If-Match` | — |
| if_match_required | 428 | patchFinding, decideFindingRisk, createPolicyRevision | `If-Match` отсутствует | — |
| workflow_transition_forbidden | 409 | patchFinding, decideFindingRisk | Недопустимый переход (подраздел «Автомат workflowState») | — |
| lifecycle_transition_forbidden | 409 | changeOrganizationLifecycle; мутации в неактивной организации | Недопустимый переход жизненного цикла или мутация, запрещённая в текущем статусе (раздел «Жизненный цикл организации») | — |
| resource_not_ready | 409 | downloadReport, downloadOrganizationExport | Состояние не `ready` | — |
| validation_failed | 422 | Мутации портала | Проверка по состоянию или времени: ответственный не член организации; `reviewAt` вне (now, now + 365 сут]; `periodEnd` позже текущего момента | — |
| policy_inputs_missing | 422 | createPolicyRevision | Режим `assessed` без обязательных входных настроек; в `activeCheckIds` нет WIN-011; активна WIN-004 без WIN-003 (подраздел «Политика клиента») | — |

Допустимые HTTP-статусы: 400, 401, 403, 404, 409, 412, 413, 415, 422, 428, 429, 503. Наборы ответов по операциям: `enrollAgent` — {400, 401, 409, 413, 415, 422, 429, 503}; `getAgentConfiguration` — {401, 403, 429, 503}; `submitHeartbeat`, `submitScan` и `renewDeviceCertificate` — {400, 401, 403, 409, 413, 415, 422, 429, 503}; портальные GET — {400, 401, 403, 404, 429, 503}, плюс 409 только у `downloadReport` и `downloadOrganizationExport`; портальные мутации — {400, 401, 403, 404, 409, 422, 429, 503}, плюс 413 и 415 только при теле запроса, плюс 412 и 428 только при обязательном `If-Match`. У GET никогда нет 412, 413, 415 и 428. `Retry-After` объявлен у 429 и 503. Два вида 409 при приёме пакета различаются по `code`: `idempotency_conflict` — тот же ключ с другим телом, `sequence_conflict` — тот же sequence с другим `scanId`.

### Конечный автомат агента

| Состояние | Вход | Поведение | Выход |
| --- | --- | --- | --- |
| Unenrolled | Установка; `await_new_token` | Ждёт токен из канала установки; после `skip_request` повторяет enroll не чаще раза в 24 ч | Успешный enroll → Active |
| Active | — | Сбор и отправка; `drop_batch`, `refresh_configuration`, `resync_sequence`, `restart_renewal` и `skip_request` выполняются внутри состояния | — |
| Backoff | `retry_after`, `retry_backoff`; сетевые ошибки; обрыв TLS при действующем локальном сертификате | Повтор по действию; heartbeat продолжается по расписанию | Успешный запрос → Active |
| VersionBlocked | `stop_until_upgrade` | scans не отправляются; heartbeat и GET configuration продолжаются; буфер хранится до `maxBufferDays` | Обновление до версии ≥ `minimumAgentVersion` → Active |
| Suspended | `suspend_until_active` | Сбор, scans, heartbeat и renew приостановлены; GET configuration раз в 24 ч; буфер хранится до `maxBufferDays` | 200 на GET configuration → Active и догоняющий сбор; `certificate_revoked` → ReinstallRequired; `certificate_expired` → ReenrollRequired |
| TrustFailed | `trust_failure` | mTLS-вызовы прекращаются, кроме GET configuration раз в 24 ч; буфер хранится до `maxBufferDays`; пишется локальная диагностика. Сервер считает `certificate_unknown` по часам и оповещает Operations о всплеске (RB-01) | 200 на GET configuration → Active; `certificate_revoked` → ReinstallRequired; `certificate_expired` → ReenrollRequired |
| ReenrollRequired | `reenroll_required`; обрыв TLS при истёкшем локальном сертификате | mTLS-вызовов нет; буфер хранится | Новый токен из канала установки → enroll → Active |
| ReinstallRequired | `stop_until_reinstall` | Без повторов, только локальный журнал | Чистая переустановка (новый `installationId`) |
| IdentityConflict | `identity_stop` | Остановка, локальный журнал | Решение ServiceManager по RB-03; для клона — чистая переустановка |

`resync_sequence` выполняется внутри Active, `restart_renewal` даёт новый ключ и новый `renewalRequestId`. Поведение ingress при истёкшем, отозванном и неизвестном сертификате — Problem-ответ или обрыв TLS-рукопожатия — устанавливает SP-02; автомат обрабатывает оба варианта: обрыв TLS при действующем локальном сертификате ведёт в Backoff, при истёкшем — в ReenrollRequired.

### Поведение клиента при нагрузке

Плановый сбор начинается в момент слота плюс случайная задержка из [0, `scanJitterMinutes`]. Догоняющий сбор после включения и heartbeat тоже получают случайную задержку, а запрос `verify_remediation` выполняется без неё. На 429 и 503 агент соблюдает `Retry-After` (не дольше 6 ч), без заголовка применяет экспоненциальный backoff с full jitter и потолком 60 мин; сетевые ошибки обрабатываются так же. Буфер отправляется последовательно по sequence.

## API портала

Portal API использует серверную сессию (`PortalSession`), назначение клиента или платформенную роль и CSRF (`CsrfToken`) для изменений. List endpoints возвращают cursor pagination, максимум 100 записей; cursor связан с организацией и фильтром, чужой или повреждённый cursor даёт 400 `invalid_cursor`. Изменения finding и политики выполняются с обязательным `If-Match`: устаревшая ревизия даёт 412 `revision_mismatch`, отсутствующий заголовок — 428 `if_match_required`. Тело портального запроса ограничено 64 KiB. Префикс `{org}` в таблице означает `/api/v1/organizations/{organizationId}`. Роли: PA — PlatformAdmin, SM — ServiceManager, T — Technician; права ролей описаны в `04`, раздел «Вход в портал и роли». PlatformAdmin — платформенная роль, а не членство: он читает и меняет данные всех клиентов, и каждый его доступ к данным клиента пишет `audit_event`.

| operationId | Метод и путь | Роли | Повтор и конкуренция | Успех |
| --- | --- | --- | --- | --- |
| listOrganizations | GET `/api/v1/organizations` | PA, SM, T | cursor; SM и T видят только назначенные организации | 200 OrganizationPage |
| createOrganization | POST `/api/v1/organizations` | PA | Создаёт `policy_revision` v1 по умолчанию | 201 Organization |
| updateOrganization | PATCH `{org}` | PA, SM | Хотя бы одно поле; последняя запись выигрывает, аудит | 200 Organization |
| listOrganizationMembers | GET `{org}/members` | PA, SM, T | cursor; нужно для выбора ответственного | 200 OrganizationMemberPage |
| putOrganizationMember | PUT `{org}/members/{entraUserId}` | PA | PUT идемпотентен | 200 OrganizationMember |
| deleteOrganizationMember | DELETE `{org}/members/{entraUserId}` | PA | Повтор → 204 | 204 |
| listPolicyRevisions | GET `{org}/policy-revisions` | PA, SM, T | cursor | 200 PolicyRevisionPage |
| createPolicyRevision | POST `{org}/policy-revisions` | PA, SM | `If-Match` (обязателен) = `"<текущая версия>"` | 201 PolicyRevision + ETag |
| changeOrganizationLifecycle | POST `{org}/lifecycle` | PA | `idempotencyKey` в теле; переходы — раздел «Жизненный цикл организации» | 202 Organization |
| createOrganizationExport | POST `{org}/exports` | PA | `idempotencyKey` в теле | 202 OrganizationExport |
| getOrganizationExport | GET `{org}/exports/{exportId}` | PA | — | 200 OrganizationExport |
| downloadOrganizationExport | GET `{org}/exports/{exportId}/download` | PA | `x-audit-read: always` | 200 `application/zip` |
| listAuditEvents | GET `{org}/audit-events` | PA | cursor; `x-audit-read: always` | 200 AuditEventPage |
| createEnrollmentToken | POST `{org}/enrollment-tokens` | PA, SM | Каждый вызов выдаёт новый секрет | 201 EnrollmentToken |
| listEnrollmentTokens | GET `{org}/enrollment-tokens` | PA, SM | cursor, без секрета | 200 EnrollmentTokenSummaryPage |
| revokeEnrollmentToken | POST `{org}/enrollment-tokens/{tokenId}/revoke` | PA, SM | Идемпотентно; сначала журнал | 204 |
| listDevices | GET `{org}/devices` | PA, SM, T | cursor; фильтр `enrollmentTokenId` | 200 DevicePage |
| updateDevice | PATCH `{org}/devices/{deviceId}` | PA, SM | Последняя запись выигрывает, аудит | 200 Device |
| revokeDevice | POST `{org}/devices/{deviceId}/revoke` | PA, SM | Идемпотентно; сначала журнал | 204 |
| requestDeviceScan | POST `{org}/devices/{deviceId}/scan-requests` | PA, SM, T | `idempotencyKey`, срок 24 ч, один незавершённый запрос на устройство; только вариант A | 202 ScanRequest |
| listDeviceAssessments | GET `{org}/devices/{deviceId}/assessments` | PA, SM, T | cursor; `Accept-Language` | 200 AssessmentPage |
| listFindings | GET `{org}/findings` | PA, SM, T | Фильтры `technicalState`, `freshness`, `deviceId`, `workflowState` (несколько значений через запятую, `style=form`, `explode=false`); `Accept-Language` | 200 FindingPage |
| getFinding | GET `{org}/findings/{findingId}` | PA, SM, T | `Accept-Language` | 200 Finding + ETag |
| patchFinding | PATCH `{org}/findings/{findingId}` | PA, SM, T | `If-Match` обязателен; `Accept-Language` | 200 Finding + ETag |
| decideFindingRisk | POST `{org}/findings/{findingId}/risk-decisions` | PA, SM | `If-Match` обязателен; `Accept-Language` | 200 Finding + ETag |
| listFindingEvents | GET `{org}/findings/{findingId}/events` | PA, SM, T | cursor | 200 FindingEventPage |
| listReports | GET `{org}/reports` | PA, SM, T | cursor | 200 ReportPage |
| createReport | POST `{org}/reports` | PA, SM | — | 202 Report |
| downloadReport | GET `{org}/reports/{reportId}/download` | PA, SM, T | `x-audit-read: always` | 200 только `text/html` |

Каждая мутация портала пишет аудит: создание, отключение и удаление организации и изменения `platform_role` — в `platform_audit_event`, остальные мутации — в `audit_event` организации; повтор с тем же `idempotencyKey` возвращает прежний результат, а тот же ключ с другим телом даёт 409 `idempotency_conflict`. Расширение `x-audit-read` есть у каждого портального GET и принимает одно из двух значений: `always` — каждое чтение пишет `audit_event` для любой роли (`downloadOrganizationExport`, `listAuditEvents` и `downloadReport`); `platform_admin` — чтение пишет `audit_event`, только если у субъекта есть `platform_role`, даже при наличии членства в организации (все остальные портальные GET). `listOrganizations` работает через функцию входа в контекст с теми же правилами. Кто создаёт организации в P1, решает вопрос 14 в `08`; по умолчанию — только PlatformAdmin. `createOrganization` требует `name`, `timezone` и `reportLanguage`; `updateOrganization` меняет любое из этих полей. `updateOrganization` введена потому, что без неё нельзя изменить `reportLanguage`.

Enrollment-токен создаётся в режиме `single_use` (срок — платформенный параметр, по умолчанию 30 мин, `maxUses` 1) или `batch` (`expiresInHours` 1…168, `maxUses` 1…100); `expiresInHours` и `maxUses` допустимы только при `batch`, необязательный `label` — SAFE_TEXT до 120 символов. Секрет показывается один раз в ответе `createEnrollmentToken` и в списке не возвращается. Устройства, зарегистрированные токеном, отбираются фильтром `listDevices?enrollmentTokenId=…`; массовый отзыв — RB-12. `updateDevice` принимает только `displayName` (SAFE_TEXT, 1…120). Отзыв устройства отзывает все его сертификаты, включая pending, и запрещает renew; finding устройства получают `resolved` с `object_retired`/`manual_action`.

Языковые заголовки. `listDeviceAssessments`, `listFindings`, `getFinding`, `patchFinding` и `decideFindingRisk` принимают необязательный заголовок `Accept-Language` со значениями `nb`, `nn` или `en`; без заголовка или при другом значении используется nb, ошибки нет. Ответ 200 содержит `Content-Language`. На выбранном языке API отдаёт `Finding.title`, `Finding.recommendation` и `Assessment.explanation`; идентификаторы, коды, evidence и `Problem` не локализуются. Если перевода нет, API отдаёт текст на nb с `Content-Language: nb`, а SPA помечает его «перевод отсутствует».

Запрос повторной проверки (`requestDeviceScan`, FR-06) действует только в варианте A. Он хранится сущностью `scan_request` (раздел «Сущности и ограничения») и имеет idempotencyKey, срок 24 часа и только известное действие `verify_remediation`. Состояния: `requested` после создания, `delivered` после выдачи `pendingScanRequestId` в конфигурации, `completed` после сохранения пакета с этим `scanRequestId`, `expired` по истечении `expiresAt`. Агент видит `pendingScanRequestId` в конфигурации, которую запрашивает при старте и не реже heartbeat. Повторную проверку агент выполняет как полный сбор: пакет содержит наблюдения всех проверок из `activeCheckIds` своей `policyVersion`, как плановый сбор, и отличается только `scanRequestId` и отсутствием случайной задержки; частичных пакетов нет. Результат включает `scanRequestId`; сервер проверяет принадлежность запроса устройству и его срок. Пакет с чужим или просроченным `scanRequestId` принимается как обычный сбор: `scanRequestId` игнорируется, пишется запись диагностики, новых кодов ошибок нет. Если повторная проверка показывает, что проблема исправлена, finding получает `resolved` с `device_change`. Офлайн-устройство не обещает немедленную проверку: задание `scan_request_expiry` раз в час отмечает истёкшие запросы как `expired`. Один незавершённый запрос на устройство объединяет повторные запросы; произвольные команды отсутствуют. Запись `scan_request` хранится 90 суток от `createdAt`.

Операции интеграций P2 описываются отдельным расширением после P0. Контракт P1 не допускает секретов в браузере, shell command и прямого изменения системных политик. Загрузка отчёта и экспорта идёт через авторизованный backend; Blob-контейнер приватный, постоянные публичные ссылки отсутствуют. `downloadReport` отвечает с заголовками `Content-Type: text/html; charset=utf-8`, `Content-Disposition: attachment; filename="report-<reportId>.html"`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:` и `Cache-Control: private, no-store`. `downloadOrganizationExport` отдаёт `application/zip` как attachment с `nosniff` и `no-store`. До состояния `ready` обе выдачи отвечают 409 `resource_not_ready`. CSP самого SPA и правила вывода недоверенных строк описаны в `04`, раздел «Недоверенные строки и выдача отчёта».

Ошибки портала используют тот же каталог `Problem.code` (подраздел «Ошибки и действия агента»): 401 `session_required`, 403 `csrf_failed` или `forbidden`, 404 `not_found` для сущности недоступной организации, 409 с кодом конфликта, 412 и 428 для `If-Match`, 413 и 415 для тела, 422 `schema_violation`, `validation_failed` или `policy_inputs_missing`, 429 и 503 с `Retry-After`.

## Отчёт и покрытие

В P1 отчёт формируется только в HTML: `ReportCreate.format` и `Report.format` принимают единственное значение `html`, а `downloadReport` отдаёт только `text/html`. Отчёт самодостаточен — без скриптов и внешних ресурсов, с print stylesheet; PDF клиент получает печатью из браузера. Серверный PDF рассматривается после пилота при подтверждённой потребности (условие пересмотра в `08`).

Язык отчёта задаётся для каждой организации полем `Organization.reportLanguage` (nb, nn, en); оно обязательно при создании и меняется через `updateOrganization`. `Report.language` фиксируется при генерации, смешения языков нет. Если перевода правила нет, отчёт получает `state=failed` и `failureCode=translation_missing`; сбой генерации по иной причине даёт `state=failed` и `failureCode=generation_error`; резервный язык в отчёте не используется до ответа на вопрос 13 в `08`. Портал по умолчанию работает на bokmål (nb), пользователь переключает язык на nb, nn или en; выбор хранится в браузере и не меняет API, а язык отчёта от него не зависит. Строки портала и отчёта с первого дня хранятся во внешних ресурсах. Тексты правил (title, recommendation, шаблоны explanation) — локализованные шаблоны по (`ruleId`, `ruleVersion`, язык); идентификаторы, коды и evidence не переводятся. До ответа на вопрос 13 в `08` новая `ruleVersion` вводится в действие только с текстами на nb, nn и en.

Период отчёта — ISO-неделя с понедельника 00:00 по понедельник 00:00 в timezone организации (`Organization.timezone`, обязательна при создании; портал предлагает Europe/Oslo); UTC-границы хранятся. Свежесть и `coverageAt` в отчёте считаются на `periodEnd`. Задание `weekly_report` создаёт отчёт автоматически; в P1 отчёт доставляется только через портал. Содержание: новые проблемы (`opened` и `reopened` с `device_change`); действительно исправленные (`resolved` с `device_change`); продолжающиеся; решения о риске: «принятые риски» (`risk_accepted`) и «подавленные срабатывания» (`suppressed`) раздельно; изменения правил, изменения политики и «стали неприменимыми по фактам устройства» (`resolved` с `applicability_change`) — отдельными категориями, ни одна из них не считается исправлением на устройстве; выведенные объекты; недоступные данные с причинами; счётчики informational, not_applicable и «не настроено политикой»; устройства без свежего полного сбора (SYS-001) и `lastSeenAt`; `coveragePeriod`, `coverageAt` на `periodEnd`, доля stale и compliance; число активных устройств, дата измерения и источник данных (агент или импорт). Отчёт за период старше 90 дней строится из `assessment.basisSnapshot` и `finding_event`. Опубликованные отчёты не пересчитываются; истёкшие подробности помечаются «подробности удалены по сроку хранения».

Определения. Обязательная проверка — checkId, у которого в действующей `policy_revision` режим `assessed`; агентская проверка, кроме того, должна входить в `activeCheckIds`. SYS-002 обязательна, если её режим `assessed`; SYS-001 всегда informational и в coverage и compliance не входит. Активное устройство — `status=active`, зарегистрированное до момента измерения или до конца периода. «Не настроено политикой» — подмножество informational: пары в режиме informational из-за отсутствующих входных настроек политики (например, WIN-008 без `allowedSids`, WIN-010 без `expectedTenantId`); в отчёте этот счётчик показывается как часть informational. Полный сбор — принятый пакет, в котором есть наблюдение для каждой проверки из `activeCheckIds` своей `policyVersion` (с любым `collectionStatus`, включая `unavailable`), без признака часов. Агент выполняет повторную проверку как полный сбор всех `activeCheckIds`; частичных пакетов агент не отправляет. `device.lastFullScanAt` обновляет только полный сбор; оценку SYS-001 пересчитывают приём полного сбора и задание `freshness_sweep`.

- **Покрытие на момент t** (`coverageAt`) = свежие pass и fail по обязательным применимым парам (объект, проверка) активных устройств / все обязательные применимые пары на момент t.
- **Покрытие периода** (`coveragePeriod`) = пары, у которых есть хотя бы одна определённая оценка без признака часов с `observedAt` внутри периода / обязательные применимые пары устройств, активных в периоде, по политике на конец периода.
- **Compliance** = свежие pass / (свежие pass + свежие fail) на момент; при нулевом знаменателе выводится «нет данных».

Informational исключаются из числителя и знаменателя, not_applicable — из знаменателя; обе группы показываются отдельными счётчиками, «не настроено политикой» — как часть informational. Принятые риски остаются fail в compliance. NFR-02 и критерий достоверности пилота используют `coveragePeriod` за неделю. В недельном отчёте основной показатель — `coveragePeriod`; отдельно показываются `coverageAt` на `periodEnd`, доля stale и число устройств без свежего полного сбора. Портал показывает `coverageAt` на текущий момент. Backend и отчёт используют одну функцию расчёта.

Пример. Обязательные проверки: WIN-001, WIN-002, WIN-005, SYS-002. WIN-008, WIN-011 и SYS-001 — informational; WIN-011 и SYS-001 informational всегда, WIN-008 — потому что `allowedSids` пуст. Для Home WIN-002 — not_applicable (по `editionId` из WIN-011), а SYS-002 — fail: редакция Home вне матрицы совместимости P1. У WIN-005 в примере окно свежести 24 ч, а последний полный сбор D1 был 30 ч назад; у остальных проверок, включая WIN-011, по которой вычисляется SYS-002, окно 72 ч.

| Устройство | WIN-001 | WIN-002 | WIN-005 | SYS-002 |
| --- | --- | --- | --- | --- |
| D1 (Pro) | pass, свежий | fail, свежий | pass, stale | pass |
| D2 (Pro) | unknown (`permission_denied`) | pass, свежий | pass, свежий | pass |
| D3 (Home) | pass, свежий | not_applicable | fail, свежий | fail |

Результат: знаменатель 11, числитель 9, `coverageAt` = 81,8%. Compliance = 6/9 = 66,7%. Счётчики: informational 9 (WIN-008, WIN-011 и SYS-001 на трёх устройствах), из них «не настроено политикой» 3 (WIN-008 на трёх устройствах), not_applicable 1, stale 1, unknown 1, устройств без свежего полного сбора 0.

Informational, not applicable и принятые риски не скрывают недостаток покрытия. Compliance не интерпретируется как вероятность безопасности и не сравнивается между разными версиями политик без пояснения.

## Инварианты вне JSON Schema

JSON Schema и OpenAPI задают структуру: evidence-структуры каждой проверки записаны только в схеме наблюдения. Правила, которые зависят от нескольких полей, от состояния сервера, от времени или от нескольких наблюдений, проверяет backend, и каждое из них записано в реестре [specs/invariants.json](specs/invariants.json). Запись реестра содержит `id` (`INV-nnn`), `rule`, `sourceDoc` (файл и раздел документа пакета), `phase` (P1 или P2), `enforcement` (schema, agent_api, portal_api, worker, db_rls, agent, infra), `negativeExample`, `expectedError` и `acceptance` (сценарий из `07`). `expectedError` описывает ожидаемый отказ или эффект в одной из форм: HTTP-статус и `Problem.code`; результат оценки и `reasonCode`; допустимая пара `eventType` и `cause`; действие аудита; повтор без второго эффекта; состояние автомата агента; 0 строк для RLS; статус возможности интеграции для P2.

Примеры правил вне схемы: `freeBytes` ≤ `totalBytes`; `maxBatchAgeDays ≥ maxBufferDays + 1`; `periodStart < periodEnd`; уникальность канонического ключа внутри пакета и ожидаемые пары объектов; межпроверочная применимость WIN-002 и WIN-004; окна времени, признак часов и выбор текущего состояния; допустимые сочетания `eventType` и `cause`; переходы finding, `workflowState` и жизненного цикла организации; идемпотентность enroll, renew, scans и портальных операций с `idempotencyKey`; аудит доступа PlatformAdmin и чтений с `x-audit-read: always`; fencing заданий и RLS без контекста организации. Каждое новое текстовое правило в `01`, `03`, `04` или `05`, которое не выражается схемой, получает запись в реестре инвариантов; реестр подчинён этим документам, и расхождение с ними — дефект пакета.

Встроенная проверка пакета поддерживает только используемое подмножество JSON Schema и не заменяет стандартные валидаторы. Полная стандартная проверка OpenAPI и JSON Schema, пробная генерация клиентов C# и TypeScript и CI — первый результат WP-01. До неё сервер проверяет форматы uuid и date-time явно.
