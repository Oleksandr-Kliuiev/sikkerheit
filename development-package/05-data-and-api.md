# Модель данных и HTTP API

Организация, объект проверки и облачная идентичность имеют разные ключи. Пользователь Microsoft 365 определяется object id в tenant клиента, устройство — `deviceId`, который создаёт сервер при регистрации агента. Имя ПК и UPN уникальными ключами не служат. Контракт — 45 операций (29 для P1, 16 для P2) в [specs/openapi.json](specs/openapi.json); этап операции задаёт расширение `x-phase`. Правила, которые не выражаются JSON Schema, перечислены в разделе «Инварианты вне JSON Schema» и в реестре [specs/invariants.json](specs/invariants.json).

## Сущности и ограничения

| Сущность | Ключевые данные | Ограничение |
| --- | --- | --- |
| organization | id, name, timezone, reportLanguage (nb, nn, en), status (active, disabled, deletion_scheduled), deletionDueAt, nextPolicyVersion, createdAt | Клиентский контекст. `timezone` — зона IANA, обязательна при создании; неизвестная зона — 422 `validation_failed`. `deletionDueAt` заполнено только в `deletion_scheduled`. Удалённая организация оставляет tombstone (id, deletedAt) и в API не отдаётся |
| staff_user | entraUserId, displayName, roles, lastSignInAt, active | Платформенная таблица: сотрудники, входившие в портал; роли берутся из app roles токена при входе и обновлении сессии. `active` — вход за последние 30 дней и последнее обновление сессии не отклонено Entra. Ответственным можно назначить только активного сотрудника с ролью Admin или Technician |
| policy_revision | organizationId, version, effectiveFrom, createdAt, createdBy, configuration | Неизменяема; хранится, пока на неё ссылаются сохраняемые записи, но не меньше 12 месяцев. Номер следующей версии хранит организация; после восстановления базы он переходит на следующую эпоху (`06`, «Резервное копирование и восстановление»). Структура — подраздел «Политика клиента» |
| tenant_connection | organizationId, status (not_connected, consent_pending, active, disconnected), entraTenantId, tenantDisplayName, primaryDomain, pendingTenantId, pendingExpiresAt, entraP1, connectedAt, connectedBy, disconnectedAt, lastCollectedAt, lastCollectionState | Одна на организацию. `entraTenantId` уникален среди подключений `active` всех организаций (частичный уникальный индекс). Автомат — раздел «Подключение M365 и сбор» |
| idempotency_record | organizationId, operationId, key, requestHash, responseStatus, resultId, createdAt, expiresAt | Повтор операций портала с `idempotencyKey`: тот же ключ и `requestHash` в течение 24 часов возвращают прежний результат, тот же ключ с другим телом — 409 `idempotency_conflict`. Удаляется через 7 суток |
| collection_run | organizationId, id, trigger (scheduled, manual), state (queued, running, completed, partial, failed), queuedAt, startedAt, completedAt, failureCode, capabilities, usersComplete | Не больше одного запуска в `queued` или `running` на организацию (частичный уникальный индекс) |
| subject | organizationId, id, type (tenant, user, device, volume), key, displayName, deviceId, firstSeenAt, lastSeenAt, retiredAt | Unique(organizationId, type, key). Ключ — подраздел «Субъекты и идентичность устройства». `displayName` — UPN пользователя или имя ПК, недоверенная строка |
| device | organizationId, id, displayName, status (active, revoked), installationId, machineFingerprintHash, publicKeyJwk, keyThumbprint, keyProtection, identityState, identityConflictAt, conflictKind (fingerprint, key), conflictFingerprintHash, conflictPublicKeyJwk, conflictDisplayName, clockStatus, enrollmentKeyId, enrolledAt, lastSeenAt, lastFullScanAt, lastAcceptedSequence, projectionSequence, projectionCompletedAt, agentVersion, configSchemaVersion, telemetry, rebootEpisodeSince, rebootEpisodeBootAt | P2. `installationId` уникален среди неудалённых устройств организации, включая отозванные; `keyThumbprint` уникален глобально. Строка устройства — точка сериализации приёма пакетов и заданий по субъектам устройства (`SELECT … FOR UPDATE`). `telemetry` — счётчики последнего check-in. Признак `dormant` в API вычисляется: последний check-in старше 14 суток |
| device_presence | organizationId, deviceId, day | P2. Unique(deviceId, day): сутки UTC, в которые был check-in или принятый пакет. Основа знаменателя покрытия Windows за период и NFR-02 |
| revoked_installation | organizationId, installationId, keyThumbprint, deviceId, revokedAt, source (revoke, restore_replay) | P2. Unique(organizationId, installationId). Создаётся при каждом отзыве устройства, а при повторе журнала безопасности — и тогда, когда строки устройства в восстановленной базе нет. `enrollAgent` отклоняет такой `installationId` |
| enrollment_key | organizationId, id, keyHash, keyPrefix, label, createdAt, createdBy, revokedAt, lastUsedAt | P2. Хранится SHA-256 ключа; активных (без `revokedAt`) не больше двух на организацию — для ротации |
| enrollment | organizationId, id, registrationRequestId, enrollmentKeyId, deviceId, requestHash, response, createdAt | P2. Unique(organizationId, registrationRequestId); основа идемпотентного повтора регистрации в течение 24 часов |
| agent_challenge | nonceHash, purpose (enroll, session), deviceId, expiresAt, usedAt | P2, платформенная: только погашенные nonce, unique(nonceHash); строка удаляется через сутки после `expiresAt`. Выдача nonce в базу не пишет (подраздел «Регистрация и сессия») |
| agent_session | tokenHash, organizationId, deviceId, expiresAt | P2, платформенная: SHA-256 сессионного токена на 60 минут. При замене ключа устройства все его сессии удаляются |
| scan_batch | organizationId, deviceId, id, scanId, sequence, policyVersion, startedAt, completedAt, sentAt (заголовок принятой попытки), receivedAt, payloadHash, clockInconsistent, full | P2. Unique(deviceId, scanId), unique(deviceId, sequence). Тело пакета не хранится: сохраняются наблюдения |
| scan_request | organizationId, id, deviceId, requestedBy, createdAt, expiresAt, state (requested, delivered, completed, expired) | P2. Не больше одного незавершённого запроса на устройство |
| observation | organizationId, id, subjectId, checkId, source (agent, graph, server), scanBatchId, collectionRunId, inputObservationId, observedAt, receivedAt, collectionStatus, evidence, reasonCode | Evidence — только по закрытой схеме проверки: агента, M365 или серверной (`evidenceSchema` проверок SYS-* в `specs/check-catalog.json`). У `agent` заполнен `scanBatchId`, у `graph` — `collectionRunId`, у `server` — ни одно из них; `inputObservationId` у SYS-002 и SYS-003 ссылается на наблюдение WIN-011, по которому они вычислены |
| assessment | organizationId, id, observationId, subjectId, checkId, ruleId, ruleVersion, sourcePolicyVersion, evaluatedPolicyVersion, assessmentScope (historical, current), assessmentMode, result, severity, reasonCode, evaluatedAt, basisSnapshot, evidenceAvailability | Исходное измерение пересчётом не переписывается. Свежесть вычисляется при чтении и при формировании отчёта |
| finding | organizationId, id, subjectId, checkId, technicalState, workflowState, severity, assigneeId, dueAt, workflowReason, reviewAt, workflowDecidedBy, revision, openedAt, resolvedAt | Unique(organizationId, subjectId, checkId). Создаётся только для режима `assessed` |
| finding_event | organizationId, findingId, id, eventType, cause, assessmentId, actorId, fromWorkflowState, toWorkflowState, occurredAt | Неизменяемы: UPDATE у роли приложения отозван. Допустимые сочетания — подраздел «Допустимые сочетания eventType и cause»; `actorId` не null тогда и только тогда, когда `cause=manual_action` |
| risk_decision | organizationId, id, findingId, decision (risk_accepted, suppressed, withdrawn), reason, reviewAt, decidedBy, decidedAt, findingEventId | Неизменяемая запись каждого решения `decideFindingRisk`, созданная в одной транзакции с его событием `workflow_changed`/`manual_action`; UPDATE у роли приложения отозван. Подраздел «Автомат workflowState» |
| report | organizationId, id, periodStart, periodEnd, timezone, language, format, state, failureCode, blobKey, policyVersions, snapshot | Unique(organizationId, periodStart, language). При переходе в `ready` записывается неизменяемый снимок, и строку `ready` изменить нельзя: UPDATE отклоняет триггер базы. Опубликованный отчёт не пересчитывается. Подраздел «Отчёт и покрытие» |
| organization_export | organizationId, id, state (queued, ready, failed, expired), blobKey, createdAt, expiresAt, requestedBy | Файл хранится 7 дней и выдаётся только через сервис |
| audit_event | organizationId, id, occurredAt, actorType (staff, device, system), actorId, action, targetType, targetId, outcome, correlationId, details | Клиентская таблица под RLS; UPDATE у роли приложения отозван. `details` — закрытая структура для трёх действий (`organization.lifecycle_change`, `finding.assignment_change`, `retention.purge_summary`), для остальных null |
| job | id, type, organizationId, inputId, periodKey, state, leaseOwner, leaseToken, leaseUntil, attempts, nextAttemptAt | Платформенная таблица. Unique(type, organizationId, coalesce(inputId, periodKey)) NULLS NOT DISTINCT: задания без организации тоже уникальны. Раздел «Фоновые задания и планировщик» |
| teams_digest | periodKey, sentAt | Платформенная: отметка отправленной ежедневной сводки Teams за дату Europe/Oslo (первичный ключ — `periodKey`); хранится 90 дней |
| windows_release | product (client), branchBuild, ubr, kb, releaseAt, kind (security_monthly, security_oob, nonsecurity_oob, preview, hotpatch), securityMonth, autoOffered, state (draft, verified), source, importedBy | P2, платформенная: каталог выпусков Windows для SYS-003. Unique(product, branchBuild, ubr). Правило — `03`, «Правило SYS-003 и каталог выпусков» |
| windows_release_month | securityMonth, state (draft, verified), verifiedAt, verifiedBy, noNewReleases | P2, платформенная: сверка месяца каталога. `verifiedThroughMonth` — последний месяц, до которого сверены все месяцы подряд |

Сотрудник в модели и API определяется `entraUserId` — object id в Entra tenant компании. Это значения `createdBy`, `requestedBy`, `connectedBy`, `assigneeId`, `workflowDecidedBy`, `finding_event.actorId` и `audit_event.actorId` при `actorType=staff`; при `actorType=device` `actorId` — `deviceId`, при `system` — null.

Ссылки между клиентскими сущностями — составные внешние ключи (`organizationId`, id). Каскада от наблюдений к истории нет: `finding_event` и `assessment` переживают удаление наблюдений по сроку. Индексы: проблемы по организации, состоянию и severity; оценки по субъекту, проверке и `observedAt`; задания по состоянию и `nextAttemptAt`. Сроки хранения — `04`, раздел «Сроки хранения»: `retention_purge` удаляет данные в порядке `risk_decision` → `finding_event` → `assessment` → `finding` → `observation` → `collection_run` → `scan_batch` → `scan_request` → `subject` → `device_presence` → `device` → `revoked_installation`.

`basisSnapshot` неизменяем и содержит checkId, ruleId, ruleVersion, evaluatedPolicyVersion, result, severity, reasonCode, observedAt и минимальные поля для explanation; у SYS-003 — также `verifiedThroughMonth` каталога, ожидаемый месяц и число пропущенных месяцев. Через 90 дней evidence удаляется, остаётся `basisSnapshot`, `evidenceAvailability=expired`, `observationId=NULL`.

### Политика клиента

`policy_revision.configuration` описывается закрытой схемой `PolicyConfiguration`. Поля:

- `activeCheckIds` — собираемые проверки M365 и WIN, по умолчанию все.
- `m365` — `collectionHourLocal` 0…23 (по умолчанию 3) и `excludedUserIds` — до 50 object id учётных записей аварийного доступа и служебных; исключение действует на M365-001 и M365-007, на M365-002 — нет.
- `agent` — `scanIntervalHours` 1…168 (24), `checkInIntervalHours` 1…24 (4), `scanJitterMinutes` 0…60 (10), `maxBufferDays` 1…30 (7), `maxBatchAgeDays` 2…32 (9).
- `checks` — объект по каждой проверке каталога: `assessmentMode`, `freshnessWindowHours` 1…720 (48 для M365, 72 для Windows), `parameters`, а для проверок Windows также `notApplicableEditionIds`.

| checkId | parameters (политика v1) | Что нужно для assessed |
| --- | --- | --- |
| M365-001 | `phoneMethodsAccepted` true | — |
| M365-002 | `privilegedRoleTemplateIds` — 18 встроенных ролей (`03`, «Правило M365-001 и M365-002»); пустой список отклоняет схема | — |
| M365-003 | `deviceAlternativeAccepted` false, `trustedLocationsExclusionAccepted` false | — |
| M365-004 | `{}` | — |
| M365-005 | `minGlobalAdmins` 2, `maxGlobalAdmins` 4 | — |
| M365-006 | `allowedPermissionGrantPolicies` [`ManagePermissionGrantsForSelf.microsoft-user-default-low`] | — |
| M365-007 | `inactiveDays` 90 | — |
| WIN-001 | `warnFreePercent` 10, `warnFreeBytes` 10737418240, `criticalFreePercent` 5, `criticalFreeBytes` 2147483648 | — |
| WIN-002 | `encryptionRequired` true; `notApplicableEditionIds` [Core, CoreN, CoreSingleLanguage, CoreCountrySpecific] | — |
| WIN-003 | `approvedProviders` [], `defenderApproved` true | Непустой `approvedProviders` или `defenderApproved=true` |
| WIN-004 | `warnDays` 3, `criticalDays` 7 | WIN-003 в `activeCheckIds` |
| WIN-005 | `requiredProfiles` [domain, private, public], `approvedFirewallProviders` [] | — |
| WIN-006 | `maxSearchAgeDays` 7 | — |
| WIN-007 | `warnDays` 3 | — |
| WIN-008 | `allowBuiltinAdministrator` true, `allowedDomainRids` [512], `allowedSids` [], `maxOtherLocalAccounts` 0 | — |
| WIN-009 | `secureBootRequired` true | — |
| WIN-010 | `expectedTenantId` null | `expectedTenantId` не null |
| WIN-011, SYS-001, SYS-002 | `{}` | WIN-011 и SYS-001 — всегда informational |
| SYS-003 | `graceDays` 14, `criticalBehindMonths` 2 | — |

`createPolicyRevision` возвращает 422 `policy_inputs_missing` в четырёх случаях: режим `assessed` без входных настроек; режим `assessed` для отложенной M365-007, которая не собирается (`03`, «Правило M365-007»); `activeCheckIds` без WIN-011; активна WIN-004 без WIN-003. Сочетания `maxBatchAgeDays` < `maxBufferDays` + 1, `minGlobalAdmins` > `maxGlobalAdmins`, порог warning WIN-001 ниже порога critical (`warnFreePercent` < `criticalFreePercent` или `warnFreeBytes` < `criticalFreeBytes`) и `warnDays` > `criticalDays` у WIN-004 дают 422 `validation_failed`. Значения вне диапазонов схемы — 422 `schema_violation`.

Политика v1 создаётся вместе с организацией; её значения — `default` схемы, режимы равны `defaultAssessmentMode` каталога. Новая ревизия создаётся только с `If-Match`, равным текущей версии; ревизии неизменяемы. Каждая новая ревизия ставит задание `recalculate_policy`.

## Субъекты и идентичность устройства

Субъект — объект, к которому относится наблюдение. Его ключ:

| Тип | `key` | Источник |
| --- | --- | --- |
| tenant | `entraTenantId` | Подключение M365 |
| user | object id пользователя в tenant клиента | `/users` |
| device | `deviceId` | Регистрация агента |
| volume | `<deviceId>/<volumeId>`, где `volumeId` — `\\?\Volume{GUID}\`; буква диска — только атрибут `mountPoint` | Пакет агента |

В API `subject` имеет вид `{type, key, displayName, deviceId}`. Внутри пакета агента уникален ключ (`checkId`, `subject.type`, `localKey`), где `localKey` = `device` для устройства и `volumeId` для тома; внутри запуска сбора M365 — (`checkId`, `subject.key`). Поэтому два ПК с томом C:, смена буквы тома ОС и повторная регистрация того же устройства не смешивают объекты.

Субъект выводится из учёта (`retiredAt`) только по положительному доказательству:

- пользователь — отсутствует в полном списке `/users` (`usersComplete=true`);
- том — полный пакет содержит наблюдения тома ОС с другим `volumeId` (переустановка ОС, замена диска). Агент определяет `volumeId` тома ОС функцией Win32 `GetVolumeNameForVolumeMountPoint` независимо от сборщиков, поэтому сбой сборщика даёт unavailable того же тома, а не его исчезновение;
- устройство — при отзыве и после 90 суток без check-in (задание `freshness_sweep`, событие `subject_retired`/`source_change`); тома устройства выводятся вместе с ним.

Если выведенный субъект снова появляется в источнике, `retiredAt` сбрасывается, и оценки идут обычным порядком: fail по закрытой проблеме даёт `reopened`.

Идентичность устройства (P2):

- `deviceId` создаёт сервер при первой регистрации.
- `installationId` — UUID, который агент создаёт при первом запуске и хранит в каталоге данных.
- `machineFingerprint` — HMAC-SHA256 в hex нижнего регистра. Ключ — 16 байт `installationId` в порядке RFC 4122. Сообщение — UTF-8 строка `Win32_ComputerSystemProduct.UUID` в нижнем регистре в виде 8-4-4-4-12 (пустая строка, если значения нет или оно состоит только из нулей или только из F), байт `0x00` и UTF-8 строка `MachineGuid` из `HKLM\SOFTWARE\Microsoft\Cryptography` в нижнем регистре без фигурных скобок. Сервер хранит SHA-256 строки признака; сырые идентификаторы не передаются. Канонизация меняется только новой версией признака с переходным периодом, в который сервер принимает обе версии.
- Тестовый вектор для контрактных тестов агента и сервиса: `installationId` `6f1c2d3e-4a5b-4c6d-8e7f-9a0b1c2d3e4f`, UUID `4C4C4544-0042-3510-8058-B4C04F4E3732`, MachineGuid `{8C1F7A2E-3B4D-4E5F-9A6B-7C8D9E0F1A2B}` дают признак `150364374d6891dc5194327d8c0500ed000a876f0d7da212e8f1b67ae6a39bd9`.
- Признак передаётся при регистрации, в check-in и в пакетах. Несовпадение даёт 409 `identity_conflict`: сервер выставляет `identityState=identity_conflict`, `conflictKind=fingerprint` и сохраняет время, хеш несовпавшего признака и имя ПК из запроса как недоверенную строку, чтобы техник опознал ПК. Устройство с совпадающим признаком продолжает работу.
- Новый ключ устройства без подписи прежним ключом — тоже конфликт идентичности (`conflictKind=key`): `installationId` и признак машины копируются вместе с образом диска и владения устройством не доказывают. Сервер отвечает 409 `identity_conflict`, сохраняет новый публичный ключ и имя ПК, а прежний ключ продолжает работать.
- `identityState` возвращается в `ok` сам, если 7 суток не было несовпадений, или операцией Admin `resolveDeviceIdentity`: `accept_new_fingerprint` принимает последний несовпавший признак (замена материнской платы), `accept_new_key` — последний отклонённый новый ключ (очищенный TPM), оба с сохранением `deviceId` и истории; `keep` оставляет прежнее. Решения пишут аудит `device.identity_resolved`, а `accept_new_key` — также `device.key_replaced`.
- Агент не входит в golden image. Клон ПК разбирается по RB-11: на клоне агент удаляется вместе с каталогом данных через RMM и ставится заново (новый `installationId`, новое устройство). Оригинал не отзывается: клон и оригинал делят один `deviceId`.
- Клон с тем же SMBIOS UUID, MachineGuid и программным ключом признаком не отличается. Такие ПК по очереди получают `sequence_conflict`, и повторяющийся `device.sequence_resync` поднимает оповещение (`06`, «Наблюдаемость и оповещения»): законный откат ПК из checkpoint даёт один resync, а пара клонов — resync почти каждые сутки.

Повторная регистрация с тем же `installationId`, совпадающим признаком машины и прежним отпечатком ключа отвечает 201 без новых эффектов. Новый ключ заменяет прежний с сохранением `deviceId` и истории (аудит `device.key_replaced`), только если запрос подписан и прежним ключом (`previousKeySignature`) или Admin принял его решением `accept_new_key`. Подпись прежним ключом — путь для плановой смены ключа, который у агента ещё есть (например, перехода с программного ключа на TPM); агент P2 сам ключ не меняет и создаёт новый только при потере прежнего, поэтому на практике замена идёт через `accept_new_key`. При любой замене все сессии устройства удаляются: токен, выданный прежнему ключу, отклоняется со следующего запроса. Так агент восстанавливается после потери ключа (очищен TPM), а клон с копией диска и новым ключом идентичность оригинала не перехватывает. Отозванное устройство повторно не регистрируется: его `installationId` записан в `revoked_installation`, и нужна переустановка с новым `installationId`, которая создаёт новое устройство.

`sequence` пакетов монотонен для устройства; `lastAcceptedSequence` — наибольший принятый, пропуски допустимы. После 409 `sequence_conflict` (например, ПК восстановлен из checkpoint) агент получает в конфигурации `lastAcceptedSequence` и `lastAcceptedCompletedAt` (это `completedAt` пакета текущей проекции), удаляет из буфера пакеты с `completedAt` не позже `lastAcceptedCompletedAt` (они уже были приняты до снимка) и перенумеровывает остальные с `lastAcceptedSequence + 1` с новыми `scanId`. Это единственное исключение из правила неизменности пакета; сервер пишет аудит `device.sequence_resync`.

## Жизненный цикл организации

Переходы выполняет Admin операцией `changeOrganizationLifecycle` с `idempotencyKey` в теле: повтор с тем же ключом возвращает прежний результат, тот же ключ с другим телом — 409 `idempotency_conflict`. Обязательное поле `reason` — свободный текст до 1000 символов, недоверенная строка; оно сохраняется в аудите `organization.lifecycle_change`. Переходы `disable`, `schedule_deletion`, `cancel_deletion` и удаление сначала записываются в журнал безопасности (`04`, «Журнал безопасности»); если запись не создана, переход не выполняется и операция отвечает 503. Отмена удаления журналируется, чтобы восстановление базы не исполнило отменённое удаление.

| Из | Действие | В | Условие | Эффекты |
| --- | --- | --- | --- | --- |
| active | disable | disabled | — | Журнал безопасности, затем БД. Сбор M365 и приём пакетов прекращаются; ключи регистрации не отзываются |
| disabled | enable | active | — | Сбор и приём возобновляются |
| disabled | schedule_deletion | deletion_scheduled | Есть экспорт, созданный после перехода в `disabled`, в состоянии `ready` или `expired`, либо `exportWaived=true` | Журнал безопасности, затем БД. `deletionDueAt` = now + 30 суток |
| deletion_scheduled | cancel_deletion | disabled | До `deletionDueAt` | Журнал безопасности, затем БД. `deletionDueAt` = null |
| deletion_scheduled | Задание `organization_delete` при `deletionDueAt ≤ now` | удалена | — | Журнал безопасности (`organization.delete`), затем удаление данных БД и Blob, tombstone |

Остальные сочетания дают 409 `lifecycle_transition_forbidden`; `exportWaived` допустим только при `schedule_deletion`.

| Статус | Портал | Агент | Задания |
| --- | --- | --- | --- |
| active | Все операции по ролям | Все операции | Все |
| disabled, deletion_scheduled | Чтение; из изменений — только `changeOrganizationLifecycle`, `createOrganizationExport` и `disconnectTenant`, остальные — 409 `lifecycle_transition_forbidden` | 403 `organization_inactive` | Только `organization_export`, `retention_purge` и `organization_delete` |
| удалена | 404 `not_found` | `createAgentSession` — 401 `device_unknown`, регистрация — 401 `enrollment_key_invalid` | — |

После восстановления базы запланированное удаление выполняется не раньше чем через 7 суток, а удаление, которое уже состоялось до сбоя (запись `organization.delete` в журнале безопасности), повторяется сразу (`06`, «Резервное копирование и восстановление»). После удаления согласие приложения Graph в tenant клиента остаётся, пока его не удалит администратор клиента; процедура — RB-03. Срок между планированием удаления и удалением (30 суток) и порядок утверждения — вопрос 6 в `08`.

## Подключение M365 и сбор

Подключение связывает организацию с одним tenant клиента. Поля `tenant_connection`:

- `status` — `not_connected`, `consent_pending`, `active` или `disconnected`;
- `entraTenantId` — tenant действующего или последнего подключения;
- `pendingTenantId` и `pendingExpiresAt` — ожидаемый tenant consent, который ещё не проверен.

| Из | Действие | В | Условие |
| --- | --- | --- | --- |
| not_connected, disconnected | `startTenantConsent` | consent_pending | Ожидаемый tenant не подключён к другой организации |
| active | `startTenantConsent` с тем же tenant | active | Повторный consent при расширении прав; сбор продолжается |
| consent_pending | `verifyTenantConnection` с выданным consent | active | Токен для ожидаемого tenant выдан, `/organization` вернул тот же id |
| active | `verifyTenantConnection` | active | Повторная проверка; повтор после успеха возвращает то же подключение |
| active | `disconnectTenant` | disconnected | Журнал безопасности, затем БД |
| consent_pending | Истёк `pendingExpiresAt` | прежний статус | Статус вычисляется при чтении: `pendingTenantId` без проверки старше 7 суток не учитывается |

1. **`startTenantConsent` (Admin)** принимает `tenantHint` — tenant ID или проверенный домен клиента. Домен сервис переводит в tenant ID через OpenID discovery Microsoft (`/{domain}/v2.0/.well-known/openid-configuration`). Проверки по порядку:
   1. tenant компании без `allowCompanyTenant=true` — 422 `validation_failed`;
   2. tenant подключён к другой организации или отличается от `entraTenantId` подключения в статусе `active` — 409 `tenant_conflict`.

   Затем записываются `pendingTenantId` и `pendingExpiresAt` = now + 7 суток. Ответ содержит ссылку admin consent именно для этого tenant: `https://login.microsoftonline.com/{pendingTenantId}/v2.0/adminconsent?client_id=…&scope=https://graph.microsoft.com/.default&redirect_uri=…`.
2. **Consent.** Ссылку открывает Admin компании, если у него есть роль Global Administrator или Privileged Role Administrator в tenant клиента через GDAP. Иначе Admin пересылает ссылку администратору клиента. Microsoft возвращает браузер на публичную страницу портала, которая без запросов к API показывает только «consent получен» или «consent не выдан». Параметры адреса этой страницы не пишутся в журналы.
3. **`verifyTenantConnection` (Admin)** — единственный путь к `active`. Целевой tenant — `pendingTenantId`, а если его нет — `entraTenantId` действующего подключения. Проверки по порядку:
   1. целевого tenant нет — 409 `connection_state_conflict`;
   2. tenant подключён к другой организации — 409 `tenant_conflict`. Глобальная уникальность обеспечена индексом, нарушение тоже даёт 409;
   3. сервис получает токен client credentials для целевого tenant и читает `/organization`; отказ в токене или другой id — 422 `consent_not_granted`;
   4. иначе подключение получает `active`, `entraTenantId`, `tenantDisplayName` и `primaryDomain`, пишется аудит `m365.connect` и ставится внеплановый сбор.

   Если новый tenant отличается от прежнего `entraTenantId` (подключение после `disconnected`), субъекты прежнего tenant выводятся из учёта событием `subject_retired`/`manual_action`. Активный субъект tenant — тот, чей ключ равен текущему `entraTenantId`. Параметрам браузера сервис не доверяет: организацию и tenant определяют запись подключения и собственный токен.
4. **`disconnectTenant` (Admin).** Сначала журнал безопасности (`m365.disconnect`), затем `disconnected`; незавершённые запуски отменяются. Проблемы остаются и со временем становятся stale. Повтор идемпотентен. Удалить приложение из tenant клиента — RB-03.

Изменения подключения в организации не в статусе `active` дают 409 `lifecycle_transition_forbidden`, кроме `disconnectTenant` (раздел «Жизненный цикл организации»).

Запуск сбора (`collection_run`): `queued` → `running` → `completed`, `partial` или `failed`. `requestCollection` (Admin, Technician) при подключении не в статусе `active` — 409 `connection_state_conflict`; при незавершённом запуске возвращается он же. Плановое задание к незавершённому запуску не присоединяется: если запуск открыт меньше 6 часов, задание завершается без сбора, а запуск старше 6 часов (процесс упал во время сбора) оно закрывает `failed`/`run_timeout` без записи наблюдений и начинает новый. Модули и порядок вызовов — `02`, «Сбор данных Microsoft 365»; статусы модулей — `03`, «Возможности подключения».

- `completed` — все модули `available`, `license_missing` или `skipped`.
- `partial` — модули `tenant` и `users` получены, а хотя бы один модуль `partial`, `permission_missing` или `temporary_error`. Сюда же относится запуск, упёршийся в таймаут после чтения пользователей: незавершённые модули получают `temporary_error`.
- `failed` — модули `tenant` или `users` не получены. `failureCode`:
  - `consent_missing` — токен не выдан, потому что consent отозван или приложение удалено;
  - `tenant_mismatch` — `/organization` вернул другой id;
  - `credential_error` — сбой подписи Key Vault или сертификата приложения;
  - `cancelled` — во время запуска подключение отключено, tenant сменился или организация перестала быть `active`;
  - `run_timeout` — таймаут запуска (30 минут) до чтения пользователей или запуск, открытый дольше 6 часов и закрытый плановым заданием;
  - `temporary_error` — остальные сбои.

  Failed-запуск наблюдений не пишет, поднимает оповещение и попадает в ежедневную сводку.

Наблюдения запуска:

- M365-001 — по каждому пользователю. Методы запрашиваются для включённых member-пользователей вне `excludedUserIds` и без роли синхронизации, а также для всех администраторов (`02`); у остальных `methodKinds` равен null, и правило даёт not_applicable. M365-007 отложена и наблюдений не имеет (`03`, «Правило M365-007»).
- M365-002 — по каждому пользователю с активной привилегированной ролью и по каждому, у кого в предыдущем полном сборе такая роль была (у него `roleTemplateIds` пуст).
- M365-003…M365-006 — по tenant.

Каждое наблюдение проверяется схемой `specs/graph-observation.schema.json` до записи. Оценка, обновление проблем и вывод субъектов из учёта выполняются в одной финальной транзакции. Эта транзакция блокирует строки организации и подключения и пишет данные, только если организация `active`, подключение `active` с прежним `entraTenantId`, а запуск всё ещё `running`; иначе запуск получает `failed`/`cancelled` без записи. Пользователь, которого нет в полном списке `/users`, выводится из учёта; при `usersComplete=false` никто не выводится, а пользователи вне полученных страниц сохраняют прежние оценки, которые со временем становятся stale.

## Состояния проблем

`technicalState=open|resolved`; `workflowState=new|in_progress|risk_accepted|suppressed`. Finding создаётся только для режима `assessed`; informational-оценка всегда имеет `result=null` и finding не создаёт. Пороги warn и critical дают `result=fail` и `Finding.severity` = `warning` или `critical`. `risk_accepted` означает, что риск реален и организация сознательно принимает его до `reviewAt`. `suppressed` означает, что срабатывание признано ложным или неприменимым для этой организации без изменения политики, до `reviewAt`.

Термины:

- **Правило** — глобальная логика проверки с `ruleId` и `ruleVersion`. Таблица жизненного цикла ОС и каталог выпусков Windows — данные правил SYS-002 и SYS-003.
- **Политика** — параметры клиента в `policy_revision`.
- **`rule_change`** пишется только при смене `ruleVersion`, **`policy_change`** — только при смене ревизии политики, в том числе окна свежести.
- **`source_change`** — изменились факты источника: настройка tenant или состояние устройства. Для SYS-002 и SYS-003 сюда же относится изменение положения устройства относительно времени и сверенного каталога: ОС вышла из обслуживания или наступил ожидаемый месяц, а устройство его не установило. Это реальное новое отклонение, поэтому оно попадает в «Новые проблемы».
- **`applicability_change`** пишется только с `resolved`, когда проверка стала not_applicable из-за фактов источника без смены ревизии (пользователь отключён, редакция Windows сменилась на Home).

Исправлением считается только `resolved` с `cause=source_change`. Событий задним числом нет: пакет с признаком часов событий не создаёт. События уровня устройства и подключения (`device.identity_conflict`, `device.key_replaced`, `device.sequence_resync`, `m365.connect`, `m365.disconnect`) пишутся в `audit_event`, а не в `finding_event`.

Свежесть задаётся `freshnessWindowHours` политики для каждой проверки: 48 часов для M365, 72 — для Windows. Она вычисляется при чтении (на текущий момент) и при формировании отчёта (на `periodEnd`). Check-in обновляет `lastSeenAt`, но не свежесть оценок. Задание `freshness_sweep` раз в час пишет `quality_changed` при переходе свежести открытого finding (идемпотентно) и записывает оценку SYS-001 при смене её значения.

### Таблица переходов finding

| Текущее | Свежий fail | Свежий pass | unknown или stale | not_applicable после смены ревизии политики | not_applicable по фактам источника | Субъект выведен из учёта |
| --- | --- | --- | --- | --- | --- | --- |
| Нет finding | Создать `open`, `new`, событие `opened` | Ничего | Ничего (видно в оценках и покрытии) | Ничего | Ничего | Ничего |
| open | Без события; `quality_changed`, если раньше качество было не свежий fail | `resolved`, `workflowState` не меняется | Остаётся `open`; `quality_changed` только при смене качества | `policy_changed`/`policy_change`, `resolved` | `resolved`/`applicability_change` | `subject_retired`, `resolved` |
| resolved | `reopened`; `workflowState=new`, если нет действующего решения (`reviewAt > now`) | Без события | Без события | Без события | Без события | Без события |

`cause` у `opened`, `resolved` и `reopened` соответствует триггеру: `source_change`, `rule_change` или `policy_change`; у `resolved` из-за неприменимости по фактам — `applicability_change`. Если проверка снова применима и даёт fail, пишется `reopened` с `source_change`. Причины вывода субъекта:

- отзыв устройства — `subject_retired`/`manual_action`;
- исчезновение пользователя или тома — `subject_retired`/`source_change`;
- исключение проверки из `activeCheckIds` или перевод в informational — `policy_changed`/`policy_change`.

Ни одна из этих категорий не считается исправлением; недельный отчёт показывает их отдельно.

### Автомат workflowState

| Переход | Кто | Как |
| --- | --- | --- |
| new ↔ in_progress | Technician, Admin | patchFinding |
| new или in_progress → risk_accepted или suppressed | Admin | decideFindingRisk |
| risk_accepted ↔ suppressed | Admin | decideFindingRisk |
| risk_accepted или suppressed → new | Admin | decideFindingRisk `withdrawn` |
| risk_accepted или suppressed → new | Система | Задание `review_expiry` при наступлении `reviewAt`, `workflow_changed`/`review_expired`, идемпотентно |
| Resolve | Система | `workflowState` не меняется |

`patchFinding` (Technician, Admin; `If-Match` обязателен) меняет независимые поля: `workflowState` (`new` ↔ `in_progress`), `assigneeId` и `dueAt`. Все поля необязательны, но нужно хотя бы одно.

- `assigneeId` — `entraUserId` сотрудника из `listStaff` с ролью Admin или Technician; иное значение — 422 `validation_failed`; `null` снимает ответственного.
- В `risk_accepted` и `suppressed` меняются только `assigneeId` и `dueAt`, передача `workflowState` — 409 `workflow_transition_forbidden`.
- Значения `risk_accepted` и `suppressed` в PATCH отклоняются схемой с 422 `schema_violation`.
- Изменение ответственного или срока пишет аудит `finding.assignment_change` с изменившимися полями.

`decideFindingRisk` (Admin; `If-Match` обязателен) принимает `decision` (`risk_accepted`, `suppressed`, `withdrawn`), `reason` (1…1000) и `reviewAt`.

- `risk_accepted` и `suppressed` допустимы только при `technicalState=open` (иначе 409 `workflow_transition_forbidden`) и при `reviewAt` в (now, now + 365 сут] (иначе 422 `validation_failed`).
- `withdrawn` возвращает `new` и допустим только из `risk_accepted` или `suppressed`; при нём `reason` необязателен, а `reviewAt` запрещён.
- Каждое решение пишет `workflow_changed`/`manual_action` с `actorId`, заполняет `workflowDecidedBy` и в той же транзакции создаёт неизменяемую запись `risk_decision`: решение, причина, срок, исполнитель, время и ссылка на событие. `reason` сохраняется как `Finding.workflowReason`; при `withdrawn` оно очищается, а переданная причина остаётся в записи.
- Записи решений создаёт только `decideFindingRisk`; истечение `reviewAt` и сброс workflow при `reopened` видны по событиям. По записям решений восстанавливаются все прежние основания и сроки, в том числе после смены `risk_accepted` на `suppressed` и отзыва: они есть в экспорте организации и в снимке отчёта. API отдаёт текущее решение (`Finding.workflowReason`, `reviewAt`, `workflowDecidedBy`) и события перехода.

Ответ обеих операций — Finding с новым ETag. Оплаченный ESU Windows 10 оформляется решением `risk_accepted` по SYS-002 с `reviewAt` не позже окончания ESU.

### Допустимые сочетания eventType и cause

| eventType | Допустимые cause | assessmentId |
| --- | --- | --- |
| opened | source_change, rule_change, policy_change | обязателен |
| resolved | source_change, rule_change, policy_change, applicability_change | обязателен |
| reopened | source_change, rule_change, policy_change | обязателен |
| quality_changed | data_quality | может быть null (переход в stale без новой оценки) |
| workflow_changed | manual_action, review_expired | null |
| policy_changed | policy_change | может быть null (без пересчёта) |
| subject_retired | source_change, manual_action | null |

`fromWorkflowState` и `toWorkflowState` равны null, если workflow не менялся. Сочетание вне таблицы — дефект реализации.

### Выбор текущего состояния

1. Историческая оценка выполняется по версии политики источника (`sourcePolicyVersion`): для пакета агента — `policyVersion` пакета, для запуска M365 — ревизия, действовавшая при старте запуска.
2. Текущая проекция пары (субъект, проверка):
   - для агента — наблюдение из пакета устройства с `sequence` = `device.projectionSequence`;
   - для M365 — наблюдение последнего завершённого (`completed` или `partial`) запуска, в котором есть этот субъект. Наблюдение `unavailable` тоже становится проекцией и даёт unknown с причиной; прежний результат остаётся в истории и учитывается в `coveragePeriod` своего периода.

   Проекция оценивается по действующей политике (`evaluatedPolicyVersion`, `assessmentScope=current`).
3. Проверка, которой нет в источнике, даёт unknown/`missing_observation` только в режиме `assessed`. При пересчёте политики пара без наблюдения в режиме informational оценки не получает, а M365-002 пересчитывается только у пользователей, о которых сообщил сборщик (у них есть проекция). В запуске сбора M365 активные проверки tenant без наблюдения получают `missing_observation` в любом режиме; informational — с `result=null`.
4. Новая ревизия политики пересчитывает текущие проекции с `cause=policy_change`, смена `ruleVersion` — с `rule_change`. Пересчёт выполняет задание `recalculate_policy` по последней ревизии организации. После новой ревизии его ставит `createPolicyRevision` с `inputId` = `policy:<version>`. Новую `ruleVersion` приносит версия сервиса, и планировщик ставит задание с `inputId` = `rule:<ruleVersion>` каждой активной организации: пока строка задания хранится, уникальность `job` не даёт поставить его повторно, а повтор после её удаления по сроку хранения пропускает уже оценённые пары. `rule_change` получает пара, у которой с последней оценки сменилась только `ruleVersion`; если сменилась и ревизия, причина — `policy_change`. `recalculate_policy` обрабатывает субъекты организации пакетами по 200 в отдельных транзакциях. Каждая транзакция порции первой проверяет lease задания (строка `job` с прежним `leaseToken` в `running`, под блокировкой); без lease порция откатывается, а уже записанные порции остаются. Пары, уже пересчитанные по той же ревизии, правилу и наблюдению, повтор пропускает, поэтому эффекты идемпотентны.
5. Пакет агента заменяет проекцию устройства, если у него нет признака часов и его `completedAt` не раньше `completedAt` пакета текущей проекции (`projectionCompletedAt`). Иначе пакет пополняет только историю (`assessmentScope=historical`), событий не создаёт и эпизод WIN-007 не меняет. Так перенумерованные старые пакеты ПК, восстановленного из checkpoint, не откатывают проекцию.
6. История, от которой зависит правило (эпизод WIN-007), ведётся в порядке приёма пакетов и задним числом не меняется.
7. Серверные проверки: SYS-002 и SYS-003 вычисляются по последнему collected наблюдению WIN-011 устройства в окне свежести WIN-011 среди пакетов, которые могли менять проекцию (без признака часов и не старше проекции по `completedAt`), даже если в последнем пакете WIN-011 `unavailable`; SYS-001 — по `lastFullScanAt`. Их наблюдения `source=server` создаются при приёме пакета, заданием `patch_level_sweep` и после ввода месяца каталога выпусков в действие (`03`, «Поддержка ОС и уровень патчей»).

Текущее состояние не выбирается по `receivedAt` или `observedAt`. Порядок пакетов задаёт `sequence`, а пакет старше проекции по `completedAt` её не меняет; порядок запусков M365 — время их завершения.

## Фоновые задания и планировщик

Типы и расписание заданий — `02`, раздел «Фоновые задания». Состояния задания: `queued` → `running` → `succeeded` или `failed`.

- **Захват.** Задание захватывается через `FOR UPDATE SKIP LOCKED` с lease 5 минут. Захват увеличивает `leaseToken` и `attempts`; долгое задание продлевает lease.
- **Завершение.** Завершение и бизнес-эффект — одна транзакция с условием `id = ? AND leaseToken = ?`; при 0 обновлённых строк транзакция откатывается. Задание с истёкшим lease захватывается заново, а прежний владелец эффекта не получает. Задание, которое пишет эффект несколькими транзакциями (порции `recalculate_policy`), проверяет lease в каждой из них.
- **Внешняя отправка.** Сообщение в Teams транзакция базы откатить не может. Отметка периода в `teams_digest` пишется сразу после того, как webhook принял сводку, и до завершения задания; повтор задания с отметкой ничего не отправляет. Сбой между принятием webhook и отметкой даёт одно повторное сообщение, а не пропуск сводки: доставка — «хотя бы один раз», а не «ровно один».
- **Область.** Обработка выполняется в области организации `job.organizationId` (`02`, «Разделение клиентов») и явно проверяет принадлежность входных сущностей организации. Задания без организации (`teams_digest`, `release_catalog_check`, `release_import`) работают только с платформенными таблицами или в области чтения всех организаций по закрытому перечню `02`.
- **Сериализация с приёмом.** Задания, меняющие проблемы субъектов устройства (`recalculate_policy`, `freshness_sweep`, `review_expiry`, `patch_level_sweep`), берут блокировку строки устройства, как приём пакета; для субъектов M365 точка сериализации — строка `tenant_connection`.
- **Ключ периода.** У периодических заданий `periodKey` — дата или час периода по времени организации; у `weekly_report` — завершённая ISO-неделя (`2026-W41`) по времени организации. Пропущенные недели догоняются не глубже 4 недель и не раньше недели, в которую создана организация. Уникальность (`type`, `organizationId`, `periodKey`) с `NULLS NOT DISTINCT` делает создание идемпотентным при нескольких экземплярах сервиса, в том числе для заданий без организации (`teams_digest`, `release_catalog_check`). Внеплановый `patch_level_sweep` после сверки месяца получает `periodKey` — сверенный месяц, поэтому не сливается с ежедневным за ту же дату.
- **Слоты.** Задания выполняет только production-слот: в слоте staging они выключены настройкой слота (`02`, «Развёртывание и окружения»).
- **Ошибки.** Повтор через 1, 5, 15 и 60 минут, затем раз в час; после 10 попыток — `failed` и оповещение (RB-04).
- **Один запуск сбора.** `m365_collect` одной организации не выполняется параллельно (частичный уникальный индекс `collection_run`): `requestCollection` возвращает незавершённый запуск, а плановое задание к нему не присоединяется и закрывает только запуск, открытый дольше 6 часов (раздел «Подключение M365 и сбор»).
- **Хранение.** Завершённые задания хранятся 30 дней, failed — 90.

## API агента

API агента (P2) обслуживается на hostname агента того же сервиса. Тела — `application/json` без `Content-Encoding`. Ответы об ошибках — Problem с кодом из каталога (подраздел «Ошибки и действия агента»). Таймаут HTTP-запроса агента — 100 секунд, с большим запасом сверх времени обработки (NFR-04).

| operationId | Метод и путь | Аутентификация | Повтор и конкуренция | Успех |
| --- | --- | --- | --- | --- |
| createAgentChallenge | POST `/api/v1/agent/challenges` | Нет; лимит частоты по IP | Каждый вызов — новый nonce без записи в базу | 201 Challenge |
| enrollAgent | POST `/api/v1/agent/enrollments` | `Authorization: Enrollment <key>` и подпись nonce новым ключом устройства | Идемпотентно по `registrationRequestId` 24 часа | 201 Enrollment |
| createAgentSession | POST `/api/v1/agent/sessions` | Подпись nonce ключом устройства | Каждый вызов — новый токен; прежний действует до срока | 201 AgentSession |
| agentCheckIn | POST `/api/v1/agent/check-ins` | Bearer-токен сессии | Последняя запись выигрывает | 200 Configuration |
| submitScan | POST `/api/v1/agent/scans` | Bearer-токен сессии | `Idempotency-Key` = `scanId`; повтор — те же байты с новым заголовком `Sikkerheit-Sent-At`, ответ — прежний receipt | 200 ScanReceipt |

Анонимные операции `createAgentChallenge`, `enrollAgent` и `createAgentSession` ограничены 60 запросами в минуту с одного IP-адреса и 1 200 в минуту на сервис; регистрации, кроме того, — 20 в час и 200 в сутки на ключ организации (`04`, «Ключ регистрации организации»). Превышение — 429 `rate_limited` с `Retry-After`.

Конфигурация версионируется. Check-in передаёт `configSchemaVersion` агента, и сервер отвечает формой этой версии, а для неизвестной ему более новой версии — формой наибольшей своей. Сервер поддерживает версии схемы конфигурации всех агентов не ниже `minimumAgentVersion`; новое поле появляется только с новой версией схемы. Внутри своей версии агент разбирает конфигурацию строго: поле вне схемы отклоняет её целиком, агент продолжает с прежней и сообщает `configRejected=true` в следующем check-in. Схемы пакета сервер поддерживает в версиях N и N−1, и агент со схемой N выпускается только после сервера, который её принимает. Контрактный тест проверяет конфигурацию и пакет каждой поддерживаемой версии их схемами.

### Регистрация и сессия

Ключ устройства — пара P-256, созданная агентом в TPM (Microsoft Platform Crypto Provider) или, если TPM нет, неэкспортируемым программным ключом CNG (`04`, «Ключ устройства и сессия»). Подпись — ECDSA P-256 SHA-256 в формате IEEE P1363, base64url. Подписываемые строки — UTF-8 с разделителем `\n`:

- регистрация: `sikkerheit-enroll-v1`, nonce, `registrationRequestId`, `installationId`, `machineFingerprint`, `keyProtection`, отпечаток JWK по RFC 7638;
- сессия: `sikkerheit-session-v1`, nonce, `deviceId`.

`keyProtection` — заявление агента без аттестации: портал его показывает, а решения доверия на него не опираются.

`createAgentChallenge` принимает `purpose` (`enroll` или `session`) и для `session` — `deviceId`; тело больше 1024 байт — 413. Nonce — 32 байта: 12 случайных, 4 байта срока (секунды Unix, через 5 минут) и первые 16 байт HMAC-SHA256 ключом сервиса от строки `sikkerheit-nonce-v1`, случайной части, срока, `purpose` и `deviceId`. Выдача nonce в базу не пишет. При использовании сервер проверяет HMAC, срок, `purpose` и `deviceId`, затем погашает nonce вставкой его SHA-256 в `agent_challenge` с уникальным ключом; повторное погашение — 401 `challenge_invalid`. Ключ HMAC — секрет Key Vault, который сервис читает при старте; смена ключа делает недействительными только уже выданные nonce, и агент повторяет запрос с новым.

`enrollAgent` выполняет проверки по порядку; первая сработавшая определяет ответ:

1. Тело больше 16384 байт — 413 `payload_too_large`, не JSON — 400 `invalid_json`, не по схеме — 422 `schema_violation`.
2. Ключ регистрации неизвестен — 401 `enrollment_key_invalid`. Отозванный ключ на этом шаге ещё принимается: он нужен для повтора.
3. Запись `enrollment` с тем же `registrationRequestId` в организации ключа: тот же `requestHash` (SHA-256 сырых байтов тела) в течение 24 часов — прежний ответ 201 без новых эффектов; иначе — 409 `idempotency_conflict`. Поэтому повтор после потерянного ответа проходит и тогда, когда ключ уже ротирован.
4. Ключ отозван — 401 `enrollment_key_invalid`.
5. Организация не `active` — 403 `organization_inactive`.
6. Nonce неизвестен, истёк, использован или не `enroll`; подпись не проверяется ключом `publicKey` — 401 `challenge_invalid`.
7. `installationId` есть в `revoked_installation` организации или устройство с ним отозвано — 401 `device_revoked`.
8. Устройство с этим `installationId` есть, а признак машины не совпадает — 409 `identity_conflict`; ключ не меняется, сведения о конфликте сохраняются.
9. Устройство есть и признак совпадает: отпечаток ключа равен сохранённому (в том числе принятому решением `accept_new_key`) — 201 с `reenrolled=true` без новых эффектов. Новый ключ с `previousKeySignature`, которая проверяется сохранённым ключом устройства, заменяет прежний (`device.key_replaced`, `reenrolled=true`), и все сессии устройства удаляются. Новый ключ без такой подписи — 409 `identity_conflict` с `conflictKind=key`: ключ не меняется, новый публичный ключ сохраняется для разбора.
10. Иначе создаются устройство и субъект `device`.

Шаги 7–10 выполняются под транзакционной advisory-блокировкой по (`organizationId`, `installationId`), поэтому два одновременных запроса одной установки не создают двух устройств. Nonce погашается, запись `enrollment` создаётся, `enrollment_key.lastUsedAt` обновляется в той же транзакции.

`createAgentSession`: тело больше 1024 байт — 413. Затем проверки по порядку:

1. Устройства нет — 401 `device_unknown`.
2. Устройство отозвано — 401 `device_revoked`.
3. Nonce не годится или подпись не проверяется сохранённым ключом — 401 `challenge_invalid`.
4. Организация не `active` — 403 `organization_inactive`.
5. Иначе выдаётся токен — 32 случайных байта, хранится SHA-256, срок 60 минут.

Запросы с токеном проверяют по БД на каждом запросе срок токена (401 `session_invalid`), статус устройства (401 `device_revoked`) и статус организации (403 `organization_inactive`), без кэша.

### Порядок приёма пакета

`submitScan` выполняет шаги по порядку; первый сработавший отказ определяет ответ:

1. Токен сессии и статусы — по правилам подраздела «Регистрация и сессия».
2. `Content-Type` не `application/json` или есть `Content-Encoding` — 415. Тело больше `maxBatchBytes` (262144 байт) — 413 до разбора.
3. Не JSON — 400 `invalid_json`.
4. `agentVersion` ниже `minimumAgentVersion` — 422 `agent_version_unsupported` с полем `minimumAgentVersion`. Версия проверяется раньше схемы, чтобы агент со снятой с поддержки схемой пакета перешёл в VersionBlocked и сохранил буфер.
5. Неизвестная `schemaVersion` — 422 `unsupported_schema_version`. Не по схеме, в том числе `freeBytes` > `totalBytes`, а также нет заголовка `Sikkerheit-Sent-At` или он не в формате date-time UTC — 422 `schema_violation`.
6. Пакет с этим `scanId` у устройства уже есть: тот же `payloadHash` — прежний receipt с `duplicate=true`; иначе — 409 `idempotency_conflict`.
7. Признак машины не совпадает — 409 `identity_conflict`.
8. `completedAt` < `startedAt` или `observedAt` вне [`startedAt`, `completedAt`] — 422 `batch_time_inconsistent`.
9. `Sikkerheit-Sent-At` − `completedAt` больше `maxBatchAgeDays` — 422 `batch_too_old`. Возраст считается по часам ПК, поэтому отстающие часы не делают свежий пакет старым.
10. `policyVersion` больше текущей версии политики или такой ревизии у организации нет (например, ревизия потеряна при восстановлении базы) — 422 `unknown_policy_version`.
11. Повтор ключа (`checkId`, `subject.type`, `localKey`) — 422 `duplicate_observation`. Наблюдение проверки, не активной в `policyVersion` пакета, или объект не того типа — 422 `unexpected_subject`.
12. Под блокировкой строки устройства шаг 6 повторяется: одновременный повтор того же `scanId` получает прежний receipt, а не `sequence_conflict`. Затем `sequence` ≤ `lastAcceptedSequence` — 409 `sequence_conflict`. Иначе в одной транзакции:
    - записываются `scan_batch` и наблюдения, вычисляется признак часов;
    - выполняется оценка: история, текущая проекция, серверные проверки SYS-*, проблемы и события;
    - обновляются `lastAcceptedSequence`, проекция (`projectionSequence` и `projectionCompletedAt`, если пакет её заменил), `lastSeenAt`, `lastFullScanAt` (если пакет полный) и строка `device_presence` за сутки;
    - `scan_request` с этим `scanRequestId` переходит в `completed`;
    - commit.
13. Ответ 200 ScanReceipt отправляется после commit.

Полный сбор — пакет, в котором есть наблюдение для каждой проверки агента (`source=agent`, WIN-*) из `activeCheckIds` своей `policyVersion` (любой `collectionStatus`), без признака часов; проверки M365 и серверные SYS-* в пакет не входят. Агент не отправляет частичных пакетов; повторную проверку он выполняет как полный сбор. Отсутствующая ожидаемая пара даёт unknown/`missing_observation`. `scanRequestId` чужого устройства или истёкшего запроса игнорируется с записью диагностики.

Агент проверяет каждое наблюдение встроенной схемой до отправки и заменяет не прошедшее проверку (в том числе неизвестное значение перечисления) на `unavailable/unsupported` с записью в свой журнал. Поэтому одно недопустимое значение не отбрасывает пакет целиком. Отказы 422 сервер считает по устройствам и кодам, а агент передаёт число удалённых пакетов `rejectedBatchCount` в check-in (`06`, «Наблюдаемость и оповещения»).

### Время и часы устройства

При приёме сервер сравнивает со своим `receivedAt` время отправки из заголовка `Sikkerheit-Sent-At` текущей попытки, а также `startedAt`, `completedAt` и каждый `observedAt`. Пакет принимается с признаком часов (`clockInconsistent=true`), если время отправки отличается от `receivedAt` больше чем на 5 минут в любую сторону, если `completedAt` позже времени отправки больше чем на 5 минут или если любая метка позже `receivedAt` + 5 минут. Время отправки в тело не входит: повтор отправляет те же байты с новым заголовком, поэтому пакет, принятый после паузы backoff, признака часов не получает.

- оценки assessed получают unknown/`clock_inconsistent`, informational — `result=null` и `clock_inconsistent`;
- все оценки пакета исторические, текущую проекцию и эпизод WIN-007 они не меняют;
- `device.clockStatus` становится `inconsistent` и возвращается в `ok` с первым пакетом без признака.

Check-in сравнивает `CheckIn.observedAt` со временем сервера по тому же правилу, обновляет `clockStatus` и без пакета и отмечает сутки в `device_presence`. SYS-002 и SYS-003 вычисляются по времени сервера: при приёме — на `receivedAt`, при пересчёте заданием — на время пересчёта; часы ПК не используются.

Метки внутри evidence при приёме не проверяются, их оценивает правило проверки (`03`). Аутентификация агента от часов ПК не зависит: nonce и срок токена задаёт сервер. В конфигурации передаётся `serverTime`, и агент пишет в свой журнал расхождение больше 5 минут. Признак `late` (`receivedAt − completedAt` больше 24 часов) показывается в оценках и на результат не влияет.

### Ошибки и действия агента

| code | HTTP | Операции | Когда | Действие агента |
| --- | --- | --- | --- | --- |
| invalid_json | 400 | Операции с телом | Тело не разбирается как JSON | submitScan: drop_batch; прочие агентские: skip_request |
| unsupported_media_type | 415 | Операции с телом | Content-Type не application/json или задан Content-Encoding | submitScan: drop_batch; прочие агентские: skip_request |
| payload_too_large | 413 | Операции с телом | Тело больше лимита: submitScan — 262144 байт, enrollAgent — 16384, createAgentChallenge и createAgentSession — 1024, agentCheckIn — 4096, портал — 65536 | submitScan: drop_batch; прочие агентские: skip_request |
| schema_violation | 422 | Операции с телом | Тело не соответствует схеме, включая межполевые правила | submitScan: drop_batch + refresh_configuration; прочие агентские: skip_request |
| unsupported_schema_version | 422 | submitScan | schemaVersion пакета не поддерживается сервером | stop_until_upgrade |
| unexpected_subject | 422 | submitScan | Проверка не активна в policyVersion пакета или объект не того типа | drop_batch + refresh_configuration |
| duplicate_observation | 422 | submitScan | Повтор ключа (checkId, subject.type, localKey) | drop_batch |
| unknown_policy_version | 422 | submitScan | policyVersion больше текущей или такой ревизии у организации нет | drop_batch + refresh_configuration |
| batch_too_old | 422 | submitScan | Время отправки `Sikkerheit-Sent-At` минус completedAt больше maxBatchAgeDays | drop_batch |
| batch_time_inconsistent | 422 | submitScan | completedAt раньше startedAt или observedAt вне [startedAt, completedAt] | drop_batch |
| agent_version_unsupported | 422 | submitScan | agentVersion ниже minimumAgentVersion | stop_until_upgrade |
| idempotency_conflict | 409 | enrollAgent, submitScan, портальные операции с idempotencyKey | Тот же ключ идемпотентности с другим содержимым | enrollAgent: reenroll; submitScan: drop_batch |
| sequence_conflict | 409 | submitScan | sequence не больше lastAcceptedSequence при новом scanId | resync_sequence |
| identity_conflict | 409 | enrollAgent, agentCheckIn, submitScan | Признак машины не совпадает с устройством; в enrollAgent также — новый ключ устройства без подписи прежним | identity_stop |
| organization_inactive | 403 | enrollAgent, createAgentSession, agentCheckIn, submitScan | Организация disabled или deletion_scheduled | suspend_until_active |
| enrollment_key_invalid | 401 | enrollAgent | Ключ регистрации неизвестен или отозван | await_enrollment_key |
| challenge_invalid | 401 | enrollAgent, createAgentSession | Nonce неизвестен, истёк, использован, другого purpose или deviceId; подпись не проверяется | new_challenge |
| session_invalid | 401 | agentCheckIn, submitScan | Токен сессии неизвестен или истёк | renew_session |
| device_unknown | 401 | createAgentSession | Устройства с этим deviceId нет | reenroll |
| device_revoked | 401 | enrollAgent, createAgentSession, agentCheckIn, submitScan | Устройство отозвано | stop_until_reinstall |
| rate_limited | 429 | Все | Превышен лимит частоты; Retry-After | retry_after |
| temporarily_unavailable | 503 | Все | Временный сбой, в том числе недоступность журнала безопасности; Retry-After, если известен | retry_after; без Retry-After: retry_backoff |
| session_required | 401 | Портал | Нет действующей сессии сотрудника | — |
| csrf_failed | 403 | Изменения портала | Нет X-CSRF-Token или он от другой сессии | — |
| forbidden | 403 | Портал | Роли не хватает для операции | — |
| not_found | 404 | Портал | Сущности нет в организации пути, или организация удалена | — |
| invalid_cursor | 400 | Списки портала | Cursor другой операции, организации или фильтра либо изменён | — |
| revision_mismatch | 412 | patchFinding, decideFindingRisk, createPolicyRevision | If-Match устарел | — |
| if_match_required | 428 | patchFinding, decideFindingRisk, createPolicyRevision | Нет If-Match | — |
| workflow_transition_forbidden | 409 | patchFinding, decideFindingRisk | Недопустимый переход workflowState | — |
| lifecycle_transition_forbidden | 409 | changeOrganizationLifecycle и изменения в неактивной организации | Переход вне таблицы или изменение в disabled и deletion_scheduled | — |
| connection_state_conflict | 409 | requestCollection, verifyTenantConnection | Подключение не в статусе active, или нет tenant для проверки | — |
| tenant_conflict | 409 | startTenantConsent, verifyTenantConnection | Tenant подключён к другой организации или отличается от действующего подключения | — |
| consent_not_granted | 422 | verifyTenantConnection | Токен для ожидаемого tenant не выдан (consent нет) или /organization вернул другой id | — |
| resource_not_ready | 409 | downloadReport, downloadOrganizationExport | Файл не в состоянии ready | — |
| validation_failed | 422 | Портал | Значение по схеме верно, но нарушает правило: timezone, неделя отчёта (не ISO-неделя или не завершена), reviewAt, assigneeId, сочетания политики, третий активный ключ регистрации, запись каталога выпусков против сверенной, сверка пустого месяца без `noNewReleases` | — |
| policy_inputs_missing | 422 | createPolicyRevision | assessed без входных настроек; нет WIN-011; WIN-004 без WIN-003 | — |

Действия агента:

- `retry_after` — пауза по `Retry-After`; `retry_backoff` — экспоненциальная пауза от 1 минуты до 1 часа с джиттером. После паузы агент возвращается в состояние, из которого вошёл в Backoff, и повторяет запрос.
- `drop_batch` — удалить пакет из буфера, записать это в журнал агента и увеличить `rejectedBatchCount`.
- `refresh_configuration` — получить конфигурацию через check-in; `resync_sequence` — получить конфигурацию и перенумеровать очередь по подразделу «Субъекты и идентичность устройства»; `renew_session` — получить новую сессию. Эти действия и `drop_batch` состояние агента не меняют.
- `new_challenge` — один повтор с новым nonce. Второй отказ подряд при доступном локальном ключе ведёт к регистрации заново с тем же `installationId` не чаще раза в сутки; без локального ключа агент создаёт новый ключ и регистрируется заново. Если сервер помнит другой ключ (например, после восстановления базы на точку до прежней замены), регистрация получает `identity_conflict` вида `key`, и действующий ключ принимает Admin (`accept_new_key`).
- `reenroll` — регистрация заново сохранённым ключом организации с новым `registrationRequestId`.
- `skip_request` — пропустить запрос; плановые запросы повторяются по расписанию: check-in — через `checkInIntervalHours`, регистрация — раз в сутки и при запуске службы.
- Остальные действия переводят агент в состояние по подразделу «Конечный автомат агента».

Ответ без тела Problem или с кодом вне каталога (500, 502 и 504 фронтенда App Service, 404 при ошибке маршрутизации hostname, 401 без кода), сетевая ошибка и таймаут — `retry_backoff`. Для `submitScan` тот же пакет повторяется. Если на один пакет сервер 5 раз подряд ответил 500, а check-in между попытками проходил, пакет считается непригодным и удаляется как при `drop_batch`, чтобы очередь не остановилась.

### Конечный автомат агента

| Состояние | Что делает агент | Выход |
| --- | --- | --- |
| Unenrolled | Регистрируется сохранённым ключом организации сразу при входе в состояние, при запуске службы и при появлении нового файла ключа; после `skip_request` — через сутки; сбор в буфер продолжается | Нет сохранённого ключа — EnrollmentBlocked; 201 — Active; `enrollment_key_invalid` — EnrollmentBlocked; `organization_inactive` — Suspended; `device_revoked` — Revoked; `identity_conflict` — IdentityConflict; `idempotency_conflict` — повтор с новым `registrationRequestId`; `challenge_invalid` — один повтор с новым nonce, затем `retry_backoff`; 429, 503 и ответы вне каталога — Backoff |
| EnrollmentBlocked | Повторяет регистрацию раз в сутки, при запуске службы и при появлении нового файла ключа от RMM; сбор в буфер продолжается | Как у Unenrolled; `enrollment_key_invalid` — остаётся в EnrollmentBlocked |
| Active | Собирает факты по расписанию, выполняет check-in, отправляет пакеты по одному от старых к новым | Действия таблицы ошибок; `device_unknown` — Unenrolled; 429, 503 и ответы вне каталога — Backoff |
| Backoff | Ждёт по `Retry-After` или экспоненциально; сбор в буфер продолжается | Пауза истекла — возврат в исходное состояние и повтор запроса |
| VersionBlocked | Пакеты не отправляет; check-in раз в 4 часа; сбор в буфер продолжается | Новая версия агента от RMM — Active; конфигурация с `minimumAgentVersion` не выше своей версии — пробная отправка одного пакета, при успехе Active; `device_unknown` — Unenrolled; `device_revoked` — Revoked |
| Suspended | Пакеты не отправляет; раз в сутки выполняет check-in, а без `deviceId` — регистрацию; сбор в буфер продолжается | Успешный check-in или регистрация — Active; `device_unknown` — Unenrolled; `device_revoked` — Revoked; `enrollment_key_invalid` — EnrollmentBlocked |
| Revoked | Удаляет ключ устройства, сессию и буфер, прекращает сбор и обращения | Только переустановка с новым `installationId` |
| IdentityConflict | Пакеты не отправляет; раз в сутки выполняет check-in, а если подпись невозможна — регистрацию; сбор в буфер продолжается | Успешный check-in или регистрация после `resolveDeviceIdentity` — Active; `device_revoked` — Revoked; переустановка по RB-11 |

`device_unknown` из любого состояния, кроме Revoked, ведёт в Unenrolled: сервер не знает устройство, например после восстановления базы или удаления организации, и агент регистрируется заново без участия техника (`04`, «Отзыв и повторная регистрация»). Буфер в любом состоянии ограничен `maxBufferDays` и 100 МБ; при переполнении удаляются самые старые пакеты, а счётчик `droppedBatchCount` передаётся в check-in. Модельный тест автомата проходит каждую строку таблицы и каждый код каталога в каждом состоянии.

## API портала

Портал использует серверную сессию сотрудника (`PortalSession`) и CSRF-токен (`CsrfToken`) для изменений. Списки возвращают cursor pagination, максимум 100 записей. Cursor связан с операцией, организацией и фильтром; чужой или изменённый cursor — 400 `invalid_cursor`. Изменения finding и политики требуют `If-Match`: устаревшая ревизия — 412 `revision_mismatch`, отсутствующий заголовок — 428 `if_match_required`. Тело запроса портала ограничено 65536 байт. Префикс `{org}` означает `/api/v1/organizations/{organizationId}`. Роли: A — Admin, T — Technician, R — Reader (`04`, «Вход сотрудников и роли»).

| operationId | Метод и путь | Роли | Повтор и конкуренция | Успех |
| --- | --- | --- | --- | --- |
| getCurrentStaff | GET `/api/v1/me` | A, T, R | Возвращает роли и CSRF-токен сессии | 200 CurrentStaff |
| listStaff | GET `/api/v1/staff` | A, T, R | cursor | 200 StaffUserPage |
| listOrganizations | GET `/api/v1/organizations` | A, T, R | cursor; область чтения всех организаций; сводка: статус M365, открытые critical и warning, активные устройства, `coverageAt` | 200 OrganizationOverviewPage |
| createOrganization | POST `/api/v1/organizations` | A | Создаёт политику v1 и `tenant_connection` в `not_connected` | 201 Organization |
| getOrganization | GET `{org}` | A, T, R | — | 200 Organization |
| updateOrganization | PATCH `{org}` | A | Хотя бы одно поле; последняя запись выигрывает, аудит | 200 Organization |
| changeOrganizationLifecycle | POST `{org}/lifecycle` | A | `idempotencyKey` в теле; раздел «Жизненный цикл организации» | 200 Organization |
| createOrganizationExport | POST `{org}/exports` | A | `idempotencyKey` в теле | 202 OrganizationExport |
| getOrganizationExport | GET `{org}/exports/{exportId}` | A | — | 200 OrganizationExport |
| downloadOrganizationExport | GET `{org}/exports/{exportId}/download` | A | Аудит каждого чтения | 200 `application/zip` |
| listAuditEvents | GET `{org}/audit-events` | A | cursor; аудит каждого чтения | 200 AuditEventPage |
| listPolicyRevisions | GET `{org}/policy-revisions` | A, T, R | cursor | 200 PolicyRevisionPage |
| createPolicyRevision | POST `{org}/policy-revisions` | A | `If-Match` = `"<текущая версия>"` | 201 PolicyRevision + ETag |
| getTenantConnection | GET `{org}/m365-connection` | A, T, R | — | 200 TenantConnection |
| startTenantConsent | POST `{org}/m365-connection/consent` | A | Тело `tenantHint`; ссылка только для ожидаемого tenant, действует 7 суток | 201 ConsentStart |
| verifyTenantConnection | POST `{org}/m365-connection/verify` | A | Повтор после успеха возвращает активное подключение | 200 TenantConnection |
| disconnectTenant | POST `{org}/m365-connection/disconnect` | A | Идемпотентно; сначала журнал безопасности | 200 TenantConnection |
| listCollectionRuns | GET `{org}/collection-runs` | A, T, R | cursor | 200 CollectionRunPage |
| requestCollection | POST `{org}/collection-runs` | A, T | `idempotencyKey`; незавершённый запуск объединяет запросы | 202 CollectionRun |
| listFindingsAcrossOrganizations | GET `/api/v1/findings` | A, T, R | cursor; область чтения всех организаций; фильтры как у listFindings; `Accept-Language` | 200 FindingPage |
| listAssessments | GET `{org}/assessments` | A, T, R | cursor; фильтры `subjectType`, `subjectKey`, `checkId`, `scope` (current или all); `Accept-Language` | 200 AssessmentPage |
| listFindings | GET `{org}/findings` | A, T, R | Фильтры `technicalState`, `freshness`, `severity`, `checkId`, `workflowState` (несколько значений через запятую); `Accept-Language` | 200 FindingPage |
| getFinding | GET `{org}/findings/{findingId}` | A, T, R | `Accept-Language` | 200 Finding + ETag |
| patchFinding | PATCH `{org}/findings/{findingId}` | A, T | `If-Match` обязателен; `Accept-Language` | 200 Finding + ETag |
| decideFindingRisk | POST `{org}/findings/{findingId}/risk-decisions` | A | `If-Match` обязателен; `Accept-Language`; запись `risk_decision` | 200 Finding + ETag |
| listFindingEvents | GET `{org}/findings/{findingId}/events` | A, T, R | cursor | 200 FindingEventPage |
| listReports | GET `{org}/reports` | A, T, R | cursor | 200 ReportPage |
| createReport | POST `{org}/reports` | A, T | Только завершённая неделя; один отчёт на неделю и язык: повтор возвращает существующий, `failed` ставит в генерацию заново, `ready` не меняет | 202 Report |
| downloadReport | GET `{org}/reports/{reportId}/download` | A, T, R | Аудит каждого чтения | 200 только `text/html` |
| createEnrollmentKey | POST `{org}/enrollment-keys` | A | Секрет показывается один раз; не больше двух активных ключей | 201 EnrollmentKey |
| listEnrollmentKeys | GET `{org}/enrollment-keys` | A | cursor, без секрета; число устройств по ключу | 200 EnrollmentKeySummaryPage |
| revokeEnrollmentKey | POST `{org}/enrollment-keys/{keyId}/revoke` | A | Идемпотентно; сначала журнал безопасности | 204 |
| listDevices | GET `{org}/devices` | A, T, R | cursor; фильтры `enrollmentKeyId`, `status` | 200 DevicePage |
| updateDevice | PATCH `{org}/devices/{deviceId}` | A | Только `displayName`; аудит | 200 Device |
| revokeDevice | POST `{org}/devices/{deviceId}/revoke` | A | Идемпотентно; сначала журнал безопасности, затем `revoked_installation` | 204 |
| resolveDeviceIdentity | POST `{org}/devices/{deviceId}/identity-resolutions` | A | `accept_new_fingerprint`, `accept_new_key` или `keep`; без конфликта этого вида — устройство без изменений; аудит | 200 Device |
| requestDeviceScan | POST `{org}/devices/{deviceId}/scan-requests` | A, T | `idempotencyKey`, срок 24 ч, один незавершённый запрос на устройство | 202 ScanRequest |
| listWindowsReleases | GET `/api/v1/windows-releases` | A, T, R | cursor; фильтры `securityMonth`, `state`; платформенные данные | 200 WindowsReleasePage |
| importWindowsReleases | POST `/api/v1/windows-releases/imports` | A | Записи месяца из MSRC CVRF или ручной ввод в состоянии draft; совпадающие со сверенными пропускаются, противоречащие им — 422 `validation_failed` | 202 WindowsReleaseMonth |
| verifyWindowsReleaseMonth | POST `/api/v1/windows-releases/months/{securityMonth}/verify` | A | Идемпотентно; вводит записи месяца в действие и ставит `patch_level_sweep` всех организаций; месяц без записей — только с `noNewReleases=true`, иначе 422 `validation_failed` | 200 WindowsReleaseMonth |

Аудит:

- **Изменения.** Каждое изменение портала пишет `audit_event` своей организации; `createOrganization` — в аудит созданной организации. Изменения каталога выпусков — платформенные: автор и время записываются в `importedBy`, `verifiedBy` и `verifiedAt` и в журнал запросов сервиса.
- **Чтения.** Выдача отчёта и экспорта и чтение журнала аудита пишут аудит при каждом обращении (расширение `x-audit-read`).
- **Прочие чтения** аудитом не сопровождаются: журнал запросов сервиса с `entraUserId`, операцией и организацией хранится 90 дней в Log Analytics (`04`, «Вход сотрудников и роли»).

Повтор с тем же `idempotencyKey` возвращает прежний результат, тот же ключ с другим телом — 409 `idempotency_conflict`.

Запрос повторной проверки (`requestDeviceScan`) хранится сущностью `scan_request`:

- состояния: `requested` после создания, `delivered` после выдачи `pendingScanRequestId` в конфигурации, `completed` после приёма пакета с этим `scanRequestId`, `expired` по истечении 24 часов;
- агент узнаёт о запросе при check-in и выполняет полный сбор без случайной задержки;
- офлайн-устройство немедленной проверки не обещает.

Языковые заголовки. `listAssessments`, `listFindings`, `listFindingsAcrossOrganizations`, `getFinding`, `patchFinding` и `decideFindingRisk` принимают необязательный `Accept-Language` (nb, nn, en; иначе nb, без ошибки) и отвечают с `Content-Language`. На выбранном языке отдаются `Finding.title`, `Finding.recommendation` и `Assessment.explanation`. Если перевода нет, API отдаёт текст на nb с `Content-Language: nb`, а портал помечает его «перевод отсутствует».

Выдача файлов:

- Отчёты и экспорт выдаются только через сервис; Blob-контейнер приватный, публичных ссылок нет.
- `downloadReport` отвечает с заголовками `Content-Type: text/html; charset=utf-8`, `Content-Disposition: attachment; filename="report-<reportId>.html"`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:` и `Cache-Control: private, no-store`.
- `downloadOrganizationExport` отдаёт `application/zip` как attachment с `nosniff` и `no-store`.
- До состояния `ready` обе выдачи отвечают 409 `resource_not_ready`.

## Отчёт и покрытие

Отчёт формируется только в HTML: `ReportCreate.format` и `Report.format` принимают единственное значение `html`. Отчёт самодостаточен — без скриптов и внешних ресурсов, с print stylesheet; PDF клиент получает печатью из браузера.

Язык отчёта — `Organization.reportLanguage`; `Report.language` фиксируется при генерации, смешения языков нет:

- нет перевода текста правила — `state=failed`, `failureCode=translation_missing`;
- иной сбой генерации — `failureCode=generation_error`;
- переход в `failed` поднимает оповещение и попадает в сводку Teams; повторный `createReport` за ту же неделю и язык ставит такой отчёт в генерацию заново (`failed` → `queued`), а отчёт `ready` не меняет;
- резервный язык не используется до ответа на вопрос 9 в `08`;
- новая `ruleVersion` вводится в действие только с текстами на nb, nn и en.

Период — ISO-неделя с понедельника 00:00 по понедельник 00:00 в timezone организации; UTC-границы хранятся. `createReport` принимает только такие границы и только завершённую неделю (`periodEnd` не позже текущего момента); иные границы, текущая и будущая неделя — 422 `validation_failed`. Свежесть и `coverageAt` в отчёте считаются на `periodEnd`. Задание `weekly_report` создаёт отчёт за завершённую неделю автоматически в понедельник 06:00 и догоняет пропущенные недели, не глубже 4 и не раньше недели создания организации. В P1–P2 отчёт выдаётся сотрудникам через портал, клиенту его передаёт техник.

**Снимок отчёта.** При генерации сервис один раз записывает неизменяемый снимок (`report.snapshot`), и HTML строится только из него:

- версии политики, действовавшие в периоде, состояние подключения Microsoft 365 на момент генерации и последний запуск сбора до конца периода. Метрики считаются на `periodEnd`, а состояние подключения при догоне пропущенной недели относится к моменту после конца периода;
- состав пар покрытия: субъект, проверка, категория (обязательная, informational, not_applicable), результат, severity, причина, `observedAt`, свежесть на `periodEnd`, определённость в периоде и активность субъекта на конец периода; счётчики и метрики покрытия;
- события периода, проблемы, открытые на конец периода, решения о риске и недоступные данные.

Поэтому смена ролей, исключений и политики, возврат субъекта и удаление evidence после генерации не меняют показатели закрытой недели. Строку `ready` изменить нельзя: UPDATE отклоняет триггер базы, а отдельной исправленной редакции отчёта в P1 нет. Если файл в Blob потерян, при выдаче он строится заново из снимка; заголовки и рекомендации берутся при этом из текстов текущей версии правил.

Содержание отдельно для Microsoft 365 и Windows:

- **Новые проблемы** — `opened` и `reopened` с `source_change`.
- **Исправленные** — `resolved` с `source_change`.
- **Продолжающиеся** проблемы.
- **Критические сейчас** — открытые `critical`.
- **Решения о риске** — «принятые риски» и «подавленные срабатывания» раздельно.
- **Отдельные категории без засчитывания как исправление** — изменения правил, изменения политики, «стали неприменимыми» (`resolved` с `applicability_change`) и выведенные субъекты.
- **Недоступные данные** с причинами и статусом модулей M365.
- **Счётчики** informational, not_applicable и «не настроено политикой».
- **Устройства** без свежего полного сбора (SYS-001) с `lastSeenAt` и отдельно — не выходившие на связь в периоде.
- **Покрытие** — `coveragePeriod`, `coverageAt` на `periodEnd`, доля stale и compliance; дата измерения и источник.

Отчёт, который впервые формируется за период старше 90 дней, строится из `basisSnapshot` и `finding_event`, а истёкшие подробности помечаются «подробности удалены по сроку хранения». Уже сформированный отчёт выдаётся из своего снимка.

Определения:

- **Обязательная проверка** — проверка с режимом `assessed` в действующей ревизии политики; собираемая проверка, кроме того, должна входить в `activeCheckIds`.
- **Применимая пара** — пара (субъект, проверка), у которой текущая оценка не not_applicable. Для M365-002 субъекты — только пользователи с привилегированной ролью.
- **Активный субъект.** Пользователь — присутствует в последнем полном списке `/users` и не выведен из учёта. Устройство на момент t — `status=active`, `enrolledAt` ≤ t и последний check-in не старше 14 суток (не dormant); в периоде — устройство с хотя бы одними сутками в `device_presence` внутри периода, то есть с подтверждённой доступностью. Остальные устройства показываются отдельным счётчиком «не выходили на связь». Tenant — подключение `active`; подключённый tenant до первого сбора тоже активен: его обязательные проверки дают пары без данных, и покрытие равно 0, а не «нет данных». У организации без подключения пар M365 нет, и покрытие — «нет данных».
- **Определённая оценка** — `result` pass или fail.
- **Покрытие для NFR-03** — `coveragePeriod`, из знаменателя которого исключены пары, у которых за период нет определённой оценки, а последняя оценка — unknown с причиной `license_missing` или `enforcement_unconfirmed` (ограничение tenant клиента или неподтверждённая семантика источника). Его считают по строкам снимка отчёта для критериев пилота (`01`, NFR-03); сам отчёт показывает `coveragePeriod` без исключений, а такие пары — с причиной в «Недоступных данных».
- **«Не настроено политикой»** — пары в режиме informational из-за отсутствующих входных настроек (WIN-010 без `expectedTenantId`, WIN-003 без одобренных продуктов).

Метрики:

- **Покрытие на момент t** (`coverageAt`) = свежие pass и fail обязательных применимых пар активных субъектов / все такие пары на момент t.
- **Покрытие периода** (`coveragePeriod`) = пары, у которых есть хотя бы одна определённая оценка с `observedAt` в периоде / обязательные применимые пары субъектов, активных в периоде, по политике на конец периода.
- **Compliance** = свежие pass / (свежие pass + свежие fail) на момент; при нулевом знаменателе выводится «нет данных».

Informational исключаются из числителя и знаменателя, not_applicable — из знаменателя; обе группы показываются счётчиками. Принятые риски остаются fail в compliance. Портал показывает `coverageAt` на текущий момент; сервис и отчёт используют одну функцию расчёта.

Пример для Microsoft 365. В tenant четыре включённых member-пользователя U1…U4 и гость G; U3 — единственный глобальный администратор. Чтение методов U4 закончилось таймаутом. В последнем запуске модуль политики авторизации получил `temporary_error`, поэтому текущая оценка M365-006 — unknown. Pass M365-006 получен во вторник той же недели и остался в истории. Обязательные проверки: M365-001, M365-002, M365-003, M365-005 и M365-006; M365-004 и M365-007 — informational.

| Субъект | M365-001 | M365-002 | M365-003 | M365-005 | M365-006 |
| --- | --- | --- | --- | --- | --- |
| U1 | pass, свежий | — | — | — | — |
| U2 | fail, свежий | — | — | — | — |
| U3 | pass, свежий | pass, свежий | — | — | — |
| U4 | unknown (`temporary_error`) | — | — | — | — |
| G | not_applicable | — | — | — | — |
| Tenant | — | — | fail, свежий | fail, свежий | unknown (`temporary_error`); pass во вторник |

Знаменатель — 8 пар: M365-001 у U1…U4, M365-002 у U3 и три проверки tenant. Числитель `coverageAt` — 6 свежих определённых оценок, без двух unknown. `coverageAt` = 6/8 = 75,0%. Если все оценки таблицы получены в отчётной неделе, `coveragePeriod` = 7/8 = 87,5%: у M365-006 есть определённая оценка в периоде (pass во вторник), у M365-001 пользователя U4 — нет. Compliance = 3/6 = 50%. Счётчики:

- informational — 1: M365-004 у tenant (informational-оценка всегда `result=null` и not_applicable не бывает; M365-007 отложена и оценок не имеет, informational-пара без оценки не считается);
- not_applicable — 1: M365-001 у G;
- unknown — 2, stale — 0.

Informational, not_applicable и принятые риски не скрывают недостаток покрытия. Compliance не означает вероятность безопасности и не сравнивается между разными версиями политик без пояснения.

## Инварианты вне JSON Schema

JSON Schema и OpenAPI задают структуру; закрытые evidence каждой проверки записаны только в схемах наблюдений агента и M365. Правила, которые зависят от нескольких полей, состояния сервера, времени или нескольких наблюдений, проверяет сервис, и каждое записано в реестре [specs/invariants.json](specs/invariants.json).

Запись реестра содержит `id` (`INV-nnn`), `rule`, `sourceDoc` (файл и раздел пакета), `phase` (P1 или P2), `enforcement` и `negativeExample`, а также `expectedError` и `acceptance` (сценарий из `07`). Значения `enforcement`: `schema`, `agent_api`, `portal_api`, `collector`, `evaluator`, `worker`, `db_rls`, `agent`, `infra`.

`expectedError` описывает ожидаемый отказ или эффект в одной из форм:

- HTTP-статус и `Problem.code`;
- оценка — `assessmentMode`, `result` и при необходимости `reasonCode`. Режим указывается всегда: у pass и fail `reasonCode` нет, у informational `result=null`, а причина — переносимая или отсутствует;
- допустимая пара `eventType` и `cause`;
- действие аудита;
- повтор без второго эффекта;
- состояние автомата агента;
- для RLS и прав базы — 0 строк: чтение без области возвращает 0 строк, а изменение чужой организации, в области чтения all или таблицы истории затрагивает 0 строк либо отклоняется ошибкой PostgreSQL (`WITH CHECK`, `READ ONLY`, отозванное право); данные не меняются;
- статус модуля M365;
- эффект задания (`none` или `single`).

Fixture записи с оценкой задаёт режим проверки в политике явно. Число записей реестра не доказывает полноту правил; её подтверждают автоматические негативные тесты, которые пишет WP, реализующий правило, на инфраструктуре WP-01.

Каждое новое текстовое правило в `01`, `03`, `04` или `05`, которое не выражается схемой, получает запись в реестре; реестр подчинён этим документам, и расхождение с ними — дефект пакета. Встроенная проверка пакета поддерживает только используемое подмножество JSON Schema и не заменяет стандартные валидаторы; полная стандартная проверка, генерация клиентов C# и TypeScript и CI — первый результат WP-01.
