# Azure и эксплуатация сервиса

Ресурсы приложения принадлежат вашей Azure-подписке. Клиент устанавливает агент и отдельно разрешает нужные проверки своей организации. Предлагается отдельное окружение test и production с отдельными credentials, базами и журналами.

## Ресурсы пилота

| Ресурс | Назначение | Конфигурация и условия |
| --- | --- | --- |
| Container Apps Environment портала и заданий | Среда Portal API и Worker | Регион ЕЭЗ после проверки доступности нужных услуг |
| Отдельный Container Apps Environment Agent API | Среда только для Agent API | Без других приложений; не является целью environment-level HTTP routes |
| Внутренний VNet-environment Issuer | Среда Issuer (там же может работать Worker) | Ingress с внутреннего load balancer, сетевая связность из environments Portal API и Agent API; схема выбирается в PKI-дизайне до WP-03 по SP-02 |
| Portal API Container App | Портал, API и регистрация агентов | Публичный HTTPS, вход Entra; `enrollAgent` имеет свой лимит |
| Agent API Container App | Телеметрия устройств и продление сертификатов | Отдельный hostname, обязательный mTLS, проверка XFCC приложением |
| Issuer Container App | Подпись сертификатов устройств | Собственная managed identity с единственным правом sign на Key Vault CA; только роль БД Issuer добавляет записи `device_certificate` |
| Worker Container App | Задания и планировщик | Без публичного ingress; min replicas 1 для PostgreSQL-очереди; планировщик работает внутри каждой реплики; Graph-сертификатов не получает |
| Azure Database for PostgreSQL Flexible Server | Основные данные | PostgreSQL 15 или новее, managed backups, private connectivity, выбранные размеры после нагрузочного теста |
| Storage Account и private Blob containers | HTML-отчёты, экспорты и подписанные MSI | Версии и lifecycle; авторизованная выдача файлов |
| Отдельный Storage Account журнала жизненного цикла | `lifecycle_journal` | Контейнер с locked time-based retention на 30 дней и protected append writes; Blob PITR выключен; запись только у identities Portal API, Worker и Issuer, права delete нет |
| Key Vault CA (P1) | Неэкспортируемый ключ CA | `key_ops` = sign/verify; право sign только у Issuer; диагностические журналы sign включены |
| Key Vault Graph (P2; в варианте B — Key Vault импорта в P1) | Graph-сертификаты, в варианте B также ключи RMM API | Доступ только у managed identity компонента Graph-сбора либо компонента импорта; у Worker, Portal API, Agent API и Issuer доступа нет |
| Container Registry | Образы сервера | Pull через Managed Identity; версии образов закрепляются digest |
| Azure Monitor и Application Insights | Метрики и логи | Лимиты бюджета, retention и редактирование чувствительных полей |
| Entra application registrations | Portal SSO и приложения клиентов | Раздельные назначения; app role `PlatformAdmin`; P1 и Graph имеют разные credentials |
| VNet и нужные private connectivity ресурсы | Доступ к данным и к Issuer | Конкретная схема и стоимость подтверждаются в P0 (SP-02) |

Container Apps и Key Vault поддерживают Managed Identity; это не выдаёт автоматически Graph-права в tenant клиента. [Секреты Container Apps](https://learn.microsoft.com/en-us/azure/container-apps/manage-secrets). Если SP-02 провален по критерию (а) или (в), Agent API переходит на запасной вариант ADR-05: TCP ingress в VNet-environment и mTLS в Kestrel.

Service Bus, email через Communication Services, Front Door/WAF и расширенная защита облака — отдельные решения по нагрузке и требованиям. Их стоимость не скрывается в базовой оценке. API rate limits, ограничения тела и серверная авторизация обязательны и в пилоте.

## Установка и выпуск агента

Windows-агент публикуется self-contained под поддерживаемую архитектуру и устанавливается подписанным MSI. Точная библиотека создания MSI выбирается в P0 после проверки лицензии, silent install, восстановления и обновления Windows-служб. Подписываются MSI, EXE и запускаемые helpers, с timestamp и закреплённым publisher. [Authenticode](https://learn.microsoft.com/en-us/windows/win32/seccrypto/time-stamping-authenticode-signatures). Агент не входит в golden image: он устанавливается каналом установки после развёртывания ОС и регистрируется при первом запуске.

Канал установки и обновления (существующий Intune или RMM вашей компании) — вопрос 2 в `08`, источник сертификата подписи кода — вопрос 8 в `08`; ADR-07 ожидает ответа. Полноценный собственный updater не включён в бюджет P1. При отсутствии подходящего инструмента выбрать проверенный установочный процесс либо явно увеличить объём. Подпись проверяется в двух точках. В CI перед публикацией в канал выполняются `signtool verify /pa` и сверка publisher по subject CN/O, для Artifact Signing также по EKU 1.3.6.1.4.1.311.97.*, но не по thumbprint. Скрипт установки выбранного канала перед `msiexec` проверяет статус Authenticode Valid и ожидаемый subject; при несовпадении установка останавливается.

Выпуск: Windows-лаборатория → собственные устройства → один клиент → остальной пилот. У каждого выпуска сохраняются version, hash, publisher, compatible schema versions, release notes, SBOM и процедура восстановления. Обновление — тихий MajorUpgrade без принудительной перезагрузки (`REBOOT=ReallySuppress`), службы перезапускаются. Сохраняются CNG-ключ, SQLite, sequence и `installationId`. Миграции SQLite совместимы с предыдущей версией либо выполняются после резервной копии файла. Смена сертификата подписи не требует изменений агента, потому что publisher закреплён по subject. Устаревшая версия получает 422 `agent_version_unsupported` с полем `minimumAgentVersion` и переходит в `VersionBlocked`: scans не отправляются, но GET configuration и heartbeat остаются доступны, поэтому агент узнаёт минимальную версию и остаётся видимым, а существующие проблемы не исчезают.

Rollback — предыдущий подписанный MSI с совместимой версией SQLite; автоматическое понижение без согласованной процедуры отсутствует. Неудачное обновление, остановка распространения через канал установки и rollback выполняются по RB-06. Внеочередной отзыв опасной версии и credentials выполняется по RB-07.

## Развёртывание сервера

Infrastructure as code — Bicep; CI — GitHub Actions либо текущая система компании. Cloud deployment использует OIDC/federated credentials. Windows-пакеты собираются Windows runner, контейнеры — Linux runner. Пайплайн включает проверку контрактов, meaningful integration tests, зависимости, SBOM и изолированную подпись без вывода ключей в logs.

Миграции базы выполняются отдельной ролью до переключения версии. Используется совместимость expand/contract: новые поля и таблицы вводятся прежде удаления старых. Автоматический destructive migration в startup отсутствует. Старые и новые экземпляры должны читать совместимую схему во время перехода.

## Наблюдаемость

Метрики: lastSeen по устройствам, возраст наблюдений, пропущенные проверки, размер офлайн-буфера и `droppedBatchCount`, p95 ingestion/evaluation, глубина очереди, failed jobs, последний такт планировщика, Graph 403/429/5xx, срок сертификатов устройств, `certificate_unknown` по часам, sign-операции Issuer, обращения PlatformAdmin к данным клиентов, выгрузки отчётов и бюджет Azure. Logs и traces не содержат тела пакетов и credentials.

Для каждого alert задать владельца и действие. Примеры: рост неоценённых пакетов → проверить worker/базу; периодические задания не создавались дольше двух периодов → проверить планировщик в репликах worker; пакет получил `processing_failed` через 7 суток после приёма → разобрать потерю данных; всплеск `certificate_unknown` → действовать по RB-01; рост Graph 403 → проверить consent; до истечения сертификата устройства меньше 30 дней, а продления не было → проверить продление по RB-04; ежечасная сверка журнала sign Key Vault CA с журналом Issuer и `device_certificate` нашла необъяснённую подпись → начать расследование, при подтверждённой компрометации — ротация CA по RB-05; объём доступа PlatformAdmin превысил ожидаемый → проверить по аудиту; доступ другого клиента → остановить выдачу затронутого пути и начать расследование.

События аудита платформенного уровня (изменения `platform_role`, создание и удаление организаций) хранятся в `audit_event` с `organizationId = null` и сроком хранения аудита. Операции API для их чтения в P1 нет: Operations читает их запросом к базе или в Log Analytics. Доступ PlatformAdmin к данным конкретной организации пишется с её `organizationId` и читается через `listAuditEvents`.

## Восстановление и удаление

План P1: резервные копии базы 14 дней и измеренная процедура PITR; раз в месяц учебный restore в карантине (RB-09, см. «Журнал жизненного цикла и restore в карантине») в изолированное окружение без обращения к реальным клиентским Graph-интеграциям. Отдельно восстановить Blob, настройки инфраструктуры и ссылки на credentials. Возможность PITR не означает достижение целевого RTO без испытания. [Backups PostgreSQL](https://learn.microsoft.com/en-us/azure/postgresql/backup-restore/concepts-backup-restore).

Прекращение обслуживания выполняется операциями контракта по RB-10 (учётной записью PlatformAdmin), без SQL; переходы и их эффекты описаны в `05`, раздел «Жизненный цикл организации». `changeOrganizationLifecycle` с действием `disable` переводит организацию в `disabled`: сначала запись в журнал, затем в базу; все enrollment-токены организации отзываются, агенты получают 403 `organization_inactive`, из заданий выполняются только `organization_export`, `retention_purge` и `organization_delete`. `enable` возвращает организацию в `active` без переустановки агентов, но отозванные токены остаются отозванными. Затем `createOrganizationExport` создаёт экспорт; файл экспорта хранится 7 дней. `schedule_deletion` допускается, только если есть экспорт, созданный после перехода в `disabled`, в состоянии `ready` или `expired`, либо `exportWaived=true`; он переводит организацию в `deletion_scheduled` и устанавливает `deletionDueAt` = now + 30 суток (платформенный параметр). До `deletionDueAt` действие `cancel_deletion` возвращает организацию в `disabled`. Планировщик ежечасно ставит задание `organization_delete` для организаций с `deletionDueAt ≤ now`; задание сначала пишет `delete` в журнал, затем отзывает все устройства и сертификаты, удаляет primary данные, Blob и вспомогательные индексы и оставляет tombstone. После удаления организация отвечает 404, а агенты получают 401 `certificate_revoked`, пока хранится запись отзыва. Срок, согласованный с клиентом, и порядок утверждения удаления — вопрос 6 в `08`. Срок окончания присутствия в backups (14 дней) сообщается клиенту по выбранной политике.

## Журнал жизненного цикла и restore в карантине

Restore из резервной копии не должен возвращать удалённые данные, обслуживаемый статус и отозванный доступ. Для этого сущность `lifecycle_journal` хранится вне PostgreSQL, append-only. Поля: `id`, `organizationId`; `targetType` (`organization`, `device`, `device_certificate`, `integration`, `enrollment_token`, `organization_member`); `targetId`, для `organization_member` — внутренний UUID строки, а не `entraUserId`; `action` (`disable`, `enable`, `schedule_deletion`, `cancel_deletion`, `delete`, `revoke`, `disconnect`, `token_revoke`), отзыв назначения записывается как `revoke` с `targetType=organization_member`; `occurredAt`, `correlationId`. `actorId` в журнале нет: исполнитель находится через `correlationId` и `audit_event`.

Журнал хранится в отдельном storage account, в контейнере с locked time-based retention на 30 дней и protected append writes; Blob PITR выключен. Писать в журнал могут только identities Portal API, Worker и Issuer; права delete нет. Если срок backup увеличивается, сначала увеличивается срок журнала. Ограничивающие действия (`disable`, `schedule_deletion`, `delete`, `revoke`, `disconnect`, `token_revoke`, отзыв назначения) сначала пишутся в журнал, затем в базу. Разрешающие действия (`enable`, `cancel_deletion`) сначала выполняются в базе, затем пишутся в журнал: если запись потеряется, итог окажется строже, а не мягче. Повторное применение журнала идемпотентно.

Restore выполняется в карантине по RB-09: (1) закрыть ingress Portal API и Agent API и остановить Worker — никаких заданий, обращений к Graph и выдачи отчётов; (2) применить журнал по порядку; (3) сверить статусы организаций, сертификатов, интеграций, enrollment-токенов и назначений; (4) удалить Blob удалённых организаций; (5) только после этого открыть доступ. Учебный restore выполняется ежемесячно.

## Модель расходов

До договора получить актуальную оценку Azure Calculator по выбранному региону. Отдельные позиции: постоянная база, работающие реплики worker/API и Issuer, второе Container Apps environment для Agent API и внутреннее VNet-environment Issuer, VNet и private endpoints, storage/requests, отдельный storage account журнала жизненного цикла, registry, Key Vault CA и Key Vault Graph (в варианте B — Key Vault импорта) с операциями, logs ingestion, backups, code signing и email. Источник подписи кода (Artifact Signing или OV-сертификат в HSM) выбирается по ответу на вопрос 8 в `08`; в модель записываются выбранный источник, его стоимость и срок оформления — у Artifact Signing он составляет 1–20 рабочих дней, поэтому оформление стартует в P0 и должно завершиться до WP-07a. Месячная стоимость делится на число оплачиваемых клиентов и устройств, но затраты onboarding и поддержки учитываются отдельно.

Для расчётной модели 1 000 устройств и одного полного сбора в сутки (11 наблюдений — по одному на каждую WIN-проверку) получается около 330 000 наблюдений за 30 дней; вместе с серверными оценками SYS-001 и SYS-002 это 13 оценок на устройство в сутки, около 390 000 оценок за 30 дней. Расчёт сделан до учёта повторов, внеплановых проверок, объёмов дисков и облачных субъектов. Это арифметическое допущение для sizing, не оценка реальной нагрузки и не прайс Azure.
