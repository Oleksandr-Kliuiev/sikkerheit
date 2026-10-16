# Первичные источники и технические основания

«Сверено» означает сверку документации, а не поведения: поведение API Microsoft 365 подтверждает SP-01, поведение Windows — SP-04, хостинг — SP-02. Даты — день сверки по первоисточнику. Перед реализацией этапа его endpoints, права, лицензии, версии и доступность услуг в регионе сверяются повторно.

## Microsoft 365 и Entra ID

| Источник | Поддерживаемое положение | Сверено |
| --- | --- | --- |
| [List users](https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0) | Наименьшее application-право — User.Read.All; `signInActivity` требует Entra ID P1/P2 и AuditLog.Read.All, страница — до 500 записей | 2026-10-15 |
| [signInActivity](https://learn.microsoft.com/en-us/graph/api/resources/signinactivity?view=graph-rest-1.0) | `lastSuccessfulSignInDateTime` в v1.0, заполняется с 2023-12-01 без досчёта | 2026-10-15 |
| [List authentication methods](https://learn.microsoft.com/en-us/graph/api/authentication-list-methods?view=graph-rest-1.0) | Наименьшее application-право — UserAuthenticationMethod.Read.All; требований к лицензии нет | 2026-10-15 |
| [authenticationMethod](https://learn.microsoft.com/en-us/graph/api/resources/authenticationmethod?view=graph-rest-1.0) | Виды методов v1.0; аппаратный OATH — только beta | 2026-10-15 |
| [Per-user MFA state (beta)](https://learn.microsoft.com/en-us/graph/api/authentication-get?view=graph-rest-beta) | `perUserMfaState` только в beta, право Policy.Read.All | 2026-10-15 |
| [userRegistrationDetails](https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails?view=graph-rest-1.0) | AuditLog.Read.All; отключённые пользователи не входят; для условия пересмотра ADR | 2026-10-15 |
| [Authentication Methods Activity](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity) | Отчётность требует Entra ID P1/P2, задержка данных до 36 часов | 2026-10-15 |
| [List roleAssignments](https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignments?view=graph-rest-1.0) | Наименьшее право — RoleManagement.Read.Directory; возвращаются активные назначения | 2026-10-15 |
| [PIM API overview](https://learn.microsoft.com/en-us/graph/api/resources/privilegedidentitymanagementv3-overview?view=graph-rest-1.0) | Назначения eligible — отдельные ресурсы и в roleAssignments до активации не видны | 2026-10-15 |
| [List roleAssignmentScheduleInstances](https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignmentscheduleinstances?view=graph-rest-1.0) | Наименьшее application-право — RoleAssignmentSchedule.Read.Directory, RoleManagement.Read.Directory тоже достаточно; `assignmentType` — `Assigned` или `Activated` | 2026-10-16 |
| [Role-assignable groups](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept) | Требуют Entra ID P1, не бывают вложенными, не больше 500 на tenant | 2026-10-15 |
| [List transitiveMembers](https://learn.microsoft.com/en-us/graph/api/group-list-transitivemembers?view=graph-rest-1.0) | Страница называет наименьшим правом GroupMember.ReadBasic.All, но в справочнике прав такого права нет; из перечисленных на странице наименьшее существующее application-право — GroupMember.Read.All | 2026-10-16 |
| [Permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference) | GroupMember.Read.All (application, `98830695-27a2-44f7-8c18-0c3ebc9698f6`) — членство и базовые свойства всех групп, требует admin consent; GroupMember.ReadBasic.All в справочнике нет | 2026-10-16 |
| [Security Defaults API](https://learn.microsoft.com/en-us/graph/api/identitysecuritydefaultsenforcementpolicy-get?view=graph-rest-1.0) | Policy.Read.All, свойство `isEnabled` | 2026-10-15 |
| [Conditional Access policies API](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies?view=graph-rest-1.0) | Policy.Read.All; более широкого права нет | 2026-10-15 |
| [Conditional Access overview](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview) | Conditional Access требует Entra ID P1, Business Premium его включает | 2026-10-15 |
| [authorizationPolicy](https://learn.microsoft.com/en-us/graph/api/authorizationpolicy-get?view=graph-rest-1.0) | Policy.Read.All; `permissionGrantPoliciesAssigned` | 2026-10-15 |
| [Configure user consent](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent?pivots=ms-graph) | Политики `…microsoft-user-default-legacy`, `…-low` и новая управляемая Microsoft `…-recommended` (по умолчанию для новых tenant); отсутствие записи — согласие выключено | 2026-10-15 |
| [List subscribedSkus](https://learn.microsoft.com/en-us/graph/api/subscribedsku-list?view=graph-rest-1.0) | Наименьшее право — LicenseAssignment.Read.All, Organization.Read.All тоже достаточно | 2026-10-15 |
| [Licensing service plan reference](https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference) | Планы `AAD_PREMIUM` и `AAD_PREMIUM_P2`; Business Premium включает P1, Business Standard — нет; имя SKU Business Standard — `O365_BUSINESS_PREMIUM` | 2026-10-15 |
| [Get organization](https://learn.microsoft.com/en-us/graph/api/organization-get?view=graph-rest-1.0) | Наименьшее право — Organization.Read.All | 2026-10-15 |
| [Certificate credentials](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials) | Client assertion: PS256 и заголовок `x5t#S256` | 2026-10-15 |
| [MSAL.NET client assertions](https://learn.microsoft.com/en-us/entra/msal/dotnet/acquiring-tokens/msal-net-client-assertions) | `WithClientAssertion` позволяет подписывать в Key Vault или HSM | 2026-10-15 |
| [Access tokens](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens) | Версию access token задаёт `requestedAccessTokenVersion` приложения API: null или 1 — v1.0, 2 — v2.0; в примерах страницы `amr` есть только в токене v1.0 | 2026-10-16 |
| [Access token claims](https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference) | Значения `amr`: `mfa` — многофакторная аутентификация, `wiaormfa` — Windows или MFA; claim `acrs` — authentication context | 2026-10-16 |
| [Admin consent endpoint](https://learn.microsoft.com/en-us/entra/identity-platform/v2-admin-consent) | Параметры ответа; значению `tenant` из ответа нельзя доверять для авторизации | 2026-10-15 |
| [Grant tenant-wide admin consent](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/grant-admin-consent) | Application permissions Graph согласует Privileged Role Administrator (и Global Administrator) | 2026-10-15 |
| [Built-in roles](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference) | Идентификаторы шаблонов 18 ролей политики M365-002 | 2026-10-15 |
| [Throttling](https://learn.microsoft.com/en-us/graph/throttling) | 429 и Retry-After, без заголовка — экспоненциальная пауза | 2026-10-15 |
| [Throttling limits](https://learn.microsoft.com/en-us/graph/throttling-limits) | Методы аутентификации и отчёты — 5 запросов за 10 с на tenant и 122 на все tenant; `signInActivity` — 10 в минуту; Conditional Access — 1 в секунду без Retry-After | 2026-10-15 |
| [JSON batching](https://learn.microsoft.com/en-us/graph/json-batching) | До 20 запросов в пакете, каждый ограничивается отдельно | 2026-10-15 |
| [Mandatory MFA](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mandatory-multifactor-authentication) | Обязательная MFA для порталов администрирования с 2024–2025 годов; сервисные principal не затронуты | 2026-10-15 |
| [SMTP AUTH Basic authentication timeline](https://techcommunity.microsoft.com/blog/exchange/updated-exchange-online-smtp-auth-basic-authentication-deprecation-timeline/4489835) | Выключение по умолчанию в конце декабря 2026 года с возможностью включить; окончательная дата будет объявлена во второй половине 2027 года | 2026-10-15 |
| [Microsoft 365 Lighthouse](https://learn.microsoft.com/en-us/microsoft-365/lighthouse/m365-lighthouse-overview?view=o365-worldwide) | Существующая платформа MSP для сравнения в SP-03 | 2026-10-12 |
| [Secure Score](https://learn.microsoft.com/microsoft-365/security/defender/microsoft-secure-score?view=o365-worldwide) | Показатель внедрения контролей, не вероятность взлома | 2026-10-12 |

## Windows

| Источник | Поддерживаемое положение | Сверено |
| --- | --- | --- |
| [Windows 11 release information](https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information) | Версии, build, даты окончания обновлений по семействам: 21H2, 22H2, 23H2, 24H2 (LTSC 2024 — до 2029-10-09, IoT Enterprise LTSC 2024 — до 2034-10-10), 25H2, 26H1 (build 28000, новые устройства), 26H2 (build 26300, выпуск 2026-09-29); hotpatch и внеочередные выпуски по веткам | 2026-10-15 |
| [Windows 10 release information](https://learn.microsoft.com/en-us/windows/release-health/release-information) | 22H2 (19045) — обслуживание закончилось 2025-10-14; LTSC 2021 — до 2027-01-12, IoT Enterprise LTSC 2021 — до 2032-01-13, LTSC 2019 — до 2029-01-09 | 2026-10-15 |
| [Windows 11 Home and Pro lifecycle](https://learn.microsoft.com/en-us/lifecycle/products/windows-11-home-and-pro) | Сроки обслуживания семейства Home — справочно | 2026-10-15 |
| [Windows 11 Enterprise and Education lifecycle](https://learn.microsoft.com/en-us/lifecycle/products/windows-11-enterprise-and-education) | Сроки обслуживания семейства Enterprise — справочно | 2026-10-15 |
| [Windows 10 ESU](https://learn.microsoft.com/en-us/windows/whats-new/extended-security-updates) | Коммерческий ESU для 22H2: годы до 2026-10-13, 2027-10-12 и 2028-10-10 | 2026-10-15 |
| [MSRC CVRF API](https://api.msrc.microsoft.com/cvrf/v3.0/updates) | Ежемесячные документы с KB и `FixedBuild` по продуктам, без аутентификации; встречаются расхождения данных | 2026-10-15 |
| [KB5089466](https://support.microsoft.com/kb/5089466) | Hotpatch мая 2026: 26100.8390 и 26200.8390 при обычном выпуске месяца .8457; UBR меняется без перезагрузки | 2026-10-15 |
| [KB5070881](https://support.microsoft.com/kb/5070881) | Внеочередной выпуск 2025-10-23 (26100.6905) — серверное исправление на общей ветке 26100 | 2026-10-15 |
| [Windows 11, version 26H1](https://techcommunity.microsoft.com/blog/windows-itpro-blog/what-to-know-about-windows-11-version-26h1/4491941) | 26H1 — для новых устройств на отдельных новых процессорах | 2026-10-15 |
| [Windows Updates API (beta)](https://learn.microsoft.com/en-us/graph/api/windowsupdates-catalog-list-entries?view=graph-rest-beta) | Каталог выпусков, только beta, лицензии Autopatch, WindowsUpdates.Read.All | 2026-10-15 |
| [Windows Service в .NET](https://learn.microsoft.com/en-us/dotnet/core/extensions/windows-service) | Worker Service и размещение как службы Windows | 2026-10-12 |
| [CNG Key Storage Providers](https://learn.microsoft.com/en-us/windows/win32/seccertenroll/cng-key-storage-providers) | Software KSP поддерживает ECDSA P-256; для Platform Crypto Provider (TPM) таблицы алгоритмов нет — поддержку P-256 проверяет SP-04 | 2026-10-15 |
| [TPM recommendations](https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/tpm-recommendations) | Не все TPM поддерживают все алгоритмы | 2026-10-15 |
| [NCryptCreatePersistedKey](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey) | Создание сохраняемого машинного ключа в выбранном KSP | 2026-10-13 |
| [Win32_EncryptableVolume](https://learn.microsoft.com/en-us/windows/win32/secprov/win32-encryptablevolume) | ConversionStatus и ProtectionStatus — отдельные значения; методы требуют прав администратора | 2026-10-13 |
| [GetConversionStatus](https://learn.microsoft.com/en-us/windows/win32/secprov/getconversionstatus-win32-encryptablevolume) | ConversionStatus 0–5, включая паузы шифрования и расшифровки | 2026-10-15 |
| [MSFT_MpComputerStatus](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/defender/msft-mpcomputerstatus) | Поля состояния и сигнатур Defender (документация архивная) | 2026-10-13 |
| [Совместимость Defender](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility) | При стороннем антивирусе Defender отключается или работает пассивно; режим показывает AMRunningMode | 2026-10-13 |
| [IWSCProductList](https://learn.microsoft.com/en-us/windows/win32/api/iwscapi/nn-iwscapi-iwscproductlist) | Перечень продуктов Windows Security Center; серверные ОС не поддерживаются | 2026-10-13 |
| [WSC_SECURITY_PRODUCT_STATE](https://learn.microsoft.com/en-us/windows/win32/api/iwscapi/ne-iwscapi-wsc_security_product_state) | Состояния ON, OFF, SNOOZED, EXPIRED | 2026-10-13 |
| [IAutomaticUpdatesResults](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nn-wuapi-iautomaticupdatesresults) | LastSearchSuccessDate и LastInstallationSuccessDate в UTC | 2026-10-13 |
| [ISystemInformation.RebootRequired](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-isysteminformation-get_rebootrequired) | Только логический признак, без времени возникновения требования | 2026-10-13 |
| [Win32_OperatingSystem](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem) | BuildNumber, OSArchitecture и LastBootUpTime | 2026-10-13 |
| [NetGetAadJoinInformation](https://learn.microsoft.com/en-us/windows/win32/api/lmjoin/nf-lmjoin-netgetaadjoininformation) | Сведения о присоединении к Entra ID зависят от контекста вызова | 2026-10-13 |
| [Local Accounts](https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts) | Встроенную учётную запись Administrator нельзя убрать из группы Administrators | 2026-10-15 |
| [Confirm-SecureBootUEFI](https://learn.microsoft.com/en-us/powershell/module/secureboot/confirm-securebootuefi) | Проверка Secure Boot требует прав администратора (источник о правах, а не способ сбора) | 2026-10-13 |
| [WinGet upgrade](https://learn.microsoft.com/en-us/windows/package-manager/winget/upgrade) | Не для всех приложений определяется версия (модуль P3) | 2026-10-12 |

## Azure, платформа и поставка

| Источник | Поддерживаемое положение | Сверено |
| --- | --- | --- |
| [PostgreSQL Flexible Server overview](https://learn.microsoft.com/en-us/azure/postgresql/overview) | Norway East в таблице регионов помечен как регион с доступом по запросу; проверяет SP-02 | 2026-10-15 |
| [Azure regions list](https://learn.microsoft.com/en-us/azure/reliability/regions-list) | Norway East — обычный регион с зонами, ограничен Norway West | 2026-10-15 |
| [PostgreSQL backup and restore](https://learn.microsoft.com/en-us/azure/postgresql/backup-restore/concepts-backup-restore) | Хранение 7–35 суток, PITR в новый сервер того же региона, геоизбыточность выбирается при создании | 2026-10-15 |
| [PostgreSQL private access (CLI)](https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/how-to-manage-virtual-network-cli) | Приватный доступ через VNet после создания сервера не меняется на публичный | 2026-10-15 |
| [Entra authentication for PostgreSQL](https://learn.microsoft.com/en-us/azure/postgresql/security/security-entra-concepts) | Вход managed identity и групп Entra | 2026-10-15 |
| [Manage Entra roles in PostgreSQL](https://learn.microsoft.com/en-us/azure/postgresql/security/security-manage-entra-users) | `pgaadauth_create_principal_with_oid(roleName, objectId, objectType, isAdmin, isMfa)` создаёт роль для объекта Entra по его object id | 2026-10-16 |
| [Trust a managed identity](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-config-app-trust-managed-identity) | Federated credential приложения от managed identity: issuer `https://login.microsoftonline.com/{tenant}/v2.0`, subject — object (principal) id identity, audience `api://AzureADTokenExchange`; секрет и сертификат не нужны | 2026-10-16 |
| [Key Vault key types and algorithms](https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys-details) | Подпись RSA: PS256 и RS256 | 2026-10-15 |
| [Key Vault keys](https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys) | Ключи RSA-HSM требуют уровня Premium | 2026-10-15 |
| [Key Vault RBAC](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide) | Роль Key Vault Crypto User для криптографических операций | 2026-10-13 |
| [Immutable storage](https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-storage-overview) | WORM по времени; заблокированную политику нельзя сократить или удалить | 2026-10-13 |
| [Storage built-in roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/storage) | Роли данных Blob: Reader, Contributor (чтение, запись и удаление), Owner, Delegator; роли «только создавать» нет | 2026-10-16 |
| [PostgreSQL row security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html) | Политики строк, FORCE и обход владельцем или superuser | 2026-10-12 |
| [PostgreSQL SET](https://www.postgresql.org/docs/current/sql-set.html) | SET LOCAL и равнозначный `set_config(..., true)` действуют только до конца текущей транзакции | 2026-10-13 |
| [PostgreSQL CREATE INDEX](https://www.postgresql.org/docs/current/sql-createindex.html) | `NULLS NOT DISTINCT` для уникальных индексов с PostgreSQL 15 | 2026-10-15 |
| [App Service deployment slots](https://learn.microsoft.com/en-us/azure/app-service/deploy-staging-slots) | Настройки, закреплённые за слотом, и порядок переключения | 2026-10-15 |
| [Azure Retail Prices API](https://learn.microsoft.com/en-us/rest/api/cost-management/retail-prices/azure-retail-prices) | Цены Norway East: P0v3 Linux около 0,0985 USD/ч, PostgreSQL B2s около 0,0876 USD/ч, ключ HSM RSA 3072 — 5 USD в месяц | 2026-10-15 |
| [Retirement of Office 365 connectors in Teams](https://devblogs.microsoft.com/microsoft365dev/retirement-of-office-365-connectors-within-microsoft-teams/) | Коннекторы Office 365 в Teams отключены в 2026 году; замена — Workflows | 2026-10-15 |
| [Adaptive Cards text features](https://learn.microsoft.com/en-us/adaptive-cards/authoring-cards/text-features) | Markdown поддерживает TextBlock; RichTextBlock с элементами TextRun Markdown не обрабатывает | 2026-10-16 |
| [Политика поддержки .NET](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core) | .NET 10 LTS до 2028-11-14 | 2026-10-15 |
| [Npgsql EF Core provider](https://www.nuget.org/packages/Npgsql.EntityFrameworkCore.PostgreSQL) | Выпуск 10.x для EF Core 10 | 2026-10-15 |
| [Artifact Signing overview](https://learn.microsoft.com/en-us/azure/artifact-signing/overview) | Новое название Trusted Signing | 2026-10-15 |
| [Artifact Signing quickstart](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart) | Public Trust для организаций Норвегии; регионы сервиса без Norway East; проверка организации занимает рабочие дни | 2026-10-15 |
| [Artifact Signing FAQ](https://learn.microsoft.com/en-us/azure/artifact-signing/faq) | Нужна платная подписка; сертификаты хранятся в сервисе | 2026-10-15 |
| [Artifact Signing pricing](https://azure.microsoft.com/en-us/pricing/details/artifact-signing/) | Basic — 9,99 USD в месяц, 5 000 подписей | 2026-10-15 |
| [Authenticode](https://learn.microsoft.com/en-us/windows/win32/seccrypto/time-stamping-authenticode-signatures) | Подпись и отметка времени | 2026-10-12 |
| [WiX Toolset OSMF](https://docs.firegiant.com/wix/osmf/) | WiX v7 под MS-RL; взнос для коммерческого использования (10 USD в месяц до 20 сотрудников, 40 USD при 20–100) и явное принятие EULA | 2026-10-15 |
| [CSP sandbox](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/sandbox) | Директива sandbox запрещает скрипты и даёт непрозрачный origin | 2026-10-13 |
| [GDPR](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng) | Минимизация, сроки хранения и обязанности обработчика | 2026-10-12 |

## Источник продуктовой идеи

[Полная переписка](source/boss-chat.md) сохранена на языке оригинала. Она объясняет происхождение идеи: агент на ПК, проверки Microsoft 365 и MFA, еженедельный отчёт «улучшено, новые отклонения, сохраняются», портал по клиентам. Технические предложения переписки спецификацией не являются. Масштаб, команда, канал установки и порядок этапов определены 2026-10-15.
