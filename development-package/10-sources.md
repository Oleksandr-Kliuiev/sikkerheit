# Первичные источники и технические основания

Дата проверки документации — 12 октября 2026 года. При реализации повторно сверить конкретные endpoints, permissions, лицензии, стабильные версии и доступность услуг в выбранном регионе. Проверенные страницы подтверждают возможности платформ; работу приложения подтверждают эксперименты P0 и испытания P1/P2.

| Источник | Поддерживаемое положение |
| --- | --- |
| [Политика поддержки .NET](https://dotnet.microsoft.com/en-us/platform/support/policy) | .NET 10 LTS и срок поддержки |
| [Npgsql EF Core 10](https://www.npgsql.org/efcore/release-notes/10.0.html) | Доступен совместимый PostgreSQL provider |
| [Windows Service в .NET](https://learn.microsoft.com/en-us/dotnet/core/extensions/windows-service) | Worker Service и Windows hosting |
| [BitLocker status](https://learn.microsoft.com/en-us/powershell/module/bitlocker/get-bitlockervolume?view=windowsserver2025-ps) | Состояние шифрования и защиты являются отдельными полями |
| [Defender status](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus?view=windowsserver2025-ps) | Получение состояния и сигнатур Defender |
| [Windows Security Center](https://learn.microsoft.com/en-us/windows/win32/api/iwscapi/) | Интерфейсы статуса зарегистрированных защитных продуктов |
| [WinGet upgrade](https://learn.microsoft.com/en-us/windows/package-manager/winget/upgrade) | Не для всех приложений определяется текущая версия |
| [Graph users](https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0) | Application User.Read.All для списка пользователей и select |
| [Graph userRegistrationDetails](https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails?view=graph-rest-1.0) | AuditLog.Read.All и отсутствие отключённых пользователей в отчёте |
| [Свойства регистрации](https://learn.microsoft.com/en-us/graph/api/resources/userregistrationdetails?view=graph-rest-1.0) | Registered и capable имеют разные значения |
| [Authentication Methods Activity](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity) | Entra P1/P2 для отчётности и возможная задержка данных |
| [Security Defaults API](https://learn.microsoft.com/en-us/graph/api/identitysecuritydefaultsenforcementpolicy-get?view=graph-rest-1.0) | Policy.Read.All и isEnabled |
| [Conditional Access policies API](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies?view=graph-rest-1.0) | Для инвентаризации требуется Policy.Read.All |
| [Sign-in API](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0) | AuditLog.Read.All, дополнительные права к CA-данным |
| [Sign-in resource](https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0) | Entra P1/P2 для Graph-выгрузки |
| [Sign-in details](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-in-log-activity-details) | CA не применяется к обычному Windows sign-in; MFA может подтверждаться token claims |
| [Intune managedDevices](https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-list?view=graph-rest-1.0) | Active Intune license и DeviceManagementManagedDevices.Read.All |
| [Graph daemon configuration](https://learn.microsoft.com/en-us/entra/identity-platform/scenario-daemon-app-configuration) | App-only токены, конкретный tenant и certificate credentials |
| [Graph throttling](https://learn.microsoft.com/en-us/graph/throttling) | 429 и Retry-After |
| [Container Apps mTLS](https://learn.microsoft.com/en-us/azure/container-apps/client-certificate-authorization) | Отдельные режимы ingress и forwarded certificate |
| [Container Apps secrets](https://learn.microsoft.com/en-us/azure/container-apps/manage-secrets) | Managed Identity и ссылки на Key Vault |
| [PostgreSQL RLS](https://www.postgresql.org/docs/current/ddl-rowsecurity.html) | Политики строк и обход владельцем/superuser |
| [PostgreSQL backups](https://learn.microsoft.com/en-us/azure/postgresql/backup-restore/concepts-backup-restore) | Managed backups и PITR с условиями конфигурации |
| [Authenticode](https://learn.microsoft.com/en-us/windows/win32/seccrypto/time-stamping-authenticode-signatures) | Подпись, timestamp и современные digest algorithms |
| [Microsoft 365 Lighthouse](https://learn.microsoft.com/en-us/microsoft-365/lighthouse/m365-lighthouse-overview?view=o365-worldwide) | Существующая платформа MSP, которую следует сравнить с собственной услугой |
| [Secure Score](https://learn.microsoft.com/microsoft-365/security/defender/microsoft-secure-score?view=o365-worldwide) | Показатель внедрения контролей, не вероятность взлома |
| [GDPR](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng) | Минимизация, сроки хранения и обязанности обработчика |

## Источник продуктовой идеи

[Полная переписка](source/boss-chat.md) сохранена на языке оригинала. Пользователь подтвердил запуск на текущих клиентах IT-компании. Архитектура, трудоёмкость, фазы, критерии пилота и решения об изоляции являются предложенным проектом, который передаётся на независимую оценку.
