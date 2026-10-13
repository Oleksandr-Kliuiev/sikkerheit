# Каталог проверок и ограничений

Каталог определяет измеряемые факты, условия вывода и границы интерпретации. Пороговые значения ниже — стартовая политика пилота; изменения имеют версию и записываются в аудит. `checkId` сохраняется в наблюдении и совпадает с машинным каталогом `specs/check-catalog.json`.

## Семантика результата

Сбор возвращает `collected`, `unavailable` либо `not_applicable`. Сервер оценивает наблюдение как `pass`, `fail`, `unknown` либо `not_applicable`. Успешное получение факта не означает pass. Информационные измерения имеют `assessmentMode=informational` и не участвуют в оценке соответствия.

Отдельно хранится `freshness=fresh|stale`. Устаревший pass показывается как прошлый результат с датой; текущая оценка покрытия учитывает его как unknown. Обязательная проверка, которой нет в пакете, получает unknown с `missing_observation`. Внешняя невозможность проверки не означает not_applicable: такой статус задаётся только явной политикой применимости.

## Проверки Windows

| ID | Проверка и данные | Условие оценки | Права и ограничения |
| --- | --- | --- | --- |
| WIN-001 | Свободное место на системном диске: totalBytes, freeBytes | Warn при менее 10% или 10 GiB; critical при менее 5% или 2 GiB | Обычное чтение; эксплуатационный показатель, не доказательство защиты |
| WIN-002 | BitLocker: volumeStatus, protectionStatus, encryptionPercentage | При требовании шифрования pass только при завершении и активной защите; пауза или расшифровка — fail | Проверка прав в P0; recovery password никогда не извлекается |
| WIN-003 | Активный антивирус: provider, productState, источник статуса | Принятый политикой продукт active — pass для этой узкой проверки; off/expired — fail; неизвестный vendor mapping — unknown | Defender подробно; WSC только предоставленный статус стороннего продукта |
| WIN-004 | Давность сигнатур Defender: signatureLastUpdatedAt | Warn старше 3 суток, critical старше 7; будущая дата — unknown | Применяется когда Defender выбран основным AV; сторонний AV оценивается по отдельной интеграции |
| WIN-005 | Брандмауэр: domain/private/public enabled | Для штатного Windows Firewall все требуемые профили включены | Альтернативный firewall требует явной политики и собственного источника |
| WIN-006 | Windows Update: securityUpdatesPending, lastSuccessfulSearchAt, configuredSource | Pass только после успешного поиска по действующему источнику и отсутствия просроченных обновлений согласно политике | Поиск может быть долгим; WSUS и отсрочки учитываются; одна дата последнего KB недостаточна |
| WIN-007 | Необходимость перезагрузки по поддерживаемому Windows Update API | Warn при подтверждённой необходимости дольше 3 дней | Отрицательный результат относится только к поддерживаемому источнику, не ко всем установщикам |
| WIN-008 | Прямые члены группы локальных администраторов по известному SID группы | Непредусмотренный политикой SID — fail | Не равнозначно полному раскрытию вложенных AD/Entra-групп и всех способов повышения прав |
| WIN-009 | Secure Boot: фактическое состояние и обнаруженная платформа | При обязательной политике disabled или подтверждённое отсутствие поддержки — fail | Access denied — unknown; виртуальная машина не исключается автоматически |
| WIN-010 | Регистрация устройства Entra: joinType, tenantId, entraDeviceId | Информационная инвентаризация; проверка tenant только при явной политике | Устройство не даёт доступа к данным всего tenant; пользовательская Hello/PIN не выводится из контекста SYSTEM |
| SYS-001 | Последний heartbeat и полный сбор | Stale после 48 часов без новых данных по стартовой политике | Вычисляется сервером; выключенный ПК не объявляется автоматически заражённым |

Каждый сборщик ограничен 30 секундами; бюджет всей сессии — 120 секунд. При исчерпании бюджета оставшиеся проверки получают `unavailable/collector_timeout`. Для медленного Windows Update в P0 проверить необходимость отдельного фонового задания с собственным лимитом. Данные произвольного PowerShell stdout не передаются; используется allowlist структуры.

Список разрешённых администраторов, источник обновлений и допустимый AV согласуются по клиенту. Без необходимых входных настроек проверка становится informational либо unknown, а не создаёт ложное отклонение.

Штатные источники: [BitLocker](https://learn.microsoft.com/en-us/powershell/module/bitlocker/get-bitlockervolume?view=windowsserver2025-ps), [Defender](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus?view=windowsserver2025-ps), [Windows Security Center](https://learn.microsoft.com/en-us/windows/win32/api/iwscapi/). Точные права каждого вызова устанавливаются экспериментом на поддерживаемых редакциях Windows.

## Проверки Microsoft 365

Все endpoints ниже относятся к Graph v1.0. Таблица показывает application permissions для фонового доступа; администратор клиента отдельно выдаёт consent. Право чтения может охватывать весь tenant, поэтому объём запрашиваемых и сохраняемых данных ограничивается allowlist.

| ID | Данные и endpoint | Application permissions | Условия и вывод |
| --- | --- | --- | --- |
| M365-001 | `/reports/authenticationMethods/userRegistrationDetails`, сопоставление с `/users?$select=id,accountEnabled,userType,userPrincipalName` | `AuditLog.Read.All`, `User.Read.All` | P2. Доступ к отчёту требует Entra P1/P2. Проверять регистрацию активных member accounts; отсутствующий пользователь в отчёте — unknown, отключённый исключается по применимости |
| M365-002 | `/policies/identitySecurityDefaultsEnforcementPolicy` | `Policy.Read.All` | P2. Информационная запись isEnabled. Disabled не означает общую слабость: клиент может использовать Conditional Access |
| M365-003 | `/identity/conditionalAccess/policies` | `Policy.Read.All` | P2. Инвентаризация состояния enabled/report-only/disabled и условий; эксплуатация CA требует подходящей лицензии. P2 не доказывает покрытие каждого сценария |
| M365-004 | `/deviceManagement/managedDevices` с `$select` необходимых полей | `DeviceManagementManagedDevices.Read.All` | P2 optional. Нужна активная лицензия Intune, управляемое устройство и свежий lastSyncDateTime; compliant относится к назначенным политикам Intune |
| M365-005 | `/auditLogs/signIns` с диапазоном времени и минимальной проекцией | `AuditLog.Read.All`; для CA-деталей дополнительно подходящее policy read permission | P3. Graph-выгрузка требует Entra P1/P2; некоторые риск-детали P2. Отсутствие входа в период не доказывает запрет доступа |

Права сверены с [отчётом регистрации](https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails?view=graph-rest-1.0), [users](https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0), [Security Defaults](https://learn.microsoft.com/en-us/graph/api/identitysecuritydefaultsenforcementpolicy-get?view=graph-rest-1.0), [CA policies](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies?view=graph-rest-1.0), [Intune](https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-list?view=graph-rest-1.0) и [signIns](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0). Endpoint или permission нельзя автоматически подменять по совпадению названий.

Для M365-001 `isMfaRegistered` и `isMfaCapable` сохраняются отдельно. Pass подтверждает выполнение требования регистрации, но не обязательность MFA. Источник может обновляться с задержкой до 36 часов; свежесть оценивает также время источника, если оно доступно. [Условия отчёта](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity).

Полный анализ покрытия CA требует групп, исключений, authentication strengths, ресурсов и сценариев; связанные права и дополнительный проект относятся к P3. Windows sign-in не считается нарушением только потому, что CA не применялась. [Различия сценариев](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-in-log-activity-details).

## Возможности интеграции

Каждый модуль имеет `capabilityStatus=available|permission_missing|license_unconfirmed|unsupported|temporary_error|disconnected`. `license_unconfirmed` означает необходимость уточнения, а не доказанное отсутствие лицензии. Проверяются выдача token, endpoint, pagination и полученные свойства. 200 с отсутствующим обязательным свойством не считается полным успешным наблюдением.

Частично доступный tenant остаётся подключённым с явным списком недоступных проверок. Обработка Graph GET ограничивается разрешёнными hosts, конкретным tenant, разрешёнными paths и проверенными nextLink; произвольный внешний URL не выполняется.

## Следующие модули

Проверка конкретных приложений начинается с согласованного каталога vendor/version. WinGet используется как дополнительный источник, а unknown version сохраняется явно. [Ограничения версий WinGet](https://learn.microsoft.com/en-us/windows/package-manager/winget/upgrade).

Настройки блокировки экрана и пользовательский Windows Hello требуют измерения правильного пользовательского контекста. Backup требует интеграции с конкретным поставщиком и отдельного подтверждения восстановления. Secure Score остаётся дополнительным индикатором внедрения контролей, без трактовки как вероятности взлома. [Смысл Secure Score](https://learn.microsoft.com/microsoft-365/security/defender/microsoft-secure-score?view=o365-worldwide).
