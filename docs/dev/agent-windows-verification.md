# Агент Windows: что проверяется только на Windows (SP-04)

Состояние на 2026-10-16. Код агента (WP-09) написан и проверен на macOS: автомат, буфер SQLite, протокол и подпись, сборка и проверка пакета схемой, конфигурация, телеметрия, запуск сборщиков в потоках с таймаутами — тестами `tests/Sikkerheit.Agent.Tests` против поддельного сервера в памяти и с программным ключом ECDSA P-256. Всё, что обращается к Windows, лежит в двух местах и на macOS только компилируется:

- `src/Agent/Sikkerheit.Agent.Collectors/Windows/` — читатели фактов (реестр, WMI, COM, Win32, LSA);
- `src/Agent/Sikkerheit.Agent/Windows/WindowsKeys.cs` — ключ устройства в CNG/TPM, DPAPI, права каталога данных; сборка службы — `Program.cs`.

Источник правды о том, что именно должен подтвердить SP-04, — этот список. Лаборатории Windows нет, поэтому ничего из раздела 1–8 не проверено. Раздел 9 — что уже делает CI на `windows-latest`.

Протокол SP-04 записывает на каждый пункт: редакцию и сборку ОС, учётную запись (LocalSystem), результат, время вызова, найденное отличие от пакета. Отличие от пакета — дефект пакета, его вносят в следующую версию (`docs/reviews/0.3.0-decisions.md`, «Реализация P2»).

## 1. Служба и защита на ПК (AT-15, `02`, «Выполнение локальной проверки», `04`, «Защита агента на ПК»)

| № | Проверка | Как |
| --- | --- | --- |
| 1.1 | Служба `Sikkerheit.Agent` работает под LocalSystem, тип запуска автоматический (отложенный не нужен) | `sc qc Sikkerheit.Agent`, `sc qprivs` |
| 1.2 | Каталог данных (`%ProgramData%\Sikkerheit\Agent`) доступен только SYSTEM, наследование снято | `icacls`; обычный пользователь и локальный администратор без смены владельца не читают `agent.db`, `enrollment.key.dpapi` |
| 1.3 | Каталог установки доступен на запись только SYSTEM и администраторам (задаёт MSI, WP-11) | `icacls`; попытка заменить `Sikkerheit.Agent.exe` обычным пользователем отклонена |
| 1.4 | Обычный пользователь не может остановить, перенастроить службу и подменить конфигурацию | `sc stop`, `sc config` от обычного пользователя; запись в `appsettings.json` |
| 1.5 | Нет входящих соединений и named pipe | `netstat -ano`, `Get-NetTCPConnection`, `handle`/`pipelist` по PID службы |
| 1.6 | Нет дочерних процессов за сутки работы и при сборе | Sysmon event 1 (ParentImage агента) или Process Monitor |
| 1.7 | Три оставленных сборщика завершают процесс кодом ошибки, SCM перезапускает службу по recovery actions MSI (`Environment.Exit(1)` в `AgentWorker`) | Зависший WMI-вызов (отключённая служба `winmgmt` или заглушка провайдера) на трёх сборщиках; Event Log «служба завершилась неожиданно», счёт `abandonedCollectors` в check-in. Сам процесс завершается без статуса STOPPED: проверить, что recovery actions срабатывают именно так |
| 1.8 | Остановка службы (`sc stop`) — чистая: следующий запуск не считается сбоем (`lastCrashAt` пуст) | `sc stop`/`sc start`, check-in |
| 1.9 | Журнал агента: Event Log (источник службы) без ключа регистрации, токена, SID членов группы | `Get-WinEvent`; локального файлового журнала нет |
| 1.10 | Плановый сбор начинается не раньше чем через 60 минут после загрузки ОС (`ProcessProbe.BootTime` = `now − Environment.TickCount64`) | Перезагрузка, первый пакет в журнале приёма; поведение при быстрой загрузке и гибернации (TickCount64 считает время без сна — проверить расхождение с реальным временем загрузки) |

## 2. Ключ устройства (H-KEY, `04`, «Ключ устройства и сессия»)

| № | Проверка | Как |
| --- | --- | --- |
| 2.1 | Microsoft Platform Crypto Provider создаёт ключ P-256, пробная подпись SHA-256 проходит; `keyProtection=tpm` | На каждой модели ПК лаборатории (TPM 2.0 разных производителей: Intel PTT, AMD fTPM, дискретные Infineon/Nuvoton/STM) |
| 2.2 | Без TPM или при отказе провайдера создаётся неэкспортируемый машинный ключ MSKSP, `keyProtection=software`, DACL только SYSTEM (`NCRYPT_SECURITY_DESCR_PROPERTY`, флаг DACL = 4) | ВМ без vTPM; `certutil -csp "Microsoft Software Key Storage Provider" -key`, проверка DACL файла ключа в `C:\ProgramData\Microsoft\Crypto\Keys`; обычный администратор не использует ключ без SYSTEM |
| 2.3 | Экспорт закрытого ключа невозможен (`ExportPolicy=None`) | Попытка `ECDsaCng.Key.Export(EccPrivateBlob)` из процесса администратора |
| 2.4 | Подпись IEEE P1363 (64 байта) принимается сервером; публичный ключ из `ExportParameters(false)` совпадает с зарегистрированным | Регистрация против сервера после WP-10 |
| 2.5 | Образ диска, перенесённый на другое ПК с TPM, не подписывает запросы (ключ не открывается), агент создаёт новый ключ и получает `identity_conflict` вида `key` (INV-106, RB-11) | Клон ВМ и физический перенос образа |
| 2.6 | Очистка TPM (`Clear-Tpm`) — тот же путь; решение `accept_new_key` возвращает агента в Active | RB-11 |
| 2.7 | Удаление ключа при `device_revoked` (INV-109): после `Revoked` ключа нет ни в TPM, ни в MSKSP | `certutil -csp … -key`, `tpmtool` |
| 2.8 | `CngKey.Exists`/`Open` по машинному ключу работают из LocalSystem после перезагрузки и смены пользователя | Перезапуск службы, перезагрузка |

## 3. Ключ регистрации и DPAPI (SP-05, `04`, «Ключ регистрации организации»)

| № | Проверка | Как |
| --- | --- | --- |
| 3.1 | Скрипт RMM под SYSTEM пишет `enrollment.key` в каталог данных; служба в течение минуты сохраняет ключ под DPAPI (LocalMachine) и удаляет файл | Файл исчезает, появляется `enrollment.key.dpapi`; содержимое не содержит текста `sikk_` |
| 3.2 | Ключ не виден в журналах: 4688 (командная строка), PowerShell 4104, Sysmon, журналы RMM | Просмотр после установки и регистрации (SP-05) |
| 3.3 | Блоб DPAPI не расшифровывается на другом ПК и непрозрачен обычному пользователю | Копия файла на другой ПК |
| 3.4 | Неверный формат файла ключа: файл удаляется, попытки регистрации нет | Файл с мусором |

## 4. Сборщики WIN-001…WIN-011 (`03`, «Проверки Windows», «Сбор данных и источники»)

Для каждой строки: вызов выполняется из LocalSystem, время вызова записывается, результат сверяется со штатным инструментом. Матрица: Windows 10 22H2 Pro, Windows 11 24H2 Pro, 25H2 Pro, Enterprise (для WIN-002 `notApplicableEditionIds`), Home (WIN-002), LTSC, ARM64 (если есть ПК).

| Проверка | Реализация | Что подтвердить |
| --- | --- | --- |
| WIN-001 | `GetVolumeNameForVolumeMountPoint` (volumeId, независимо от сборщиков) + `GetDiskFreeSpaceExW` по пути тома | volumeId совпадает с `mountvol`; `freeBytes` совпадает с `Get-Volume` с учётом квот. После смены буквы тома `volumeId` тот же |
| WIN-002 | WMI `root\CIMV2\Security\MicrosoftVolumeEncryption`, `Win32_EncryptableVolume` по `DeviceID`, методы `GetConversionStatus`, `GetProtectionStatus` | **Эталонный отрицательный тест**: BitLocker включён, защита приостановлена (`Suspend-BitLocker`) → `fully_encrypted`/`off`/100; `Resume`; шифрование в процессе; Home (класс отсутствует → `unsupported`); recovery password не читается и не передаётся (проверить по трассе WMI) |
| WIN-003 | `root\SecurityCenter2\AntiVirusProduct` (вместо `IWSCProductList`, см. «Реализация P2») + `root\Microsoft\Windows\Defender\MSFT_MpComputerStatus` | **Таблица `productState`**: средний байт 0x10 → `on`, 0x00 → `off`, 0x01 → `snoozed`, 0x11 → `expired` проверить на пяти конфигурациях `03` (только Defender; активен сторонний; сторонний + MDE/Smart App Control; лицензия истекла; snoozed). Режимы `AMRunningMode`: Normal, Passive mode, EDR Block Mode, SxS Passive Mode, Not running. Стабильность GUID продукта. Серверная редакция: `SecurityCenter2` отсутствует — ожидается `temporary_error`/`unsupported`, матрица ОС |
| WIN-004 | `MSFT_MpComputerStatus.AntivirusSignatureLastUpdated` (CIM datetime → UTC) | Совпадение с `Get-MpComputerStatus`; часовой пояс и летнее время; Defender снят сторонним продуктом (класс отсутствует → `unsupported`) |
| WIN-005 | COM `HNetCfg.FwPolicy2`, свойство `FirewallEnabled` для профилей 1, 2, 4; сторонний firewall — `SecurityCenter2\FirewallProduct` | Позднее связывание через IDispatch в STA-потоке из LocalSystem; профили против `Get-NetFirewallProfile`; групповая политика, отключающая профиль |
| WIN-006 | COM `Microsoft.Update.AutoUpdate` → `Results.LastSearchSuccessDate`/`LastInstallationSuccessDate` (DATE; пустое значение 1899 → `null`); реестр `Policies\Microsoft\Windows\WindowsUpdate` (`WUServer`, `AU\UseWUServer`) | Совпадение с `wuauclt`/журналом обновлений; WSUS/WUfB; Windows Update for Business |
| WIN-007 | COM `Microsoft.Update.SystemInfo.RebootRequired`, WMI `Win32_OperatingSystem.LastBootUpTime` | Требование перезагрузки после установки обновления; `lastBootAt` после быстрой загрузки (Fast Startup меняет «время загрузки») |
| WIN-008 | `NetLocalGroupGetMembers` (уровень 0, SID) по имени группы из SID `S-1-5-32-544` (локализованное имя); SID машины — `NetUserModalsGet` ур. 2; SID домена — LSA `PolicyDnsDomainInformation` | Классы `builtin_administrator`, `local_account`, `domain`, `entra` (`S-1-12-1-…`), `well_known`, `unknown`; **переименованный Administrator** (RID 500 остаётся); учётная запись Windows LAPS; Domain Admins (RID 512); Entra Global Administrator и Device Local Administrator; рабочая группа (SID домена нет); русская и английская локаль; ПК вне сети (LSA не обращается к контроллеру) |
| WIN-009 | `GetFirmwareType` + реестр `SYSTEM\CurrentControlSet\Control\SecureBoot\State\UEFISecureBootEnabled` (вместо `GetFirmwareEnvironmentVariable`: не нужна привилегия `SeSystemEnvironmentPrivilege`) | UEFI с Secure Boot включённым и выключенным, legacy BIOS (ВМ gen1), ВМ gen2 без Secure Boot; ключ отсутствует на UEFI → `unsupported` |
| WIN-010 | `NetGetAadJoinInformation` (смещения `DSREG_JOIN_INFO`: тип, сертификат, `pszDeviceId`, `pszIdpDomain`, `pszTenantId`) + `NetGetJoinInformation` (домен) | Entra joined, hybrid joined, domain joined, рабочая группа; регистрация уровня пользователя (workplace join) не считается присоединением; структура на x64 и ARM64; вызов от LocalSystem |
| WIN-011 | Реестр `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` (`EditionID`, `DisplayVersion`, `ReleaseId`, `CurrentBuild`, `UBR`), `RuntimeInformation.OSArchitecture` (вместо `IsWow64Process2`) | Значения на 10 22H2, 11 24H2/25H2, Server; `DisplayVersion` отсутствует у старых сборок → `ReleaseId`; ARM64 и x64 под эмуляцией |
| Идентичность | WMI `Win32_ComputerSystemProduct.UUID`, реестр `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` (Registry64) | Признак стабилен между перезагрузками; пустой/нулевой UUID у части ВМ; тестовый вектор из `05` пройден на macOS |

Общие требования ко всем сборщикам: права LocalSystem достаточны (иначе `permission_denied`); время каждого вызова меньше 30 с на референсном ПК; WMI-запросы получают собственный таймаут 20 с (`System.Management.EnumerationOptions.Timeout`); отсутствие класса/пространства имён даёт `unsupported` без исключения наружу; временная ошибка (недоступен RPC, WMI-репозиторий повреждён) — `temporary_error` (INV-154); для перегруженного ПК (диск 100%) каждая проверка укладывается в 30 с или получает `collector_timeout`.

## 5. Бюджет и поведение под нагрузкой (NFR-05, AT-15)

- CPU, память (`workingSetMb`, `cpuSeconds` из check-in) и время сбора на референсном ПК; сессия — до 120 с (INV-153).
- Зависший сборщик: 7 суток подряд (счётчик `abandonedCollectors` растёт, после трёх — перезапуск, п. 1.7).
- Сбор при нехватке памяти и на ПК с медленным диском.

## 6. Сеть и прокси (`02`, «Выполнение локальной проверки»; `06`, «Распространение агента через RMM»)

- Только HTTPS на hostname агента, сертификат проверяется по хранилищу доверия Windows; перехватывающий прокси клиента с доверенным корнем (TLS inspection) не ломает запросы.
- Прокси: свойство MSI `PROXY` (`Agent:Proxy`) → `WebProxy`; иначе системный прокси. **PAC и WPAD в P2 не поддерживаются**, а `SocketsHttpHandler` с системным прокси может пытаться автоопределение: проверить поведение под LocalSystem и при необходимости перейти на `System.Net.Http.WinHttpHandler` с `WindowsProxyUsePolicy` без автоопределения (изменение кода — после SP-04).
- Автоматическое перенаправление выключено; сжатие ответа выключено (нет `Accept-Encoding`).
- 502/504 фронтенда и обрыв соединения — `retry_backoff` (проверено в тестах на поддельном сервере, на сети — повторить).

## 7. Сценарии AT-12, AT-13, AT-15 с настоящим сервером

После WP-10 (серверная часть P2): весь пакет AT-12 (регистрация, сессия, клоны, замена ключа), AT-13 (7 суток офлайн, потеря ответа, повтор пакета, часы ПК на сутки вперёд и на трое суток назад, лимит размера, переполнение буфера, повторная проверка `scanRequestId`) и AT-15 (защита) — на ПК лаборатории, не на заглушках. Тесты `Sikkerheit.Agent.Tests` проверяют агентскую сторону; серверную — WP-10.

## 8. Записи реестра уровня `agent`

Покрыты тестами `Sikkerheit.Agent.Tests` без Windows: **INV-105, 106, 107, 108, 109, 110, 111, 113, 114, 116, 152, 153, 154** (все 13). Что по ним остаётся для Windows:

| Запись | Что осталось |
| --- | --- |
| INV-106, INV-109 | Поведение настоящего ключа CNG/TPM (п. 2.5–2.7): клон и очистка TPM, удаление ключа |
| INV-114 | Только схема; значения перечислений реальных API (например, новый `AMRunningMode`) попадают в `other`/`unknown` — проверить на новых сборках Windows |
| INV-152 | 11 продуктов в настоящем WSC (п. 4, WIN-003) |
| INV-153 | Зависание настоящего COM/WMI-вызова и перезапуск службы по SCM (п. 1.7); STA-поток для COM (в тестах проверяется на Windows в CI) |
| INV-154 | Типы исключений настоящих API (`COMException`, `ManagementException`, `IOException`) на сбоях RPC/WMI: сейчас всё, кроме отказа в доступе и `NotSupported`, даёт `temporary_error` |

## 9. Что делает CI на Windows

Задание `agent-windows` в `.github/workflows/ci.yml` (`windows-latest`) запускает `Sikkerheit.Agent.Tests`: на Windows выполняются тесты `WindowsSmokeTests` — DPAPI (круг шифрования), создание и подпись ключа CNG (на раннере нет TPM, поэтому проверяется путь MSKSP), запуск всех 11 читателей под учётной записью раннера с проверкой, что каждый даёт факт или причину контракта и не бросает исключения, стабильность отпечатка машины. Задание не заменяет SP-04: нет TPM, домена, Entra, сторонних антивирусов и LocalSystem, и оно помечено `continue-on-error`, пока не прошло ни одного реального запуска на GitHub (первый запуск покажет, какие читатели ведут себя иначе, чем описано здесь).
