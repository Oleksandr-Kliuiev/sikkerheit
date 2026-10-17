# Распространение агента: что проверяется только с Windows, подписью и RMM (SP-05)

Состояние на 2026-10-16. Скрипт RMM (`tools/rmm/Sikkerheit-Rmm.ps1`), описание MSI (`src/Agent/Installer/Package.wxs`, `build.ps1`) и runbooks RB-08…RB-12 написаны без Windows-лаборатории, без подписанного MSI и без канала RMM. На macOS и в CI проверено только то, что не требует Windows; всё остальное — список ниже, протокол SP-05 записывает по каждому пункту редакцию ОС и сборку, учётную запись, результат и найденное отличие от пакета (отличие — дефект пакета, `docs/reviews/0.3.0-decisions.md`, «Реализация P2»). Агент и Windows-слой — отдельный список: [agent-windows-verification.md](agent-windows-verification.md) (SP-04).

## 0. Что уже проверено автоматически

| Что | Чем | Где |
| --- | --- | --- |
| Негативные случаи INV-201 и требования к ключу: изменённый MSI, старая подписанная версия, подписанная неутверждённая версия, чужой издатель (в том числе второй `CN`, префикс, регистр), подпись не `Valid` или без отметки времени, ARM64, серверная ОС, сборка < 17763 — отказ без `msiexec`, без файла ключа, без следа в каталоге; ключ не в аргументах, не в выводе (все потоки, включая verbose и debug), формат ключа, очистка переменной, права файла запрашиваются до записи ключа, вывод только фиксированных слов, текст исключения не печатается | `tools/rmm/tests/Run-RmmTests.ps1` на PowerShell 7 (31 случай; факты машины, подпись, `msiexec`, ACL, COM подменены, хеш и файлы реальные); из `dotnet test` — `RmmScriptInvariantTests` (INV-201) | CI, задание `rmm`; `ContractTests` |
| В тексте скрипта нет параметра для секрета, нет команд вывода и записи в журнал (`Write-Host`, `Write-Verbose`, `Start-Transcript` и т. п.), ровно одно упоминание `sikk_` (проверка формата) | тот же набор, статическая проверка по синтаксическому дереву | то же |
| Синтаксис всех `.ps1` | `tools/rmm/Test-Syntax.ps1` (PSScriptAnalyzer на машинах проекта не установлен) | CI, `rmm` и `rmm-windows` |
| Те же тесты в Windows PowerShell 5.1 — в нём работает RMM | задание `rmm-windows` на `windows-latest` (не блокирует, `continue-on-error`) | CI |
| `Package.wxs` согласован с агентом и скриптом: условия запуска (клиентская ОС, 64 бит, `NATIVEARCH = "AMD64"`, сборка ≥ 17763, `PROXY` без `@`), recovery actions (три перезапуска через 60 секунд), `LocalSystem`, автозапуск, имя службы и продукта, `MsiHiddenProperties`, настройки службы `Agent__ServerUrl`/`Agent__Proxy` без ключа и без литерала сервера, каталог данных `%ProgramData%\Sikkerheit\Agent` с единственным правом SYSTEM и удалением при деинсталляции, `MajorUpgrade` с понижением и расписанием `afterInstallExecute` | `python3 -I tools/rmm/check_installer.py`; тесты проверки ломают файл по каждому правилу: `tools/rmm/tests/test_check_installer.py` | CI, `rmm` |
| Метрики для критериев остановки колец: `agent.working_set_mb`, `agent.cpu_seconds`, `agent.recent_crashes` (с версией агента в тегах) | `AgentMetricsTests` | `UnitTests` |

Не сделано и не проверено: **сборка MSI** (WiX не установлен: v7 требует EULA и взноса — вопрос 8 в `08`; `wix build` не запускался, на macOS он собирает только часть, ICE-проверки нет), **подпись**, запуск на Windows, RMM. Схема `Package.wxs` написана по документации WiX v4; на v7 возможны отличия в именах атрибутов — первая сборка их покажет.

## 1. Коды выхода скрипта (для журнала заданий RMM)

`SIKKERHEIT-RMM result=<ok|refused|failed> code=<n> reason=<слово> [msiexec=<код>]`

| Код | Причина (`reason`) | Смысл |
| --- | --- | --- |
| 0 | `installed`, `already_installed`, `key_file_written`, `uninstalled`, `not_installed` | успех (код `msiexec` 3010 и 1641 — тоже успех) |
| 10 | `approved_version_invalid`, `approved_sha256_invalid`, `publisher_missing`, `msi_source_ambiguous`, `msi_url_not_https` | неверные параметры задания |
| 11 | `proxy_invalid` | `PROXY` не http(s)-URL, с учётными данными или с метасимволами |
| 20 / 21 / 22 | `os_not_client` / `arch_not_x64` / `build_too_old` | ОС не подходит: сервер, ARM64, сборка < 17763 |
| 30 / 35 | `msi_missing` / `download_failed` | нет файла, не скачан |
| 31 | `sha256_mismatch` | не тот файл (изменён или не утверждён) — не повторять, сверить с release notes |
| 32 / 33 / 34 | `signature_invalid` / `publisher_mismatch` / `version_mismatch` | подпись не `Valid` или без отметки времени / чужой издатель / версия MSI не утверждённая |
| 40 / 41 | `install_failed` / `uninstall_failed` + `msiexec=` | сбой установки (коды `msiexec`, например 1603) |
| 50 / 51 / 52 / 53 | `key_variable_empty` / `key_format_invalid` / `key_write_failed` / `agent_not_installed` | ключ не передан / неверный формат / не записан / агента нет |
| 60 | `unexpected`, `type=<имя типа>` | непредвиденная ошибка |

## 2. Скрипт RMM (SP-05, AT-16)

| № | Проверка | Как |
| --- | --- | --- |
| 2.1 | Установка подписанного MSI на ПК лаборатории и на ПК компании: код 0, служба `Sikkerheit.Agent` работает, `DisplayVersion` в «Programs and Features» равна `ApprovedVersion` (скрипт читает версию из `Uninstall`) | Задание RMM от SYSTEM |
| 2.2 | `Get-AuthenticodeSignature` для MSI с Artifact Signing: `Valid`, `TimeStamperCertificate` не пуст, `SignerCertificate.Subject` содержит ровно один `CN` и один `O`; какой набор полей закреплять (CN+O или иначе — SP-05) и стабильность subject между короткоживущими сертификатами | Подписанный тестовый MSI; два выпуска с разными сертификатами |
| 2.3 | Отказ на изменённом MSI (код 31), MSI чужого издателя (33), правильно подписанной, но не утверждённой версии (31 или 34), ARM64 (21), серверной ОС (20): `msiexec` не запускался, службы нет, каталога данных нет, файла ключа нет, каталог `%ProgramData%\Sikkerheit\Staging` пуст | Реальные файлы и ПК: подпись своим тестовым сертификатом (не доверенным — код 32), чужой MSI, MSI старой версии, ВМ Windows Server, ARM64-ПК или ВМ |
| 2.4 | Определение ARM64: `PROCESSOR_ARCHITECTURE` в `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment` показывает архитектуру **машины** и на ARM64 при x64-эмуляции (процесс RMM может быть x64) | ARM64-ПК с Windows 11, запуск из 32-/64-битной эмуляции; то же значение читает условие MSI `NATIVEARCH` |
| 2.5 | `Get-MsiProductVersion` (COM `WindowsInstaller.Installer`) работает из Windows PowerShell 5.1 под SYSTEM; `Get-CimInstance Win32_OperatingSystem` — `ProductType` 1 (клиент) на Windows 10/11, 2/3 на Server | ПК и ВМ |
| 2.6 | Права: `Protect-Path` оставляет у каталога данных, каталога `Staging` и файла ключа только SYSTEM без наследования; владелец SYSTEM; обычный пользователь не читает; `icacls` | `icacls "%ProgramData%\Sikkerheit\Agent"` и файл `enrollment.key` сразу после записи |
| 2.7 | Запись файла ключа: файл `enrollment.key` (UTF-8 без BOM, 48 байт, без перевода строки) появляется и в течение минуты исчезает, появляется `enrollment.key.dpapi`, агент регистрируется (устройство в портале); `enrollment.key.tmp` не остаётся; повторная запись (ротация) обрабатывается так же без переустановки | RB-10, А.2 |
| 2.8 | **Ключа нет** в событиях 4688 (командная строка `powershell.exe`, `msiexec.exe`), PowerShell 4104 (Script Block Logging включить на ПК испытания), 4103, Sysmon (события 1, 11, 13), EDR, журнале заданий RMM и его консоли; ключ не виден и в `msiexec` `/l*v` (журнала у скрипта нет) | Поиск по `sikk_` и по самому ключу после установки, регистрации и ротации; включить журналы заранее |
| 2.9 | Как RMM передаёт секрет: переменная окружения процесса, а не подстановка текста в скрипт или командную строку (иначе секрет окажется в 4104, 4688 и журнале RMM). Если RMM только подставляет текст — скрипт не годится, нужен другой путь доставки (результат SP-05: «если RMM не может записать файл от SYSTEM, пилот сужается») | Настройка секретной переменной RMM, пробное задание с ложным ключом `sikk_…` |
| 2.10 | `-MsiUrl` (ссылка SAS): скачивание по https из `agent-releases` с TLS 1.2 на Windows PowerShell 5.1; ссылка нигде не печатается (проверка по журналам, как 2.8); срок ссылки ≤ 7 суток; доступ по ключу учётной записи выключен — `az storage blob generate-sas --as-user --auth-mode login` работает | RB-08, шаг 2 |
| 2.11 | `-Action Uninstall`: продукт найден по `DisplayName` = «Sikkerheit Agent» в `Uninstall`; служба и каталог данных удалены; устройство остаётся в портале (RB-11) | Лаборатория |
| 2.12 | Код `msiexec` 1641/3010 (перезагрузка) не считается сбоем и перезагрузки не вызывает (`/norestart`, `REBOOT=ReallySuppress`) | Установка поверх с занятыми файлами |

## 3. MSI (WiX; AT-15, AT-16)

| № | Проверка | Как |
| --- | --- | --- |
| 3.1 | `build.ps1` собирает MSI WiX v7 (схема v4 принимается; атрибуты `Files`/`Exclude`, `util:ServiceConfig`, `util:PermissionEx`, `util:RemoveFolderEx`, `RegistrySearch Bitness`, `Launch`); ICE-проверки без ошибок; EULA v7 принята владельцем, взнос оплачен или выбран другой инструмент (вопрос 8) | Сборка на Windows; `wix msi validate` |
| 3.2 | Условия запуска: MSI не устанавливается на Windows Server (`MsiNTProductType` ≠ 1), на ARM64 (`NATIVEARCH`), на сборке < 17763, с `PROXY=http://user:pass@…`; сообщение видно, код 1603; при `/qn` установка отклоняется молча, но с кодом | ВМ каждой ОС, ПК ARM64 |
| 3.3 | Служба: `sc qc Sikkerheit.Agent` — `LocalSystem`, `AUTO_START`; `sc qfailure` — перезапуск через 60 секунд на первый, второй и третий сбой, сброс счётчика через сутки; **завершение процесса с кодом ошибки без статуса STOPPED (`Environment.Exit(1)` при трёх оставленных сборщиках) запускает recovery actions** (в `util:ServiceConfig` задан `FailureActionsWhen="failedToStopOrReturnedError"`; проверить `sc qfailureflag` и п. 1.7 в [agent-windows-verification.md](agent-windows-verification.md)) | `taskkill /f`, зависший WMI, `sc qfailureflag` |
| 3.4 | `PROXY`: `msiexec /i … PROXY=http://proxy:3128` — в `HKLM\SYSTEM\CurrentControlSet\Services\Sikkerheit.Agent` значение `Environment` содержит `Agent__ServerUrl=…` и `Agent__Proxy=…` (REG_MULTI_SZ, два элемента); без `PROXY` — один элемент; агент ходит через прокси (журнал прокси). Значение `PROXY` не попадает в журнал MSI (`MsiHiddenProperties`) и не видно в командной строке `msiexec` в 4688 кроме самого URL без учётных данных | `reg query`, `/l*v`, Sysmon |
| 3.5 | Две пары компонентов с одним значением реестра (`ServiceEnvironment` и `ServiceEnvironmentWithProxy`): обновление с `PROXY` на без `PROXY` и обратно записывает правильное значение (переключение компонентов при обновлении не оставляет старое и не удаляет новое) | Обновление с изменением свойства |
| 3.6 | Каталог данных `%ProgramData%\Sikkerheit\Agent` создан, DACL — только SYSTEM (`PermissionEx`), наследование снято агентом при запуске (родитель `Sikkerheit` доступен на чтение пользователям — проверить, что это не раскрывает содержимое); каталог установки `%ProgramFiles%\Sikkerheit\Agent` недоступен на запись обычному пользователю | `icacls` |
| 3.7 | **Обновление**: `msiexec /i новая.msi /qn /norestart REBOOT=ReallySuppress` поверх старой версии без перезагрузки; служба перезапущена; **`installation.id`, ключ устройства (TPM/MSKSP), `agent.db`, sequence и `enrollment.key.dpapi` сохранены** (устройство то же, очередь пакетов цела, `RemoveFolderEx` не сработал); версия в `Uninstall` новая | Установка 0.3.0 → 0.3.1, регистрация, накопление буфера, обновление |
| 3.8 | **Откат/понижение** тем же скриптом на предыдущую утверждённую версию: `AllowDowngrades` принимает, данные те же | 0.3.1 → 0.3.0 |
| 3.9 | **Неудачное обновление** (сбой посреди установки): откат Windows Installer возвращает прежнюю версию с работающей службой и данными | Принудительный сбой (недоступное место, kill `msiexec`) |
| 3.10 | **Удаление**: служба удалена, файлы и каталог данных удалены (`RemoveFolderEx`), ключ в TPM удалён или нет (решение: ключ TPM остаётся до RB-11; если нужен — удалить при деинсталляции), реестровая запись `Environment` удалена | `sc query`, `dir`, `reg query` |
| 3.11 | Установка поверх работающего агента, запущенного с `PROXY`, и второй запуск `msiexec` одновременно: один заканчивает с 1618; скрипт возвращает 40 с `msiexec=1618` | Параллельные задания RMM |
| 3.12 | Исполняемые файлы: после публикации self-contained EXE, собственные DLL и MSI подписаны (CI, `signtool verify /pa`, subject CN и O); `Package.wxs` не включает `*.pdb` | CI подписи (после проверки организации в Artifact Signing) |

## 4. Кольца и телеметрия (RB-08, AT-16)

| № | Проверка | Как |
| --- | --- | --- |
| 4.1 | В Application Insights видны `customMetrics` `agent.check_ins`, `agent.service_starts`, `agent.recent_crashes`, `agent.abandoned_collectors`, `agent.rejected_batches`, `agent.config_rejected`, `agent.working_set_mb`, `agent.cpu_seconds`, `agent.batches` с `customDimensions.agentVersion`; запросы RB-08 возвращают значения (имена измерений и метрик OpenTelemetry → Azure Monitor подтвердить; в частности, как экспортируются счётчики и гистограммы: `valueSum`, `valueCount`, `valueMax`) | Тестовый агент или реальный; запросы RB-08, шаг 4 |
| 4.2 | Остановка кольца по каждому критерию: искусственно вызвать рост перезапусков, свежий `lastCrashAt`, `configRejected`, отказы 422 — запросы показывают превышение порога RB-08, раскатку останавливают | Лаборатория, версия-«пугало» с тестовым дефектом |
| 4.3 | Числовые пороги RB-08 (2% ошибок, 24 часа выдержки, > 3 запуска службы) подходят: нет ложных остановок на штатных версиях | Данные пилота; поправить RB-08 |
| 4.4 | `requests` в Application Insights: имя запроса содержит `/api/v1/agent/check-ins`, `resultCode` числовой | Запрос RB-08 |
| 4.5 | Версия ниже `minimumAgentVersion`: агент уходит в `VersionBlocked`, виден через check-in, выходит после обновления через RMM или снятия ограничения (AT-16); поднять `Agents__MinimumAgentVersion` через `az webapp config appsettings set --slot-settings` и убедиться, что swap слота её не сбрасывает, а перезапуск не прерывает приём | RB-09, шаг 5; production и staging |
| 4.6 | Агент N−1 с сервером N+1: конфигурация версии N−1 принята, resync и повторная проверка работают (AT-16) | Тест совместимости версий |
| 4.7 | Проверка организации Artifact Signing завершена; профиль подписи активен; CI подписывает по OIDC без закрытых ключей; `signtool verify /pa` и сверка subject проходят в CI перед публикацией | Вопрос 8 в `08` |

## 5. Что нужно владельцу

Конвейер кандидата подготовлен в `.github/workflows/agent-release.yml`: отдельные publish/подпись файлов/package/подпись MSI, затем `tools/rmm/Verify-Release.ps1` и manifest. Он запускается вручную из `main` через защищённое окружение `agent-release`, только после явного подтверждения владельцем условий WiX; версии WiX и Util — 7.0.0. Пока workflow не запускался, сборка, подписи и ICE-проверки остаются неподтверждёнными. Настройка — [pilot-readiness.md](pilot-readiness.md#подготовка-windows-параллельно-с-пилотом-m365).

- Решение по WiX v7: EULA и взнос Open Source Maintenance Fee (вопрос 8 в `08`) или другой инструмент.
- Завершить проверку организации в Artifact Signing, назначить владельца подписи.
- Канал RMM: может ли RMM передать секрет окружением процесса и запустить скрипт от SYSTEM; нужен ли URL (SAS) или хватит библиотеки ПО.
- Состав колец K0…K4 в RMM (RB-08).
