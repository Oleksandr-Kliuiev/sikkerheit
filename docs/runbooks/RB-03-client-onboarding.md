# RB-03. Подключение и отключение клиента

## Назначение

Завести клиента в портале (организация и политика), подключить его tenant Microsoft 365 через admin consent приложения «Sikkerheit Graph Reader», проверить подключение и первый сбор; повторить consent, когда приложению добавлены права; отключить tenant и удалить приложение из tenant клиента. Полное удаление данных клиента — RB-07.

## Владелец роли и этап

Service Manager (роль Admin в портале), этап P1. Consent выдаёт глобальный администратор клиента или Privileged Role Administrator, либо Admin компании с такой ролью в tenant клиента через GDAP (`04`, «Права Graph»).

## Признак запуска

- Новый клиент подписал договор и договор обработки данных (вопрос 6 в `08`).
- Владелец решил добавить право приложению Graph вместе с новой версией правил: повторный consent во всех tenant (`04`, «Права Graph»).
- Клиент отключает Microsoft 365 от сервиса, меняет tenant или уходит (вместе с RB-07).

## Предусловия и доступы

- Роль Admin в «Sikkerheit Portal (prod)», вход с MFA.
- Договор обработки данных подписан: [ЗАПОЛНИТЬ: где это отмечается]. Без него tenant клиента не подключается (`04`, «Сроки хранения»).
- От клиента: tenant ID или проверенный домен; кто выдаст consent; object ID учётных записей аварийного доступа и служебных учётных записей; часовой пояс и язык отчёта.
- Издатель «Sikkerheit Graph Reader» подтверждён (publisher verification) — до пилота (`04`, «Подключение и отзыв»). До этого экран consent показывает пометку «unverified»: предупредить клиента заранее.

## Подключение

1. **Организация** — `createOrganization`: «Kunder» → «Ny kunde» → «Navn», «Tidssone», «Rapportspråk» → «Opprett». Портал открывает клиента; созданы политика версии 1 и подключение «Ikke tilkoblet».
2. **Политика** — `createPolicyRevision`: вкладка «Policy». Заполнить «Unntatte brukere (objekt-ID, én per linje)» — аварийный доступ и служебные учётные записи (на администраторов исключение не действует); «Minst antall globale administratorer» и «Høyst antall globale administratorer»; «Tillatte samtykkepolicyer (én per linje)»; флажки и режимы проверок — по договорённости с клиентом. «Innsamlingstidspunkt (lokal time)» оставить внутри 01:00–05:00 (по умолчанию 3). «Lagre ny policyversjon» → «Policyversjon 2 er lagret. Vurderingene beregnes på nytt.».
3. **Ссылка consent** — `startTenantConsent`: вкладка «Oversikt» → «Lag samtykkelenke» → поле «Tenant-ID eller verifisert domene» (`tenantHint`) → «Lag samtykkelenke». Флажок «Tillat selskapets egen tenant» — только если клиент — сама компания. Скопировать ссылку («Kopier»), записать «Forventet tenant» и «Lenken gjelder til …» (7 суток), нажать «Lukk». Статус — «Venter på samtykke». Отказы:
   - «Verdiene er ikke gyldige.» (422 `validation_failed`) — домен не найден или это tenant компании без флажка;
   - «Denne tenanten er allerede koblet til en annen kunde.» (409 `tenant_conflict`) — RB-01, шаг 4.
4. **Consent.** Admin компании с ролью Global Administrator или Privileged Role Administrator в tenant клиента через GDAP открывает ссылку сам; иначе пересылает её администратору клиента: [ЗАПОЛНИТЬ: канал, например письмо из системы заявок]. На экране согласия — «Sikkerheit Graph Reader» и только шесть прав на чтение (`infra/scripts/setup.sh`): `Organization.Read.All`, `User.Read.All`, `UserAuthenticationMethod.Read.All`, `RoleManagement.Read.Directory`, `GroupMember.Read.All`, `Policy.Read.All`; другие права — повод остановиться и сообщить Security Owner. После согласия открывается страница портала «Tilgangen er gitt», при отказе — «Samtykket ble ikke gitt».
5. **Проверка** — `verifyTenantConnection`: «Kontroller tilkobling». Статус «Tilkoblet»; сверить «Tenant» (имя и домен) с клиентом — сервис получил его собственным токеном. Сервис сразу ставит внеплановый сбор. Отказы — RB-01, шаг 4.
6. **Первый сбор** — `listCollectionRuns`: в «Innsamlinger» строка «Manuell» → «Fullført» или «Delvis». Если строки нет — `requestCollection`: «Samle inn nå». Открыть «Datakilder ved siste innsamling»: «Mangler tillatelse» — consent неполный, повторить шаг 4; «Krever lisens» — у клиента нет нужной лицензии (например, Entra ID P1, см. строку «Entra ID P1» карточки); это не ошибка (`03`, «Возможности подключения»).
7. **Итог.** Проверить вкладку «Problemer»; первый недельный отчёт появится во вкладке «Rapporter» в понедельник после 06:00 по времени клиента.

## Повторный consent

Нужен, когда приложению добавлено право (после изменения `infra/scripts/setup.sh` и решения владельца), когда клиент отозвал согласие или снял права (RB-01) и когда приложение удалено в tenant клиента, а клиент остаётся.

1. `startTenantConsent` с тем же tenant: подключение остаётся «Tilkoblet», сбор продолжается (`05`, «Подключение M365 и сбор»).

   > Отступление текущей версии портала: на подключении «Tilkoblet» кнопки «Lag samtykkelenke» и «Kontroller tilkobling» не показываются, хотя API их допускает. До исправления ссылку составить вручную — она совпадает с той, что строит сервис:
   >
   > `https://login.microsoftonline.com/<tenant-id>/v2.0/adminconsent?client_id=<graph-app-id>&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default&redirect_uri=https%3A%2F%2F<prod-host>%2Fconsent-complete`
   >
   > `<tenant-id>` — «Tenant ID» из карточки «Microsoft 365-tilkobling», `<graph-app-id>` — Application (client) ID «Sikkerheit Graph Reader», `<prod-host>` — hostname портала (README, «Имена ресурсов»).

2. Ссылку открывает администратор клиента, как в шаге 4 подключения.
3. Проверочный сбор — «Samle inn nå». При добавленном праве — не раньше чем через час после согласия: новые права попадают только в новый токен, а сервис держит токен tenant до часа. В «Datakilder ved siste innsamling» модули должны быть «Tilgjengelig» (или «Krever lisens»).
4. При добавлении права — вести список организаций с датой согласия; клиентам без согласия напоминать: [ЗАПОЛНИТЬ: срок и кто напоминает].

## Отключение с удалением приложения из tenant клиента

1. **Отключить** — `disconnectTenant`: «Oversikt» → «Koble fra» → в диалоге «Koble fra Microsoft 365? …» снова «Koble fra». Статус «Frakoblet», незавершённые запуски отменены. Операция сначала пишет журнал безопасности; «Tjenesten er midlertidig utilgjengelig. Prøv igjen.» (503) — журнал недоступен: RB-04, раздел «Журнал безопасности недоступен».
2. **Удалить приложение в tenant клиента.** Отключение не снимает права приложения в tenant клиента (`04`, «Подключение и отзыв»). Администратор клиента или Admin компании через GDAP удаляет корпоративное приложение: Microsoft Entra admin center → Enterprise applications → «Sikkerheit Graph Reader» → Properties → Delete. Письмо клиенту: [ЗАПОЛНИТЬ: шаблон].
3. Данные и проблемы клиента остаются в портале, проблемы со временем становятся «Utdatert». Удаление данных — RB-07. Позже подключить тот же или другой tenant — раздел «Подключение», шаги 3–6; при другом tenant субъекты прежнего выводятся из учёта.

## Проверка результата

- Подключение: «Tilkoblet», «Tenant» совпадает с клиентом, первый сбор «Fullført» или «Delvis» без «Mangler tillatelse»; во вкладке «Innstillinger» → «Revisjonslogg» есть `organization.create`, `policy.revision_create`, `m365.consent_start` и `m365.connect`.
- Повторный consent: у всех организаций модули новых прав «Tilgjengelig».
- Отключение: «Frakoblet», в «Revisjonslogg» — `m365.disconnect`; клиент подтвердил удаление приложения (кто и когда).

## Запись в протокол

Шаблон — [README](README.md), раздел «Протокол». Записать организацию, tenant ID и домен, кто выдал consent и каким путём (GDAP или администратор клиента), версию политики, результат первого сбора и статусы модулей; при отключении — время «Koble fra» и подтверждение удаления приложения клиентом.

## Связанные документы

- [05-data-and-api.md](../../development-package/05-data-and-api.md) — «Подключение M365 и сбор», «Политика клиента», «API портала».
- [04-security-and-privacy.md](../../development-package/04-security-and-privacy.md) — «Доступ к Microsoft 365».
- [07-delivery-plan-and-acceptance.md](../../development-package/07-delivery-plan-and-acceptance.md) — AT-03.
- [infra/README.md](../../infra/README.md) — «После установки».
- [RB-01](RB-01-m365-connection-failure.md), [RB-07](RB-07-client-offboarding.md).
