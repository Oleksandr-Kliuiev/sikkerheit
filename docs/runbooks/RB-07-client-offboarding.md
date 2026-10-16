# RB-07. Уход клиента

## Назначение

Прекратить обслуживание клиента операциями контракта, без SQL (`06`, «Удаление данных клиента»): отключить организацию, передать клиенту экспорт, запланировать удаление через 30 суток, дождаться удаления заданием `organization_delete` и удалить приложение Graph из tenant клиента. Данные остаются в резервных копиях базы до 14 дней после удаления — это сообщается клиенту.

## Владелец роли и этап

Service Manager (роль Admin в портале), этап P1. Удаление агента Windows через RMM — P2.

## Признак запуска

- Клиент расторгает договор или письменно просит удалить данные.
- Организация заведена по ошибке или дублирует другую (тогда экспорт можно не передавать — флажок «Slett uten eksport», шаг 4).

## Предусловия и доступы

- Роль Admin в «Sikkerheit Portal (prod)», вход с MFA.
- Письменный запрос клиента или решение о прекращении и кто утвердил удаление: [ЗАПОЛНИТЬ: порядок утверждения — вопрос 6 в `08`].
- Защищённый канал передачи экспорта клиенту: [ЗАПОЛНИТЬ].
- Сообщить клиенту заранее: после удаления данные хранятся в резервных копиях базы до 14 дней; записи журнала безопасности (идентификаторы организации и сотрудников, без данных пользователей клиента) удаляются через 45 суток, журналы сервиса — через 90 дней (`04`, «Сроки хранения»). Какие сроки называются клиенту — по договору обработки данных.

## Шаги

1. **Отключить организацию** — `changeOrganizationLifecycle`: «Kunder» → клиент → вкладка «Innstillinger» → карточка «Livssyklus» → «Begrunnelse» (обязательно, до 1000 символов, без персональных данных — текст хранится в аудите) → «Deaktiver». Статус «Deaktivert»: сбор Microsoft 365 прекращается. 503 «Tjenesten er midlertidig utilgjengelig. Prøv igjen.» — журнал безопасности недоступен: RB-04, раздел «Журнал безопасности недоступен».
2. **Отключить tenant** — `disconnectTenant`: вкладка «Oversikt» → «Koble fra» → в диалоге снова «Koble fra». Статус «Frakoblet»: сервис больше не запрашивает токены этого tenant.
3. **Экспорт** — `createOrganizationExport`: «Innstillinger» → «Eksport av kundedata» → «Lag eksport». Не уходить со страницы, пока `getOrganizationExport` не покажет «Eksporten er klar.» и «Tilgjengelig til …» (7 дней); если страница перезагружена — «Lag eksport» заново. «Last ned eksport» — `downloadOrganizationExport`, каждое скачивание пишет аудит. Архив содержит все данные и отчёты клиента с манифестом SHA-256: передать клиенту по защищённому каналу, локальную копию удалить после передачи по правилам компании [ЗАПОЛНИТЬ].
4. **Запланировать удаление** — `changeOrganizationLifecycle`: «Livssyklus» → «Begrunnelse» → «Planlegg sletting». Нужен экспорт, созданный после отключения, в состоянии `ready` или `expired` («Eksporten er klar.» или «Eksporten er utløpt.»); иначе «Denne endringen er ikke tillatt for kundens status.» (409 `lifecycle_transition_forbidden`). «Slett uten eksport» (`exportWaived`) — только если клиент письменно отказался от экспорта или организация ошибочная; основание — в протокол. Статус «Planlagt sletting», в заголовке — «Slettes …» (now + 30 суток). Передумали до этой даты — «Avbryt sletting»: статус снова «Deaktivert», затем при необходимости «Aktiver» и RB-03.
5. **Удаление** выполняет задание `organization_delete` в течение часа после срока: сначала запись журнала безопасности, затем все строки клиента в базе и файлы Blob, остаётся tombstone. Проверка после срока: организации нет в «Kunder», прямая ссылка на неё показывает «Finnes ikke.»; в журнале сервиса (Application Insights → «Logs»):

   ```kusto
   traces
   | where timestamp > ago(3d)
   | where message has "deleted after its deletion date"
   | project timestamp, message
   ```

   Организация осталась дольше двух часов после срока — RB-04 (`organization_delete`).
6. **Удалить приложение Graph из tenant клиента** — RB-03, раздел «Отключение с удалением приложения из tenant клиента», шаг 2. Получить подтверждение клиента (кто и когда).
7. **Агент Windows (P2).** Удалить агент с ПК клиента через RMM; до этого агенты получают `device_unknown`, повторная регистрация отклоняется, и агент ждёт в `EnrollmentBlocked`.

Файлы клиента, перенесённые восстановлением базы в `restore-orphans/` (RB-05), удаление организации не затрагивает: их удаляет правило жизненного цикла через 30 суток после переноса.

## Проверка результата

- Перед удалением: в «Revisjonslogg» есть `organization.lifecycle_change` (disable, затем schedule_deletion), `organization_export.create` и `organization_export.download`; экспорт передан клиенту.
- После срока: организации нет в портале, запрос шага 5 показывает удаление, приложение удалено из tenant клиента.
- Клиент получил сообщение о сроке хранения резервных копий (14 дней).

## Запись в протокол

Шаблон — [README](README.md), раздел «Протокол». Записать основание и кто утвердил, время каждого шага, идентификатор экспорта и способ передачи (или основание «Slett uten eksport»), дату «Slettes …», фактическое время удаления, подтверждение клиента об удалении приложения и текст сообщения о сроках хранения.

## Связанные документы

- [06-azure-and-operations.md](../../development-package/06-azure-and-operations.md) — «Удаление данных клиента».
- [05-data-and-api.md](../../development-package/05-data-and-api.md) — «Жизненный цикл организации», «API портала».
- [04-security-and-privacy.md](../../development-package/04-security-and-privacy.md) — «Журнал безопасности», «Сроки хранения».
- [07-delivery-plan-and-acceptance.md](../../development-package/07-delivery-plan-and-acceptance.md) — AT-09.
- [08-risks-and-decisions.md](../../development-package/08-risks-and-decisions.md) — вопрос 6.
- [RB-03](RB-03-client-onboarding.md), [RB-04](RB-04-jobs-and-scheduler.md), [RB-05](RB-05-database-restore.md).
