"""Document checks: catalog rows in 03, FR contracts in 01, 05 tables, 04 roles and Graph permissions, ID
references, links, chat, acceptance-hours plan, calendar, acceptance stages, runbook operations, agent states and
OS lifecycle tables. Only files inside the package root are read; links may not leave it."""
from datetime import date, datetime, time, timedelta, timezone
import hashlib
import re
from urllib.parse import unquote

from contract_catalog import (ACTION_PREFIXES, AGENT_ACTIONS, AGENT_STATES, EVENT_TABLE, GRAPH_PERMISSIONS,
                              OS_FAMILIES, PROBLEM_HTTP, RETENTION_PURGE_ORDER, ROLES)
from doc_tables import row_ids, table_exact, tables_with

FR_HEADER = ['ID', 'Требование', 'Этап', 'Приёмка', 'Контракт']
PROBLEM_HEADER = ['code', 'HTTP', 'Операции', 'Когда', 'Действие агента']
EVENT_HEADER = ['eventType', 'Допустимые cause', 'assessmentId']
ROLE_HEADER = ['Роль', 'Область', 'Разрешения']
PERMISSION_HEADER = ['Право', 'Endpoints', 'Проверки']
STAGES = ['P1', 'P2']
FR_COUNT, AT_COUNT, RB_COUNT, CHAT_MESSAGES = 13, 17, 14, 12
GENERATED = {'REVIEW-BUNDLE.md', 'VALIDATION.md'}
REFERENCE = re.compile(r'\b(?:(R|FR|AT|RB|SP|ADR)-[0-9]{2}|(INV)-[0-9]{3}|(WP)-[0-9]{2}[A-Za-z]?)\b')
EFFORT_HEADER = ['Работа', 'Этап', 'Часы приёмки']
# The calendar rate is a parameter of 07: «| Параметр | Значение |», row RATE_ROW, a whole number of hours.
RATE_HEADER = ['Параметр', 'Значение']
RATE_ROW = 'Часы приёмки человеком в неделю'
LIFECYCLE_HEADER = ['Продукт', 'Семейство', 'displayVersion', 'build', 'Последний день обслуживания',
                    'servicingEndsAt']
AT_HEADER = ['ID', 'Этап', 'Сценарий', 'Ожидаемый результат', 'Ответственный WP']
AT_STAGES = {'P1': {'P1'}, 'P2': {'P2'}, 'P1, P2': {'P1', 'P2'}}
# Steps of «Условия допуска» and the stage whose scenario parts they require.
ADMISSION_STAGE = {'Пилот M365': 'P1', 'Подключение всех клиентов к M365': 'P1',
                   'Пилот Windows': 'P2', 'Раскатка агента на все ПК': 'P2'}
RB_HEADER = ['RB-nn', 'Название', 'Владелец роли', 'Этап', 'Операции']
CALENDAR_HEADER = ['Отрезок', 'Состав', 'Часы приёмки', 'Минимум, недель', 'Календарные недели']
FSM_HEADER = ['Состояние', 'Что делает агент', 'Выход']
FAMILY_HEADER = ['Семейство', 'editionId']
PLAN = '07-delivery-plan-and-acceptance.md'
CHAT_SHA256 = 'c9a5c429c5d6274710320dc858fc2a096c730138273785d221a6d540707454fb'
# Documents that state the retention_purge deletion order as a chain of `entity` → `entity`.
PURGE_DOCS = ['04-security-and-privacy.md', '05-data-and-api.md']
CHAIN = re.compile(r'`[a-z_]+`(?: → `[a-z_]+`){2,}')
DEFINED_IN = {'R': '08-risks-and-decisions.md', 'ADR': '08-risks-and-decisions.md',
              'FR': '01-product-and-scope.md', 'AT': '07-delivery-plan-and-acceptance.md',
              'RB': '07-delivery-plan-and-acceptance.md', 'SP': '07-delivery-plan-and-acceptance.md',
              'WP': '07-delivery-plan-and-acceptance.md'}


def read_docs(root):
    return {p.relative_to(root).as_posix(): p.read_text(encoding='utf-8') for p in sorted(root.rglob('*.md'))
            if p.name not in GENERATED}


def check_catalog_rows(report, ctx, docs):
    text = docs.get('03-check-catalog.md', '')
    rows = {}
    for table in tables_with(text, ['ID', 'Объект', 'Режим по умолчанию']):
        rows.update({row.get('ID'): row for row in table})
    for item in ctx['catalog']:
        cid = item['checkId']
        row = rows.get(cid)
        report.check(row is not None, 'docs', f'03: {cid} absent from a table with «Объект» and «Режим по умолчанию»')
        if row:
            report.check(row.get('Объект') == item['subjectType'], 'docs', f'03: {cid} «Объект» ≠ subjectType')
            report.check(row.get('Режим по умолчанию') == item['defaultAssessmentMode'], 'docs',
                         f'03: {cid} «Режим по умолчанию» ≠ defaultAssessmentMode')


def check_requirements(report, ctx, docs):
    requirements = docs.get('01-product-and-scope.md', '')
    plan = docs.get('07-delivery-plan-and-acceptance.md', '')
    plan_ids = row_ids(plan)
    for number in range(1, FR_COUNT + 1):
        report.check(f'| FR-{number:02} |' in requirements, 'docs', f'01: FR-{number:02} row missing')
    for number in range(1, AT_COUNT + 1):
        report.check(f'AT-{number:02}' in plan_ids, 'docs', f'07: AT-{number:02} row missing')
    for number in range(1, RB_COUNT + 1):
        report.check(f'RB-{number:02}' in plan_ids, 'docs', f'07: RB-{number:02} row missing')
    rows = table_exact(requirements, FR_HEADER)
    report.check(len(rows) == FR_COUNT, 'docs', '01: FR table with column «Контракт» must have every FR')
    phases = {op['operationId']: op.get('x-phase') for _, _, op in ctx['operations']}
    covered = set()
    for row in rows:
        fr, stage, contract = row.get('ID'), row.get('Этап', ''), row.get('Контракт', '')
        report.check(stage in STAGES, 'docs', f'01: {fr} stage «{stage}» not allowed')
        report.check(contract not in ('', '—'), 'docs', f'01: {fr} has empty «Контракт»')
        for item in filter(None, contract.split(', ')):
            procedure = re.fullmatch(r'процедура: (RB-[0-9]{2})', item)
            if procedure:
                report.check(procedure.group(1) in plan_ids, 'docs', f'01: {fr} refers to missing {item}')
                continue
            report.check(item in phases, 'docs', f'01: {fr} refers to unknown operationId {item}')
            report.check(phases.get(item, stage) == stage, 'docs', f'01: {fr} ({stage}) lists {item} of another phase')
            covered.add(item)
    for operation_id in phases:
        report.check(operation_id in covered, 'docs', f'01: operationId {operation_id} not in any FR «Контракт»')
    report.summary.update(requirements=FR_COUNT, acceptance=AT_COUNT, runbooks=RB_COUNT)


def _action_ok(cell):
    if cell == '—':
        return True
    for variant in cell.split('; '):
        for prefix in ACTION_PREFIXES:
            if variant.startswith(prefix + ' '):
                variant = variant[len(prefix) + 1:]
                break
        if not all(action in AGENT_ACTIONS for action in variant.split(' + ')):
            return False
    return True


def check_data_api(report, ctx, docs):
    text = docs.get('05-data-and-api.md', '')
    schemas = ctx['schemas']
    problems = table_exact(text, PROBLEM_HEADER)
    report.check(bool(problems), 'docs', '05: Problem.code table missing')
    documented = {row.get('code') for row in problems}
    enum = set(schemas['Problem']['properties']['code']['enum'])
    for code in sorted(enum - documented):
        report.fail('docs', f'05: Problem.code {code} has no row')
    for code in sorted(documented - enum) if problems else []:
        report.fail('docs', f'05: row {code} is not in Problem.code enum')
    for row in problems:
        code = row.get('code')
        if code in PROBLEM_HTTP:
            report.check(row.get('HTTP') == str(PROBLEM_HTTP[code]), 'docs', f'05: {code} HTTP differs')
        report.check(_action_ok(row.get('Действие агента', '')), 'docs', f'05: {code} agent action outside the list')
        if code == 'payload_too_large':
            for token in ('262144', '16384', '1024', '65536'):
                report.check(token in row.get('Когда', ''), 'docs', f'05: payload_too_large row lacks {token}')
    events = table_exact(text, EVENT_HEADER)
    report.check(bool(events), 'docs', '05: eventType/cause table missing')
    if events:
        documented = {row['eventType']: row.get('Допустимые cause', '').split(', ') for row in events}
        finding_event = schemas['FindingEvent']['properties']
        report.check(set(documented) == set(finding_event['eventType']['enum']), 'docs',
                     '05: eventType set differs from FindingEvent.eventType')
        causes = {cause for values in documented.values() for cause in values}
        report.check(causes == set(finding_event['cause']['enum']), 'docs',
                     '05: cause union differs from FindingEvent.cause')
        for event_type, values in documented.items():
            report.check(sorted(values) == sorted(EVENT_TABLE.get(event_type, ([],))[0]), 'docs',
                         f'05: causes of {event_type} differ from the contract')
    listed = {row.get('operationId') for table in tables_with(text, ['operationId']) for row in table}
    for operation_id in ctx['operation_ids']:
        report.check(operation_id in listed, 'docs', f'05: operationId {operation_id} absent from API tables')


def check_purge_order(report, docs):
    for file in PURGE_DOCS:
        chains = [re.findall(r'`([a-z_]+)`', match) for match in CHAIN.findall(docs.get(file, ''))]
        purge = [chain for chain in chains if chain[0] == RETENTION_PURGE_ORDER[0]]
        report.check(bool(purge) and all(chain == RETENTION_PURGE_ORDER for chain in purge), 'docs',
                     f'{file[:2]}: retention_purge order differs from RETENTION_PURGE_ORDER')


def check_roles(report, ctx, docs):
    text = docs.get('04-security-and-privacy.md', '')
    rows = table_exact(text, ROLE_HEADER)
    roles = {row['Роль'] for row in rows}
    report.check(roles == set(ROLES), 'docs', f'04: role table must list exactly {ROLES}')
    for _, _, op in ctx['operations']:
        missing = set(op.get('x-allowed-roles', [])) - roles
        report.check(not missing, 'docs', f'04: roles {sorted(missing)} of {op["operationId"]} not defined')
    permissions = [row['Право'].strip('`') for row in table_exact(text, PERMISSION_HEADER)]
    report.check(permissions == GRAPH_PERMISSIONS, 'docs',
                 '04: Graph permission table must list GRAPH_PERMISSIONS in catalog order')
    report.summary['graphPermissions'] = len(permissions)


def check_references(report, docs, invariant_ids):
    defined = {prefix: row_ids(docs.get(file, '')) for prefix, file in DEFINED_IN.items()}
    defined['INV'] = invariant_ids
    for file, text in docs.items():
        if file.startswith('source/'):
            continue
        for match in REFERENCE.finditer(text):
            prefix = next(group for group in match.groups() if group)
            if match.group(0) not in defined[prefix]:
                report.fail('docs', f'{file}: {match.group(0)} has no definition')


def check_markdown(report, root, docs):
    base = root.resolve()
    for file, text in docs.items():
        report.check(text.count('```') % 2 == 0, 'docs', f'{file}: unclosed code fence')
        for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)', text):
            if target.startswith(('https:', 'http:', '#', 'mailto:')):
                continue
            local = ((root / file).parent / unquote(target.split('#')[0])).resolve()
            if not local.is_relative_to(base):
                report.fail('docs', f'{file}: local link {target} leaves the package')
                continue
            report.check(local.exists(), 'docs', f'{file}: broken local link {target}')


def _number(cell):
    return float(cell.strip('*').replace(',', '.'))


def _range(cell):
    low, _, high = cell.strip('*').partition('–')
    return (0.0, 0.0) if low == '—' else (_number(low), _number(high or low))


def _whole_weeks(value):
    return int(value + 0.5 + 1e-9)


def _rate(report, text):
    """Acceptance hours per week from the parameter table of 07; 0 when absent or not a positive whole number."""
    rows = [row for row in table_exact(text, RATE_HEADER) if row['Параметр'] == RATE_ROW]
    value = rows[0]['Значение'] if len(rows) == 1 else ''
    report.check(value.isdigit() and int(value) > 0, 'docs', f'07: parameter «{RATE_ROW}» must be one whole number')
    return int(value) if value.isdigit() else 0


def check_calendar(report, docs):
    """Each calendar segment sums its plan rows; weeks = max(minimum, acceptance hours / weekly hours), rounded."""
    text = docs.get(PLAN, '')
    rate = _rate(report, text)
    effort = {row['Работа']: _range(row['Часы приёмки'])
              for row in table_exact(text, EFFORT_HEADER) if not row['Работа'].startswith('**')}
    rows = table_exact(text, CALENDAR_HEADER)
    report.check(bool(rows), 'docs', '07: calendar table «Отрезок | Состав | …» missing')
    used = []
    for row in rows:
        name, parts = row['Отрезок'], row['Состав'].split(', ')
        unknown = [part for part in parts if part not in effort]
        report.check(not unknown, 'docs', f'07: calendar «{name}» lists unknown work {unknown}')
        used.extend(parts)
        hours = tuple(round(sum(effort.get(part, (0.0, 0.0))[i] for part in parts), 2) for i in (0, 1))
        report.check(_range(row['Часы приёмки']) == hours, 'docs', f'07: calendar «{name}» must sum to {hours}')
        minimum = _range(row['Минимум, недель'])
        expected = tuple(float(max(minimum[i], _whole_weeks(hours[i] / rate) if rate else 0)) for i in (0, 1))
        report.check(_range(row['Календарные недели']) == expected, 'docs',
                     f'07: calendar «{name}» must last {expected} weeks')
    report.check(sorted(used) == sorted(effort), 'docs', '07: every plan row must be in exactly one calendar segment')
    report.summary['acceptanceHoursPerWeek'] = rate


def _at_refs(text):
    """AT IDs in a text; a range «AT-01…AT-11» stands for every ID between its ends."""
    found = set()
    for first, last in re.findall(r'AT-([0-9]{2})(?:…AT-([0-9]{2}))?', text):
        found.update(f'AT-{number:02}' for number in range(int(first), int(last or first) + 1))
    return found


def check_acceptance_stages(report, ctx, docs):
    """Scenario parts per stage: FR, invariant records and admission steps refer only to parts of their stage."""
    plan = docs.get(PLAN, '')
    rows = table_exact(plan, AT_HEADER)
    stages = {row['ID']: AT_STAGES.get(row['Этап'], set()) for row in rows}
    report.check(len(rows) == AT_COUNT and all(stages.values()), 'docs',
                 '07: every AT row needs «Этап» P1, P2 or «P1, P2»')
    for row in table_exact(docs.get('01-product-and-scope.md', ''), FR_HEADER):
        for at in sorted(_at_refs(row.get('Приёмка', ''))):
            report.check(row.get('Этап') in stages.get(at, ()), 'docs', f'01: {row["ID"]} uses {at} without its stage')
    for record in ctx['invariants']:
        at = record.get('acceptance')
        report.check(record.get('phase') in stages.get(at, ()), 'docs',
                     f'{record.get("id")}: acceptance {at} has no {record.get("phase")} part')
    for table in tables_with(plan, ['Шаг', 'Условия']):
        for row in table:
            stage = ADMISSION_STAGE.get(row['Шаг'])
            report.check(stage is not None, 'docs', f'07: unknown admission step «{row["Шаг"]}»')
            for at in sorted(_at_refs(row['Условия'])):
                report.check(stage in stages.get(at, ()), 'docs', f'07: admission «{row["Шаг"]}» needs {at} of {stage}')


def check_runbooks(report, ctx, docs):
    phases = {op['operationId']: op.get('x-phase') for _, _, op in ctx['operations']}
    rows = table_exact(docs.get(PLAN, ''), RB_HEADER)
    report.check(len(rows) == RB_COUNT, 'docs', '07: runbook table must have «Операции» for every RB')
    for row in rows:
        allowed = STAGES[:STAGES.index(row['Этап']) + 1] if row['Этап'] in STAGES else []
        for operation_id in ([] if row['Операции'] == '—' else row['Операции'].split(', ')):
            report.check(phases.get(operation_id) in allowed, 'docs',
                         f'07: {row["RB-nn"]} lists {operation_id}: unknown or of a later stage')


def check_agent_states(report, docs):
    rows = table_exact(docs.get('05-data-and-api.md', ''), FSM_HEADER)
    report.check([row['Состояние'] for row in rows] == AGENT_STATES, 'docs',
                 '05: agent state table must list AGENT_STATES in catalog order')


def check_effort(report, docs):
    rows = table_exact(docs.get(PLAN, ''), EFFORT_HEADER)
    report.check(bool(rows), 'docs', '07: plan table «Работа | Этап | Часы приёмки» missing')
    for row in rows:
        report.check(row['Этап'] in STAGES, 'docs', f'07: plan row {row["Работа"]}: stage «{row["Этап"]}» not allowed')
    totals = {}
    for stage in STAGES:
        items = [row for row in rows if row['Этап'] == stage and not row['Работа'].startswith('**')]
        expected = tuple(round(sum(_range(row['Часы приёмки'])[i] for row in items), 2) for i in (0, 1))
        found = [row for row in rows if row['Работа'] == f'**Итого {stage}**']
        report.check(bool(items) and len(found) == 1 and _range(found[0]['Часы приёмки']) == expected, 'docs',
                     f'07: «Итого {stage}» differs from the sum of its rows {expected}')
        totals[stage] = expected
    report.summary['acceptanceHours'] = {stage: '–'.join(f'{v:g}'.replace('.', ',') for v in value)
                                         for stage, value in totals.items()}


def _nth_sunday(year, month, n):
    first = date(year, month, 1)
    return first + timedelta(days=(6 - first.weekday()) % 7 + 7 * (n - 1))


def pacific_day_end(day):
    """Exclusive UTC end of a calendar day in America/Los_Angeles (US DST rule since 2007, no tzdata)."""
    following = day + timedelta(days=1)
    dst = _nth_sunday(following.year, 3, 2) < following <= _nth_sunday(following.year, 11, 1)
    return datetime.combine(following, time(), timezone.utc) + timedelta(hours=7 if dst else 8)


def check_os_lifecycle(report, docs):
    text = docs.get('03-check-catalog.md', '')
    families = [row['Семейство'] for row in table_exact(text, FAMILY_HEADER)]
    report.check(families == OS_FAMILIES, 'docs', '03: family table must list OS_FAMILIES in catalog order')
    rows = table_exact(text, LIFECYCLE_HEADER)
    report.check(bool(rows), 'docs', '03: OS lifecycle table missing')
    keys = [(row['Продукт'], row['Семейство'], row['displayVersion']) for row in rows]
    report.check(len(keys) == len(set(keys)), 'docs', '03: duplicate OS lifecycle row')
    for row in rows:
        report.check(row['Семейство'] in OS_FAMILIES, 'docs', f'03: unknown family {row["Семейство"]}')
        day = row['Последний день обслуживания']
        report.check(row['build'].isdigit(), 'docs', f'03: {row["displayVersion"]}: build must be a number')
        try:
            parsed = date.fromisoformat(day) if re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}', day) else None
        except ValueError:
            parsed = None
        if parsed is None:
            report.fail('docs', f'03: {row["displayVersion"]}: date «{day}» is not YYYY-MM-DD')
            continue
        expected = pacific_day_end(parsed).strftime('%Y-%m-%dT%H:%M:%SZ')
        report.check(row['servicingEndsAt'] == expected, 'docs',
                     f'03: {row["Продукт"]} {row["displayVersion"]}: servicingEndsAt must be {expected}')
    report.summary['osLifecycleRows'] = len(rows)


def check_chat(report, root):
    copy = root / 'source' / 'boss-chat.md'
    if not copy.exists():
        report.fail('docs', 'source/boss-chat.md missing')
        return
    data = copy.read_bytes()
    report.check(hashlib.sha256(data).hexdigest() == CHAT_SHA256, 'docs',
                 'source/boss-chat.md differs from the pinned transcript hash')
    messages = len(re.findall(r'^## [0-9]+\. \S+$', data.decode('utf-8'), re.M))
    report.check(messages == CHAT_MESSAGES, 'docs', f'Chat transcript has {messages} messages')
    report.summary['chatMessages'] = messages
