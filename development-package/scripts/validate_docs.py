"""Document checks: catalog rows in 03, FR contracts in 01, 05 tables, 04 roles, ID references, links, chat,
plan P0 and OS lifecycle tables; the transcript original outside the package is optional."""
from datetime import date, datetime, time, timedelta, timezone
import hashlib
import re
from urllib.parse import unquote

from contract_catalog import ACTION_PREFIXES, AGENT_ACTIONS, EVENT_TABLE, PROBLEM_HTTP, RETENTION_PURGE_ORDER
from doc_tables import row_ids, table_exact, tables_with

FR_HEADER = ['ID', 'Требование', 'Этап', 'Приёмка', 'Контракт']
PROBLEM_HEADER = ['code', 'HTTP', 'Операции', 'Когда', 'Действие агента']
EVENT_HEADER = ['eventType', 'Допустимые cause', 'assessmentId']
ROLE_HEADER = ['Роль', 'Область', 'Разрешения']
STAGES = ['P1', 'P1, вариант A', 'P2']
FR_COUNT, AT_COUNT, RB_COUNT, CHAT_MESSAGES = 13, 17, 14, 12
GENERATED = {'REVIEW-BUNDLE.md', 'VALIDATION.md'}
REFERENCE = re.compile(r'\b(?:(R|FR|AT|RB|SP|ADR)-[0-9]{2}|(INV)-[0-9]{3}|(WP)-[0-9]{2}[A-Za-z]?)\b')
P0_HEADER = ['Работа', 'Исполнитель', 'Недели', 'Инженерные недели']
EFFORT_HEADER = ['Работа', 'Вариант A', 'Вариант B']
LIFECYCLE_HEADER = ['Семейство', 'displayVersion', 'Последний день обслуживания', 'servicingEndsAt']
P0_WEEKS, P0_LOAD, P0_ENGINEERS = 5, 0.8, ('И1', 'И2')
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
        report.check(f'| {cid} |' in text, 'docs', f'03: no row for {cid}')
        if item['source'] in ('agent', 'server'):
            row = rows.get(cid)
            report.check(row is not None, 'docs', f'03: {cid} absent from the table with «Объект» and «Режим по умолчанию»')
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
    report.check(bool(rows), 'docs', '01: FR table with column «Контракт» missing')
    operations = set(ctx['operation_ids'])
    for row in rows:
        fr, stage, contract = row.get('ID'), row.get('Этап', ''), row.get('Контракт', '')
        report.check(stage in STAGES, 'docs', f'01: {fr} stage «{stage}» not allowed')
        if not stage.startswith('P1'):
            continue
        report.check(contract not in ('', '—'), 'docs', f'01: {fr} has empty «Контракт»')
        for item in filter(None, contract.split(', ')):
            procedure = re.fullmatch(r'процедура: (RB-[0-9]{2})', item)
            if procedure:
                report.check(procedure.group(1) in plan_ids, 'docs', f'01: {fr} refers to missing {item}')
            elif item != '—':
                report.check(item in operations, 'docs', f'01: {fr} refers to unknown operationId {item}')
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
            for token in ('262144', '16384', '65536', 'enrollAgent'):
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
    report.check('| PlatformAdmin | платформа |' in text, 'docs', '04: row «| PlatformAdmin | платформа |» missing')
    rows = table_exact(text, ROLE_HEADER)
    report.check(bool(rows), 'docs', '04: role table missing')
    roles = {row['Роль'] for row in rows if 'P3' not in row.get('Область', '')}
    for _, _, op in ctx['operations']:
        missing = set(op.get('x-allowed-roles', [])) - roles
        report.check(not missing or not rows, 'docs', f'04: roles {sorted(missing)} of {op["operationId"]} not defined')


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
    for file, text in docs.items():
        report.check(text.count('```') % 2 == 0, 'docs', f'{file}: unclosed code fence')
        for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)', text):
            if target.startswith(('https:', 'http:', '#', 'mailto:')):
                continue
            local = ((root / file).parent / unquote(target.split('#')[0])).resolve()
            report.check(local.exists(), 'docs', f'{file}: broken local link {target}')


def _number(cell):
    return float(cell.strip('*').replace(',', '.'))


def _range(cell):
    low, _, high = cell.strip('*').partition('–')
    return (0.0, 0.0) if low == '—' else (_number(low), _number(high or low))


def check_p0_plan(report, docs):
    text = docs.get('07-delivery-plan-and-acceptance.md', '')
    rows = table_exact(text, P0_HEADER)
    report.check(bool(rows), 'docs', '07: table «План P0» missing')
    load, spans, total = {}, {}, 0.0
    for row in rows:
        match = re.fullmatch(r'([1-9])(?:–([1-9]))?', row['Недели'])
        first, last = (int(match[1]), int(match[2] or match[1])) if match else (0, 0)
        if not 1 <= first <= last <= P0_WEEKS:
            report.fail('docs', f'07: «План P0» {row["Работа"]}: weeks «{row["Недели"]}» outside 1–{P0_WEEKS}')
            continue
        weeks = range(first, last + 1)
        if row['Исполнитель'] in P0_ENGINEERS:
            value = _number(row['Инженерные недели'])
            total += value
            for week in weeks:
                key = (row['Исполнитель'], week)
                load[key] = load.get(key, 0.0) + value / len(weeks)
        else:
            report.check(row['Инженерные недели'] == '—', 'docs',
                         f'07: «План P0» {row["Работа"]}: non-engineer row must be —')
        sp = re.match(r'SP-[0-9]{2}', row['Работа'])
        if sp:
            spans.setdefault(sp[0], set()).update(weeks)
    for (who, week), value in sorted(load.items()):
        report.check(value <= P0_LOAD + 1e-9, 'docs', f'07: «План P0» {who} week {week}: {value:.2f} > {P0_LOAD}')
    total, capacity = round(total, 2), round(len(P0_ENGINEERS) * P0_LOAD * P0_WEEKS, 2)
    report.check(total == capacity, 'docs', f'07: «План P0» sums to {total}, capacity is {capacity}')
    limits = {row['SP']: int(re.search(r'([0-9]+) нед', row['Лимит'])[1])
              for table in tables_with(text, ['SP', 'Лимит']) for row in table}
    for sp, weeks in sorted(spans.items()):
        report.check(max(weeks) - min(weeks) + 1 <= limits.get(sp, 0), 'docs',
                     f'07: «План P0» {sp} spans more weeks than its limit')
    effort = table_exact(text, EFFORT_HEADER)
    p0 = [row for row in effort if row['Работа'].startswith('P0')]
    report.check(len(p0) == 1 and all(_range(p0[0][c]) == (total, total) for c in EFFORT_HEADER[1:]), 'docs',
                 f'07: row «P0» of the effort plan must equal {total}')
    items = [row for row in effort if not row['Работа'].startswith('**')]
    totals = [row for row in effort if row['Работа'].startswith('**Итого')]
    for column in EFFORT_HEADER[1:]:
        expected = tuple(sum(_range(row[column])[i] for row in items) for i in (0, 1))
        report.check(len(totals) == 1 and _range(totals[0][column]) == expected, 'docs',
                     f'07: «Итого» {column} differs from the sum of rows')
    report.summary['p0EngineerWeeks'] = total


def _nth_sunday(year, month, n):
    first = date(year, month, 1)
    return first + timedelta(days=(6 - first.weekday()) % 7 + 7 * (n - 1))


def pacific_day_end(day):
    """Exclusive UTC end of a calendar day in America/Los_Angeles (US DST rule since 2007, no tzdata)."""
    following = day + timedelta(days=1)
    dst = _nth_sunday(following.year, 3, 2) < following <= _nth_sunday(following.year, 11, 1)
    return datetime.combine(following, time(), timezone.utc) + timedelta(hours=7 if dst else 8)


def check_os_lifecycle(report, docs):
    rows = table_exact(docs.get('03-check-catalog.md', ''), LIFECYCLE_HEADER)
    report.check(bool(rows), 'docs', '03: OS lifecycle table missing')
    keys = [(row['Семейство'], row['displayVersion']) for row in rows]
    report.check(len(keys) == len(set(keys)), 'docs', '03: duplicate OS lifecycle row')
    for row in rows:
        day = row['Последний день обслуживания']
        try:
            parsed = date.fromisoformat(day) if re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}', day) else None
        except ValueError:
            parsed = None
        if parsed is None:
            report.fail('docs', f'03: {row["displayVersion"]}: date «{day}» is not YYYY-MM-DD')
            continue
        expected = pacific_day_end(parsed).strftime('%Y-%m-%dT%H:%M:%SZ')
        report.check(row['servicingEndsAt'] == expected, 'docs',
                     f'03: {row["displayVersion"]}: servicingEndsAt must be {expected}')
    report.summary['osLifecycleRows'] = len(rows)


def check_chat(report, root):
    copy = root / 'source' / 'boss-chat.md'
    if not copy.exists():
        report.fail('docs', 'source/boss-chat.md missing')
        return
    data = copy.read_bytes()
    report.check(hashlib.sha256(data).hexdigest() == CHAT_SHA256, 'docs',
                 'source/boss-chat.md differs from the pinned transcript hash')
    original = root.parent / 'sikkerheit-app-chat-transcript.md'
    compared = original.exists()
    if compared:
        report.check(original.read_bytes() == data, 'docs', 'source/boss-chat.md differs from the transcript')
    messages = len(re.findall(r'^## [0-9]+\. \S+$', data.decode('utf-8'), re.M))
    report.check(messages == CHAT_MESSAGES, 'docs', f'Chat transcript has {messages} messages')
    report.summary.update(chatMessages=messages, chatOriginalCompared=compared)
