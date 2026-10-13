"""Document checks: catalog rows in 03, FR contracts in 01, 05 tables, 04 roles, ID references, links, chat."""
import re
from urllib.parse import unquote

from contract_catalog import ACTION_PREFIXES, AGENT_ACTIONS, EVENT_TABLE, PROBLEM_HTTP
from doc_tables import row_ids, table_exact, tables_with

FR_HEADER = ['ID', 'Требование', 'Этап', 'Приёмка', 'Контракт']
PROBLEM_HEADER = ['code', 'HTTP', 'Операции', 'Когда', 'Действие агента']
EVENT_HEADER = ['eventType', 'Допустимые cause', 'assessmentId']
ROLE_HEADER = ['Роль', 'Область', 'Разрешения']
STAGES = ['P1', 'P1, вариант A', 'P2']
FR_COUNT, AT_COUNT, RB_COUNT, CHAT_MESSAGES = 13, 17, 14, 12
GENERATED = {'REVIEW-BUNDLE.md', 'VALIDATION.md'}
REFERENCE = re.compile(r'\b(?:(R|FR|AT|RB|SP|ADR)-[0-9]{2}|(INV)-[0-9]{3}|(WP)-[0-9]{2}[A-Za-z]?)\b')
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


def check_chat(report, root):
    original = root.parent / 'sikkerheit-app-chat-transcript.md'
    copy = root / 'source' / 'boss-chat.md'
    if not original.exists() or not copy.exists():
        report.fail('docs', 'Chat transcript or its copy source/boss-chat.md missing')
        return
    report.check(original.read_bytes() == copy.read_bytes(), 'docs', 'source/boss-chat.md differs from the transcript')
    messages = len(re.findall(r'^## [0-9]+\. \S+$', copy.read_text(encoding='utf-8'), re.M))
    report.check(messages == CHAT_MESSAGES, 'docs', f'Chat transcript has {messages} messages')
    report.summary['chatMessages'] = messages
