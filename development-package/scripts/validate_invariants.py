"""Checks of specs/invariants.json: fields, expectedError forms, coverage and document anchors."""
import re

from contract_catalog import (AGENT_STATES, CAPABILITY_STATUSES, ENFORCEMENTS, EVENT_TABLE, PROBLEM_HTTP,
                              REASON_CODES, REPLAY_STATUSES, RESULTS, UNCOVERED_CODES)
from doc_tables import headings, row_ids

FIELDS = ['id', 'rule', 'sourceDoc', 'phase', 'enforcement', 'negativeExample', 'expectedError', 'acceptance']
# Sections that must carry at least one P1 record: organization lifecycle, scheduler and fencing,
# privileged collection boundary.
REQUIRED_SECTIONS = [('05-data-and-api.md', 'Жизненный цикл организации'),
                     ('02-architecture-and-stack.md', 'Очередь заданий'),
                     ('02-architecture-and-stack.md', 'Выполнение локальной проверки')]
# The five P2 records: nextLink, partial without a property, MFA registration is not a requirement,
# Intune mapping, consent beyond enabled modules.
P2_TOPICS = ['nextLink', 'partial_property', 'mfa_registered_not_required', 'intune_mapping', 'extra_consent']


def form_error(expected, record, audit_pattern):
    """Return a message if expectedError does not have exactly one allowed form, else None."""
    keys = set(expected) if isinstance(expected, dict) else set()
    if keys == {'http', 'code'}:
        if PROBLEM_HTTP.get(expected['code']) != expected['http']:
            return 'http/code pair not in the Problem catalog'
    elif keys in ({'result'}, {'result', 'reasonCode'}):
        if expected['result'] not in RESULTS or expected.get('reasonCode', REASON_CODES[0]) not in REASON_CODES:
            return 'result/reasonCode outside closed sets'
    elif keys == {'event'}:
        event = expected['event']
        if set(event) != {'eventType', 'cause'} or event['cause'] not in EVENT_TABLE.get(event['eventType'], ([],))[0]:
            return 'eventType/cause pair not allowed'
    elif keys == {'audit'}:
        if not re.match(audit_pattern, str(expected['audit'])):
            return 'audit action does not match AuditEvent.action'
    elif keys == {'replay'}:
        replay = expected['replay']
        if replay.get('http') not in REPLAY_STATUSES or replay.get('duplicate') is not True or len(replay) != 2:
            return 'replay form invalid'
    elif keys == {'agentState'}:
        if expected['agentState'] not in AGENT_STATES:
            return 'unknown agent state'
    elif keys == {'rows'}:
        if expected['rows'] != 0 or record.get('enforcement') != 'db_rls':
            return 'rows form only {rows: 0} with enforcement=db_rls'
    elif keys == {'capabilityStatus'}:
        if expected['capabilityStatus'] not in CAPABILITY_STATUSES or record.get('phase') != 'P2':
            return 'capabilityStatus only for P2 with a closed value'
    else:
        return 'unknown expectedError form'
    return None


def check_invariants(report, ctx, docs):
    records = ctx['invariants']
    audit_pattern = ctx['schemas']['AuditEvent']['properties']['action']['pattern']
    ids = [r.get('id') for r in records]
    report.check(len(ids) == len(set(ids)), 'contract', 'Duplicate INV id')
    acceptance_ids = row_ids(docs.get('07-delivery-plan-and-acceptance.md', ''))
    for record in records:
        rid = record.get('id', '?')
        report.check(re.fullmatch(r'INV-[0-9]{3}', str(rid)) is not None, 'contract', f'{rid}: id format')
        report.check(sorted(record) == sorted(FIELDS), 'contract', f'{rid}: fields differ from the required set')
        report.check(record.get('phase') in ('P1', 'P2'), 'contract', f'{rid}: phase')
        report.check(record.get('enforcement') in ENFORCEMENTS, 'contract', f'{rid}: enforcement')
        report.check(bool(record.get('negativeExample')), 'contract', f'{rid}: negativeExample empty')
        problem = form_error(record.get('expectedError'), record, audit_pattern)
        report.check(problem is None, 'contract', f'{rid}: expectedError {problem}')
        source = record.get('sourceDoc', {})
        text = docs.get(source.get('file'))
        report.check(text is not None, 'docs', f'{rid}: sourceDoc file {source.get("file")} missing')
        if text is not None:
            report.check(source.get('section') in headings(text), 'docs',
                         f'{rid}: heading «{source.get("section")}» absent in {source.get("file")}')
        report.check(record.get('acceptance') in acceptance_ids, 'docs',
                     f'{rid}: acceptance {record.get("acceptance")} absent in 07')
    p1 = [r for r in records if r.get('phase') == 'P1']
    expected = [r.get('expectedError', {}) for r in p1]
    codes = {e.get('code') for e in expected}
    for code in PROBLEM_HTTP:
        if code not in UNCOVERED_CODES:
            report.check(code in codes, 'contract', f'invariants.json: Problem.code {code} not covered')
    reasons = {e.get('reasonCode') for e in expected}
    for reason in REASON_CODES:
        report.check(reason in reasons, 'contract', f'invariants.json: reasonCode {reason} not covered')
    events = {e['event']['eventType'] for e in expected if 'event' in e}
    for event_type in EVENT_TABLE:
        report.check(event_type in events, 'contract', f'invariants.json: event row {event_type} not covered')
    sections = {(r['sourceDoc']['file'], r['sourceDoc']['section']) for r in p1 if 'sourceDoc' in r}
    for section in REQUIRED_SECTIONS:
        report.check(section in sections, 'contract', f'invariants.json: no record for {section[1]}')
    bitlocker = [r for r in p1 if r.get('expectedError') == {'result': 'fail'} and 'WIN-002' in r.get(
        'negativeExample', '') + r.get('rule', '')]
    report.check(bool(bitlocker), 'contract', 'invariants.json: BitLocker reference record missing')
    p2 = [r for r in records if r.get('phase') == 'P2']
    report.check(len(p2) == len(P2_TOPICS), 'contract', 'invariants.json: P2 records must be exactly the five topics')
    report.summary.update(invariants=len(records), invariantsP1=len(p1), invariantsP2=len(p2))
    return set(ids)
