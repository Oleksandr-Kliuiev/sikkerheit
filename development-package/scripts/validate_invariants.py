"""Checks of specs/invariants.json: fields, expectedError forms, coverage and document anchors."""
import re

from contract_catalog import (AGENT_STATES, CAPABILITY_STATUSES, CHECKS, COLLECTION_REASONS, ENFORCEMENTS,
                              EVENT_TABLE, INFORMATIONAL_REASONS, PROBLEM_HTTP, REASON_CODES, REPLAY_STATUSES,
                              RESULTS, UNCOVERED_CODES)
from doc_tables import headings, row_ids

FIELDS = ['id', 'rule', 'sourceDoc', 'phase', 'enforcement', 'negativeExample', 'expectedError', 'acceptance']
# Sections that must carry at least one record: organization lifecycle, background jobs, local collection
# boundary, M365 connection and collection, security log.
REQUIRED_SECTIONS = [('05-data-and-api.md', 'Жизненный цикл организации'),
                     ('02-architecture-and-stack.md', 'Фоновые задания'),
                     ('02-architecture-and-stack.md', 'Выполнение локальной проверки'),
                     ('05-data-and-api.md', 'Подключение M365 и сбор'),
                     ('04-security-and-privacy.md', 'Журнал безопасности')]
EFFECTS = ['none', 'single']


def form_error(expected, record, audit_pattern):
    """Return a message if expectedError does not have exactly one allowed form, else None."""
    keys = set(expected) if isinstance(expected, dict) else set()
    if keys == {'http', 'code'}:
        if PROBLEM_HTTP.get(expected['code']) != expected['http']:
            return 'http/code pair not in the Problem catalog'
    elif keys in ({'assessmentMode', 'result'}, {'assessmentMode', 'result', 'reasonCode'}):
        mode, value, reason = expected['assessmentMode'], expected['result'], expected.get('reasonCode')
        if mode == 'assessed':
            if value not in RESULTS or (reason is not None and reason not in REASON_CODES) \
                    or (value in ('pass', 'fail') and 'reasonCode' in expected):
                return 'assessed result/reasonCode outside closed sets'
        elif mode == 'informational':
            if value is not None or (reason is not None and reason not in INFORMATIONAL_REASONS):
                return 'informational result must be null with a transferable reasonCode'
        else:
            return 'unknown assessmentMode'
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
        if expected['agentState'] not in AGENT_STATES or record.get('phase') != 'P2':
            return 'agentState only for P2 with a known state'
    elif keys == {'rows'}:
        if expected['rows'] != 0 or record.get('enforcement') != 'db_rls':
            return 'rows form only {rows: 0} with enforcement=db_rls'
    elif keys == {'capabilityStatus'}:
        if expected['capabilityStatus'] not in CAPABILITY_STATUSES or record.get('enforcement') != 'collector':
            return 'capabilityStatus only with enforcement=collector and a closed value'
    elif keys == {'effect'}:
        if expected['effect'] not in EFFECTS:
            return 'effect must be none or single'
    else:
        return 'unknown expectedError form'
    return None


def _check_record(report, record, docs, acceptance_ids, audit_pattern):
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


def check_invariants(report, ctx, docs):
    records = ctx['invariants']
    audit_pattern = ctx['schemas']['AuditEvent']['properties']['action']['pattern']
    ids = [r.get('id') for r in records]
    report.check(len(ids) == len(set(ids)), 'contract', 'Duplicate INV id')
    acceptance_ids = row_ids(docs.get('07-delivery-plan-and-acceptance.md', ''))
    for record in records:
        _check_record(report, record, docs, acceptance_ids, audit_pattern)
    expected = [r.get('expectedError', {}) for r in records]
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
    sections = {(r['sourceDoc']['file'], r['sourceDoc']['section']) for r in records if 'sourceDoc' in r}
    for section in REQUIRED_SECTIONS:
        report.check(section in sections, 'contract', f'invariants.json: no record for {section[1]}')
    informational = [e for e in expected if e.get('assessmentMode') == 'informational']
    report.check(any(e.get('reasonCode') in COLLECTION_REASONS for e in informational), 'contract',
                 'invariants.json: no informational record with a collection reasonCode')
    report.check(any('reasonCode' not in e for e in informational), 'contract',
                 'invariants.json: no informational record without reasonCode')
    text = {r['id']: r.get('rule', '') + ' ' + r.get('negativeExample', '') for r in records}
    fail = {'assessmentMode': 'assessed', 'result': 'fail'}
    for check, marker in (('WIN-002', 'BitLocker'), ('M365-003', 'report-only')):
        found = [r for r in records if r.get('expectedError') == fail and check in text[r['id']]]
        report.check(bool(found), 'contract', f'invariants.json: {check} reference record ({marker}) missing')
    for cid, _, _, mode, _, _ in CHECKS:
        if mode == 'assessed':
            report.check(any(cid in value for value in text.values()), 'contract',
                         f'invariants.json: assessed check {cid} has no record')
    phases = [r.get('phase') for r in records]
    report.summary.update(invariants=len(records), invariantsP1=phases.count('P1'), invariantsP2=phases.count('P2'))
    return set(ids)
