"""Generate the proposed contracts, invariant registry and synthetic examples; no network calls."""
import sys

sys.dont_write_bytecode = True
from pathlib import Path  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
import copy  # noqa: E402
import json  # noqa: E402

from contract_catalog import (AGENT_IDS, CATALOG_VERSION, CHECKS, DEFERRED_IDS, DEFERRED_MODULES, GRAPH_IDS,  # noqa: E402
                              GRAPH_MODULES, VOLUME_IDS)
from contract_paths import PORTAL_HOST, SECURITY, build_paths  # noqa: E402
from contract_schemas import (SERVER_EVIDENCE, api_schemas, batch_schema, graph_collection_schema,  # noqa: E402
                              graph_observation_schema, observation_schema)
from invariants_data import build_invariants  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / 'specs'
EXAMPLES = ROOT / 'examples'

VOLUME_ID = '\\\\?\\Volume{5f1c2c1e-8a8f-4b3e-9a51-3c1d2e4f6a7b}\\'
SYNTHETIC_EVIDENCE = {
    'WIN-001': {'totalBytes': 256000000000, 'freeBytes': 18000000000},
    # Reference negative test: fully encrypted, protection suspended -> fail when encryptionRequired=true.
    'WIN-002': {'volumeStatus': 'fully_encrypted', 'protectionStatus': 'off', 'encryptionPercentage': 100},
    'WIN-003': {'products': [{'provider': 'Microsoft Defender Antivirus', 'productState': 'on',
                              'statusSource': 'defender', 'rawState': None}],
                'defender': {'amRunningMode': 'normal', 'realTimeProtectionEnabled': True}},
    'WIN-004': {'signatureLastUpdatedAt': '2026-10-14T08:00:00Z'},
    'WIN-005': {'domainEnabled': True, 'privateEnabled': True, 'publicEnabled': True, 'firewallProducts': []},
    'WIN-006': {'lastSearchSuccessAt': '2026-10-14T06:15:00Z', 'lastInstallSuccessAt': '2026-10-14T03:40:00Z',
                'wsusConfigured': False},
    'WIN-007': {'rebootRequired': False, 'lastBootAt': '2026-10-14T07:30:00Z'},
    'WIN-008': {'members': [{'sid': 'S-1-5-21-1000-2000-3000-500', 'kind': 'builtin_administrator', 'relativeId': 500},
                            {'sid': 'S-1-12-1-1111111111-2222222222-3333333333-4444444444', 'kind': 'entra',
                             'relativeId': None}],
                'membershipScope': 'direct_members'},
    'WIN-009': {'enabled': True, 'platform': 'uefi'},
    'WIN-010': {'joinType': 'entra_joined', 'tenantId': '22222222-2222-4222-8222-222222222222',
                'entraDeviceId': '33333333-3333-4333-8333-333333333333'},
    # 26200.9711 is the October 2026 security release (KB5127648).
    'WIN-011': {'editionId': 'Professional', 'displayVersion': '25H2', 'build': 26200, 'ubr': 9711,
                'architecture': 'x64'},
}
assert list(SYNTHETIC_EVIDENCE) == AGENT_IDS, 'Synthetic example must contain exactly all agent checks'

TENANT = '22222222-2222-4222-8222-222222222222'
USERS = [('aaaaaaaa-0000-4000-8000-000000000001', 'kari.nordmann@example.invalid'),
         ('aaaaaaaa-0000-4000-8000-000000000002', 'ola.admin@example.invalid')]
GLOBAL_ADMIN = '62e90394-69f5-4237-9190-012177145e10'
SYNTHETIC_GRAPH = [
    # Member user without an MFA method: M365-001 fail.
    ('M365-001', 0, {'accountEnabled': True, 'userType': 'Member', 'directorySyncAccount': False,
                     'methodKinds': ['password']}),
    ('M365-001', 1, {'accountEnabled': True, 'userType': 'Member', 'directorySyncAccount': False,
                     'methodKinds': ['password', 'microsoft_authenticator']}),
    ('M365-002', 1, {'accountEnabled': True, 'userType': 'Member', 'roleTemplateIds': [GLOBAL_ADMIN],
                     'temporaryRoleTemplateIds': [], 'assignment': 'direct',
                     'methodKinds': ['password', 'microsoft_authenticator']}),
    # Reference case: only a report-only CA policy requires MFA, per-user MFA is off -> M365-003 fail, not pass.
    ('M365-003', None, {'securityDefaults': 'disabled', 'conditionalAccess': 'available', 'mfaPolicies': [
        {'policyId': '44444444-0000-4000-8000-000000000001', 'state': 'enabledForReportingButNotEnforced',
         'allUsers': True, 'allApplications': True, 'excludedApplications': 0, 'conditions': [],
         'excludedUsersOutsidePolicy': 0, 'unresolvedExclusions': 0, 'allClientAppTypes': True,
         'grantOperator': 'AND', 'grantControls': ['mfa'], 'authStrengthRequiresMfa': None}],
        'perUserMfa': {'required': 0, 'notRequired': 2, 'unknown': 0}}),
    ('M365-004', None, {'securityDefaults': 'disabled', 'conditionalAccess': 'available', 'legacyBlockPolicies': []}),
    # Global Reader is outside privilegedRoleTemplateIds of policy v1: listed, not assessed by M365-002.
    ('M365-005', None, {'globalAdminUserIds': [USERS[1][0]], 'disabledGlobalAdminUserIds': [],
                        'unresolvedGroupAssignments': 0,
                        'uncoveredRoleTemplateIds': ['f2ef992c-3afb-46b9-b7cf-a126ee74c451']}),
    ('M365-006', None, {'permissionGrantPolicies': ['ManagePermissionGrantsForSelf.microsoft-user-default-legacy']}),
]
# A P1 run: every collected check, none of the deferred ones; their modules are skipped (03 «Правило M365-007»).
assert sorted({c for c, _, _ in SYNTHETIC_GRAPH}) == [c for c in GRAPH_IDS if c not in DEFERRED_IDS], \
    'Graph example must cover exactly the collected M365 checks'


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def subject(cid):
    if cid in VOLUME_IDS:
        return {'type': 'volume', 'volumeId': VOLUME_ID, 'mountPoint': 'C:', 'role': 'os'}
    return {'type': 'device'}


def scan_examples():
    sample = {
        'schemaVersion': '2.0', 'scanId': '11111111-1111-4111-8111-111111111111',
        'sequence': 1, 'agentVersion': '0.1.0', 'policyVersion': 1,
        'machineFingerprint': '9f2c4e6a8b0d1f3e5a7c9b1d3f5e7a9c0b2d4f6e8a1c3e5b7d9f0a2c4e6b8d0f',
        'startedAt': '2026-10-14T10:00:00Z', 'completedAt': '2026-10-14T10:01:30Z',
        'observations': [
            {'checkId': cid, 'collectorVersion': '0.1.0', 'subject': subject(cid),
             'observedAt': '2026-10-14T10:01:00Z', 'collectionStatus': 'collected', 'evidence': value}
            for cid, value in SYNTHETIC_EVIDENCE.items()
        ],
    }
    unavailable = copy.deepcopy(sample)
    unavailable['scanId'] = '44444444-4444-4444-8444-444444444444'
    unavailable['sequence'] = 2
    for item in unavailable['observations']:
        if item['checkId'] in ['WIN-002', 'WIN-009']:
            item.pop('evidence')
            item['collectionStatus'] = 'unavailable'
            item['reasonCode'] = 'permission_denied' if item['checkId'] == 'WIN-002' else 'unsupported'
    return sample, unavailable


def graph_example():
    observations = []
    for cid, user, evidence in SYNTHETIC_GRAPH:
        subject_value = ({'type': 'tenant', 'key': TENANT} if user is None else
                         {'type': 'user', 'key': USERS[user][0], 'userPrincipalName': USERS[user][1]})
        observations.append({'checkId': cid, 'collectorVersion': '0.1.0', 'subject': subject_value,
                             'observedAt': '2026-10-12T03:04:00Z', 'collectionStatus': 'collected',
                             'evidence': evidence})
    return {'schemaVersion': '1.0', 'collectionRunId': '55555555-5555-4555-8555-555555555555',
            'tenantId': TENANT, 'startedAt': '2026-10-12T03:00:00Z', 'completedAt': '2026-10-12T03:05:00Z',
            'state': 'completed', 'entraP1': True, 'usersComplete': True,
            'modules': [{'module': module, 'status': 'skipped' if module in DEFERRED_MODULES else 'available'}
                        for module in GRAPH_MODULES],
            'observations': observations}


def openapi_copy(schema):
    """Copy an agent schema into components: no $id/$schema, internal references only."""
    result = copy.deepcopy(schema)
    result.pop('$id', None)
    result.pop('$schema', None)
    items = result['properties'].get('observations', {}).get('items')
    if items:
        items['$ref'] = '#/components/schemas/Observation'
    return result


def main():
    SPEC.mkdir(exist_ok=True)
    EXAMPLES.mkdir(exist_ok=True)
    save(SPEC / 'check-catalog.json', {
        'catalogVersion': CATALOG_VERSION,
        'checks': [{'checkId': cid, 'name': name, 'phase': phase, 'defaultAssessmentMode': mode,
                    'source': source, 'subjectType': subject_type,
                    **({'evidenceSchema': SERVER_EVIDENCE[cid]} if cid in SERVER_EVIDENCE else {})}
                   for cid, name, phase, mode, source, subject_type in CHECKS]})
    observation, batch = observation_schema(), batch_schema()
    save(SPEC / 'observation.schema.json', observation)
    save(SPEC / 'scan-batch.schema.json', batch)
    save(SPEC / 'graph-observation.schema.json', graph_observation_schema())
    save(SPEC / 'graph-collection.schema.json', graph_collection_schema())
    sample, unavailable = scan_examples()
    save(EXAMPLES / 'scan-batch.json', sample)
    save(EXAMPLES / 'scan-batch-unavailable.json', unavailable)
    save(EXAMPLES / 'm365-collection.json', graph_example())
    spec = {
        'openapi': '3.1.0',
        'jsonSchemaDialect': 'https://json-schema.org/draft/2020-12/schema',
        'info': {'title': 'Sikkerheit Proposed API', 'version': CATALOG_VERSION,
                 'description': 'Проект контракта P1 (портал и Microsoft 365) и P2 (агент Windows); этап операции '
                                '— расширение x-phase. Example hosts не являются развёрнутыми сервисами. '
                                'Бизнес-инварианты (specs/invariants.json) и полномочия проверяются дополнительно к '
                                'схемам; форматы uuid и date-time сервер проверяет явно.'},
        'servers': [{'url': PORTAL_HOST, 'description': 'Hostname портала'}],
        'paths': build_paths(),
        'components': {'securitySchemes': SECURITY,
                       'schemas': api_schemas(openapi_copy(observation), openapi_copy(batch))},
    }
    save(SPEC / 'openapi.json', spec)
    save(SPEC / 'invariants.json', {'version': CATALOG_VERSION, 'invariants': build_invariants()})
    print('Generated OpenAPI, agent and M365 schemas, catalog, invariant registry and three synthetic examples.')


if __name__ == '__main__':
    main()
