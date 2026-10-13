"""Generate the proposed P1 contracts, invariant registry and synthetic examples; no network calls."""
import sys

sys.dont_write_bytecode = True
from pathlib import Path  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
import copy  # noqa: E402
import json  # noqa: E402

from contract_catalog import AGENT_IDS, CATALOG_VERSION, CHECKS, VOLUME_IDS  # noqa: E402
from contract_paths import PORTAL_HOST, SECURITY, build_paths  # noqa: E402
from contract_schemas import api_schemas, batch_schema, observation_schema  # noqa: E402
from invariants_data import build_invariants  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / 'specs'
EXAMPLES = ROOT / 'examples'

VOLUME_ID = '\\\\?\\Volume{5f1c2c1e-8a8f-4b3e-9a51-3c1d2e4f6a7b}\\'
SECURITY_UPDATES_CATEGORY = '0FA1201D-4330-4FA8-8AE9-B877473B6441'
SYNTHETIC_EVIDENCE = {
    'WIN-001': {'totalBytes': 256000000000, 'freeBytes': 18000000000},
    # Reference negative test: fully encrypted, protection suspended -> fail when encryptionRequired=true.
    'WIN-002': {'volumeStatus': 'fully_encrypted', 'protectionStatus': 'off', 'encryptionPercentage': 100},
    'WIN-003': {'products': [{'provider': 'Microsoft Defender Antivirus', 'productState': 'on',
                              'statusSource': 'defender', 'rawState': None}],
                'defender': {'amRunningMode': 'normal', 'realTimeProtectionEnabled': True}},
    'WIN-004': {'signatureLastUpdatedAt': '2026-10-12T08:00:00Z'},
    'WIN-005': {'domainEnabled': True, 'privateEnabled': True, 'publicEnabled': True},
    'WIN-006': {'configuredSource': 'windows_update', 'auLastSearchSuccessAt': '2026-10-12T06:15:00Z',
                'agentSearch': {'mode': 'offline_cache', 'completedAt': '2026-10-12T10:00:40Z',
                                'resultCode': 'succeeded'},
                'pendingSecurityUpdates': [{
                    'updateId': '6b8e2f4a-1c3d-4e5f-8a9b-0c1d2e3f4a5b', 'revisionNumber': 200,
                    'kbArticleIds': ['5066835'], 'categoryIds': [SECURITY_UPDATES_CATEGORY],
                    'msrcSeverity': 'Important', 'lastDeploymentChangeAt': '2026-10-08T17:00:00Z',
                    'deadlineAt': None, 'firstSeenPendingAt': '2026-10-09T10:01:00Z'}],
                'pendingSecurityUpdatesTotal': 1, 'truncated': False},
    'WIN-007': {'rebootRequired': False, 'lastBootAt': '2026-10-11T07:30:00Z',
                'statusSource': 'windows_update_api'},
    'WIN-008': {'memberSids': ['S-1-5-21-1000-2000-3000-500'], 'membershipScope': 'direct_members'},
    'WIN-009': {'enabled': True, 'platform': 'uefi'},
    'WIN-010': {'joinType': 'entra_joined', 'tenantId': '22222222-2222-4222-8222-222222222222',
                'entraDeviceId': '33333333-3333-4333-8333-333333333333'},
    'WIN-011': {'editionId': 'Professional', 'displayVersion': '25H2', 'build': 26200, 'ubr': 6899,
                'architecture': 'x64'},
}
assert list(SYNTHETIC_EVIDENCE) == AGENT_IDS, 'Synthetic example must contain exactly all agent checks'


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def subject(cid):
    if cid in VOLUME_IDS:
        return {'type': 'volume', 'volumeId': VOLUME_ID, 'mountPoint': 'C:', 'role': 'os'}
    return {'type': 'device'}


def examples():
    sample = {
        'schemaVersion': '1.0', 'scanId': '11111111-1111-4111-8111-111111111111',
        'sequence': 1, 'agentVersion': '0.1.0', 'policyVersion': 1,
        'machineFingerprint': '9f2c4e6a8b0d1f3e5a7c9b1d3f5e7a9c0b2d4f6e8a1c3e5b7d9f0a2c4e6b8d0f',
        'startedAt': '2026-10-12T10:00:00Z', 'completedAt': '2026-10-12T10:01:30Z',
        'observations': [
            {'checkId': cid, 'collectorVersion': '0.1.0', 'subject': subject(cid),
             'observedAt': '2026-10-12T10:01:00Z', 'collectionStatus': 'collected', 'evidence': value}
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
                    'source': source, 'subjectType': subject_type}
                   for cid, name, phase, mode, source, subject_type in CHECKS]})
    observation, batch = observation_schema(), batch_schema()
    save(SPEC / 'observation.schema.json', observation)
    save(SPEC / 'scan-batch.schema.json', batch)
    sample, unavailable = examples()
    save(EXAMPLES / 'scan-batch.json', sample)
    save(EXAMPLES / 'scan-batch-unavailable.json', unavailable)
    spec = {
        'openapi': '3.1.0',
        'jsonSchemaDialect': 'https://json-schema.org/draft/2020-12/schema',
        'info': {'title': 'Sikkerheit P1 Proposed API', 'version': CATALOG_VERSION,
                 'description': 'Проект контракта. Example hosts не являются развёрнутыми сервисами. '
                                'Бизнес-инварианты (specs/invariants.json) и полномочия проверяются '
                                'дополнительно к схемам; форматы uuid и date-time сервер проверяет явно. '
                                'P2-интеграции требуют отдельного расширения после части P2 SP-03.'},
        'servers': [{'url': PORTAL_HOST, 'description': 'Portal API and bootstrap host'}],
        'paths': build_paths(),
        'components': {'securitySchemes': SECURITY,
                       'schemas': api_schemas(openapi_copy(observation), openapi_copy(batch))},
    }
    save(SPEC / 'openapi.json', spec)
    save(SPEC / 'invariants.json', {'version': CATALOG_VERSION, 'invariants': build_invariants()})
    print('Generated P1 OpenAPI, agent schemas, catalog, invariant registry and two synthetic scan examples.')


if __name__ == '__main__':
    main()
