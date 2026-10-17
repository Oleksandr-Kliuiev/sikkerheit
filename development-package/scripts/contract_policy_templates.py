"""Portable shared policy templates. Client-specific inputs cannot enter the library."""
from copy import deepcopy

SCOPES = {
    'm365': [f'M365-{n:03}' for n in range(1, 7)],
    'windows': [f'WIN-{n:03}' for n in list(range(1, 10)) + [11]] + [f'SYS-{n:03}' for n in range(1, 4)],
}
SCOPES['all'] = SCOPES['m365'] + SCOPES['windows']
PROTECTED = {'M365-002': ['privilegedRoleTemplateIds'], 'M365-006': ['allowedPermissionGrantPolicies'],
             'WIN-003': ['approvedProviders', 'defenderApproved'], 'WIN-005': ['approvedFirewallProviders'],
             'WIN-008': ['allowedDomainRids', 'allowedSids']}


def schemas(policy, obj, array, enum, integer, ref, string, nullable, safe_text, uuid, time, boolean, problem_codes):
    branches = []
    for scope, ids in SCOPES.items():
        checks = {cid: deepcopy(policy['properties']['checks']['properties'][cid]) for cid in ids}
        for cid, check in checks.items():
            check['properties'].pop('notApplicableEditionIds', None)
            parameters = check['properties']['parameters']
            for name in PROTECTED.get(cid, []):
                parameters['properties'].pop(name, None)
                parameters['required'].remove(name)
        active = [cid for cid in ids if not cid.startswith('SYS-')]
        branches.append(obj({'scope': {'const': scope}, 'activeCheckIds': array(enum(*active), len(active), unique=True),
                             'checks': obj(checks)}))
    content = {'oneOf': branches}
    create = {'name': safe_text(80), 'description': string(500, minimum=0, pattern=r'^[^\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2066-\u2069<>]*$'), 'content': ref('PolicyTemplateContent')}
    return {
        'PolicyTemplateContent': content,
        'PolicyTemplateApplicationAuditDetails': obj({'templateId': uuid, 'templateRevision': integer(1), 'policyVersion': integer(1)}),
        'PolicyTemplateCreate': obj(create),
        'PolicyTemplateRevisionCreate': obj({**create, 'archived': boolean}),
        'PolicyTemplate': obj({**create, 'id': uuid, 'revision': integer(1), 'archived': boolean,
                               'createdAt': time, 'createdBy': uuid}),
        'PolicyTemplatePreviewRequest': obj({'organizationIds': array(uuid, 50, 1, unique=True)}),
        'PolicyTemplatePreviewItem': obj({'organizationId': uuid, 'organizationName': nullable(safe_text(200)),
            'status': enum('ready', 'unchanged', 'unavailable'), 'policyVersion': nullable(integer(1)),
            'before': {'oneOf': [ref('PolicyConfiguration'), {'type': 'null'}]}, 'after': {'oneOf': [ref('PolicyConfiguration'), {'type': 'null'}]},
            'previewToken': nullable(string(2048)), 'problemCode': nullable(enum(*problem_codes))}),
        'PolicyTemplatePreview': obj({'templateId': uuid, 'templateRevision': integer(1), 'expiresAt': time,
                                     'items': array(ref('PolicyTemplatePreviewItem'), 50, 1)}),
        'PolicyTemplateApplyRequest': obj({'templateId': uuid, 'templateRevision': integer(1), 'previewToken': string(2048)}),
        'PolicyTemplateApplication': obj({'templateId': uuid, 'templateRevision': integer(1), 'policyVersion': integer(1),
                                         'appliedAt': time, 'replayed': boolean}),
    }
