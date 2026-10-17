"""Closed catalogs shared by the contract generator and the package validator.

Each list here is the single machine source for a closed set described in 03, 04 and 05:
checks, Graph permissions, Problem.code with agent actions, Assessment.reasonCode, finding_event pairs,
agent states and portal role sets. Counts are never hard-coded elsewhere.
"""

CATALOG_VERSION = '0.3.2'

# checkId, name, phase, defaultAssessmentMode, source, subjectType
CHECKS = [
    ('M365-001', 'mfa_registration', 'P1', 'assessed', 'graph', 'user'),
    ('M365-002', 'admin_mfa_registration', 'P1', 'assessed', 'graph', 'user'),
    ('M365-003', 'mfa_enforcement', 'P1', 'assessed', 'graph', 'tenant'),
    ('M365-004', 'legacy_auth_blocking', 'P1', 'informational', 'graph', 'tenant'),
    ('M365-005', 'global_admin_count', 'P1', 'assessed', 'graph', 'tenant'),
    ('M365-006', 'user_app_consent', 'P1', 'assessed', 'graph', 'tenant'),
    ('M365-007', 'inactive_accounts', 'P1', 'informational', 'graph', 'user'),
    ('WIN-001', 'disk_space', 'P2', 'assessed', 'agent', 'volume'),
    ('WIN-002', 'bitlocker_protection', 'P2', 'assessed', 'agent', 'volume'),
    ('WIN-003', 'antivirus_state', 'P2', 'informational', 'agent', 'device'),
    ('WIN-004', 'defender_signature_age', 'P2', 'assessed', 'agent', 'device'),
    ('WIN-005', 'firewall_profiles', 'P2', 'assessed', 'agent', 'device'),
    ('WIN-006', 'windows_update_health', 'P2', 'informational', 'agent', 'device'),
    ('WIN-007', 'reboot_pending', 'P2', 'assessed', 'agent', 'device'),
    ('WIN-008', 'local_admin_membership', 'P2', 'informational', 'agent', 'device'),
    ('WIN-009', 'secure_boot', 'P2', 'assessed', 'agent', 'device'),
    ('WIN-010', 'entra_device_join', 'P2', 'informational', 'agent', 'device'),
    ('WIN-011', 'os_inventory', 'P2', 'informational', 'agent', 'device'),
    ('SYS-001', 'agent_freshness', 'P2', 'informational', 'server', 'device'),
    ('SYS-002', 'os_support_status', 'P2', 'assessed', 'server', 'device'),
    ('SYS-003', 'os_patch_level', 'P2', 'assessed', 'server', 'device'),
]
CHECK_IDS = [c[0] for c in CHECKS]
GRAPH_IDS = [c[0] for c in CHECKS if c[4] == 'graph']
AGENT_IDS = [c[0] for c in CHECKS if c[4] == 'agent']
SERVER_IDS = [c[0] for c in CHECKS if c[4] == 'server']
WINDOWS_IDS = AGENT_IDS + SERVER_IDS
SUBJECT_TYPES = ['tenant', 'user', 'device', 'volume']
VOLUME_IDS = [c[0] for c in CHECKS if c[5] == 'volume' and c[4] == 'agent']
GRAPH_SUBJECTS = {c[0]: c[5] for c in CHECKS if c[4] == 'graph'}
ALWAYS_INFORMATIONAL = ['WIN-011', 'SYS-001']

# Application permissions of the multi-tenant Graph app (04 «Права Graph»): read-only, the first consent of P1.
# AuditLog.Read.All (sign_in_activity, M365-007) is deferred: it comes only with a new rule version and re-consent.
GRAPH_PERMISSIONS = ['Organization.Read.All', 'User.Read.All', 'UserAuthenticationMethod.Read.All',
                     'RoleManagement.Read.Directory', 'GroupMember.Read.All', 'Policy.Read.All']
# Role template of the Entra Connect synchronization account: M365-001 and M365-007 are not applicable to it.
DIRECTORY_SYNC_ROLE = 'd29b2b05-8046-44ba-8758-1e26182fcf32'
# Built-in Microsoft Entra role templates counted as privileged by M365-002 (03, «Правило M365-001 и M365-002»).
PRIVILEGED_ROLE_TEMPLATES = [
    '62e90394-69f5-4237-9190-012177145e10',  # Global Administrator
    'e8611ab8-c189-46e8-94e1-60213ab1f814',  # Privileged Role Administrator
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13',  # Privileged Authentication Administrator
    '194ae4cb-b126-40b2-bd5b-6091b380977d',  # Security Administrator
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9',  # Conditional Access Administrator
    '29232cdf-9323-42fd-ade2-1d097af3e4de',  # Exchange Administrator
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c',  # SharePoint Administrator
    'fe930be7-5e62-47db-91af-98c3a49a38b1',  # User Administrator
    'c4e39bd9-1100-46d3-8c65-fb160da0071f',  # Authentication Administrator
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3',  # Application Administrator
    '158c047a-c907-4556-b7ef-446551a6b5f7',  # Cloud Application Administrator
    '3a2c62db-5318-420d-8d74-23affee5d9d5',  # Intune Administrator
    '729827e3-9c14-49f7-bb1b-9608f156bbb8',  # Helpdesk Administrator
    'b0f54661-2d74-4c50-afa3-1ec803f12efe',  # Billing Administrator
    '0526716b-113d-4c15-b2c8-68e3c22b9f80',  # Authentication Policy Administrator
    '966707d0-3269-4727-9be2-8c3a10f19b9d',  # Password Administrator
    '9360feb5-f418-4baa-8175-e2a00bac4301',  # Directory Writers
    'e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8',  # Partner Tier2 Support
]
# Conditions of a Conditional Access policy that make its MFA requirement conditional (03 «Правило M365-003»).
CA_CONDITIONS = ['user_risk', 'sign_in_risk', 'insider_risk', 'locations_trusted_excluded', 'locations_other',
                 'platforms', 'devices', 'authentication_flows', 'client_applications']
CA_GRANT_CONTROLS = ['mfa', 'authentication_strength', 'compliant_device', 'domain_joined_device',
                     'approved_application', 'compliant_application', 'password_change', 'terms_of_use', 'other']
# Normalized authentication method kinds stored for M365-001/M365-002 (03 «Правило M365-001 и M365-002»).
# hardware_oath is listed by Graph only in beta; P1 reads v1.0 and does not observe it.
METHOD_KINDS = ['password', 'microsoft_authenticator', 'fido2', 'windows_hello_for_business',
                'platform_credential', 'software_oath', 'hardware_oath', 'phone', 'external', 'email',
                'temporary_access_pass', 'qr_code_pin', 'other']
MFA_METHOD_KINDS = ['microsoft_authenticator', 'fido2', 'windows_hello_for_business', 'platform_credential',
                    'software_oath', 'hardware_oath', 'phone', 'external']
# Modules of an M365 collection run and their capability statuses (03 «Возможности подключения»).
GRAPH_MODULES = ['tenant', 'licenses', 'users', 'auth_methods', 'roles', 'security_defaults',
                 'conditional_access', 'authorization_policy', 'sign_in_activity', 'per_user_mfa']
# Checks of the catalog that are not collected yet and their modules (03 «Правило M365-007»): the module is always
# skipped and a run has no observations of the check. M365-007 waits for AuditLog.Read.All and re-consent.
DEFERRED_IDS = ['M365-007']
DEFERRED_MODULES = ['sign_in_activity']
# skipped: the module is not needed in this run (per_user_mfa when Security Defaults or Conditional Access decide).
CAPABILITY_STATUSES = ['available', 'skipped', 'permission_missing', 'license_missing', 'partial',
                       'temporary_error']

# Agent actions: closed list; each leads to a state of the agent state machine (05). None — the action keeps the
# current state; new_challenge escalates to reenroll after a second refusal (05, «Конечный автомат агента»).
AGENT_ACTIONS = {
    'retry_after': 'Backoff',
    'retry_backoff': 'Backoff',
    'drop_batch': None,
    'refresh_configuration': None,
    'resync_sequence': None,
    'renew_session': None,
    'new_challenge': None,
    'skip_request': None,
    'reenroll': 'Unenrolled',
    'await_enrollment_key': 'EnrollmentBlocked',
    'stop_until_upgrade': 'VersionBlocked',
    'suspend_until_active': 'Suspended',
    'stop_until_reinstall': 'Revoked',
    'identity_stop': 'IdentityConflict',
}
AGENT_STATES = ['Unenrolled', 'EnrollmentBlocked', 'Active', 'Backoff', 'VersionBlocked', 'Suspended',
                'Revoked', 'IdentityConflict']
# Prefixes allowed before conditional action variants in the 05 table.
ACTION_PREFIXES = ['enrollAgent:', 'submitScan:', 'прочие агентские:', 'без Retry-After:']

_SCAN_OTHER_DROP = 'submitScan: drop_batch; прочие агентские: skip_request'
_SCAN_OTHER_REFRESH = 'submitScan: drop_batch + refresh_configuration; прочие агентские: skip_request'
# code, HTTP status, agent action ('—' for portal-only codes)
PROBLEM_CODES = [
    ('invalid_json', 400, _SCAN_OTHER_DROP),
    ('unsupported_media_type', 415, _SCAN_OTHER_DROP),
    ('payload_too_large', 413, _SCAN_OTHER_DROP),
    ('schema_violation', 422, _SCAN_OTHER_REFRESH),
    ('unsupported_schema_version', 422, 'stop_until_upgrade'),
    ('unexpected_subject', 422, 'drop_batch + refresh_configuration'),
    ('duplicate_observation', 422, 'drop_batch'),
    ('unknown_policy_version', 422, 'drop_batch + refresh_configuration'),
    ('batch_too_old', 422, 'drop_batch'),
    ('batch_time_inconsistent', 422, 'drop_batch'),
    ('agent_version_unsupported', 422, 'stop_until_upgrade'),
    ('idempotency_conflict', 409, 'enrollAgent: reenroll; submitScan: drop_batch'),
    ('sequence_conflict', 409, 'resync_sequence'),
    ('identity_conflict', 409, 'identity_stop'),
    ('organization_inactive', 403, 'suspend_until_active'),
    ('enrollment_key_invalid', 401, 'await_enrollment_key'),
    ('challenge_invalid', 401, 'new_challenge'),
    ('session_invalid', 401, 'renew_session'),
    ('device_unknown', 401, 'reenroll'),
    ('device_revoked', 401, 'stop_until_reinstall'),
    ('rate_limited', 429, 'retry_after'),
    ('temporarily_unavailable', 503, 'retry_after; без Retry-After: retry_backoff'),
    ('session_required', 401, '—'),
    ('csrf_failed', 403, '—'),
    ('forbidden', 403, '—'),
    ('not_found', 404, '—'),
    ('invalid_cursor', 400, '—'),
    ('revision_mismatch', 412, '—'),
    ('if_match_required', 428, '—'),
    ('workflow_transition_forbidden', 409, '—'),
    ('lifecycle_transition_forbidden', 409, '—'),
    ('connection_state_conflict', 409, '—'),
    ('tenant_conflict', 409, '—'),
    ('consent_not_granted', 422, '—'),
    ('resource_not_ready', 409, '—'),
    ('validation_failed', 422, '—'),
    ('policy_inputs_missing', 422, '—'),
]
PROBLEM_HTTP = {code: status for code, status, _ in PROBLEM_CODES}
# Codes that invariants.json does not need to cover (generic transport throttling).
UNCOVERED_CODES = ['rate_limited', 'temporarily_unavailable']

# Collection reasons: the agent sends the first four; the M365 collector sets only GRAPH_COLLECTOR_REASONS,
# never unsupported or collector_timeout (03 «Семантика результата»).
AGENT_COLLECTOR_REASONS = ['permission_denied', 'unsupported', 'collector_timeout', 'temporary_error']
GRAPH_COLLECTOR_REASONS = ['permission_denied', 'temporary_error', 'license_missing', 'partial_data']
COLLECTION_REASONS = AGENT_COLLECTOR_REASONS + ['license_missing', 'partial_data']
REASON_CODES = COLLECTION_REASONS + [
    'missing_observation', 'clock_inconsistent', 'unmapped_state', 'applicability_input_missing',
    'policy_not_applicable', 'evidence_time_invalid', 'os_version_unknown', 'os_inventory_missing',
    'release_catalog_stale', 'build_not_in_catalog', 'enforcement_unconfirmed',
]
# reasonCode values allowed for an informational assessment (result=null) when data is missing.
INFORMATIONAL_REASONS = COLLECTION_REASONS + ['missing_observation', 'clock_inconsistent',
                                              'applicability_input_missing']
RESULTS = ['pass', 'fail', 'unknown', 'not_applicable']

EVENT_CAUSES = ['source_change', 'rule_change', 'policy_change', 'applicability_change', 'data_quality',
                'manual_action', 'review_expired']
_TRIGGERS = ['source_change', 'rule_change', 'policy_change']
# eventType -> (allowed causes, assessmentId: 'required' | 'nullable' | 'null')
EVENT_TABLE = {
    'opened': (_TRIGGERS, 'required'),
    # applicability_change: not_applicable from facts of the source without a policy_revision change.
    'resolved': (_TRIGGERS + ['applicability_change'], 'required'),
    'reopened': (_TRIGGERS, 'required'),
    'quality_changed': (['data_quality'], 'nullable'),
    'workflow_changed': (['manual_action', 'review_expired'], 'null'),
    'policy_changed': (['policy_change'], 'nullable'),
    'subject_retired': (['source_change', 'manual_action'], 'null'),
}
WORKFLOW_STATES = ['new', 'in_progress', 'risk_accepted', 'suppressed']
ENFORCEMENTS = ['schema', 'agent_api', 'portal_api', 'collector', 'evaluator', 'worker', 'db_rls', 'agent',
                'infra']
REPLAY_STATUSES = [200, 201, 202, 204]

ROLES = ['Admin', 'Technician', 'Reader']
READ_ROLES = ['Admin', 'Technician', 'Reader']
WORK_ROLES = ['Admin', 'Technician']
ADMIN_ROLES = ['Admin']
LANGUAGES = ['nb', 'nn', 'en']
ACCEPT_LANGUAGE_MAX = 35
# Portal GET operations whose every read writes audit_event.
AUDIT_READS = ['downloadOrganizationExport', 'listAuditEvents', 'downloadReport']
# Portal operations outside /organizations/{organizationId}: reads across organizations or staff data.
CROSS_ORG_OPERATIONS = ['listOrganizations', 'createOrganization', 'listFindingsAcrossOrganizations', 'listStaff',
                        'listPolicyTemplates', 'createPolicyTemplate', 'getPolicyTemplate', 'listPolicyTemplateRevisions',
                        'createPolicyTemplateRevision', 'previewPolicyTemplate', 'getCurrentStaff', 'listWindowsReleases', 'importWindowsReleases', 'verifyWindowsReleaseMonth']
# Actions of changeOrganizationLifecycle (OrganizationLifecycleChange.action and audit details).
LIFECYCLE_ACTIONS = ['disable', 'enable', 'schedule_deletion', 'cancel_deletion']
# Deletion order of retention_purge (04 «Сроки хранения», 05); keys of RetentionPurgeAuditDetails.deleted.
RETENTION_PURGE_ORDER = ['risk_decision', 'finding_event', 'assessment', 'finding', 'observation', 'collection_run',
                         'scan_batch', 'scan_request', 'subject', 'device_presence', 'device', 'revoked_installation']
# AuditEvent.action -> schema of AuditEvent.details; details is null for every other action.
AUDIT_DETAILS = {'policy.template_apply': 'PolicyTemplateApplicationAuditDetails',
                'organization.lifecycle_change': 'OrganizationLifecycleAuditDetails',
                 'finding.assignment_change': 'FindingAssignmentAuditDetails',
                 'retention.purge_summary': 'RetentionPurgeAuditDetails'}
# Operations accepting Accept-Language and answering with Content-Language.
LOCALIZED_OPERATIONS = ['listAssessments', 'listFindings', 'listFindingsAcrossOrganizations', 'getFinding',
                        'patchFinding', 'decideFindingRisk']
# Portal GET operations that may answer 409 (resource not ready).
DOWNLOAD_OPERATIONS = ['downloadReport', 'downloadOrganizationExport']
# Restrictive security actions written to the append-only security log before commit (04, 06).
# organization.cancel_deletion is permissive, but it is logged too: replay must not execute a cancelled deletion.
SECURITY_LOG_ACTIONS = ['device.revoke', 'enrollment_key.revoke', 'organization.disable',
                        'organization.schedule_deletion', 'organization.cancel_deletion', 'organization.delete',
                        'm365.disconnect']
# Classes of members of the local Administrators group (03 «Правило WIN-008»).
LOCAL_ADMIN_KINDS = ['builtin_administrator', 'local_account', 'domain', 'entra', 'well_known', 'unknown']
RELEASE_KINDS = ['security_monthly', 'security_oob', 'nonsecurity_oob', 'preview', 'hotpatch']
# OS families of the lifecycle table by editionId (03 «Жизненный цикл ОС»).
OS_FAMILIES = ['home_pro', 'enterprise_education', 'ltsc', 'iot_ltsc']
