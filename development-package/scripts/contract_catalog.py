"""Closed catalogs shared by the contract generator and the package validator.

Each list here is the single machine source for a closed set described in 03 and 05:
checks, Problem.code with agent actions, Assessment.reasonCode, finding_event pairs,
agent states and portal role sets. Counts are never hard-coded elsewhere.
"""

CATALOG_VERSION = '0.2.0'

# checkId, name, phase, defaultAssessmentMode, source, subjectType
CHECKS = [
    ('WIN-001', 'disk_space', 'P1', 'assessed', 'agent', 'volume'),
    ('WIN-002', 'bitlocker_protection', 'P1', 'assessed', 'agent', 'volume'),
    ('WIN-003', 'antivirus_state', 'P1', 'informational', 'agent', 'device'),
    ('WIN-004', 'defender_signature_age', 'P1', 'assessed', 'agent', 'device'),
    ('WIN-005', 'firewall_profiles', 'P1', 'assessed', 'agent', 'device'),
    ('WIN-006', 'windows_update', 'P1', 'informational', 'agent', 'device'),
    ('WIN-007', 'reboot_required', 'P1', 'assessed', 'agent', 'device'),
    ('WIN-008', 'local_admin_membership', 'P1', 'informational', 'agent', 'device'),
    ('WIN-009', 'secure_boot', 'P1', 'assessed', 'agent', 'device'),
    ('WIN-010', 'entra_device_join', 'P1', 'informational', 'agent', 'device'),
    ('WIN-011', 'os_inventory', 'P1', 'informational', 'agent', 'device'),
    ('SYS-001', 'agent_freshness', 'P1', 'informational', 'server', 'device'),
    ('SYS-002', 'os_support_status', 'P1', 'assessed', 'server', 'device'),
    ('M365-001', 'mfa_registration', 'P2', 'assessed', 'graph', 'user'),
    ('M365-002', 'security_defaults', 'P2', 'informational', 'graph', 'tenant'),
    ('M365-003', 'conditional_access_inventory', 'P2', 'informational', 'graph', 'tenant'),
    ('M365-004', 'intune_compliance', 'P2', 'assessed', 'graph', 'managed_device'),
    ('M365-005', 'sign_in_evidence', 'P3', 'informational', 'graph', 'tenant'),
]
AGENT_IDS = [c[0] for c in CHECKS if c[4] == 'agent']
P1_IDS = [c[0] for c in CHECKS if c[2] == 'P1']
SUBJECT_TYPES = sorted({c[5] for c in CHECKS})
VOLUME_IDS = [c[0] for c in CHECKS if c[5] == 'volume' and c[4] == 'agent']
ALWAYS_INFORMATIONAL = ['WIN-011', 'SYS-001']

# Agent actions: closed list; each leads to a state of the agent state machine (05).
AGENT_ACTIONS = {
    'retry_after': 'Backoff',
    'retry_backoff': 'Backoff',
    'drop_batch': 'Active',
    'refresh_configuration': 'Active',
    'resync_sequence': 'Active',
    'restart_renewal': 'Active',
    'skip_request': None,  # stays in the current state (Active or Unenrolled)
    'stop_until_upgrade': 'VersionBlocked',
    'suspend_until_active': 'Suspended',
    'reenroll_required': 'ReenrollRequired',
    'await_new_token': 'Unenrolled',
    'trust_failure': 'TrustFailed',
    'stop_until_reinstall': 'ReinstallRequired',
    'identity_stop': 'IdentityConflict',
}
AGENT_STATES = ['Unenrolled', 'Active', 'Backoff', 'VersionBlocked', 'Suspended', 'TrustFailed',
                'ReenrollRequired', 'ReinstallRequired', 'IdentityConflict']
# Prefixes allowed before conditional action variants in the 05 table.
ACTION_PREFIXES = ['submitScan:', 'прочие агентские:', 'без Retry-After:']

_SCAN_OTHER_DROP = 'submitScan: drop_batch; прочие агентские: skip_request'
_SCAN_OTHER_REFRESH = 'submitScan: drop_batch + refresh_configuration; прочие агентские: skip_request'
# code, HTTP status, agent action ('—' for portal-only codes)
PROBLEM_CODES = [
    ('invalid_json', 400, _SCAN_OTHER_DROP),
    ('unsupported_media_type', 415, _SCAN_OTHER_DROP),
    ('payload_too_large', 413, _SCAN_OTHER_DROP),
    ('schema_violation', 422, _SCAN_OTHER_REFRESH),
    ('unsupported_schema_version', 422, 'drop_batch + refresh_configuration'),
    ('unknown_check_id', 422, 'drop_batch + refresh_configuration'),
    ('unexpected_subject', 422, 'drop_batch + refresh_configuration'),
    ('duplicate_observation', 422, 'drop_batch'),
    ('unknown_policy_version', 422, 'drop_batch + refresh_configuration'),
    ('batch_too_old', 422, 'drop_batch'),
    ('batch_time_inconsistent', 422, 'drop_batch'),
    ('agent_version_unsupported', 422, 'stop_until_upgrade'),
    ('idempotency_conflict', 409, 'submitScan: drop_batch'),
    ('sequence_conflict', 409, 'resync_sequence'),
    ('identity_conflict', 409, 'identity_stop'),
    ('organization_inactive', 403, 'suspend_until_active'),
    ('certificate_expired', 401, 'reenroll_required'),
    ('certificate_revoked', 401, 'stop_until_reinstall'),
    ('certificate_unknown', 401, 'trust_failure'),
    ('renewal_request_conflict', 409, 'restart_renewal'),
    ('enrollment_token_invalid', 401, 'await_new_token'),
    ('installation_already_enrolled', 409, 'stop_until_reinstall'),
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
    ('resource_not_ready', 409, '—'),
    ('validation_failed', 422, '—'),
    ('policy_inputs_missing', 422, '—'),
]
PROBLEM_HTTP = {code: status for code, status, _ in PROBLEM_CODES}
# Codes that invariants.json does not need to cover (generic transport throttling).
UNCOVERED_CODES = ['rate_limited', 'temporarily_unavailable']

COLLECTOR_REASONS = ['permission_denied', 'unsupported', 'collector_timeout', 'temporary_error']
REASON_CODES = COLLECTOR_REASONS + [
    'missing_observation', 'clock_inconsistent', 'unmapped_state', 'update_search_failed',
    'update_search_outdated', 'update_source_mismatch', 'update_list_truncated',
    'os_version_unknown', 'os_inventory_missing', 'applicability_input_missing',
    'policy_not_applicable', 'evidence_time_invalid',
]
# reasonCode values allowed for an informational assessment (result=null) when data is missing.
INFORMATIONAL_REASONS = COLLECTOR_REASONS + ['missing_observation', 'clock_inconsistent',
                                             'applicability_input_missing']
RESULTS = ['pass', 'fail', 'unknown', 'not_applicable']

EVENT_CAUSES = ['device_change', 'rule_change', 'policy_change', 'applicability_change', 'data_quality',
                'manual_action', 'review_expired']
_TRIGGERS = ['device_change', 'rule_change', 'policy_change']
# eventType -> (allowed causes, assessmentId: 'required' | 'nullable' | 'null')
EVENT_TABLE = {
    'opened': (_TRIGGERS, 'required'),
    # applicability_change: not_applicable from device facts of the batch without a policy_revision change.
    'resolved': (_TRIGGERS + ['applicability_change'], 'required'),
    'reopened': (_TRIGGERS, 'required'),
    'quality_changed': (['data_quality'], 'nullable'),
    'workflow_changed': (['manual_action', 'review_expired'], 'null'),
    'policy_changed': (['policy_change'], 'nullable'),
    'object_retired': (['device_change', 'manual_action'], 'null'),
}
WORKFLOW_STATES = ['new', 'in_progress', 'risk_accepted', 'suppressed']
CAPABILITY_STATUSES = ['permission_missing', 'license_unconfirmed', 'partial']
ENFORCEMENTS = ['schema', 'agent_api', 'portal_api', 'worker', 'db_rls', 'agent', 'infra']
REPLAY_STATUSES = [200, 202, 204]

READ_ROLES = ['PlatformAdmin', 'ServiceManager', 'Technician']
MANAGE_ROLES = ['PlatformAdmin', 'ServiceManager']
PLATFORM_ROLES = ['PlatformAdmin']
LANGUAGES = ['nb', 'nn', 'en']
ACCEPT_LANGUAGE_MAX = 35
# Portal GET operations whose every read writes audit_event for any role.
AUDIT_ALWAYS = ['downloadOrganizationExport', 'listAuditEvents', 'downloadReport']
# Operations accepting Accept-Language and answering with Content-Language.
LOCALIZED_OPERATIONS = ['listDeviceAssessments', 'listFindings', 'getFinding', 'patchFinding',
                        'decideFindingRisk']
# Portal GET operations that may answer 409 (resource not ready).
DOWNLOAD_OPERATIONS = ['downloadReport', 'downloadOrganizationExport']
