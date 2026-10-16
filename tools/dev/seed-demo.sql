-- Demo data for local development only: synthetic tenants, users and results. Run as the postgres superuser after
-- seed-demo.sh created the organizations through the API (policy v1 comes from the service).
\set ON_ERROR_STOP on

create function pg_temp.caps(conditional text) returns jsonb language sql as $$
  select jsonb_agg(jsonb_build_object('module', m, 'status',
           case when m = 'conditional_access' then conditional when m = 'sign_in_activity' then 'skipped' else 'available' end))
  from unnest(array['tenant','licenses','users','auth_methods','roles','security_defaults','conditional_access',
                    'authorization_policy','sign_in_activity','per_user_mfa']) m
$$;

create function pg_temp.subject(org uuid, kind text, key text, name text) returns uuid language plpgsql as $$
declare id uuid := gen_random_uuid();
begin
  insert into subject (organization_id, id, type, key, display_name, first_seen_at, last_seen_at)
  values (org, id, kind, key, name, now() - interval '30 days', now() - interval '3 hours');
  return id;
end $$;

-- An assessment with its observation in the latest run: evidence for «collected», a reason for «unavailable».
create function pg_temp.assess(org uuid, subj uuid, check_id text, mode text, result text, severity text, reason text,
                               observed timestamptz, explanation text, arguments jsonb default null,
                               evidence jsonb default null) returns uuid language plpgsql as $$
declare
  id uuid := gen_random_uuid();
  observation uuid;
begin
  if evidence is not null or reason is not null then
    observation := gen_random_uuid();
    insert into observation (organization_id, id, subject_id, check_id, source, collection_run_id, observed_at, received_at,
                             collection_status, evidence, reason_code)
    values (org, observation, subj, check_id, 'graph',
            (select r.id from collection_run r where r.organization_id = org and r.state in ('completed', 'partial')
             order by r.completed_at desc limit 1),
            observed, observed, case when evidence is null then 'unavailable' else 'collected' end, evidence,
            case when evidence is null then reason end);
  end if;
  insert into assessment (organization_id, id, observation_id, subject_id, check_id, rule_id, rule_version,
                          source_policy_version, evaluated_policy_version, assessment_scope, assessment_mode, result,
                          severity, reason_code, observed_at, received_at, evaluated_at, basis_snapshot)
  values (org, id, observation, subj, check_id, check_id, '1.0.0', 1, 1, 'current', mode, result, severity, reason,
          observed, observed, observed,
          jsonb_build_object('checkId', check_id, 'ruleId', check_id, 'ruleVersion', '1.0.0',
            'evaluatedPolicyVersion', 1, 'assessmentMode', mode, 'result', result, 'severity', severity,
            'reasonCode', reason, 'observedAt', observed, 'explanation', explanation, 'arguments', arguments));
  return id;
end $$;

create function pg_temp.member(methods text[]) returns jsonb language sql as $$
  select jsonb_build_object('accountEnabled', true, 'userType', 'Member', 'directorySyncAccount', false,
                            'methodKinds', to_jsonb(methods))
$$;

create function pg_temp.admin(methods text[]) returns jsonb language sql as $$
  select jsonb_build_object('accountEnabled', true, 'userType', 'Member', 'assignment', 'direct',
                            'roleTemplateIds', jsonb_build_array('62e90394-69f5-4237-9190-012177145e10'),
                            'methodKinds', to_jsonb(methods))
$$;

create function pg_temp.finding(org uuid, subj uuid, check_id text, severity text, workflow text, opened timestamptz,
                                assessment uuid, resolved timestamptz default null) returns uuid language plpgsql as $$
declare id uuid := gen_random_uuid();
begin
  insert into finding (organization_id, id, subject_id, check_id, technical_state, workflow_state, assessment_result,
                       severity, quality, latest_assessment_id, latest_observed_at, opened_at, resolved_at)
  values (org, id, subj, check_id, case when resolved is null then 'open' else 'resolved' end, workflow,
          case when resolved is null then 'fail' else 'pass' end, severity, 'fresh_fail', assessment,
          now() - interval '3 hours', opened, resolved);
  insert into finding_event (organization_id, finding_id, id, event_type, cause, assessment_id, occurred_at)
  values (org, id, gen_random_uuid(), 'opened', 'source_change', assessment, opened);
  if resolved is not null then
    insert into finding_event (organization_id, finding_id, id, event_type, cause, assessment_id, occurred_at)
    values (org, id, gen_random_uuid(), 'resolved', 'source_change', assessment, resolved);
  end if;
  return id;
end $$;

do $$
declare
  fjord uuid := (select id from organization where name = 'Fjord Regnskap AS');
  nordlys uuid := (select id from organization where name = 'Nordlys Tannklinikk AS');
  vestland uuid := (select id from organization where name = 'Vestland Bygg AS');
  observed timestamptz := now() - interval '3 hours';
  tenant uuid; u uuid; a uuid; f uuid; e uuid; day int;
begin
  if fjord is null or nordlys is null or vestland is null then
    raise exception 'Run seed-demo.sh: the organizations must exist first';
  end if;

  -- Fjord Regnskap AS: Entra ID P1, only a report-only Conditional Access policy requires MFA.
  update tenant_connection set status = 'active', entra_tenant_id = 'a1f3c0de-0000-4000-8000-00000000f001',
      tenant_display_name = 'Fjord Regnskap AS', primary_domain = 'fjordregnskap.no', entra_p1 = true,
      connected_at = now() - interval '30 days', last_collected_at = observed, last_collection_state = 'completed',
      capabilities = pg_temp.caps('available')
  where organization_id = fjord;
  for day in 0..6 loop
    insert into collection_run (organization_id, id, trigger, state, queued_at, started_at, completed_at, capabilities,
                                users_complete, entra_p1, policy_version)
    values (fjord, gen_random_uuid(), 'scheduled', 'completed', observed - make_interval(days => day),
            observed - make_interval(days => day), observed - make_interval(days => day) + interval '2 minutes',
            pg_temp.caps('available'), true, true, 1);
  end loop;
  tenant := pg_temp.subject(fjord, 'tenant', 'a1f3c0de-0000-4000-8000-00000000f001', 'Fjord Regnskap AS');
  a := pg_temp.assess(fjord, tenant, 'M365-003', 'assessed', 'fail', 'critical', null, observed, 'm365-003.fail', null,
    jsonb_build_object('securityDefaults', 'disabled', 'conditionalAccess', 'available', 'perUserMfa',
      jsonb_build_object('required', 0, 'notRequired', 5, 'unknown', 0),
      'mfaPolicies', jsonb_build_array(jsonb_build_object('policyId', '5f0b0c1e-0000-4000-8000-0000000000aa',
        'state', 'enabledForReportingButNotEnforced', 'allUsers', true, 'allApplications', true, 'excludedApplications', 0,
        'conditions', '[]'::jsonb, 'excludedUsersOutsidePolicy', 0, 'unresolvedExclusions', 0, 'allClientAppTypes', true,
        'grantOperator', 'OR', 'grantControls', jsonb_build_array('mfa'), 'authStrengthRequiresMfa', null))));
  perform pg_temp.finding(fjord, tenant, 'M365-003', 'critical', 'new', now() - interval '12 days', a);
  a := pg_temp.assess(fjord, tenant, 'M365-004', 'informational', null, null, null, observed, 'm365-004.fail', null,
    jsonb_build_object('securityDefaults', 'disabled', 'conditionalAccess', 'available', 'legacyBlockPolicies', '[]'::jsonb));
  a := pg_temp.assess(fjord, tenant, 'M365-005', 'assessed', 'pass', null, null, observed, 'm365-005.pass', '{"count":"2"}',
    jsonb_build_object('globalAdminUserIds', jsonb_build_array('b0000000-0000-4000-8000-0000000f0001', 'b0000000-0000-4000-8000-0000000f0002'),
      'disabledGlobalAdminUserIds', '[]'::jsonb, 'unresolvedGroupAssignments', 0));
  a := pg_temp.assess(fjord, tenant, 'M365-006', 'assessed', 'fail', 'warning', null, observed, 'm365-006.fail.legacy',
                      '{"policies":"ManagePermissionGrantsForSelf.microsoft-user-default-legacy"}',
                      jsonb_build_object('permissionGrantPolicies', jsonb_build_array('ManagePermissionGrantsForSelf.microsoft-user-default-legacy')));
  f := pg_temp.finding(fjord, tenant, 'M365-006', 'warning', 'risk_accepted', now() - interval '20 days', a);
  e := gen_random_uuid();
  insert into finding_event (organization_id, finding_id, id, event_type, cause, actor_id, from_workflow_state,
                             to_workflow_state, occurred_at)
  values (fjord, f, e, 'workflow_changed', 'manual_action', '00000000-0000-4000-8000-000000000001', 'new', 'risk_accepted',
          now() - interval '18 days');
  insert into risk_decision (organization_id, id, finding_id, decision, reason, review_at, decided_by, decided_at, finding_event_id)
  values (fjord, gen_random_uuid(), f, 'risk_accepted', 'Regnskapssystemet krever brukersamtykke til integrasjonen til mars.',
          now() + interval '150 days', '00000000-0000-4000-8000-000000000001', now() - interval '18 days', e);
  update finding set workflow_reason = 'Regnskapssystemet krever brukersamtykke til integrasjonen til mars.',
      review_at = now() + interval '150 days', workflow_decided_by = '00000000-0000-4000-8000-000000000001'
  where organization_id = fjord and id = f;

  u := pg_temp.subject(fjord, 'user', 'b0000000-0000-4000-8000-0000000f0001', 'ola.nordmann@fjordregnskap.no');
  a := pg_temp.assess(fjord, u, 'M365-001', 'assessed', 'pass', null, null, observed, 'm365-001.pass', '{"methods":"microsoft_authenticator"}', pg_temp.member(array['microsoft_authenticator']::text[]));
  a := pg_temp.assess(fjord, u, 'M365-002', 'assessed', 'pass', null, null, observed, 'm365-002.pass', '{"methods":"fido2"}', pg_temp.admin(array['fido2']::text[]));
  u := pg_temp.subject(fjord, 'user', 'b0000000-0000-4000-8000-0000000f0002', 'kari.admin@fjordregnskap.no');
  a := pg_temp.assess(fjord, u, 'M365-001', 'assessed', 'fail', 'warning', null, observed, 'm365-001.fail', '{"methods":"password"}', pg_temp.member(array['password']::text[]));
  perform pg_temp.finding(fjord, u, 'M365-001', 'warning', 'in_progress', now() - interval '5 days', a);
  a := pg_temp.assess(fjord, u, 'M365-002', 'assessed', 'fail', 'critical', null, observed, 'm365-002.fail', '{"methods":"password"}', pg_temp.admin(array['password']::text[]));
  f := pg_temp.finding(fjord, u, 'M365-002', 'critical', 'in_progress', now() - interval '5 days', a);
  update finding set assignee_id = '00000000-0000-4000-8000-000000000002', due_at = now() + interval '2 days'
  where organization_id = fjord and id = f;
  u := pg_temp.subject(fjord, 'user', 'b0000000-0000-4000-8000-0000000f0003', 'per.hansen@fjordregnskap.no');
  a := pg_temp.assess(fjord, u, 'M365-001', 'assessed', 'fail', 'warning', null, observed, 'm365-001.fail', '{"methods":"password, email"}', pg_temp.member(array['password', 'email']::text[]));
  perform pg_temp.finding(fjord, u, 'M365-001', 'warning', 'new', now() - interval '2 days', a);
  u := pg_temp.subject(fjord, 'user', 'b0000000-0000-4000-8000-0000000f0004', 'lise.berg@fjordregnskap.no');
  a := pg_temp.assess(fjord, u, 'M365-001', 'assessed', 'pass', null, null, observed, 'm365-001.pass', '{"methods":"microsoft_authenticator"}', pg_temp.member(array['microsoft_authenticator']::text[]));
  perform pg_temp.finding(fjord, u, 'M365-001', 'warning', 'new', now() - interval '9 days', a, now() - interval '4 days');
  u := pg_temp.subject(fjord, 'user', 'b0000000-0000-4000-8000-0000000f0005', 'nodtilgang@fjordregnskap.onmicrosoft.com');
  a := pg_temp.assess(fjord, u, 'M365-001', 'assessed', 'unknown', null, 'temporary_error', observed, 'm365-001.fail');

  -- Nordlys Tannklinikk AS: Microsoft 365 Business Standard without P1, Security Defaults on.
  update tenant_connection set status = 'active', entra_tenant_id = 'a1f3c0de-0000-4000-8000-00000000a002',
      tenant_display_name = 'Nordlys Tannklinikk', primary_domain = 'nordlystann.no', entra_p1 = false,
      connected_at = now() - interval '14 days', last_collected_at = observed, last_collection_state = 'partial',
      capabilities = pg_temp.caps('license_missing')
  where organization_id = nordlys;
  for day in 0..6 loop
    insert into collection_run (organization_id, id, trigger, state, queued_at, started_at, completed_at, capabilities,
                                users_complete, entra_p1, policy_version)
    values (nordlys, gen_random_uuid(), case when day = 2 then 'manual' else 'scheduled' end,
            case when day = 4 then 'failed' else 'partial' end, observed - make_interval(days => day),
            observed - make_interval(days => day), observed - make_interval(days => day) + interval '1 minute',
            pg_temp.caps('license_missing'), day <> 4, false, 1);
  end loop;
  update collection_run set failure_code = 'temporary_error' where organization_id = nordlys and state = 'failed';
  tenant := pg_temp.subject(nordlys, 'tenant', 'a1f3c0de-0000-4000-8000-00000000a002', 'Nordlys Tannklinikk');
  a := pg_temp.assess(nordlys, tenant, 'M365-003', 'assessed', 'pass', null, null, observed, 'm365-003.pass.security_defaults', null,
    jsonb_build_object('securityDefaults', 'enabled', 'conditionalAccess', 'license_missing', 'mfaPolicies', '[]'::jsonb, 'perUserMfa', null));
  a := pg_temp.assess(nordlys, tenant, 'M365-004', 'informational', null, null, null, observed, 'm365-004.pass.security_defaults', null,
    jsonb_build_object('securityDefaults', 'enabled', 'conditionalAccess', 'license_missing', 'legacyBlockPolicies', '[]'::jsonb));
  a := pg_temp.assess(nordlys, tenant, 'M365-005', 'assessed', 'fail', 'warning', null, observed, 'm365-005.fail.too_few', '{"count":"1"}',
    jsonb_build_object('globalAdminUserIds', jsonb_build_array('c0000000-0000-4000-8000-00000000a002'),
      'disabledGlobalAdminUserIds', '[]'::jsonb, 'unresolvedGroupAssignments', 0));
  perform pg_temp.finding(nordlys, tenant, 'M365-005', 'warning', 'new', now() - interval '14 days', a);
  a := pg_temp.assess(nordlys, tenant, 'M365-006', 'assessed', 'pass', null, null, observed, 'm365-006.pass.disabled', null,
    jsonb_build_object('permissionGrantPolicies', '[]'::jsonb));
  u := pg_temp.subject(nordlys, 'user', 'c0000000-0000-4000-8000-00000000a001', 'resepsjon@nordlystann.no');
  a := pg_temp.assess(nordlys, u, 'M365-001', 'assessed', 'fail', 'warning', null, observed, 'm365-001.fail', '{"methods":"password"}', pg_temp.member(array['password']::text[]));
  perform pg_temp.finding(nordlys, u, 'M365-001', 'warning', 'new', now() - interval '1 days', a);
  u := pg_temp.subject(nordlys, 'user', 'c0000000-0000-4000-8000-00000000a002', 'tannlege@nordlystann.no');
  a := pg_temp.assess(nordlys, u, 'M365-001', 'assessed', 'pass', null, null, observed, 'm365-001.pass', '{"methods":"microsoft_authenticator"}', pg_temp.member(array['microsoft_authenticator']::text[]));
  a := pg_temp.assess(nordlys, u, 'M365-002', 'assessed', 'pass', null, null, observed, 'm365-002.pass', '{"methods":"microsoft_authenticator"}', pg_temp.admin(array['microsoft_authenticator']::text[]));

  -- Vestland Bygg AS: consent link sent, not granted yet.
  update tenant_connection set status = 'consent_pending', pending_tenant_id = 'a1f3c0de-0000-4000-8000-00000000b003',
      pending_expires_at = now() + interval '6 days'
  where organization_id = vestland;
end $$;

insert into staff_user (entra_user_id, display_name, roles, last_sign_in_at)
values ('00000000-0000-4000-8000-000000000002', 'Dev Technician', array['Technician'], now() - interval '1 day')
on conflict (entra_user_id) do nothing;
