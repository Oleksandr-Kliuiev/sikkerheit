-- P1 core schema: organizations, staff, policy, M365 connection and collection, assessments, findings,
-- reports, exports, audit and jobs. Row-level security per 02 «Разделение клиентов»:
-- SELECT — own organization or the read-all scope; INSERT/UPDATE/DELETE — own organization only.
-- {{app_role}} is the application role; it owns nothing and has no BYPASSRLS.

create schema if not exists app;

-- Scope of the current transaction. set_config(..., true) lasts until the end of the transaction.
create function app.scope_org() returns uuid
    language sql stable
    as $$ select nullif(current_setting('app.scope_org', true), '')::uuid $$;

create function app.scope_all() returns boolean
    language sql stable
    as $$ select coalesce(current_setting('app.scope_all', true), '') = 'on' $$;

create function app.set_scope(org uuid) returns void
    language plpgsql volatile
    as $$
begin
    if org is null then
        raise exception 'scope organization is required';
    end if;
    perform set_config('app.scope_org', org::text, true);
    perform set_config('app.scope_all', 'off', true);
end $$;

-- The read-all scope is allowed only in a READ ONLY transaction.
create function app.set_scope_all() returns void
    language plpgsql volatile
    as $$
begin
    if current_setting('transaction_read_only') <> 'on' then
        raise exception 'read-all scope requires a READ ONLY transaction';
    end if;
    perform set_config('app.scope_org', '', true);
    perform set_config('app.scope_all', 'on', true);
end $$;

-- Platform tables (no client data, no RLS).

create table staff_user (
    entra_user_id uuid primary key,
    display_name text,
    roles text[] not null,
    last_sign_in_at timestamptz,
    last_refresh_ok boolean not null default true,
    created_at timestamptz not null default now(),
    constraint staff_user_roles check (roles <@ array['Admin', 'Technician', 'Reader']::text[] and cardinality(roles) >= 1)
);

-- Server-side staff session; the browser holds only the session id cookie (04 «Вход сотрудников и роли»).
create table staff_session (
    id_hash text primary key,
    entra_user_id uuid not null references staff_user (entra_user_id),
    roles text[] not null,
    csrf_token text not null,
    token_cache bytea,
    created_at timestamptz not null,
    last_seen_at timestamptz not null,
    refresh_due_at timestamptz not null,
    expires_at timestamptz not null
);
create index staff_session_expires on staff_session (expires_at);

create table organization_tombstone (
    id uuid primary key,
    deleted_at timestamptz not null
);

create table job (
    id uuid primary key,
    type text not null,
    organization_id uuid,
    input_id text,
    period_key text,
    state text not null default 'queued' check (state in ('queued', 'running', 'succeeded', 'failed')),
    lease_owner text,
    lease_token bigint not null default 0,
    lease_until timestamptz,
    attempts integer not null default 0,
    next_attempt_at timestamptz not null default now(),
    created_at timestamptz not null default now(),
    completed_at timestamptz,
    last_error text,
    constraint job_input_or_period check (input_id is not null or period_key is not null)
);
-- A sign-in attempt between /auth/login and /auth/callback: PKCE verifier and nonce stay on the server.
create table staff_login (
    state_hash text primary key,
    code_verifier text not null,
    nonce text not null,
    return_path text not null,
    expires_at timestamptz not null
);

-- Sent marks of the daily Teams digest: one message per period even when the job is repeated.
create table teams_digest (
    period_key text primary key,
    sent_at timestamptz not null
);

create unique index job_identity on job (type, organization_id, (coalesce(input_id, period_key))) nulls not distinct;
create index job_ready on job (state, next_attempt_at);

-- Client tables. Every row has organization_id; references between client tables are composite.

create table organization (
    id uuid primary key,
    name text not null,
    timezone text not null,
    report_language text not null check (report_language in ('nb', 'nn', 'en')),
    status text not null check (status in ('active', 'disabled', 'deletion_scheduled')),
    deletion_due_at timestamptz,
    disabled_at timestamptz,
    created_at timestamptz not null,
    next_policy_version integer not null default 2,
    constraint organization_deletion check ((status = 'deletion_scheduled') = (deletion_due_at is not null))
);

create table policy_revision (
    organization_id uuid not null references organization (id),
    version integer not null,
    effective_from timestamptz not null,
    created_at timestamptz not null,
    created_by uuid,
    configuration jsonb not null,
    primary key (organization_id, version)
);

create table tenant_connection (
    organization_id uuid primary key references organization (id),
    status text not null check (status in ('not_connected', 'consent_pending', 'active', 'disconnected')),
    entra_tenant_id uuid,
    tenant_display_name text,
    primary_domain text,
    pending_tenant_id uuid,
    pending_expires_at timestamptz,
    allow_company_tenant boolean not null default false,
    entra_p1 boolean,
    connected_at timestamptz,
    connected_by uuid,
    disconnected_at timestamptz,
    last_collected_at timestamptz,
    last_collection_state text check (last_collection_state in ('completed', 'partial', 'failed')),
    capabilities jsonb not null default '[]'::jsonb
);
create unique index tenant_connection_active_tenant on tenant_connection (entra_tenant_id) where status = 'active';

create table idempotency_record (
    organization_id uuid not null references organization (id),
    operation_id text not null,
    key uuid not null,
    request_hash text not null,
    response_status integer not null,
    result_id text,
    response_body text,
    created_at timestamptz not null,
    expires_at timestamptz not null,
    primary key (organization_id, operation_id, key)
);

create table collection_run (
    organization_id uuid not null references organization (id),
    id uuid not null,
    trigger text not null check (trigger in ('scheduled', 'manual')),
    state text not null check (state in ('queued', 'running', 'completed', 'partial', 'failed')),
    queued_at timestamptz not null,
    started_at timestamptz,
    completed_at timestamptz,
    failure_code text check (failure_code in ('consent_missing', 'tenant_mismatch', 'credential_error', 'cancelled',
                                              'run_timeout', 'temporary_error')),
    capabilities jsonb not null default '[]'::jsonb,
    users_complete boolean not null default false,
    entra_p1 boolean,
    policy_version integer,
    primary key (organization_id, id)
);
create unique index collection_run_one_open on collection_run (organization_id) where state in ('queued', 'running');

create table subject (
    organization_id uuid not null references organization (id),
    id uuid not null,
    type text not null check (type in ('tenant', 'user', 'device', 'volume')),
    key text not null,
    display_name text,
    device_id uuid,
    first_seen_at timestamptz not null,
    last_seen_at timestamptz not null,
    retired_at timestamptz,
    primary key (organization_id, id),
    unique (organization_id, type, key)
);

create table observation (
    organization_id uuid not null,
    id uuid not null,
    subject_id uuid not null,
    check_id text not null,
    source text not null check (source in ('agent', 'graph', 'server')),
    scan_batch_id uuid,
    collection_run_id uuid,
    input_observation_id uuid,
    observed_at timestamptz not null,
    received_at timestamptz not null,
    collection_status text not null check (collection_status in ('collected', 'unavailable')),
    evidence jsonb,
    reason_code text,
    primary key (organization_id, id),
    foreign key (organization_id, subject_id) references subject (organization_id, id),
    foreign key (organization_id, collection_run_id) references collection_run (organization_id, id),
    constraint observation_source check (
        (source = 'graph' and collection_run_id is not null and scan_batch_id is null)
        or (source = 'agent' and scan_batch_id is not null and collection_run_id is null)
        or (source = 'server' and scan_batch_id is null and collection_run_id is null)),
    constraint observation_status check (
        (collection_status = 'collected' and evidence is not null and reason_code is null)
        or (collection_status = 'unavailable' and evidence is null and reason_code is not null))
);
create index observation_subject_check on observation (organization_id, subject_id, check_id, observed_at);

create table assessment (
    organization_id uuid not null,
    id uuid not null,
    observation_id uuid,
    subject_id uuid not null,
    check_id text not null,
    rule_id text not null,
    rule_version text not null,
    source_policy_version integer not null,
    evaluated_policy_version integer not null,
    assessment_scope text not null check (assessment_scope in ('historical', 'current')),
    assessment_mode text not null check (assessment_mode in ('assessed', 'informational')),
    result text check (result in ('pass', 'fail', 'unknown', 'not_applicable')),
    severity text check (severity in ('critical', 'warning')),
    reason_code text,
    observed_at timestamptz not null,
    received_at timestamptz not null,
    evaluated_at timestamptz not null,
    basis_snapshot jsonb not null,
    evidence_availability text not null default 'available' check (evidence_availability in ('available', 'expired')),
    primary key (organization_id, id),
    foreign key (organization_id, subject_id) references subject (organization_id, id),
    foreign key (organization_id, observation_id) references observation (organization_id, id),
    constraint assessment_mode_result check (
        (assessment_mode = 'informational' and result is null and severity is null)
        or (assessment_mode = 'assessed' and result is not null)),
    constraint assessment_severity check ((result = 'fail') = (severity is not null))
);
create index assessment_subject_check on assessment (organization_id, subject_id, check_id, observed_at);

create table finding (
    organization_id uuid not null,
    id uuid not null,
    subject_id uuid not null,
    check_id text not null,
    technical_state text not null check (technical_state in ('open', 'resolved')),
    workflow_state text not null check (workflow_state in ('new', 'in_progress', 'risk_accepted', 'suppressed')),
    assessment_result text not null check (assessment_result in ('pass', 'fail', 'unknown', 'not_applicable')),
    severity text not null check (severity in ('critical', 'warning')),
    -- Last quality written as quality_changed: fresh_fail, unknown or stale (05 «Таблица переходов finding»).
    quality text not null default 'fresh_fail' check (quality in ('fresh_fail', 'unknown', 'stale')),
    latest_assessment_id uuid,
    latest_observed_at timestamptz,
    assignee_id uuid,
    due_at timestamptz,
    workflow_reason text,
    review_at timestamptz,
    workflow_decided_by uuid,
    revision integer not null default 1,
    opened_at timestamptz not null,
    resolved_at timestamptz,
    primary key (organization_id, id),
    unique (organization_id, subject_id, check_id),
    foreign key (organization_id, subject_id) references subject (organization_id, id)
);
create index finding_queue on finding (organization_id, technical_state, severity);

create table finding_event (
    organization_id uuid not null,
    finding_id uuid not null,
    id uuid not null,
    event_type text not null check (event_type in ('opened', 'resolved', 'reopened', 'quality_changed',
                                                   'workflow_changed', 'policy_changed', 'subject_retired')),
    cause text not null check (cause in ('source_change', 'rule_change', 'policy_change', 'applicability_change',
                                         'data_quality', 'manual_action', 'review_expired')),
    assessment_id uuid,
    actor_id uuid,
    from_workflow_state text,
    to_workflow_state text,
    occurred_at timestamptz not null,
    primary key (organization_id, id),
    foreign key (organization_id, finding_id) references finding (organization_id, id),
    constraint finding_event_actor check ((cause = 'manual_action') = (actor_id is not null))
);
create index finding_event_finding on finding_event (organization_id, finding_id, occurred_at);

-- Immutable record of every risk decision: the reason and review date stay explainable after later changes.
create table risk_decision (
    organization_id uuid not null,
    id uuid not null,
    finding_id uuid not null,
    decision text not null check (decision in ('risk_accepted', 'suppressed', 'withdrawn')),
    reason text,
    review_at timestamptz,
    decided_by uuid not null,
    decided_at timestamptz not null,
    finding_event_id uuid not null,
    primary key (organization_id, id),
    foreign key (organization_id, finding_id) references finding (organization_id, id),
    foreign key (organization_id, finding_event_id) references finding_event (organization_id, id)
);

create table report (
    organization_id uuid not null references organization (id),
    id uuid not null,
    period_start timestamptz not null,
    period_end timestamptz not null,
    timezone text not null,
    language text not null check (language in ('nb', 'nn', 'en')),
    format text not null default 'html' check (format = 'html'),
    state text not null check (state in ('queued', 'ready', 'failed')),
    failure_code text check (failure_code in ('translation_missing', 'generation_error')),
    blob_key text,
    policy_versions integer[] not null default '{}',
    snapshot jsonb,
    created_at timestamptz not null,
    created_by uuid,
    primary key (organization_id, id),
    unique (organization_id, period_start, language),
    constraint report_ready check (state <> 'ready' or (snapshot is not null and blob_key is not null))
);

-- A ready report keeps its snapshot forever (immutable report basis); only deletion removes it.
create function app.report_ready_immutable() returns trigger
    language plpgsql
    as $$
begin
    if old.state = 'ready' then
        raise exception 'report % is ready and immutable', old.id using errcode = 'P0001';
    end if;
    return new;
end $$;
create trigger report_ready_immutable before update on report
    for each row execute function app.report_ready_immutable();

create table organization_export (
    organization_id uuid not null references organization (id),
    id uuid not null,
    state text not null check (state in ('queued', 'ready', 'failed', 'expired')),
    blob_key text,
    created_at timestamptz not null,
    expires_at timestamptz,
    requested_by uuid not null,
    primary key (organization_id, id)
);

create table audit_event (
    organization_id uuid not null references organization (id),
    id uuid not null,
    occurred_at timestamptz not null,
    actor_type text not null check (actor_type in ('staff', 'device', 'system')),
    actor_id uuid,
    action text not null,
    target_type text not null,
    target_id text not null,
    outcome text not null check (outcome in ('success', 'denied', 'failed')),
    correlation_id text not null,
    details jsonb,
    primary key (organization_id, id)
);
create index audit_event_time on audit_event (organization_id, occurred_at desc);

-- Row-level security on every client table.
do $$
declare
    t text;
    org_column text;
begin
    foreach t in array array['organization', 'policy_revision', 'tenant_connection', 'idempotency_record',
                             'collection_run', 'subject', 'observation', 'assessment', 'finding', 'finding_event',
                             'risk_decision', 'report', 'organization_export', 'audit_event']
    loop
        org_column := case when t = 'organization' then 'id' else 'organization_id' end;
        execute format('alter table %I enable row level security', t);
        execute format('alter table %I force row level security', t);
        execute format('create policy %I on %I for select using (%I = app.scope_org() or app.scope_all())',
                       t || '_select', t, org_column);
        execute format('create policy %I on %I for insert with check (%I = app.scope_org())',
                       t || '_insert', t, org_column);
        execute format('create policy %I on %I for update using (%I = app.scope_org()) with check (%I = app.scope_org())',
                       t || '_update', t, org_column, org_column);
        execute format('create policy %I on %I for delete using (%I = app.scope_org())',
                       t || '_delete', t, org_column);
    end loop;
end $$;

-- Lookup by secret before the organization is known: returns only the owning organization of an active tenant.
-- The lookup switches the read-all scope on only for its own query and restores the caller's value.
create function app.active_tenant_owner(tenant uuid) returns uuid
    language plpgsql volatile security definer
    set search_path = public, pg_temp
    as $$
declare
    previous text := coalesce(current_setting('app.scope_all', true), '');
    owner_id uuid;
begin
    perform set_config('app.scope_all', 'on', true);
    select organization_id into owner_id from tenant_connection where entra_tenant_id = tenant and status = 'active';
    perform set_config('app.scope_all', previous, true);
    return owner_id;
end $$;

grant usage on schema app to {{app_role}};
grant execute on all functions in schema app to {{app_role}};
grant select, insert, update, delete on all tables in schema public to {{app_role}};
revoke all on table schema_migrations from {{app_role}};
-- Append-only history: events, risk decisions and audit are never rewritten, only deleted with their organization.
revoke update on table finding_event, risk_decision, audit_event from {{app_role}};
