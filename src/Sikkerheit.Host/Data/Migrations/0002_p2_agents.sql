-- P2 schema: enrollment keys, devices and their identity, agent sessions and challenges, scan batches and requests, the
-- Windows release catalog (05 «Сущности и ограничения»). Client tables follow the row-level security of 0001;
-- agent_challenge, agent_session, windows_release and windows_release_month are platform tables without client scope.

-- Platform tables.

-- Redeemed nonces only: issuing a nonce writes nothing (05 «Регистрация и сессия»).
create table agent_challenge (
    nonce_hash text primary key,
    purpose text not null check (purpose in ('enroll', 'session')),
    device_id uuid,
    expires_at timestamptz not null,
    used_at timestamptz not null
);
create index agent_challenge_expires on agent_challenge (expires_at);

-- SHA-256 of the session token; the organization is where the token belongs (05 «Регистрация и сессия»).
create table agent_session (
    token_hash text primary key,
    organization_id uuid not null,
    device_id uuid not null,
    expires_at timestamptz not null
);
create index agent_session_device on agent_session (device_id);
create index agent_session_expires on agent_session (expires_at);

create table windows_release (
    product text not null check (product in ('client')),
    branch_build integer not null,
    ubr integer not null,
    kb text not null,
    release_at timestamptz not null,
    kind text not null check (kind in ('security_monthly', 'security_oob', 'nonsecurity_oob', 'preview', 'hotpatch')),
    security_month text check (security_month ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
    -- The month of the catalog the entry was imported for: verifyWindowsReleaseMonth puts its entries into effect.
    catalog_month text not null check (catalog_month ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
    auto_offered boolean not null,
    state text not null check (state in ('draft', 'verified')),
    source text not null check (source in ('msrc_cvrf', 'manual')),
    imported_by uuid not null,
    imported_at timestamptz not null,
    primary key (product, branch_build, ubr)
);
create index windows_release_month_idx on windows_release (catalog_month);

create table windows_release_month (
    security_month text primary key check (security_month ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
    state text not null check (state in ('draft', 'verified')),
    verified_at timestamptz,
    verified_by uuid,
    no_new_releases boolean not null default false,
    constraint windows_release_month_verified check ((state = 'verified') = (verified_at is not null))
);

-- Client tables.

create table enrollment_key (
    organization_id uuid not null references organization (id),
    id uuid not null,
    key_hash text not null,
    key_prefix text not null,
    label text not null,
    created_at timestamptz not null,
    created_by uuid not null,
    revoked_at timestamptz,
    last_used_at timestamptz,
    primary key (organization_id, id)
);
create unique index enrollment_key_hash on enrollment_key (key_hash);

create table device (
    organization_id uuid not null references organization (id),
    id uuid not null,
    display_name text not null,
    status text not null default 'active' check (status in ('active', 'revoked')),
    installation_id uuid not null,
    machine_fingerprint_hash text not null,
    public_key_jwk jsonb not null,
    key_thumbprint text not null,
    key_protection text not null check (key_protection in ('tpm', 'software')),
    identity_state text not null default 'ok' check (identity_state in ('ok', 'identity_conflict')),
    identity_conflict_at timestamptz,
    conflict_kind text check (conflict_kind in ('fingerprint', 'key')),
    conflict_fingerprint_hash text,
    conflict_public_key_jwk jsonb,
    conflict_display_name text,
    clock_status text not null default 'ok' check (clock_status in ('ok', 'inconsistent')),
    enrollment_key_id uuid,
    enrolled_at timestamptz not null,
    revoked_at timestamptz,
    last_seen_at timestamptz,
    last_full_scan_at timestamptz,
    last_accepted_sequence bigint not null default 0,
    projection_sequence bigint,
    projection_completed_at timestamptz,
    agent_version text,
    config_schema_version integer,
    telemetry jsonb not null default '{}'::jsonb,
    reboot_episode_since timestamptz,
    reboot_episode_boot_at timestamptz,
    primary key (organization_id, id),
    unique (organization_id, installation_id),
    foreign key (organization_id, enrollment_key_id) references enrollment_key (organization_id, id)
        on delete set null (enrollment_key_id),
    constraint device_conflict check ((identity_state = 'identity_conflict') = (identity_conflict_at is not null))
);
-- The key of a device is unique inside its organization; a key shared with another organization (a PC moved between
-- customers, an agent installed again with the same software key) must not turn a registration into an error.
create unique index device_key_thumbprint on device (organization_id, key_thumbprint);
create index device_status on device (organization_id, status);

-- Unique(deviceId, day): a UTC day with a check-in or an accepted batch.
create table device_presence (
    organization_id uuid not null,
    device_id uuid not null,
    day date not null,
    primary key (organization_id, device_id, day),
    foreign key (organization_id, device_id) references device (organization_id, id)
);

create table revoked_installation (
    organization_id uuid not null references organization (id),
    installation_id uuid not null,
    key_thumbprint text,
    device_id uuid,
    revoked_at timestamptz not null,
    source text not null check (source in ('revoke', 'restore_replay')),
    primary key (organization_id, installation_id)
);

create table enrollment (
    organization_id uuid not null,
    id uuid not null,
    registration_request_id uuid not null,
    enrollment_key_id uuid not null,
    device_id uuid not null,
    request_hash text not null,
    response jsonb not null,
    created_at timestamptz not null,
    primary key (organization_id, id),
    unique (organization_id, registration_request_id),
    foreign key (organization_id, enrollment_key_id) references enrollment_key (organization_id, id),
    foreign key (organization_id, device_id) references device (organization_id, id)
);

create table scan_batch (
    organization_id uuid not null,
    device_id uuid not null,
    id uuid not null,
    scan_id uuid not null,
    sequence bigint not null,
    policy_version integer not null,
    started_at timestamptz not null,
    completed_at timestamptz not null,
    sent_at timestamptz not null,
    received_at timestamptz not null,
    payload_hash text not null,
    clock_inconsistent boolean not null,
    is_full boolean not null,
    -- The batch replaced the current projection of the device (05 «Выбор текущего состояния», step 5).
    replaced_projection boolean not null,
    primary key (organization_id, id),
    unique (device_id, scan_id),
    unique (device_id, sequence),
    foreign key (organization_id, device_id) references device (organization_id, id)
);

create table scan_request (
    organization_id uuid not null,
    id uuid not null,
    device_id uuid not null,
    requested_by uuid not null,
    created_at timestamptz not null,
    expires_at timestamptz not null,
    state text not null check (state in ('requested', 'delivered', 'completed', 'expired')),
    primary key (organization_id, id),
    foreign key (organization_id, device_id) references device (organization_id, id)
);
-- At most one unfinished request per device.
create unique index scan_request_open on scan_request (device_id) where state in ('requested', 'delivered');

alter table observation add constraint observation_scan_batch
    foreign key (organization_id, scan_batch_id) references scan_batch (organization_id, id);

do $$
declare
    t text;
begin
    foreach t in array array['enrollment_key', 'device', 'device_presence', 'revoked_installation', 'enrollment',
                             'scan_batch', 'scan_request']
    loop
        execute format('alter table %I enable row level security', t);
        execute format('alter table %I force row level security', t);
        execute format('create policy %I on %I for select using (organization_id = app.scope_org() or app.scope_all())',
                       t || '_select', t);
        execute format('create policy %I on %I for insert with check (organization_id = app.scope_org())', t || '_insert', t);
        execute format('create policy %I on %I for update using (organization_id = app.scope_org()) with check (organization_id = app.scope_org())',
                       t || '_update', t);
        execute format('create policy %I on %I for delete using (organization_id = app.scope_org())', t || '_delete', t);
    end loop;
end $$;

-- Lookups by secret before the organization is known (02 «Разделение клиентов»): they return only the owning
-- organization and the id of the object. Each switches the read-all scope on for its own query only.
create function app.enrollment_key_owner(hash text) returns table (organization_id uuid, key_id uuid)
    language plpgsql volatile security definer
    set search_path = public, pg_temp
    as $$
declare
    previous text := coalesce(current_setting('app.scope_all', true), '');
begin
    perform set_config('app.scope_all', 'on', true);
    return query select k.organization_id, k.id from enrollment_key k where k.key_hash = hash;
    perform set_config('app.scope_all', previous, true);
end $$;

create function app.device_owner(device uuid) returns uuid
    language plpgsql volatile security definer
    set search_path = public, pg_temp
    as $$
declare
    previous text := coalesce(current_setting('app.scope_all', true), '');
    owner_id uuid;
begin
    perform set_config('app.scope_all', 'on', true);
    select d.organization_id into owner_id from device d where d.id = device;
    perform set_config('app.scope_all', previous, true);
    return owner_id;
end $$;

grant execute on function app.enrollment_key_owner(text), app.device_owner(uuid) to {{app_role}};
grant select, insert, update, delete on table agent_challenge, agent_session, windows_release, windows_release_month,
    enrollment_key, device, device_presence, revoked_installation, enrollment, scan_batch, scan_request to {{app_role}};
