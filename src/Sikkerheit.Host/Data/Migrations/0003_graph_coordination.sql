-- Shared Graph quotas/cooldowns are platform operational state, without evidence, tokens or request paths.
create table graph_rate_window (
    bucket text primary key,
    hits timestamptz[] not null default '{}',
    blocked_until timestamptz not null default '-infinity',
    expires_at timestamptz not null
);
create index graph_rate_window_expiry on graph_rate_window (expires_at);
grant select, insert, update, delete on graph_rate_window to {{app_role}};

-- Admission checks active leases before capturing jobs; no change to existing migration checksums.
create index job_active_leases on job (type, lease_until, organization_id) where state = 'running';
