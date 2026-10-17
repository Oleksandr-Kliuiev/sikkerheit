-- Shared portable settings, without customer-specific configuration. Versions are append-only.
create table policy_template (
    id uuid primary key,
    current_revision integer not null check (current_revision > 0)
);
create table policy_template_revision (
    template_id uuid not null references policy_template(id),
    revision integer not null check (revision > 0),
    name text not null check (length(name) between 1 and 80),
    description text not null check (length(description) <= 500),
    content jsonb not null,
    archived boolean not null,
    created_at timestamptz not null,
    created_by uuid not null,
    primary key (template_id, revision)
);
grant select, insert, update on policy_template to {{app_role}};
grant select, insert on policy_template_revision to {{app_role}};

-- Only receipts are stored: reviewed client configurations stay in policy_revision, within that client's RLS.
create table policy_template_application (
    organization_id uuid not null references organization(id),
    token_hash text not null,
    template_id uuid not null,
    template_revision integer not null,
    policy_version integer not null,
    applied_at timestamptz not null,
    applied_by uuid not null,
    primary key (organization_id, token_hash),
    foreign key (template_id, template_revision) references policy_template_revision(template_id, revision),
    foreign key (organization_id, policy_version) references policy_revision(organization_id, version) on delete cascade
);
alter table policy_template_application enable row level security;
alter table policy_template_application force row level security;
create policy policy_template_application_select on policy_template_application for select
    using (organization_id = app.scope_org() or app.scope_all());
create policy policy_template_application_insert on policy_template_application for insert
    with check (organization_id = app.scope_org());
create policy policy_template_application_delete on policy_template_application for delete
    using (organization_id = app.scope_org());
grant select, insert, delete on policy_template_application to {{app_role}};
