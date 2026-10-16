#!/usr/bin/env bash
# Local PostgreSQL 17 for development: roles as in production (owner migrates, the app role has no BYPASSRLS).
set -euo pipefail
name=sikkerheit-dev-pg
if ! docker ps --format '{{.Names}}' | grep -qx "$name"; then
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" -e POSTGRES_PASSWORD=postgres -p 55432:5432 postgres:17-alpine >/dev/null
fi
until docker exec "$name" pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
docker exec -i "$name" psql -v ON_ERROR_STOP=1 -U postgres <<'SQL'
select 'create role sikkerheit_owner login password ''owner-dev''' where not exists (select 1 from pg_roles where rolname = 'sikkerheit_owner') \gexec
select 'create role sikkerheit_app login password ''app-dev'' nobypassrls' where not exists (select 1 from pg_roles where rolname = 'sikkerheit_app') \gexec
select 'create database sikkerheit owner sikkerheit_owner' where not exists (select 1 from pg_database where datname = 'sikkerheit') \gexec
SQL
echo "PostgreSQL is ready on localhost:55432 (database sikkerheit)."
