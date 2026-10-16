#!/usr/bin/env bash
# Creates three demo customers through the API (development sign-in), then fills synthetic M365 data with SQL.
set -euo pipefail
api="${API:-http://localhost:5080}"
here="$(cd "$(dirname "$0")" && pwd)"
jar="$(mktemp)"
trap 'rm -f "$jar"' EXIT
csrf="$(curl -sf -c "$jar" -H 'Content-Type: application/json' \
  -d '{"entraUserId":"00000000-0000-4000-8000-000000000001","displayName":"Dev Admin","roles":["Admin"]}' \
  "$api/auth/dev/login" | python3 -c 'import json,sys; print(json.load(sys.stdin)["csrfToken"])')"
for name in "Fjord Regnskap AS" "Nordlys Tannklinikk AS" "Vestland Bygg AS"; do
  curl -sf -b "$jar" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' \
    -d "{\"name\":\"$name\",\"timezone\":\"Europe/Oslo\",\"reportLanguage\":\"nb\"}" "$api/api/v1/organizations" >/dev/null
done
docker exec -i sikkerheit-dev-pg psql -q -U postgres -d sikkerheit < "$here/seed-demo.sql"
echo "Demo data is ready."
