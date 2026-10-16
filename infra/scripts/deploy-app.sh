#!/usr/bin/env bash
# Builds the portal and the service and deploys through the staging slot (06 «Окружения и развёртывание»):
# publish to staging → expand migrations at its start → smoke tests → swap → stop staging.
#
#   infra/scripts/deploy-app.sh prod
set -euo pipefail

env="${1:-prod}"
group="rg-sikkerheit-${env}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
state="$root/infra/.state/$env.json"
[[ -f "$state" ]] || { echo "Run infra/scripts/setup.sh $env first"; exit 1; }
site="$(jq -r .siteName.value "$state")"
prod_host="$(jq -r .productionHost.value "$state")"
staging_host="$(jq -r .stagingHost.value "$state")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
say() { printf '\n== %s\n' "$*"; }

wait_healthy() {
  local host="$1" deadline=$((SECONDS + 900))
  until [[ "$(curl -s -o /dev/null -w '%{http_code}' "https://$host/health")" == 200 ]]; do
    (( SECONDS < deadline )) || { echo "https://$host/health did not answer 200 in 15 minutes"; return 1; }
    sleep 10
  done
}

expect() {
  local description="$1" expected="$2" actual="$3"
  if [[ "$actual" != "$expected" ]]; then
    echo "SMOKE FAILED: $description — expected $expected, got $actual"
    exit 1
  fi
  echo "   ok: $description"
}

say "Build the portal"
(cd "$root/src/Portal" && npm ci --ignore-scripts --no-fund --no-audit && npm run build)

say "Publish the service"
version="$(git -C "$root" describe --tags --always --dirty 2>/dev/null || echo dev)"
dotnet publish "$root/src/Sikkerheit.Host" -c Release -o "$work/out" --nologo -p:InformationalVersion="$version"
[[ -f "$work/out/wwwroot/index.html" ]] || { echo "The portal is missing from the package"; exit 1; }
(cd "$work/out" && zip -qr "$work/app.zip" .)

say "Deploy $version to the staging slot (migrations run at its start)"
az webapp start --resource-group "$group" --name "$site" --slot staging -o none
az webapp deploy --resource-group "$group" --name "$site" --slot staging --src-path "$work/app.zip" --type zip --restart true -o none
wait_healthy "$staging_host"

say "Smoke tests on https://$staging_host"
expect "health" 200 "$(curl -s -o /dev/null -w '%{http_code}' "https://$staging_host/health")"
expect "portal page" 200 "$(curl -s -o /dev/null -w '%{http_code}' "https://$staging_host/")"
expect "API without a session" 401 "$(curl -s -o /dev/null -w '%{http_code}' "https://$staging_host/api/v1/me")"
location="$(curl -s -o /dev/null -w '%{redirect_url}' "https://$staging_host/auth/login")"
expect "sign-in goes to Entra" "https://login.microsoftonline.com" "${location:0:33}"
csp="$(curl -sI "https://$staging_host/" | tr -d '\r' | awk -F': ' 'tolower($1)=="content-security-policy"{print $2}')"
expect "portal CSP" "default-src 'self'" "${csp:0:18}"

say "Swap staging → production"
az webapp deployment slot swap --resource-group "$group" --name "$site" --slot staging --target-slot production -o none
wait_healthy "$prod_host"
az webapp stop --resource-group "$group" --name "$site" --slot staging -o none

say "Deployed $version to https://$prod_host"
