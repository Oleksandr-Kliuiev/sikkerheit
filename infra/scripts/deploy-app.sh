#!/usr/bin/env bash
# Builds the portal and the service and deploys them (06 «Окружения и развёртывание»). The same script runs on a
# workstation after «az login» and in .github/workflows/deploy.yml after the OIDC sign-in.
#   prod: publish to the staging slot → migrations at its start under the migrations identity → smoke tests → swap →
#         stop staging.
#   test: B1 has no slots. The migrations identity and Database__MigrateOnStart are added to the app for the time of
#         the deployment → publish → smoke tests → both are removed and the app restarts; a trap removes them also
#         when a step fails.
#
#   infra/scripts/deploy-app.sh prod|test
#   infra/scripts/deploy-app.sh prod|test --cleanup   # after a cancelled run: stop staging (prod) or remove the
#                                                     # temporary migrations access (test)
set -euo pipefail

env="${1:-prod}"
mode="${2:-deploy}"
[[ "$env" == prod || "$env" == test ]] || { echo "Usage: $0 prod|test [--cleanup]"; exit 2; }
[[ "$mode" == deploy || "$mode" == --cleanup ]] || { echo "Usage: $0 prod|test [--cleanup]"; exit 2; }
group="rg-sikkerheit-${env}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
state="$root/infra/.state/$env.json"
say() { printf '\n== %s\n' "$*"; }

# Names and hosts: from the outputs of setup.sh, or from Azure when they are absent (CI, another workstation).
if [[ -f "$state" ]]; then
  site="$(jq -r .siteName.value "$state")"
  prod_host="$(jq -r .productionHost.value "$state")"
  staging_host="$(jq -r '.stagingHost.value // ""' "$state")"
else
  site="$(az webapp list --resource-group "$group" --query "[?starts_with(name, 'app-sikkerheit-${env}-')].name | [0]" -o tsv)"
  [[ -n "$site" ]] || { echo "No web app in $group: run infra/scripts/setup.sh $env first"; exit 1; }
  prod_host="$(az webapp show --resource-group "$group" --name "$site" --query defaultHostName -o tsv)"
  staging_host=""
  if [[ "$env" == prod ]]; then
    staging_host="$(az webapp show --resource-group "$group" --name "$site" --slot staging --query defaultHostName -o tsv)"
  fi
fi
if [[ "$env" == prod && -z "$staging_host" ]]; then
  echo "Production deploys through the staging slot, and $site has none: run infra/scripts/setup.sh prod"
  exit 1
fi
agent_host="$(az webapp config appsettings list --resource-group "$group" --name "$site" \
  --query "[?name=='Hosting__AgentHosts__0'].value | [0]" -o tsv)"
agent_host="${agent_host:-disabled.invalid}"

work=""
staging_running=no   # prod: the staging slot runs and must be stopped again
swapped=no           # prod: production already runs the new version
temporary=no         # test: the migrations identity and settings may be on the app
migrations_id=""

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

smoke() {
  local host="$1" location csp
  say "Smoke tests on https://$host"
  expect "health" 200 "$(curl -s -o /dev/null -w '%{http_code}' "https://$host/health")"
  expect "portal page" 200 "$(curl -s -o /dev/null -w '%{http_code}' "https://$host/")"
  expect "API without a session" 401 "$(curl -s -o /dev/null -w '%{http_code}' "https://$host/api/v1/me")"
  location="$(curl -s -o /dev/null -w '%{redirect_url}' "https://$host/auth/login" || true)"
  expect "sign-in goes to Entra" "https://login.microsoftonline.com" "${location:0:33}"
  csp="$(curl -sI "https://$host/" | tr -d '\r' | awk -F': ' 'tolower($1)=="content-security-policy"{print $2}' || true)"
  expect "portal CSP" "default-src 'self'" "${csp:0:18}"
  local challenge_host="$host" challenge_status=404
  if [[ "$agent_host" != disabled.invalid ]]; then
    challenge_status=201
    [[ "$host" == "$staging_host" ]] || challenge_host="$agent_host"
  fi
  expect "agent challenge" "$challenge_status" "$(curl --max-time 30 -s -o /dev/null -w '%{http_code}' \
    -H 'Content-Type: application/json' -d '{"purpose":"enroll"}' "https://$challenge_host/api/v1/agent/challenges")"
  if [[ "$agent_host" != disabled.invalid && "$host" != "$staging_host" ]]; then
    expect "agent API closed on the portal host" 404 "$(curl --max-time 30 -s -o /dev/null -w '%{http_code}' \
      -H 'Content-Type: application/json' -d '{"purpose":"enroll"}' "https://$host/api/v1/agent/challenges")"
    expect "portal closed on the agent host" 404 "$(curl --max-time 30 -s -o /dev/null -w '%{http_code}' "https://$agent_host/")"
  fi
}

# The migrations identity of the environment: owner of the schema, Entra administrator of the server (main.bicep).
resolve_migrations() {
  local identity
  identity="$(az identity show --resource-group "$group" --name "id-sikkerheit-${env}-migrations" -o json)"
  migrations_id="$(jq -r .id <<<"$identity")"
  migrations_name="$(jq -r .name <<<"$identity")"
  migrations_client="$(jq -r .clientId <<<"$identity")"
}

remove_identity() {
  local assigned present
  assigned="$(az webapp identity show --resource-group "$group" --name "$site" -o json)" || return 1
  present="$(jq -r --arg id "$migrations_id" \
    '[(.userAssignedIdentities // {}) | keys[] | ascii_downcase] | any(. == ($id | ascii_downcase))' <<<"$assigned")" || return 1
  if [[ "$present" == true ]]; then
    az webapp identity remove --resource-group "$group" --name "$site" --identities "$migrations_id" -o none
  fi
}

# Back to the state of main.bicep: no migrations at start, no owner settings, no migrations identity. Every settings
# change restarts the app, so Database__MigrateOnStart goes off first: a start that migrates without the owner settings
# or without the identity fails.
remove_migration_access() {
  az webapp config appsettings set --resource-group "$group" --name "$site" -o none \
      --settings Database__MigrateOnStart=false &&
    az webapp config appsettings delete --resource-group "$group" --name "$site" -o none --setting-names \
      ConnectionStrings__SikkerheitOwner Database__OwnerIdentityClientId \
      Database__AppPrincipals__0__Name Database__AppPrincipals__0__ObjectId &&
    remove_identity &&
    az webapp restart --resource-group "$group" --name "$site" -o none
}

cleanup() {
  local status=$? failed=no
  trap - EXIT
  set +e
  if [[ "$temporary" == yes ]]; then
    echo "Removing the temporary migrations access from $site"
    remove_migration_access || failed=yes
  fi
  if [[ "$staging_running" == yes ]]; then
    echo "Stopping the staging slot"
    az webapp stop --resource-group "$group" --name "$site" --slot staging -o none || failed=yes
    if [[ "$swapped" == yes ]]; then
      echo "Production already runs the new version. Rollback: start the staging slot and swap it back"
      echo "  az webapp start --resource-group $group --name $site --slot staging"
      echo "  az webapp deployment slot swap --resource-group $group --name $site --slot staging --target-slot production"
    fi
  fi
  [[ -n "$work" ]] && rm -rf "$work"
  if [[ "$failed" == yes ]]; then
    echo "CLEANUP FAILED: check $site in $group by hand (migrations identity, Database__MigrateOnStart, staging slot)"
    (( status != 0 )) || status=1
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ "$mode" == --cleanup ]]; then
  if [[ "$env" == prod ]]; then
    staging_running=yes
  else
    resolve_migrations
    temporary=yes
  fi
  exit 0
fi

deploy_with_slot() {
  say "Deploy $version to the staging slot (migrations run at its start)"
  staging_running=yes
  az webapp start --resource-group "$group" --name "$site" --slot staging -o none
  az webapp deploy --resource-group "$group" --name "$site" --slot staging --src-path "$work/app.zip" --type zip --restart true -o none
  wait_healthy "$staging_host"
  smoke "$staging_host"

  say "Swap staging → production"
  az webapp deployment slot swap --resource-group "$group" --name "$site" --slot staging --target-slot production -o none
  swapped=yes
  wait_healthy "$prod_host"
  smoke "$prod_host"
  az webapp stop --resource-group "$group" --name "$site" --slot staging -o none
  staging_running=no
}

deploy_without_slot() {
  local app_principal db_host
  resolve_migrations
  if [[ -f "$state" ]]; then
    app_principal="$(jq -r .productionPrincipalId.value "$state")"
  else
    app_principal="$(az webapp identity show --resource-group "$group" --name "$site" --query principalId -o tsv)"
  fi
  # The host comes from the app's own connection string: after a restore (RB-05) the app runs on the restored server
  # before setup.sh updates infra/.state, and the deploy identity may read the app but not the server.
  db_host="$(az webapp config appsettings list --resource-group "$group" --name "$site" \
    --query "[?name=='ConnectionStrings__Sikkerheit'].value | [0]" -o tsv | sed -n 's/^Host=\([^;]*\);.*/\1/p')"
  [[ -n "$app_principal" && -n "$db_host" ]] || { echo "Cannot resolve the app identity or the database host"; exit 1; }

  say "Attach the migrations identity and Database__MigrateOnStart to $site for this deployment"
  temporary=yes
  az webapp identity assign --resource-group "$group" --name "$site" --identities "$migrations_id" -o none
  az webapp config appsettings set --resource-group "$group" --name "$site" -o none --settings \
    Database__MigrateOnStart=true \
    "ConnectionStrings__SikkerheitOwner=Host=$db_host;Database=sikkerheit;Username=$migrations_name;Ssl Mode=VerifyFull" \
    "Database__OwnerIdentityClientId=$migrations_client" \
    Database__AppPrincipals__0__Name=sikkerheit-app \
    "Database__AppPrincipals__0__ObjectId=$app_principal"

  say "Deploy $version to $site (migrations run at its start)"
  az webapp deploy --resource-group "$group" --name "$site" --src-path "$work/app.zip" --type zip --restart true -o none
  wait_healthy "$prod_host"
  smoke "$prod_host"

  say "Remove the migrations identity and the temporary settings, restart"
  remove_migration_access
  temporary=no
  wait_healthy "$prod_host"
}

work="$(mktemp -d)"

say "Build the portal"
(cd "$root/src/Portal" && npm ci --ignore-scripts --no-fund --no-audit && npm run build)

say "Publish the service"
version="$(git -C "$root" describe --tags --always --dirty 2>/dev/null || echo dev)"
dotnet publish "$root/src/Sikkerheit.Host" -c Release -o "$work/out" --nologo -p:InformationalVersion="$version"
python3 -I "$root/tools/iac/check_startup.py" --assembly "$work/out/Sikkerheit.Host.dll"
[[ -f "$work/out/wwwroot/index.html" ]] || { echo "The portal is missing from the package"; exit 1; }
(cd "$work/out" && zip -qr "$work/app.zip" .)

if [[ "$env" == prod ]]; then
  deploy_with_slot
else
  deploy_without_slot
fi

say "Deployed $version to https://$prod_host"
