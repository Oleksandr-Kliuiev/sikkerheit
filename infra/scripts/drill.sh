#!/usr/bin/env bash
# Restore drill of RB-05 («Учебное восстановление»; 06 «Резервное копирование и восстановление»): a point-in-time copy
# of the production database goes into the isolated group rg-sikkerheit-drill, with no inbound access and no M365
# collection. The drill instance reads the security log and the files of production with the restore identity of
# production, which may only read, so the command lists the files and never moves them (--drill). In rg-sikkerheit-prod
# the script only reads.
#
#   infra/scripts/drill.sh start --since 2026-11-03T14:20:00Z [--package app.zip]   # Д1–Д4; Д5 is run by hand
#   infra/scripts/drill.sh check                                                     # Д6: the report and the RTO
#   infra/scripts/drill.sh cleanup                                                   # Д7: deletes rg-sikkerheit-drill
#
# Run after «az login» with Contributor on the subscription. Without --package the current checkout is built as
# deploy-app.sh does: check out the tag that runs in production first. The drill group holds a copy of client data;
# «cleanup» deletes it, also after a failed «start».
set -euo pipefail

usage() {
  echo "Usage: $0 start --since <UTC time, e.g. 2026-11-03T14:20:00Z> [--package <app.zip>] | check | cleanup"
  exit 2
}

production="rg-sikkerheit-prod"
group="rg-sikkerheit-drill"
root="$(cd "$(dirname "$0")/../.." && pwd)"
state="$root/infra/.state/drill.json"
downloads="$root/infra/.state/drill"
rto_limit=14400   # NFR-07: 4 hours
say() { printf '\n== %s  %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
remember() { jq --arg key "$1" --arg value "$2" '.[$key] = $value' "$state" > "$state.tmp" && mv "$state.tmp" "$state"; }
recall() { jq -r --arg key "$1" '.[$key] // ""' "$state"; }
digits() { local value="${1:0:19}"; echo "${value//[!0-9]/}"; }

work=""
started=no   # the drill group exists and may hold a copy of client data
finish() {
  local status=$?
  trap - EXIT
  [[ -n "$work" ]] && rm -rf "$work"
  if (( status != 0 )) && [[ "$started" == yes ]]; then
    echo "The drill stopped. $group remains and may hold a copy of client data: $0 cleanup"
  fi
  exit "$status"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

start() {
  local since="" package="" now
  while (( $# )); do
    [[ $# -ge 2 ]] || usage
    case "$1" in
      --since) since="$2" ;;
      --package) package="$2" ;;
      *) usage ;;
    esac
    shift 2
  done
  [[ "$since" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || usage
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  (( $(digits "$since") < $(digits "$now") )) || { echo "--since $since lies in the future"; exit 2; }
  [[ -z "$package" || -f "$package" ]] || { echo "No package $package"; exit 2; }
  if [[ -f "$state" || "$(az group exists --name "$group")" == true ]]; then
    echo "A previous drill is not cleaned up: $0 cleanup"
    exit 1
  fi

  say "Production (read only): the database server, storage and identities the service uses now"
  local site settings host primary migrations restore earliest location
  site="$(az webapp list --resource-group "$production" --query "[?starts_with(name, 'app-sikkerheit-prod-')].name | [0]" -o tsv)"
  [[ -n "$site" ]] || { echo "No production app in $production"; exit 1; }
  settings="$(az webapp config appsettings list --resource-group "$production" --name "$site" -o json \
    --query "[?name=='ConnectionStrings__Sikkerheit' || name=='Storage__BlobServiceUri' || name=='SecurityLog__ContainerUri']")"
  setting() { jq -r --arg name "$1" '.[] | select(.name == $name) | .value' <<<"$settings"; }
  # After a restore (RB-05) production runs on the restored server: the source is the server of the connection string.
  host="$(setting ConnectionStrings__Sikkerheit | sed -n 's/^Host=\([^;]*\);.*/\1/p')"
  primary="$(az postgres flexible-server show --resource-group "$production" --name "${host%%.*}" -o json \
    --query "{id:id, name:name, location:location, earliest:backup.earliestRestoreDate}")"
  migrations="$(az identity show --resource-group "$production" --name id-sikkerheit-prod-migrations -o json \
    --query "{id:id, clientId:clientId, principalId:principalId}")"
  restore="$(az identity show --resource-group "$production" --name id-sikkerheit-prod-restore -o json \
    --query "{id:id, clientId:clientId}")" || { echo "No id-sikkerheit-prod-restore: run infra/scripts/setup.sh prod"; exit 1; }
  earliest="$(jq -r .earliest <<<"$primary")"
  location="$(jq -r .location <<<"$primary")"
  [[ -n "$(digits "$earliest")" ]] || { echo "No earliest restore point of the server: $earliest"; exit 1; }
  (( $(digits "$since") >= $(digits "$earliest") )) || { echo "--since is before the earliest restore point $earliest"; exit 2; }
  echo "   source $(jq -r .name <<<"$primary"), restore point $since (earliest $earliest), storage $(setting Storage__BlobServiceUri)"

  local stamp server drill_site report
  stamp="$(date -u +%Y%m%d%H%M)"
  server="psql-sikkerheit-drill-$stamp"
  drill_site="app-sikkerheit-drill-$stamp-$(openssl rand -hex 2)"
  report="restore-drill-$stamp.json"

  work="$(mktemp -d)"
  if [[ -z "$package" ]]; then
    local version
    version="$(git -C "$root" describe --tags --always --dirty 2>/dev/null || echo dev)"
    say "Build $version as deploy-app.sh does: production must run the same version"
    (cd "$root/src/Portal" && npm ci --ignore-scripts --no-fund --no-audit && npm run build)
    dotnet publish "$root/src/Sikkerheit.Host" -c Release -o "$work/out" --nologo -p:InformationalVersion="$version"
    [[ -f "$work/out/wwwroot/index.html" ]] || { echo "The portal is missing from the package"; exit 1; }
    (cd "$work/out" && zip -qr "$work/app.zip" .)
    package="$work/app.zip"
  fi

  say "Д1 Group $group and the network of infra/bicep/modules/network.bicep, as in production"
  mkdir -p "$(dirname "$state")"
  jq -n --arg since "$since" --arg site "$drill_site" --arg server "$server" --arg report "$report" \
    '{since: $since, site: $site, server: $server, report: $report}' > "$state"
  started=yes
  az group create --name "$group" --location "$location" --tags app=sikkerheit environment=drill -o none
  az deployment group create --resource-group "$group" --name "drill-network-$stamp" -o none \
    --template-file "$root/infra/bicep/modules/network.bicep" --parameters name=sikkerheit-drill location="$location"

  say "Д2 Drill instance $drill_site: inbound access denied, no M365 and no Entra sign-in, jobs off"
  az appservice plan create --resource-group "$group" --name asp-sikkerheit-drill --location "$location" --is-linux --sku B1 -o none
  az webapp create --resource-group "$group" --plan asp-sikkerheit-drill --name "$drill_site" --runtime "DOTNETCORE:10.0" \
    --startup-file "dotnet Sikkerheit.Host.dll" --https-only true --vnet vnet-sikkerheit-drill --subnet app -o none
  az webapp config access-restriction set --resource-group "$group" --name "$drill_site" --default-action Deny -o none
  az webapp config set --resource-group "$group" --name "$drill_site" --always-on true --ftps-state Disabled -o none
  az webapp log config --resource-group "$group" --name "$drill_site" --docker-container-logging filesystem -o none
  # The system identity signs in to the restored copy. The migrations identity of production creates its role there at
  # start, as the staging slot does in production; the restore identity reads the security log and the files.
  local principal
  principal="$(az webapp identity assign --resource-group "$group" --name "$drill_site" --query principalId -o tsv \
    --identities '[system]' "$(jq -r .id <<<"$migrations")" "$(jq -r .id <<<"$restore")")"
  az webapp config appsettings set --resource-group "$group" --name "$drill_site" -o none --settings \
    ASPNETCORE_ENVIRONMENT=Drill Jobs__Enabled=false Database__EntraAuth=true Database__AppRole=sikkerheit_app \
    "Database__OwnerIdentityClientId=$(jq -r .clientId <<<"$migrations")" \
    Database__AppPrincipals__0__Name=sikkerheit-drill "Database__AppPrincipals__0__ObjectId=$principal" \
    "Storage__BlobServiceUri=$(setting Storage__BlobServiceUri)" "SecurityLog__ContainerUri=$(setting SecurityLog__ContainerUri)" \
    "Restore__ManagedIdentityClientId=$(jq -r .clientId <<<"$restore")"

  say "Д3 Point-in-time restore of $(jq -r .name <<<"$primary") at $since into $server (the RTO starts)"
  remember restoreStarted "$(date -u +%s)"
  az postgres flexible-server restore --resource-group "$group" --name "$server" --source-server "$(jq -r .id <<<"$primary")" \
    --restore-time "$since" --vnet vnet-sikkerheit-drill --subnet database \
    --private-dns-zone sikkerheit-drill.private.postgres.database.azure.com --yes -o none
  local info fqdn
  info="$(az postgres flexible-server show --resource-group "$group" --name "$server" -o json --query \
    "{state:state, fqdn:fullyQualifiedDomainName, access:network.publicNetworkAccess, entra:authConfig.activeDirectoryAuth, password:authConfig.passwordAuth}")"
  echo "   $(jq -c . <<<"$info")"
  [[ "$(jq -r .state <<<"$info")" == Ready ]] || { echo "The restored server is not Ready"; exit 1; }
  [[ "$(jq -r .access <<<"$info")" == Disabled ]] || { echo "The restored server is reachable publicly"; exit 1; }
  fqdn="$(jq -r .fqdn <<<"$info")"
  if [[ "$(jq -r .entra <<<"$info")" != Enabled || "$(jq -r .password <<<"$info")" != Disabled ]]; then
    az postgres flexible-server update --resource-group "$group" --name "$server" --microsoft-entra-auth Enabled --password-auth Disabled -o none
  fi
  if ! az postgres flexible-server microsoft-entra-admin list --resource-group "$group" --server-name "$server" \
      --query "[].objectId" -o tsv | grep -qx "$(jq -r .principalId <<<"$migrations")"; then
    az postgres flexible-server microsoft-entra-admin create --resource-group "$group" --server-name "$server" -o none \
      --display-name id-sikkerheit-prod-migrations --object-id "$(jq -r .principalId <<<"$migrations")" --type ServicePrincipal
  fi
  remember restoreFinished "$(date -u +%s)"

  say "Д4 Connection strings to $fqdn and the release; migrations at start create the role sikkerheit-drill"
  az webapp config appsettings set --resource-group "$group" --name "$drill_site" -o none --settings Database__MigrateOnStart=true \
    "ConnectionStrings__Sikkerheit=Host=$fqdn;Database=sikkerheit;Username=sikkerheit-drill;Ssl Mode=VerifyFull" \
    "ConnectionStrings__SikkerheitOwner=Host=$fqdn;Database=sikkerheit;Username=id-sikkerheit-prod-migrations;Ssl Mode=VerifyFull"
  az webapp deploy --resource-group "$group" --name "$drill_site" --src-path "$package" --type zip -o none
  remember instanceReady "$(date -u +%s)"

  say "Д5 By hand: the restore command in the drill instance, RB-05 step 3 with --drill"
  cat <<NEXT
   az webapp ssh --resource-group $group --name $drill_site
   In the session: «printenv Jobs__Enabled» shows false, «printenv Restore__ManagedIdentityClientId» a client id; then
     cd /home/site/wwwroot && dotnet Sikkerheit.Host.dll restore-replay --since $since --drill --report /home/LogFiles/$report
     echo \$?
   Then: infra/scripts/drill.sh check
NEXT
}

check() {
  [[ -f "$state" ]] || { echo "No drill in progress: $0 start"; exit 1; }
  local site since report logs entry problems rto
  site="$(recall site)"; since="$(recall since)"; report="$(recall report)"
  [[ -n "$(recall instanceReady)" ]] || { echo "«start» did not finish: $0 cleanup, then start again"; exit 1; }
  say "Д6 The report of $site and the RTO"
  mkdir -p "$downloads"
  logs="$downloads/${report%.json}-logs.zip"
  rm -f "$logs" "$downloads/$report"
  az webapp log download --resource-group "$group" --name "$site" --log-file "$logs"
  entry="$(unzip -Z1 "$logs" | grep -E "(^|/)$report\$" | head -n 1 || true)"
  [[ -n "$entry" ]] || { echo "No $report in the logs of $site yet: run step Д5 with --report /home/LogFiles/$report, then check again"; exit 1; }
  unzip -p "$logs" "$entry" > "$downloads/$report"
  jq '{passed: .verification.passed, problems: .verification.problems, recordsRead, applied: ([.records[] | select(.outcome == "applied")] | length), deletionsPostponed, policyEpochs, orphanFiles: (.orphanFiles | length), leasesReset, steps}' "$downloads/$report"
  # AT-11, part P1: the command verified the journal, the 7-day deletion grace and the leases; a drill moves no file.
  problems="$(jq -r --arg since "$since" '
    (if .drill != true then "the report is not a drill: files may have been moved" else empty end),
    (if .since != $since then "the report is for \(.since), the drill restored \($since)" else empty end),
    (if .verification.passed != true then "verification failed: \(.verification.problems | join("; "))" else empty end),
    (.orphanFiles[] | select(.moved) | "\(.container)/\(.key) was moved")' "$downloads/$report")"
  rto=$(( $(date -u +%s) - $(recall restoreStarted) ))
  printf '   RTO %d:%02d from the start of the restore (limit 4:00); restore %d min, instance %d min\n' \
    $(( rto / 3600 )) $(( rto % 3600 / 60 )) $(( ($(recall restoreFinished) - $(recall restoreStarted)) / 60 )) \
    $(( ($(recall instanceReady) - $(recall restoreFinished)) / 60 ))
  (( rto <= rto_limit )) || problems+="${problems:+$'\n'}the RTO is above 4 hours"
  if [[ -n "$problems" ]]; then
    echo "DRILL FAILED:"
    echo "$problems"
    echo "Record it in the protocol with $downloads/$report, then: $0 cleanup"
    exit 1
  fi
  echo "Drill passed. Attach $downloads/$report to the protocol, then: $0 cleanup"
}

cleanup() {
  say "Д7 Delete $group: it holds a copy of client data"
  if [[ "$(az group exists --name "$group")" == true ]]; then
    [[ "$(az group show --name "$group" --query tags.environment -o tsv)" == drill ]] \
      || { echo "$group is not tagged environment=drill: check it and delete it by hand"; exit 1; }
    az group delete --name "$group" --yes
  fi
  [[ "$(az group exists --name "$group")" == false ]] || { echo "$group still exists"; exit 1; }
  rm -f "$state"
  echo "Deleted. Reports in $downloads: attach them to the protocol, then delete them."
}

case "${1:-}" in
  start) shift; start "$@" ;;
  check) [[ $# -eq 1 ]] || usage; check ;;
  cleanup) [[ $# -eq 1 ]] || usage; cleanup ;;
  *) usage ;;
esac
