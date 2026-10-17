#!/usr/bin/env bash
# Explicit operator action after DNS preparation (SP-05). --plan only reads Azure; --apply binds DNS/TLS.
set -euo pipefail
env="${1:-}"; host="${2:-}"; mode="${3:---plan}"
[[ "$env" == prod || "$env" == test ]] && [[ "$mode" == --plan || "$mode" == --apply ]] \
  || { echo "Usage: $0 prod|test agent.example.no [--plan|--apply]" >&2; exit 2; }
[[ ${#host} -le 253 && "$host" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ && "$host" != disabled.invalid ]] \
  || { echo "Use a lowercase DNS hostname without scheme, path or wildcard" >&2; exit 2; }
group="rg-sikkerheit-$env"
site="$(az webapp list --resource-group "$group" --query "[?starts_with(name, 'app-sikkerheit-${env}-')].name | [0]" -o tsv)"
[[ -n "$site" ]] || { echo "Run setup.sh $env first" >&2; exit 1; }
default_host="$(az webapp show --resource-group "$group" --name "$site" --query defaultHostName -o tsv)"
verification="$(az webapp show --resource-group "$group" --name "$site" --query customDomainVerificationId -o tsv)"
[[ -n "$default_host" && -n "$verification" && "$host" != "$default_host" ]] \
  || { echo "Cannot resolve the app or the agent hostname equals the portal hostname" >&2; exit 1; }
printf 'DNS: CNAME %s -> %s\nDNS: TXT asuid.%s -> %s\n' "$host" "$default_host" "$host" "$verification"
[[ "$mode" == --apply ]] || exit 0
az webapp config hostname add --resource-group "$group" --webapp-name "$site" --hostname "$host" -o none
thumb="$(az webapp config ssl list --resource-group "$group" --query "[?canonicalName=='$host'].thumbprint | [0]" -o tsv)"
if [[ -z "$thumb" ]]; then
  az webapp config ssl create --resource-group "$group" --name "$site" --hostname "$host" -o none
  for ((attempt=0; attempt<20; attempt++)); do
    thumb="$(az webapp config ssl list --resource-group "$group" --query "[?canonicalName=='$host'].thumbprint | [0]" -o tsv)"
    [[ -z "$thumb" ]] || break
    sleep 30
  done
fi
[[ -n "$thumb" ]] || { echo "Managed certificate is not ready; retry after Azure finishes issuance" >&2; exit 1; }
az webapp config ssl bind --resource-group "$group" --name "$site" --certificate-thumbprint "$thumb" --ssl-type SNI -o none
echo "TLS bound. Enable this hostname with SIKKERHEIT_AGENT_HOST=$host and setup.sh $env; then deploy-app.sh $env."
