#!/usr/bin/env bash
# One-time setup of a Sikkerheit environment in the company's Azure subscription and Entra tenant (06).
# Run after «az login» by a person with Owner on the subscription and Application Administrator (or Global
# Administrator) in Entra. Idempotent: a repeated run updates what exists.
#
#   SIKKERHEIT_ALERT_EMAIL=drift@firma.no infra/scripts/setup.sh prod
#
# Optional: SIKKERHEIT_LOCATION (norwayeast), SIKKERHEIT_TEAMS_WEBHOOK (Workflows webhook URL),
#           SIKKERHEIT_LOCK_SECURITY_LOG=yes (locks the 30-day immutability policy; cannot be undone).
set -euo pipefail

env="${1:-prod}"
location="${SIKKERHEIT_LOCATION:-norwayeast}"
group="rg-sikkerheit-${env}"
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
state="$root/infra/.state"
mkdir -p "$state"
: "${SIKKERHEIT_ALERT_EMAIL:?Set SIKKERHEIT_ALERT_EMAIL to the operations mailbox}"

say() { printf '\n== %s\n' "$*"; }
tenant="$(az account show --query tenantId -o tsv)"
me="$(az ad signed-in-user show --query id -o tsv)"
say "Subscription $(az account show --query name -o tsv), tenant $tenant, environment $env in $location"

deploy() {
  az deployment group create --resource-group "$group" --name "sikkerheit-$(date +%Y%m%d%H%M%S)" \
    --template-file "$root/infra/bicep/main.bicep" \
    --parameters environmentName="$env" location="$location" alertEmail="$SIKKERHEIT_ALERT_EMAIL" \
                 portalClientId="${1:-}" graphClientId="${2:-}" \
    --query properties.outputs -o json > "$state/$env.json"
}
output() { jq -r ".$1.value" "$state/$env.json"; }

say "1/7 Resource group and resources (first pass)"
az group create --name "$group" --location "$location" --tags app=sikkerheit environment="$env" -o none
deploy "$(cat "$state/$env.portal" 2>/dev/null || true)" "$(cat "$state/$env.graph" 2>/dev/null || true)"
site="$(output siteName)"; prod_host="$(output productionHost)"; staging_host="$(output stagingHost)"
prod_principal="$(output productionPrincipalId)"; staging_principal="$(output stagingPrincipalId)"
vault="$(output vaultName)"; storage="$(output storageAccountName)"

app_id_by_name() { az ad app list --display-name "$1" --query "[0].appId" -o tsv; }
ensure_app() {
  local name="$1" audience="$2" id
  id="$(app_id_by_name "$name")"
  if [[ -z "$id" ]]; then
    id="$(az ad app create --display-name "$name" --sign-in-audience "$audience" --query appId -o tsv)"
  fi
  az ad sp show --id "$id" -o none 2>/dev/null || az ad sp create --id "$id" -o none
  echo "$id"
}
graph_patch() { az rest --method PATCH --url "https://graph.microsoft.com/v1.0/applications(appId='$1')" --headers 'Content-Type=application/json' --body "$2" -o none; }

say "2/7 Entra application «Sikkerheit Portal ($env)»: sign-in, app roles, own API with v1 tokens (amr)"
portal="$(ensure_app "Sikkerheit Portal ($env)" AzureADMyOrg)"
scope_id="$(az ad app show --id "$portal" --query "api.oauth2PermissionScopes[?value=='access_as_user'].id | [0]" -o tsv)"
[[ -n "$scope_id" ]] || scope_id="$(uuidgen | tr 'A-Z' 'a-z')"
role_id() { az ad app show --id "$portal" --query "appRoles[?value=='$1'].id | [0]" -o tsv; }
admin_role="$(role_id Admin)"; technician_role="$(role_id Technician)"; reader_role="$(role_id Reader)"
[[ -n "$admin_role" ]] || admin_role="$(uuidgen | tr 'A-Z' 'a-z')"
[[ -n "$technician_role" ]] || technician_role="$(uuidgen | tr 'A-Z' 'a-z')"
[[ -n "$reader_role" ]] || reader_role="$(uuidgen | tr 'A-Z' 'a-z')"
graph_patch "$portal" "$(jq -n --arg portal "$portal" --arg scope "$scope_id" --arg prod "$prod_host" --arg staging "$staging_host" \
  --arg admin "$admin_role" --arg technician "$technician_role" --arg reader "$reader_role" '{
  identifierUris: ["api://\($portal)"],
  web: { redirectUris: ["https://\($prod)/auth/callback", "https://\($staging)/auth/callback"],
         implicitGrantSettings: { enableIdTokenIssuance: false, enableAccessTokenIssuance: false } },
  api: { requestedAccessTokenVersion: 1, oauth2PermissionScopes: [{ id: $scope, value: "access_as_user", type: "User",
         isEnabled: true, adminConsentDisplayName: "Use Sikkerheit", adminConsentDescription: "Sign in to the Sikkerheit portal.",
         userConsentDisplayName: "Use Sikkerheit", userConsentDescription: "Sign in to the Sikkerheit portal." }] },
  appRoles: [
    { id: $admin, value: "Admin", displayName: "Admin", description: "Administrator of Sikkerheit", allowedMemberTypes: ["User"], isEnabled: true },
    { id: $technician, value: "Technician", displayName: "Technician", description: "Technician", allowedMemberTypes: ["User"], isEnabled: true },
    { id: $reader, value: "Reader", displayName: "Reader", description: "Read-only access", allowedMemberTypes: ["User"], isEnabled: true } ],
  requiredResourceAccess: [ { resourceAppId: $portal, resourceAccess: [ { id: $scope, type: "Scope" } ] } ] }')"
portal_sp="$(az ad sp show --id "$portal" --query id -o tsv)"
az rest --method PATCH --url "https://graph.microsoft.com/v1.0/servicePrincipals/$portal_sp" --headers 'Content-Type=application/json' \
  --body '{"appRoleAssignmentRequired": true}' -o none
for principal in "$prod_principal" "$staging_principal"; do
  name="slot-$principal"
  if [[ -z "$(az ad app federated-credential list --id "$portal" --query "[?name=='$name'].id | [0]" -o tsv)" ]]; then
    az ad app federated-credential create --id "$portal" --parameters "$(jq -n --arg name "$name" --arg tenant "$tenant" --arg subject "$principal" \
      '{name: $name, issuer: "https://login.microsoftonline.com/\($tenant)/v2.0", subject: $subject, audiences: ["api://AzureADTokenExchange"]}')" -o none
  fi
done
az ad app permission admin-consent --id "$portal" -o none 2>/dev/null || echo "   (admin consent for the own API scope: grant it in the Entra admin center if this failed)"
if [[ -z "$(az rest --method GET --url "https://graph.microsoft.com/v1.0/servicePrincipals/$portal_sp/appRoleAssignedTo" --query "value[?principalId=='$me'].id | [0]" -o tsv)" ]]; then
  az rest --method POST --url "https://graph.microsoft.com/v1.0/servicePrincipals/$portal_sp/appRoleAssignedTo" --headers 'Content-Type=application/json' \
    --body "$(jq -n --arg me "$me" --arg sp "$portal_sp" --arg role "$admin_role" '{principalId: $me, resourceId: $sp, appRoleId: $role}')" -o none
fi
echo "$portal" > "$state/$env.portal"

say "3/7 Entra application «Sikkerheit Graph Reader»: multi-tenant, application permissions to read only"
graph="$(ensure_app "Sikkerheit Graph Reader$([[ $env == prod ]] || echo " ($env)")" AzureADMultipleOrgs)"
graph_sp_id="$(az ad sp show --id 00000003-0000-0000-c000-000000000000 --query id -o tsv)"
permissions='[]'
for value in Organization.Read.All User.Read.All UserAuthenticationMethod.Read.All RoleManagement.Read.Directory GroupMember.Read.All Policy.Read.All; do
  id="$(az rest --method GET --url "https://graph.microsoft.com/v1.0/servicePrincipals/$graph_sp_id/appRoles" --query "value[?value=='$value'].id | [0]" -o tsv)"
  [[ -n "$id" ]] || { echo "Microsoft Graph has no application permission $value"; exit 1; }
  permissions="$(jq --arg id "$id" '. + [{id: $id, type: "Role"}]' <<<"$permissions")"
done
graph_patch "$graph" "$(jq -n --arg prod "$prod_host" --argjson access "$permissions" '{
  web: { redirectUris: ["https://\($prod)/consent-complete"] },
  requiredResourceAccess: [ { resourceAppId: "00000003-0000-0000-c000-000000000000", resourceAccess: $access } ] }')"
echo "$graph" > "$state/$env.graph"

say "4/7 Key Vault: Graph certificate (RSA-HSM 3072, not exportable), secrets"
vault_id="$(az keyvault show --name "$vault" --query id -o tsv)"
for role in "Key Vault Certificates Officer" "Key Vault Secrets Officer"; do
  az role assignment create --assignee-object-id "$me" --assignee-principal-type User --role "$role" --scope "$vault_id" -o none 2>/dev/null || true
done
sleep 30
if ! az keyvault certificate show --vault-name "$vault" --name graph-reader -o none 2>/dev/null; then
  policy="$(jq -n '{ issuerParameters: { name: "Self" }, keyProperties: { exportable: false, keyType: "RSA-HSM", keySize: 3072, reuseKey: false },
    secretProperties: { contentType: "application/x-pem-file" },
    x509CertificateProperties: { subject: "CN=Sikkerheit Graph Reader", validityInMonths: 12, keyUsage: ["digitalSignature"] },
    lifetimeActions: [ { trigger: { daysBeforeExpiry: 30 }, action: { actionType: "EmailContacts" } } ] }')"
  az keyvault certificate create --vault-name "$vault" --name graph-reader --policy "$policy" -o none
fi
az keyvault certificate download --vault-name "$vault" --name graph-reader --file "$state/graph-reader.pem" --encoding PEM
thumb="$(az keyvault certificate show --vault-name "$vault" --name graph-reader --query x509ThumbprintHex -o tsv)"
if [[ -z "$(az ad app credential list --id "$graph" --cert --query "[?customKeyIdentifier=='$thumb'].keyId | [0]" -o tsv)" ]]; then
  az ad app credential reset --id "$graph" --cert "@$state/graph-reader.pem" --append -o none
fi
rm -f "$state/graph-reader.pem"
# Only the production slot may sign with the Graph key (04 «Ключ приложения»).
az role assignment create --assignee-object-id "$prod_principal" --assignee-principal-type ServicePrincipal \
  --role "Key Vault Crypto User" --scope "$vault_id/keys/graph-reader" -o none
az role assignment create --assignee-object-id "$prod_principal" --assignee-principal-type ServicePrincipal \
  --role "Key Vault Certificate User" --scope "$vault_id/certificates/graph-reader" -o none
az keyvault secret show --vault-name "$vault" --name cursor-key -o none 2>/dev/null \
  || az keyvault secret set --vault-name "$vault" --name cursor-key --value "$(openssl rand -base64 32)" -o none
if [[ -n "${SIKKERHEIT_TEAMS_WEBHOOK:-}" ]]; then
  az keyvault secret set --vault-name "$vault" --name teams-webhook --value "$SIKKERHEIT_TEAMS_WEBHOOK" -o none
fi

say "5/7 Security log immutability"
if [[ "${SIKKERHEIT_LOCK_SECURITY_LOG:-no}" == yes ]]; then
  etag="$(az storage container immutability-policy show --account-name "$storage" --container-name security-log --auth-mode login --query etag -o tsv 2>/dev/null \
    || az storage container immutability-policy show --account-name "$storage" --container-name security-log --query etag -o tsv)"
  az storage container immutability-policy lock --account-name "$storage" --container-name security-log --if-match "$etag" -o none
  echo "   locked for 30 days per record"
else
  echo "   not locked yet: set SIKKERHEIT_LOCK_SECURITY_LOG=yes before the pilot (locking cannot be undone)"
fi

say "6/7 Resources with the application ids (second pass)"
deploy "$portal" "$graph"

say "7/7 Done"
cat <<NEXT
Portal:        https://$prod_host
Staging slot:  https://$staging_host
Next:
  * Deploy the service:  infra/scripts/deploy-app.sh $env
  * Give staff roles: Entra admin center → Enterprise applications → «Sikkerheit Portal ($env)» → Users and groups
    (Admin, Technician, Reader). You have the Admin role already.
  * Conditional Access in the company tenant must require MFA for «Sikkerheit Portal ($env)».
  * Publisher verification of «Sikkerheit Graph Reader» before the pilot (04).
NEXT
