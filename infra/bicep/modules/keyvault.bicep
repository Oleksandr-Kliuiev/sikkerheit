// Key Vault Premium (06 «Ресурсы»): RBAC, soft delete and purge protection, audit to Log Analytics. The Graph
// certificate (RSA-HSM 3072, non-exportable) and the secrets are created by setup.sh.
param name string
param location string
param tenantId string
param workspaceId string

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: take('kv-${name}', 24)
  location: location
  properties: {
    tenantId: tenantId
    sku: { family: 'A', name: 'premium' }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true
    publicNetworkAccess: 'Enabled'
  }
}

// Wraps the ASP.NET Core Data Protection keys that protect the staff token caches.
resource dataProtection 'Microsoft.KeyVault/vaults/keys@2023-07-01' = {
  parent: vault
  name: 'dataprotection'
  properties: { kty: 'RSA-HSM', keySize: 3072, keyOps: [ 'wrapKey', 'unwrapKey' ] }
}

resource audit 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: vault
  name: 'audit'
  properties: {
    workspaceId: workspaceId
    logs: [ { categoryGroup: 'audit', enabled: true } ]
  }
}

output vaultId string = vault.id
output vaultName string = vault.name
output vaultUri string = vault.properties.vaultUri
output dataProtectionKeyName string = dataProtection.name
output dataProtectionKeyUri string = dataProtection.properties.keyUri
