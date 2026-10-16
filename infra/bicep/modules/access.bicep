// Least-privilege data access of the slot identities (06 «Ресурсы»). The sign right on the Graph certificate key is
// given to the production slot only by setup.sh after the certificate exists.
param storageAccountName string
param vaultName string
param dataProtectionKeyName string
param principalIds array

var roles = {
  blobContributor: 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
  secretsUser: '4633458b-17de-408a-b874-0445c86b69e6'
  cryptoServiceEncryptionUser: 'e147488a-f6f5-4113-8e2d-b22465e65bf6'
}

resource account 'Microsoft.Storage/storageAccounts@2023-05-01' existing = {
  name: storageAccountName
}

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: vaultName
}

resource dataProtectionKey 'Microsoft.KeyVault/vaults/keys@2023-07-01' existing = {
  parent: vault
  name: dataProtectionKeyName
}

resource blobAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for id in principalIds: {
  scope: account
  name: guid(account.id, id, roles.blobContributor)
  properties: {
    principalId: id
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.blobContributor)
  }
}]

resource secretAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for id in principalIds: {
  scope: vault
  name: guid(vault.id, id, roles.secretsUser)
  properties: {
    principalId: id
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.secretsUser)
  }
}]

resource keyWrapAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for id in principalIds: {
  scope: dataProtectionKey
  name: guid(dataProtectionKey.id, id, roles.cryptoServiceEncryptionUser)
  properties: {
    principalId: id
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.cryptoServiceEncryptionUser)
  }
}]
