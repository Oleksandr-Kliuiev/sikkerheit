// Storage (06 «Ресурсы»): no account keys, RBAC only, private containers with soft delete 7 days; security-log with
// time-based immutability 30 days (locked by setup.sh — locking cannot be undone) and deletion after 45 days; files
// that a restore moved to restore-orphans/ are deleted after 30 days (06 «Резервное копирование и восстановление»).
@description('Globally unique base name, for example sikkerheit-prod-ab12c.')
@minLength(5)
param name string
param location string
@description('True once the security-log policy is locked: Azure then allows only extending it, so it is not redeployed.')
param securityLogLocked bool = false

resource account 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  #disable-next-line BCP334
  name: take('st${replace(name, '-', '')}', 24)
  location: location
  sku: { name: 'Standard_ZRS' }
  kind: 'StorageV2'
  properties: {
    allowSharedKeyAccess: false
    allowBlobPublicAccess: false
    defaultToOAuthAuthentication: true
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    publicNetworkAccess: 'Enabled'
  }
}

resource blobs 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: account
  name: 'default'
  properties: {
    deleteRetentionPolicy: { enabled: true, days: 7 }
    containerDeleteRetentionPolicy: { enabled: true, days: 7 }
  }
}

resource containers 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = [for container in [
  'reports', 'exports', 'agent-releases', 'dataprotection', 'security-log'
]: {
  parent: blobs
  name: container
  properties: { publicAccess: 'None' }
}]

resource retention 'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2023-05-01' = if (!securityLogLocked) {
  name: '${account.name}/default/security-log/default'
  properties: { immutabilityPeriodSinceCreationInDays: 30, allowProtectedAppendWrites: false }
  dependsOn: [ containers ]
}

resource lifecycle 'Microsoft.Storage/storageAccounts/managementPolicies@2023-05-01' = {
  parent: account
  name: 'default'
  properties: {
    policy: {
      rules: [
        {
          name: 'security-log-45-days'
          enabled: true
          type: 'Lifecycle'
          definition: {
            filters: { blobTypes: [ 'blockBlob' ], prefixMatch: [ 'security-log/' ] }
            actions: { baseBlob: { delete: { daysAfterCreationGreaterThan: 45 } } }
          }
        }
        {
          // Report and export files without database rows after a restore (RB-05): kept for reconciliation only.
          name: 'restore-orphans-30-days'
          enabled: true
          type: 'Lifecycle'
          definition: {
            filters: { blobTypes: [ 'blockBlob' ], prefixMatch: [ 'reports/restore-orphans/', 'exports/restore-orphans/' ] }
            actions: { baseBlob: { delete: { daysAfterCreationGreaterThan: 30 } } }
          }
        }
      ]
    }
  }
}

output accountId string = account.id
output accountName string = account.name
output blobEndpoint string = account.properties.primaryEndpoints.blob
