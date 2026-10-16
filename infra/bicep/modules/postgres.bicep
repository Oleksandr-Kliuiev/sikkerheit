// PostgreSQL 17 Flexible Server: private access only, Entra sign-in only (no passwords), PITR 14 days (06 «Ресурсы»).
param name string
param location string
param tenantId string
param skuName string
param subnetId string
param dnsZoneId string
@description('The migrations identity: Entra administrator of the server and owner of the schema.')
param adminPrincipalId string
param adminPrincipalName string

resource server 'Microsoft.DBforPostgreSQL/flexibleServers@2024-08-01' = {
  name: 'psql-${name}'
  location: location
  sku: { name: skuName, tier: 'Burstable' }
  properties: {
    version: '17'
    storage: { storageSizeGB: 32, autoGrow: 'Enabled' }
    backup: { backupRetentionDays: 14, geoRedundantBackup: 'Disabled' }
    network: { delegatedSubnetResourceId: subnetId, privateDnsZoneArmResourceId: dnsZoneId, publicNetworkAccess: 'Disabled' }
    authConfig: { activeDirectoryAuth: 'Enabled', passwordAuth: 'Disabled', tenantId: tenantId }
    highAvailability: { mode: 'Disabled' }
  }
}

resource admin 'Microsoft.DBforPostgreSQL/flexibleServers/administrators@2024-08-01' = {
  parent: server
  name: adminPrincipalId
  properties: { principalType: 'ServicePrincipal', principalName: adminPrincipalName, tenantId: tenantId }
}

resource database 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2024-08-01' = {
  parent: server
  name: 'sikkerheit'
  properties: { charset: 'UTF8', collation: 'en_US.utf8' }
  dependsOn: [ admin ]
}

output host string = server.properties.fullyQualifiedDomainName
output serverId string = server.id
