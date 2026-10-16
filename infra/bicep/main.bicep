// Sikkerheit in Azure (06 «Azure и эксплуатация»): one resource group per environment.
targetScope = 'resourceGroup'

@allowed([ 'prod', 'test' ])
param environmentName string = 'prod'
@description('Norway East; Sweden Central when PostgreSQL Flexible Server cannot be created there (06).')
param location string = resourceGroup().location
param alertEmail string
@description('Client id of «Sikkerheit Portal» from setup.sh; empty on the first pass.')
param portalClientId string = ''
@description('Client id of «Sikkerheit Graph Reader» from setup.sh; empty on the first pass.')
param graphClientId string = ''
param monthlyBudget int = 200
param budgetStartDate string = '${utcNow('yyyy-MM')}-01'

var name = 'sikkerheit-${environmentName}'
var unique = '${name}-${take(uniqueString(resourceGroup().id), 5)}'
var tenantId = subscription().tenantId

module monitoring 'modules/monitoring.bicep' = {
  name: 'monitoring'
  params: { name: name, location: location, alertEmail: alertEmail, dailyCapGb: environmentName == 'prod' ? 2 : 1 }
}

module network 'modules/network.bicep' = {
  name: 'network'
  params: { name: name, location: location }
}

resource migrations 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-${name}-migrations'
  location: location
}

module postgres 'modules/postgres.bicep' = {
  name: 'postgres'
  params: {
    name: unique
    location: location
    tenantId: tenantId
    skuName: 'Standard_B1ms'
    subnetId: network.outputs.databaseSubnetId
    dnsZoneId: network.outputs.dnsZoneId
    adminPrincipalId: migrations.properties.principalId
    adminPrincipalName: migrations.name
  }
}

module storage 'modules/storage.bicep' = {
  name: 'storage'
  params: { name: unique, location: location }
}

module vault 'modules/keyvault.bicep' = {
  name: 'keyvault'
  params: { name: unique, location: location, tenantId: tenantId, workspaceId: monitoring.outputs.workspaceId }
}

module app 'modules/app.bicep' = {
  name: 'app'
  params: {
    name: unique
    location: location
    planSku: environmentName == 'prod' ? 'P0v3' : 'B1'
    subnetId: network.outputs.appSubnetId
    tenantId: tenantId
    databaseHost: postgres.outputs.host
    migrationsIdentityId: migrations.id
    migrationsIdentityClientId: migrations.properties.clientId
    migrationsIdentityName: migrations.name
    blobEndpoint: storage.outputs.blobEndpoint
    vaultName: vault.outputs.vaultName
    vaultUri: vault.outputs.vaultUri
    dataProtectionKeyUri: vault.outputs.dataProtectionKeyUri
    insightsConnectionString: monitoring.outputs.connectionString
    portalClientId: portalClientId
    graphClientId: graphClientId
  }
}

module access 'modules/access.bicep' = {
  name: 'access'
  params: {
    storageAccountName: storage.outputs.accountName
    vaultName: vault.outputs.vaultName
    dataProtectionKeyName: vault.outputs.dataProtectionKeyName
    principalIds: [ app.outputs.productionPrincipalId, app.outputs.stagingPrincipalId ]
  }
}

module alerts 'modules/alerts.bicep' = {
  name: 'alerts'
  params: {
    name: name
    location: location
    siteId: app.outputs.siteId
    insightsId: monitoring.outputs.insightsId
    actionGroupId: monitoring.outputs.actionGroupId
    alertEmail: alertEmail
    monthlyBudget: monthlyBudget
    budgetStartDate: budgetStartDate
  }
}

output siteName string = app.outputs.siteName
output productionHost string = app.outputs.productionHost
output stagingHost string = app.outputs.stagingHost
output productionPrincipalId string = app.outputs.productionPrincipalId
output stagingPrincipalId string = app.outputs.stagingPrincipalId
output vaultName string = vault.outputs.vaultName
output storageAccountName string = storage.outputs.accountName
output databaseHost string = postgres.outputs.host
