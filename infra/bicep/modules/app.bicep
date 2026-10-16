// App Service (02 «Развёртывание и окружения», 06 «Ресурсы»): one Linux instance with Always On and a health check,
// VNet integration, managed identities and no secrets in settings. Production deploys through a staging slot; test
// runs on B1 without slots (Basic has none), and its deployment attaches the migrations identity only for that time.
param name string
param location string
param planSku string
@description('Production: the staging slot that runs only during deployments and alone carries the migrations identity.')
param stagingSlot bool
param subnetId string
param tenantId string
param databaseHost string
param migrationsIdentityId string
param migrationsIdentityClientId string
param migrationsIdentityName string
@description('The restore identity: the restore command reads the security log with it (RB-05); the service never uses it.')
param restoreIdentityId string
param restoreIdentityClientId string
param blobEndpoint string
param vaultName string
param vaultUri string
param dataProtectionKeyUri string
param insightsConnectionString string
@description('Client id of «Sikkerheit Portal»; empty until setup.sh has registered the application.')
param portalClientId string = ''
@description('Client id of «Sikkerheit Graph Reader»; empty until setup.sh has registered the application.')
param graphClientId string = ''

resource plan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: 'asp-${name}'
  location: location
  kind: 'linux'
  sku: { name: planSku }
  properties: { reserved: true }
}

var siteConfig = {
  linuxFxVersion: 'DOTNETCORE|10.0'
  appCommandLine: 'dotnet Sikkerheit.Host.dll'
  alwaysOn: true
  healthCheckPath: '/health'
  http20Enabled: true
  minTlsVersion: '1.2'
  ftpsState: 'Disabled'
  remoteDebuggingEnabled: false
  vnetRouteAllEnabled: true
}

resource site 'Microsoft.Web/sites@2024-04-01' = {
  name: 'app-${name}'
  location: location
  kind: 'app,linux'
  // The service signs in with the system identity; the restore identity is only for restore-replay (RB-05, step 3).
  identity: {
    type: 'SystemAssigned, UserAssigned'
    userAssignedIdentities: { '${restoreIdentityId}': {} }
  }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    clientAffinityEnabled: false
    virtualNetworkSubnetId: subnetId
    keyVaultReferenceIdentity: 'SystemAssigned'
    siteConfig: siteConfig
  }
}

// The staging slot runs only during deployments; it alone carries the migrations identity (02).
resource staging 'Microsoft.Web/sites/slots@2024-04-01' = if (stagingSlot) {
  parent: site
  name: 'staging'
  location: location
  kind: 'app,linux'
  identity: {
    type: 'SystemAssigned, UserAssigned'
    userAssignedIdentities: { '${migrationsIdentityId}': {} }
  }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    clientAffinityEnabled: false
    virtualNetworkSubnetId: subnetId
    keyVaultReferenceIdentity: 'SystemAssigned'
    siteConfig: siteConfig
  }
}

var common = {
  ASPNETCORE_ENVIRONMENT: 'Production'
  APPLICATIONINSIGHTS_CONNECTION_STRING: insightsConnectionString
  Database__EntraAuth: 'true'
  Database__AppRole: 'sikkerheit_app'
  Auth__Entra__TenantId: tenantId
  Auth__Entra__ClientId: portalClientId
  Auth__Entra__Credential: 'ManagedIdentity'
  M365__ClientId: graphClientId
  M365__CompanyTenantId: tenantId
  M365__KeyVaultUri: vaultUri
  M365__CertificateName: 'graph-reader'
  Storage__BlobServiceUri: blobEndpoint
  SecurityLog__ContainerUri: '${blobEndpoint}security-log'
  DataProtection__BlobUri: '${blobEndpoint}dataprotection/keys.xml'
  DataProtection__KeyVaultKeyId: dataProtectionKeyUri
  Cursors__Key: '@Microsoft.KeyVault(VaultName=${vaultName};SecretName=cursor-key)'
  Teams__WebhookUrl: '@Microsoft.KeyVault(VaultName=${vaultName};SecretName=teams-webhook)'
}

var productionHost = site.properties.defaultHostName
// staging! is safe: every use is guarded by stagingSlot, the condition of the slot itself.
var stagingHost = stagingSlot ? staging!.properties.defaultHostName : ''

resource productionSettings 'Microsoft.Web/sites/config@2024-04-01' = {
  parent: site
  name: 'appsettings'
  properties: union(common, {
    ConnectionStrings__Sikkerheit: 'Host=${databaseHost};Database=sikkerheit;Username=sikkerheit-app;Ssl Mode=VerifyFull;Maximum Pool Size=20'
    Hosting__PortalHosts__0: productionHost
    Auth__Entra__RedirectUri: 'https://${productionHost}/auth/callback'
    M365__ConsentRedirectUri: 'https://${productionHost}/consent-complete'
    Teams__PortalUrl: 'https://${productionHost}'
    Jobs__Enabled: 'true'
    Database__MigrateOnStart: 'false'
    Restore__ManagedIdentityClientId: restoreIdentityClientId
  })
}

resource stagingSettings 'Microsoft.Web/sites/slots/config@2024-04-01' = if (stagingSlot) {
  parent: staging
  name: 'appsettings'
  properties: union(common, {
    ConnectionStrings__Sikkerheit: 'Host=${databaseHost};Database=sikkerheit;Username=sikkerheit-staging;Ssl Mode=VerifyFull;Maximum Pool Size=10'
    Hosting__PortalHosts__0: stagingHost
    Auth__Entra__RedirectUri: 'https://${stagingHost}/auth/callback'
    M365__ConsentRedirectUri: 'https://${productionHost}/consent-complete'
    Teams__PortalUrl: 'https://${productionHost}'
    Jobs__Enabled: 'false'
    Database__MigrateOnStart: 'true'
    ConnectionStrings__SikkerheitOwner: 'Host=${databaseHost};Database=sikkerheit;Username=${migrationsIdentityName};Ssl Mode=VerifyFull'
    Database__OwnerIdentityClientId: migrationsIdentityClientId
    Database__AppPrincipals__0__Name: 'sikkerheit-app'
    Database__AppPrincipals__0__ObjectId: site.identity.principalId
    Database__AppPrincipals__1__Name: 'sikkerheit-staging'
    Database__AppPrincipals__1__ObjectId: staging!.identity.principalId
  })
}

// Settings that stay with their slot when slots are swapped.
resource sticky 'Microsoft.Web/sites/config@2024-04-01' = if (stagingSlot) {
  parent: site
  name: 'slotConfigNames'
  properties: {
    appSettingNames: [
      'ConnectionStrings__Sikkerheit', 'ConnectionStrings__SikkerheitOwner', 'Database__OwnerIdentityClientId'
      'Database__AppPrincipals__0__Name', 'Database__AppPrincipals__0__ObjectId', 'Database__AppPrincipals__1__Name'
      'Database__AppPrincipals__1__ObjectId', 'Hosting__PortalHosts__0', 'Auth__Entra__RedirectUri', 'M365__ConsentRedirectUri'
      'Teams__PortalUrl', 'Jobs__Enabled', 'Database__MigrateOnStart', 'Restore__ManagedIdentityClientId'
    ]
  }
}

output siteName string = site.name
output siteId string = site.id
output productionHost string = productionHost
output stagingHost string = stagingHost
output productionPrincipalId string = site.identity.principalId
output stagingPrincipalId string = stagingSlot ? staging!.identity.principalId : ''
