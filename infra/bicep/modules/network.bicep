// VNet with the App Service integration subnet and the delegated PostgreSQL subnet; private DNS for the server.
param name string
param location string

resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: 'vnet-${name}'
  location: location
  properties: {
    addressSpace: { addressPrefixes: [ '10.40.0.0/16' ] }
    subnets: [
      {
        name: 'app'
        properties: {
          addressPrefix: '10.40.1.0/24'
          delegations: [ { name: 'web', properties: { serviceName: 'Microsoft.Web/serverFarms' } } ]
        }
      }
      {
        name: 'database'
        properties: {
          addressPrefix: '10.40.2.0/24'
          delegations: [ { name: 'postgres', properties: { serviceName: 'Microsoft.DBforPostgreSQL/flexibleServers' } } ]
        }
      }
    ]
  }
}

resource dns 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: '${name}.private.postgres.database.azure.com'
  location: 'global'
}

resource link 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: dns
  name: 'vnet-${name}'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: { id: vnet.id }
  }
}

output appSubnetId string = '${vnet.id}/subnets/app'
output databaseSubnetId string = '${vnet.id}/subnets/database'
output dnsZoneId string = dns.id
