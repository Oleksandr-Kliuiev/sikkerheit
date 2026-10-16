// Log Analytics and Application Insights (06 «Наблюдаемость и оповещения»): 90 days, a daily cap, alerts by email.
param name string
param location string
param alertEmail string
param dailyCapGb int

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: 'log-${name}'
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 90
    workspaceCapping: { dailyQuotaGb: dailyCapGb }
  }
}

resource insights 'Microsoft.Insights/components@2020-02-02' = {
  name: 'appi-${name}'
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: workspace.id
    DisableIpMasking: false
    RetentionInDays: 90
  }
}

resource actions 'Microsoft.Insights/actionGroups@2023-01-01' = {
  name: 'ag-${name}'
  location: 'global'
  properties: {
    groupShortName: 'sikkerheit'
    enabled: true
    emailReceivers: [
      { name: 'operations', emailAddress: alertEmail, useCommonAlertSchema: true }
    ]
  }
}

output workspaceId string = workspace.id
output insightsId string = insights.id
output connectionString string = insights.properties.ConnectionString
output actionGroupId string = actions.id
