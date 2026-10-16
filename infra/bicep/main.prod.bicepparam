using 'main.bicep'

param environmentName = 'prod'
param alertEmail = readEnvironmentVariable('SIKKERHEIT_ALERT_EMAIL')
param portalClientId = readEnvironmentVariable('SIKKERHEIT_PORTAL_CLIENT_ID', '')
param graphClientId = readEnvironmentVariable('SIKKERHEIT_GRAPH_CLIENT_ID', '')
param monthlyBudget = 200
