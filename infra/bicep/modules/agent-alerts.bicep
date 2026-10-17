// P2 (RB-08/RB-12). Fleet conditions are also checked by agent_health_check and the common Error alert.
param name string
param location string
param insightsId string
param actionGroupId string
param enabled bool

var rules = [
  {
    suffix: 'agent-failures'
    description: 'RB-08/RB-12: dropped batches, rejected configuration, abandoned collectors or a recent crash.'
    query: '''
      customMetrics
      | where name in ("agent.dropped_batches", "agent.config_rejected", "agent.abandoned_collectors", "agent.recent_crashes")
      | summarize signal=max(coalesce(valueMax, value)) by name, organizationId=tostring(customDimensions.organizationId), deviceId=tostring(customDimensions.deviceId)
      | where signal > 0
      '''
  }
  {
    suffix: 'agent-restarts'
    description: 'RB-08: more than three service starts reported by one device.'
    query: '''
      customMetrics
      | where name == "agent.service_starts"
      | summarize signal=max(coalesce(valueMax, value)) by organizationId=tostring(customDimensions.organizationId), deviceId=tostring(customDimensions.deviceId)
      | where signal > 3
      '''
  }
  {
    suffix: 'agent-memory'
    description: 'RB-08: agent memory above the 150 MB budget.'
    query: '''
      customMetrics
      | where name == "agent.working_set_mb"
      | summarize signal=max(coalesce(valueMax, value)) by organizationId=tostring(customDimensions.organizationId), deviceId=tostring(customDimensions.deviceId)
      | where signal > 150
      '''
  }
  {
    suffix: 'agent-rejected-batches'
    description: 'RB-12: more than 5 percent of submitted batches refused in 24 hours.'
    query: '''
      customMetrics
      | where name == "agent.batches"
      | extend outcome=tostring(customDimensions.outcome), samples=coalesce(valueSum, value)
      | summarize total=sum(samples), rejected=sumif(samples, outcome !in ("accepted", "duplicate")) by organizationId=tostring(customDimensions.organizationId)
      | where total > 0 and rejected * 100.0 / total > 5
      '''
  }
  {
    suffix: 'agent-intake'
    description: 'RB-12: scan intake p95 over 2 seconds or more than 1 percent server errors.'
    query: '''
      requests
      | where url has "/api/v1/agent/scans"
      | summarize p95=percentile(duration, 95), total=count(), errors=countif(toint(resultCode) >= 500)
      // Application Insights requests.duration is a number in milliseconds.
      | where total > 0 and (p95 > 2000 or errors * 100.0 / total > 1)
      '''
  }
]

resource alerts 'Microsoft.Insights/scheduledQueryRules@2023-12-01' = [for rule in rules: {
  name: 'alert-${name}-${rule.suffix}'
  location: location
  kind: 'LogAlert'
  properties: {
    description: rule.description
    severity: 2
    enabled: enabled
    scopes: [ insightsId ]
    evaluationFrequency: 'PT15M'
    windowSize: 'P1D'
    autoMitigate: true
    criteria: {
      allOf: [
        {
          query: rule.query
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
          failingPeriods: { numberOfEvaluationPeriods: 1, minFailingPeriodsToAlert: 1 }
        }
      ]
    }
    actions: { actionGroups: [ actionGroupId ] }
  }
}]
