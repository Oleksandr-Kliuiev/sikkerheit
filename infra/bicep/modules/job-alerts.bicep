// Initial operational thresholds. Validate metric ingestion, KQL and delivery in Azure before relying on them.
param name string
param location string
param insightsId string
param actionGroupId string

var rules = [
  {
    suffix: 'job-backlog'
    description: 'Ready jobs wait over 15 minutes (maintenance) or 3 hours (collections), in three five-minute periods.'
    query: '''
      customMetrics
      | where name == "sikkerheit.jobs.oldest_ready_age"
      | extend lane=tostring(customDimensions.lane)
      | summarize age=max(coalesce(valueMax, value)) by bin(timestamp, 5m), lane
      | summarize periods=countif((lane == "maintenance" and age > 900) or (lane == "collection" and age > 10800)) by lane
      | where periods >= 3
      '''
  }
  {
    suffix: 'graph-throttling'
    description: 'More than 10 percent Graph subrequests throttled, with at least 100 observed requests in 30 minutes.'
    query: '''
      customMetrics
      | where name == "sikkerheit.graph.responses" and tostring(customDimensions.kind) == "request"
      | extend status=tostring(customDimensions.status), samples=coalesce(valueSum, value)
      | summarize total=sum(samples), throttled=sumif(samples, status == "429")
      | where total >= 100 and throttled * 100.0 / total > 10
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
    enabled: true
    scopes: [ insightsId ]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT30M'
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
