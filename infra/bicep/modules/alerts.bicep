// Alerts of 06 «Наблюдаемость и оповещения» that the platform can see directly, and the monthly budget (RB-14).
param name string
param location string
param siteId string
param insightsId string
param actionGroupId string
param alertEmail string
param monthlyBudget int
param budgetStartDate string

resource serverErrors 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'alert-${name}-5xx'
  location: 'global'
  properties: {
    description: 'Server errors of the service (share of 5xx).'
    severity: 2
    enabled: true
    scopes: [ siteId ]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        { name: 'http5xx', metricName: 'Http5xx', operator: 'GreaterThan', threshold: 5, timeAggregation: 'Total', criterionType: 'StaticThresholdCriterion' }
      ]
    }
    actions: [ { actionGroupId: actionGroupId } ]
  }
}

resource health 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'alert-${name}-health'
  location: 'global'
  properties: {
    description: 'The health check of the service fails.'
    severity: 1
    enabled: true
    scopes: [ siteId ]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        { name: 'health', metricName: 'HealthCheckStatus', operator: 'LessThan', threshold: 100, timeAggregation: 'Average', criterionType: 'StaticThresholdCriterion' }
      ]
    }
    actions: [ { actionGroupId: actionGroupId } ]
  }
}

// Failed jobs and reports, refused security log writes and Graph credential errors are logged as errors (RB-04).
resource errors 'Microsoft.Insights/scheduledQueryRules@2023-03-15-preview' = {
  name: 'alert-${name}-errors'
  location: location
  properties: {
    description: 'Errors in the service log: failed jobs or reports, security log writes, credential errors.'
    severity: 2
    enabled: true
    scopes: [ insightsId ]
    evaluationFrequency: 'PT15M'
    windowSize: 'PT15M'
    criteria: {
      allOf: [
        {
          query: 'traces | where severityLevel >= 3 | summarize count()'
          timeAggregation: 'Total'
          metricMeasureColumn: 'count_'
          operator: 'GreaterThan'
          threshold: 0
          failingPeriods: { numberOfEvaluationPeriods: 1, minFailingPeriodsToAlert: 1 }
        }
      ]
    }
    actions: { actionGroups: [ actionGroupId ] }
  }
}

resource budget 'Microsoft.Consumption/budgets@2023-11-01' = {
  name: 'budget-${name}'
  properties: {
    category: 'Cost'
    amount: monthlyBudget
    timeGrain: 'Monthly'
    timePeriod: { startDate: budgetStartDate }
    notifications: {
      actual80: { enabled: true, operator: 'GreaterThanOrEqualTo', threshold: 80, contactEmails: [ alertEmail ], thresholdType: 'Actual' }
      actual100: { enabled: true, operator: 'GreaterThanOrEqualTo', threshold: 100, contactEmails: [ alertEmail ], thresholdType: 'Actual' }
    }
  }
}
