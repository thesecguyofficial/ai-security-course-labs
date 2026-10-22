// A $5 monthly budget on the twin's resource group: alert at 50 % actual and 100 % forecast.
// A budget ALERTS; it never stops anything (lesson 10.5).
targetScope = 'resourceGroup'

param email string
@description('First day of the current month, yyyy-MM-01')
param startDate string

resource budget 'Microsoft.Consumption/budgets@2024-08-01' = {
  name: 'az10-twin-budget'
  properties: {
    amount: 5
    category: 'Cost'
    timeGrain: 'Monthly'
    timePeriod: {
      startDate: startDate
    }
    notifications: {
      actual50: {
        enabled: true
        operator: 'GreaterThan'
        threshold: 50
        thresholdType: 'Actual'
        contactEmails: [
          email
        ]
      }
      forecast100: {
        enabled: true
        operator: 'GreaterThan'
        threshold: 100
        thresholdType: 'Forecasted'
        contactEmails: [
          email
        ]
      }
    }
  }
}
