// AZ10 Azure twin: one Foundry resource + project, NO model deployment, in a resource group you own.
// Based on Microsoft's foundry-samples 00-basic main.bicep (which ships with disableLocalAuth: false).
// Cost: nothing here is billed by the hour; see README Step 8.
targetScope = 'resourceGroup'

@description('Globally unique, lowercase letters, digits and hyphens, e.g. az10-twin-<initials><4 digits>')
param name string
param location string = resourceGroup().location
@description('false = keys work (Contoso today); true = Microsoft Entra ID only (the fix)')
param disableLocalAuth bool = false

resource foundry 'Microsoft.CognitiveServices/accounts@2025-06-01' = {
  name: name
  location: location
  kind: 'AIServices'
  sku: {
    name: 'S0'
  }
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    allowProjectManagement: true
    customSubDomainName: name
    disableLocalAuth: disableLocalAuth
  }
}

resource project 'Microsoft.CognitiveServices/accounts/projects@2025-06-01' = {
  parent: foundry
  name: '${name}-proj'
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {}
}

output accountId string = foundry.id
