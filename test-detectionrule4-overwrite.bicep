extension MicrosoftSecurity

// targetScope = 'tenant'

resource detectionRule 'Microsoft.Security/detectionRules@2026-01-01-preview' = {
  displayName: 'test bicep detection rule4.4'
  isEnabled: true
  queryCondition: {
    queryText: 'SigninLogs\r\n| take 2'
  }
  schedule: {
    period: '24H'
  }
  detectionAction: {
    alertTemplate: {
      title: 'test bicep detection rule4'
      description: 'test bicep detection rule4'
      severity: 'medium'
      category: 'Exfiltration'
      recommendedActions: 'test bicep detection rule 4'
      mitreTechniques: []      
      impactedAssets: [
        {
          '@odata.type': '#microsoft.graph.security.impactedUserAsset'
          identifier: 'servicePrincipalId'
        }
]
    }
    responseActions: []
  }
}
