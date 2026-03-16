extension MicrosoftSecurity

// targetScope = 'tenant'

resource detectionRule 'Microsoft.Security/detectionRules@2026-01-01-preview' = {
  displayName: 'test bicep detection rule3'
  isEnabled: true
  queryCondition: {
    queryText: 'SigninLogs\r\n| take 2'
  }
  schedule: {
    period: '24H'
  }
  detectionAction: {
    alertTemplate: {
      title: 'test bicep detection rule 3 {{ResultSignature}}'
      description: 'test bicep detection rule with Sentinel data {{Category}}'
      severity: 'medium'
      category: 'Exfiltration'
      recommendedActions: 'test bicep detection rule 3'
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
