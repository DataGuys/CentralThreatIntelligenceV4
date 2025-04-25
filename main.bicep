// main.bicep
targetScope = 'subscription'

@description('Prefix for all resources')
param prefix string = 'cti'

@description('Environment (prod, dev, test)')
param environment string = 'prod'

@description('Primary Azure region')
param location string = 'eastus'

@description('Enable protection for non-Microsoft clouds')
param enableCrossCloudProtection bool = true

@description('Enable network security appliance integrations')
param enableNetworkProtection bool = true

@description('Enable EDR/XDR system integrations')
param enableEndpointProtection bool = true

@description('Table plan for Log Analytics')
@allowed(['Analytics', 'Basic', 'Standard'])
param tablePlan string = 'Analytics'

// Resource group
resource rg 'Microsoft.Resources/resourceGroups@2022-09-01' = {
  name: '${prefix}-${environment}-rg'
  location: location
  tags: {
    Environment: environment
    Solution: 'Central Threat Intelligence V4'
    Owner: 'Security Operations'
  }
}

// Deploy core resources
module coreResources 'modules/core-resources.bicep' = {
  scope: rg
  name: 'coreResources-deployment'
  params: {
    prefix: prefix
    environment: environment
    location: location
    tagsMap: {
      Environment: environment
      Solution: 'Central Threat Intelligence V4'
      Owner: 'Security Operations'
    }
  }
}

// Deploy unified schema tables
module ctiTables 'modules/cti-tables.bicep' = {
  scope: rg
  name: 'ctiTables-deployment'
  params: {
    workspaceName: coreResources.outputs.workspaceName
    tablePlan: tablePlan
    location: location
  }
  dependsOn: [
    coreResources
  ]
}

// Deploy the inoculation engine
module inoculationEngine 'modules/inoculation-engine.bicep' = {
  scope: rg
  name: 'inoculationEngine-deployment'
  params: {
    prefix: prefix
    environment: environment
    location: location
    managedIdentityId: coreResources.outputs.managedIdentityId
    logAnalyticsConnectionId: coreResources.outputs.logAnalyticsConnectionId
    logAnalyticsQueryConnectionId: coreResources.outputs.logAnalyticsQueryConnectionId
    ctiWorkspaceName: coreResources.outputs.workspaceName
    ctiWorkspaceId: coreResources.outputs.workspaceId
    keyVaultName: coreResources.outputs.keyVaultName
    tags: {
      Environment: environment
      Solution: 'Central Threat Intelligence V4'
      Component: 'Inoculation Engine'
    }
  }
  dependsOn: [
    ctiTables
  ]
}

// Deploy Microsoft connectors
module microsoftConnectors 'modules/microsoft-connectors.bicep' = {
  scope: rg
  name: 'microsoftConnectors-deployment'
  params: {
    location: location
    managedIdentityId: coreResources.outputs.managedIdentityId
    logAnalyticsConnectionId: coreResources.outputs.logAnalyticsConnectionId
    logAnalyticsQueryConnectionId: coreResources.outputs.logAnalyticsQueryConnectionId
    microsoftGraphConnectionId: coreResources.outputs.microsoftGraphConnectionId
    ctiWorkspaceName: coreResources.outputs.workspaceName
    ctiWorkspaceId: coreResources.outputs.workspaceId
    keyVaultName: coreResources.outputs.keyVaultName
    clientSecretName: 'CTI-APP-SECRET'
    appClientId: coreResources.outputs.appClientId
    tenantId: subscription().tenantId
    tags: {
      Environment: environment
      Solution: 'Central Threat Intelligence V4'
      Component: 'Microsoft Connectors'
    }
  }
  dependsOn: [
    inoculationEngine
  ]
}

// Deploy AWS connectors (conditional)
module awsConnectors 'modules/aws-connectors.bicep' = if (enableCrossCloudProtection) {
  scope: rg
  name: 'awsConnectors-deployment'
  params: {
    location: location
    managedIdentityId: coreResources.outputs.managedIdentityId
    logAnalyticsConnectionId: coreResources.outputs.logAnalyticsConnectionId
    logAnalyticsQueryConnectionId: coreResources.outputs.logAnalyticsQueryConnectionId
    ctiWorkspaceName: coreResources.outputs.workspaceName
    ctiWorkspaceId: coreResources.outputs.workspaceId
    keyVaultName: coreResources.outputs.keyVaultName
    awsSecretName: 'AWS-CREDENTIALS'
    tags: {
      Environment: environment
      Solution: 'Central Threat Intelligence V4'
      Component: 'AWS Connectors'
    }
  }
  dependsOn: [
    inoculationEngine
  ]
}

// Deploy GCP connectors (conditional)
module gcpConnectors 'modules/gcp-connectors.bicep' = if (enableCrossCloudProtection) {
  scope: rg
  name: 'gcpConnectors-deployment'
  params: {
    location: location
    managedIdentityId: coreResources.outputs.managedIdentityId
    logAnalyticsConnectionId: coreResources.outputs.logAnalyticsConnectionId
    logAnalyticsQueryConnectionId: coreResources.outputs.logAnalyticsQueryConnectionId
    ctiWorkspaceName: coreResources.outputs.workspaceName
    ctiWorkspaceId: coreResources.outputs.workspaceId
    keyVaultName: coreResources.outputs.keyVaultName
    gcpSecretName: 'GCP-CREDENTIALS'
    tags: {
      Environment: environment
      Solution: 'Central Threat Intelligence V4'
      Component: 'GCP Connectors'
    }
  }
  dependsOn: [
    inoculationEngine
  ]
}

// Deploy network security connectors (conditional)
module networkConnectors 'modules/network-connectors.bicep' = if (enableNetworkProtection) {
  scope: rg
  name: 'networkConnectors-deployment'
  params: {
    location: location
    managedIdentityId: coreResources.outputs.managedIdentityId
    logAnalyticsConnectionId: coreResources.outputs.logAnalyticsConnectionId
    logAnalyticsQueryConnectionId: coreResources.outputs.logAnalyticsQueryConnectionId
    ctiWorkspaceName: coreResources.outputs.workspaceName
    ctiWorkspaceId: coreResources.outputs.workspaceId
    keyVaultName: coreResources.outputs.keyVaultName
    tags: {
      Environment: environment
      Solution: 'Central Threat Intelligence V4'
      Component: 'Network Connectors'
    }
  }
  dependsOn: [
    inoculationEngine
  ]
}

// Deploy EDR/XDR connectors (conditional)
module edrConnectors 'modules/edr-connectors.bicep' = if (enableEndpointProtection) {
  scope: rg
  name: 'edrConnectors-deployment'
  params: {
    location: location
    managedIdentityId: coreResources.outputs.managedIdentityId
    logAnalyticsConnectionId: coreResources.outputs.logAnalyticsConnectionId
    logAnalyticsQueryConnectionId: coreResources.outputs.logAnalyticsQueryConnectionId
    ctiWorkspaceName: coreResources.outputs.workspaceName
    ctiWorkspaceId: coreResources.outputs.workspaceId
    keyVaultName: coreResources.outputs.keyVaultName
    tags: {
      Environment: environment
      Solution: 'Central Threat Intelligence V4'
      Component: 'EDR Connectors'
    }
  }
  dependsOn: [
    inoculationEngine
  ]
}

// Deploy risk assessment engine
module riskAssessmentEngine 'modules/risk-assessment-engine.bicep' = {
  scope: rg
  name: 'riskAssessmentEngine-deployment'
  params: {
    location: location
    managedIdentityId: coreResources.outputs.managedIdentityId
    logAnalyticsConnectionId: coreResources.outputs.logAnalyticsConnectionId
    logAnalyticsQueryConnectionId: coreResources.outputs.logAnalyticsQueryConnectionId
    ctiWorkspaceName: coreResources.outputs.workspaceName
    ctiWorkspaceId: coreResources.outputs.workspaceId
    keyVaultName: coreResources.outputs.keyVaultName
    tags: {
      Environment: environment
      Solution: 'Central Threat Intelligence V4'
      Component: 'Risk Assessment Engine'
    }
  }
  dependsOn: [
    ctiTables
  ]
}

// Deploy effectiveness measurement engine
module effectivenessEngine 'modules/effectiveness-engine.bicep' = {
  scope: rg
  name: 'effectivenessEngine-deployment'
  params: {
    location: location
    managedIdentityId: coreResources.outputs.managedIdentityId
    logAnalyticsConnectionId: coreResources.outputs.logAnalyticsConnectionId
    logAnalyticsQueryConnectionId: coreResources.outputs.logAnalyticsQueryConnectionId
    ctiWorkspaceName: coreResources.outputs.workspaceName
    ctiWorkspaceId: coreResources.outputs.workspaceId
    keyVaultName: coreResources.outputs.keyVaultName
    tags: {
      Environment: environment
      Solution: 'Central Threat Intelligence V4'
      Component: 'Effectiveness Engine'
    }
  }
  dependsOn: [
    microsoftConnectors
    awsConnectors
    gcpConnectors
    networkConnectors
    edrConnectors
  ]
}

// Deploy workbooks and dashboards
module dashboards 'modules/dashboards.bicep' = {
  scope: rg
  name: 'dashboards-deployment'
  params: {
    location: location
    workspaceId: coreResources.outputs.workspaceId
    tags: {
      Environment: environment
      Solution: 'Central Threat Intelligence V4'
      Component: 'Dashboards'
    }
  }
  dependsOn: [
    effectivenessEngine
  ]
}

// Output key resource identifiers
output resourceGroupName string = rg.name
output workspaceId string = coreResources.outputs.workspaceId
output workspaceName string = coreResources.outputs.workspaceName
output keyVaultName string = coreResources.outputs.keyVaultName
output managedIdentityName string = coreResources.outputs.managedIdentityName
