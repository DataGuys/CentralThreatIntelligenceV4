// modules/cti-tables.bicep
@description('Name of the Log Analytics workspace')
param workspaceName string

@description('Table plan: Analytics, Basic, or Standard')
@allowed(['Analytics', 'Basic', 'Standard'])
param tablePlan string = 'Analytics'

@description('Location for all resources')
param location string = resourceGroup().location

// Main threat intelligence table - unified schema
resource threatIntelIndicatorTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  name: '${workspaceName}/CTI_ThreatIntelIndicator_CL'
  properties: {
    schema: {
      name: 'CTI_ThreatIntelIndicator_CL'
      columns: [
        { name: 'TimeGenerated', type: 'datetime' }
        { name: 'Type_s', type: 'string' }          // ip-addr, domain-name, url, file-sha256, etc.
        { name: 'Value_s', type: 'string' }         // Actual indicator value
        { name: 'Pattern_s', type: 'string' }       // STIX pattern (if applicable)
        { name: 'PatternType_s', type: 'string' }   // Pattern type (STIX, regex, etc.)
        { name: 'Name_s', type: 'string' }          // Human-readable name
        { name: 'Description_s', type: 'string' }   // Description
        { name: 'Action_s', type: 'string' }        // alert, block, monitor
        { name: 'Confidence_d', type: 'double' }    // 0-100 confidence score
        { name: 'ValidFrom_t', type: 'datetime' }   // Start validity
        { name: 'ValidUntil_t', type: 'datetime' }  // End validity
        { name: 'CreatedTimeUtc_t', type: 'datetime' } // Creation time
        { name: 'UpdatedTimeUtc_t', type: 'datetime' } // Last update time
        { name: 'Source_s', type: 'string' }        // Source feed or system
        { name: 'SourceRef_s', type: 'string' }     // Reference ID in source system
        { name: 'KillChainPhases_s', type: 'string' } // Comma-separated kill chain phases
        { name: 'Labels_s', type: 'string' }        // Comma-separated labels/tags
        { name: 'ThreatType_s', type: 'string' }    // C2, malware, phishing, etc.
        { name: 'TLP_s', type: 'string' }           // TLP:RED, TLP:AMBER, etc.
        { name: 'DistributionTargets_s', type: 'string' } // Comma-separated list of targets
        { name: 'EnforcementStatus_s', type: 'string' }   // Distribution status tracking
        { name: 'ThreatActorName_s', type: 'string' }     // Associated threat actor
        { name: 'CampaignName_s', type: 'string' }        // Associated campaign
        { name: 'Active_b', type: 'bool' }                // Is active flag
        { name: 'ObjectId_g', type: 'guid' }              // Object ID
        { name: 'IndicatorId_g', type: 'guid' }           // Indicator ID
        { name: 'RiskScore_d', type: 'double' }           // 0-100 risk score
        { name: 'ReputationScore_d', type: 'double' }     // 0-100 reputation score
        { name: 'PrevalenceScore_d', type: 'double' }     // 0-100 prevalence score
        { name: 'RelevanceScore_d', type: 'double' }      // 0-100 relevance score
        { name: 'EffectivenessScore_d', type: 'double' }  // 0-100 effectiveness score
        { name: 'MatchCount_d', type: 'double' }          // Number of matches
        { name: 'LastMatchTime_t', type: 'datetime' }     // Last match time
        { name: 'EnrichmentSources_s', type: 'string' }   // Comma-separated enrichment sources
        { name: 'AdditionalFields', type: 'dynamic' }     // Additional fields as JSON
      ]
    }
    retentionInDays: 90
    plan: tablePlan
  }
}

// Distribution targets mapping table
resource distributionTargetsTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  name: '${workspaceName}/CTI_DistributionTargets_CL'
  properties: {
    schema: {
      name: 'CTI_DistributionTargets_CL'
      columns: [
        { name: 'TimeGenerated', type: 'datetime' }
        { name: 'TargetId_g', type: 'guid' }
        { name: 'TargetType_s', type: 'string' }        // Microsoft, AWS, GCP, Network, EDR
        { name: 'TargetName_s', type: 'string' }        // Specific target name
        { name: 'TargetDescription_s', type: 'string' } // Description
        { name: 'ConnectionDetails_s', type: 'string' } // Connection details (encrypted)
        { name: 'ApiEndpoint_s', type: 'string' }       // API endpoint
        { name: 'MinConfidence_d', type: 'double' }     // Minimum confidence threshold
        { name: 'TLPLevels_s', type: 'string' }         // Allowed TLP levels
        { name: 'IndicatorTypes_s', type: 'string' }    // Supported indicator types
        { name: 'ActionMapping_s', type: 'string' }     // Action mapping as JSON
        { name: 'LastSyncTime_t', type: 'datetime' }    // Last successful sync
        { name: 'SyncInterval_d', type: 'double' }      // Sync interval in minutes
        { name: 'Status_s', type: 'string' }            // Enabled, Disabled, Error
        { name: 'Active_b', type: 'bool' }              // Is active flag
        { name: 'Configuration', type: 'dynamic' }      // Additional config as JSON
      ]
    }
    retentionInDays: 90
    plan: tablePlan
  }
}

// Distribution history table
resource distributionHistoryTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  name: '${workspaceName}/CTI_DistributionHistory_CL'
  properties: {
    schema: {
      name: 'CTI_DistributionHistory_CL'
      columns: [
        { name: 'TimeGenerated', type: 'datetime' }
        { name: 'DistributionId_g', type: 'guid' }
        { name: 'IndicatorId_g', type: 'guid' }
        { name: 'TargetId_g', type: 'guid' }
        { name: 'TargetType_s', type: 'string' }
        { name: 'TargetName_s', type: 'string' }
        { name: 'Status_s', type: 'string' }          // Success, Failure, Pending
        { name: 'StatusDetails_s', type: 'string' }   // Detailed status
        { name: 'Action_s', type: 'string' }          // alert, block, monitor
        { name: 'ExternalId_s', type: 'string' }      // External ID in target system
        { name: 'ExpirationTime_t', type: 'datetime' }// Expiration in target system
        { name: 'ResponseTime_d', type: 'double' }    // API response time in ms
        { name: 'Etag_s', type: 'string' }            // For updates/versioning
        { name: 'AdditionalInfo', type: 'dynamic' }   // Additional info as JSON
      ]
    }
    retentionInDays: 90
    plan: tablePlan
  }
}

// Effectiveness metrics table
resource effectivenessMetricsTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  name: '${workspaceName}/CTI_EffectivenessMetrics_CL'
  properties: {
    schema: {
      name: 'CTI_EffectivenessMetrics_CL'
      columns: [
        { name: 'TimeGenerated', type: 'datetime' }
        { name: 'MetricId_g', type: 'guid' }
        { name: 'IndicatorId_g', type: 'guid' }      // Related indicator ID
        { name: 'TargetId_g', type: 'guid' }         // Related target ID
        { name: 'MetricType_s', type: 'string' }     // TPR, FPR, TTD, etc.
        { name: 'MetricValue_d', type: 'double' }    // Numeric value
        { name: 'TimeFrame_s', type: 'string' }      // Daily, Weekly, Monthly
        { name: 'SourceId_s', type: 'string' }       // Source of the metric
        { name: 'TargetType_s', type: 'string' }     // Target type
        { name: 'IndicatorType_s', type: 'string' }  // Indicator type
        { name: 'ThreatType_s', type: 'string' }     // Threat type
        { name: 'Details', type: 'dynamic' }         // Additional details as JSON
      ]
    }
    retentionInDays: 90
    plan: tablePlan
  }
}

output tablesCreated array = [
  threatIntelIndicatorTable.name
  distributionTargetsTable.name
  distributionHistoryTable.name
  effectivenessMetricsTable.name
]
