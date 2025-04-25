// modules/inoculation-engine.bicep
param location string
param prefix string = 'cti'
param environment string = 'prod'
param managedIdentityId string
param logAnalyticsConnectionId string
param logAnalyticsQueryConnectionId string
param ctiWorkspaceName string
param ctiWorkspaceId string
param keyVaultName string
param tags object = {}

// The core inoculation engine - decides where indicators should be distributed
resource inoculationEngine 'Microsoft.Logic/workflows@2019-05-01' = {
  name: '${prefix}-InoculationEngine-${environment}'
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentityId}': {}
    }
  }
  properties: {
    state: 'Enabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {
        '$connections': {
          defaultValue: {}
          type: 'Object'
        }
        workspaceName: {
          defaultValue: ctiWorkspaceName
          type: 'String'
        }
      }
      triggers: {
        Recurrence: {
          recurrence: {
            frequency: 'Minute'
            interval: 5
          }
          type: 'Recurrence'
        }
      }
      actions: {
        Initialize_Variables: {
          runAfter: {}
          type: 'InitializeVariable'
          inputs: {
            variables: [
              {
                name: 'allPlatforms',
                type: 'array',
                value: [
                  'Microsoft Defender XDR',
                  'Microsoft Sentinel',
                  'Exchange Online',
                  'Microsoft Security Copilot',
                  'Entra ID',
                  'AWS Security Hub',
                  'AWS Network Firewall',
                  'AWS WAF',
                  'GCP Security Command Center',
                  'GCP Cloud Armor',
                  'Palo Alto',
                  'Cisco',
                  'Fortinet',
                  'Check Point',
                  'CrowdStrike',
                  'Carbon Black',
                  'SentinelOne'
                ]
              }
            ]
          }
        },
        Get_New_Indicators: {
          runAfter: {
            Initialize_Variables: [
              'Succeeded'
            ]
          },
          type: 'ApiConnection',
          inputs: {
            body: 'CTI_ThreatIntelIndicator_CL \n| where TimeGenerated > ago(15m) and Active_b == true and isnotempty(Value_s)\n| where isempty(EnforcementStatus_s) or EnforcementStatus_s == "Pending"\n| project TimeGenerated, Type_s, Value_s, Name_s, Description_s, Action_s, Confidence_d, \nValidFrom_t, ValidUntil_t, TLP_s, ThreatType_s, DistributionTargets_s, IndicatorId_g, \nRiskScore_d, EnforcementStatus_s',
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuremonitorlogs\'][\'connectionId\']'
              }
            },
            method: 'post',
            path: '/queryData',
            queries: {
              resourcegroups: '@resourceGroup().name',
              resourcename: '@{parameters(\'workspaceName\')}',
              resourcetype: 'Log Analytics Workspace',
              subscriptions: '@{subscription().subscriptionId}',
              timerange: 'Last 15 minutes'
            }
          }
        },
        For_Each_Indicator: {
          foreach: '@body(\'Get_New_Indicators\').tables[0].rows',
          actions: {
            // Tier 1: High Confidence + Green/White TLP → Auto-distribute everywhere
            Process_Tier1_Indicators: {
              type: 'If',
              expression: {
                and: [
                  {
                    greaterOrEquals: ['@item()[6]', 85] // Confidence >= 85
                  },
                  {
                    or: [
                      { equals: ['@item()[9]', 'TLP:GREEN'] },
                      { equals: ['@item()[9]', 'TLP:WHITE'] }
                    ]
                  }
                ]
              },
              actions: {
                Set_Enforcement_Status_Processing: {
                  runAfter: {},
                  type: 'ApiConnection',
                  inputs: {
                    body: 'let indicatorId = "@{item()[12]}";\nlet now = now();\nCTI_ThreatIntelIndicator_CL\n| where IndicatorId_g == indicatorId\n| extend EnforcementStatus_s = "Processing"\n| extend UpdatedTimeUtc_t = now',
                    host: {
                      connection: {
                        name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                      }
                    },
                    method: 'post',
                    path: '/api/logs'
                  }
                },
                Distribute_to_All_Targets: {
                  runAfter: {
                    Set_Enforcement_Status_Processing: [
                      'Succeeded'
                    ]
                  },
                  type: 'ApiConnection',
                  inputs: {
                    host: {
                      connection: {
                        name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                      }
                    },
                    method: 'post',
                    body: '@{item()[0]},@{guid()},@{item()[12]},,,@{item()[1]},@{item()[2]},@{item()[11]},AutoDistribute,Success,High confidence + TLP:GREEN/WHITE = Auto-distribute,@{utcNow()}',
                    headers: {
                      'Log-Type': 'CTI_DistributionHistory_CL'
                    },
                    path: '/api/logs'
                  }
                },
                For_Each_Target_Platform: {
                  runAfter: {
                    Distribute_to_All_Targets: [
                      'Succeeded'
                    ]
                  },
                  type: 'Foreach',
                  foreach: '@split(item()[11], \', \')',
                  actions: {
                    Switch_Platform_Type: {
                      type: 'Switch',
                      expression: '@items(\'For_Each_Target_Platform\')',
                      cases: {
                        // Microsoft Defender XDR
                        'Microsoft Defender XDR': {
                          actions: {
                            Send_to_Defender_Connector: {
                              type: 'Http',
                              inputs: {
                                method: 'POST',
                                uri: 'https://prod-04.eastus.logic.azure.com:443/workflows/...',
                                body: {
                                  indicatorType: '@{item()[1]}',
                                  indicatorValue: '@{item()[2]}',
                                  action: '@{item()[5]}',
                                  title: '@{item()[3]}',
                                  description: '@{item()[4]}',
                                  confidenceScore: '@{item()[6]}',
                                  tlp: '@{item()[9]}',
                                  threatType: '@{item()[10]}',
                                  validFrom: '@{item()[7]}',
                                  validUntil: '@{item()[8]}',
                                  indicatorId: '@{item()[12]}'
                                }
                              }
                            }
                          }
                        },
                        // Microsoft Sentinel
                        'Microsoft Sentinel': {
                          actions: {
                            Send_to_Sentinel_Connector: {
                              type: 'Http',
                              inputs: {
                                method: 'POST',
                                uri: 'https://prod-05.eastus.logic.azure.com:443/workflows/...',
                                body: {
                                  indicatorType: '@{item()[1]}',
                                  indicatorValue: '@{item()[2]}',
                                  action: '@{item()[5]}',
                                  title: '@{item()[3]}',
                                  description: '@{item()[4]}',
                                  confidenceScore: '@{item()[6]}',
                                  tlp: '@{item()[9]}',
                                  threatType: '@{item()[10]}',
                                  validFrom: '@{item()[7]}',
                                  validUntil: '@{item()[8]}',
                                  indicatorId: '@{item()[12]}'
                                }
                              }
                            }
                          }
                        },
                        // AWS Security Hub
                        'AWS Security Hub': {
                          actions: {
                            Send_to_AWS_Connector: {
                              type: 'Http',
                              inputs: {
                                method: 'POST',
                                uri: 'https://prod-06.eastus.logic.azure.com:443/workflows/...',
                                body: {
                                  indicatorType: '@{item()[1]}',
                                  indicatorValue: '@{item()[2]}',
                                  action: '@{item()[5]}',
                                  title: '@{item()[3]}',
                                  description: '@{item()[4]}',
                                  confidenceScore: '@{item()[6]}',
                                  tlp: '@{item()[9]}',
                                  threatType: '@{item()[10]}',
                                  validFrom: '@{item()[7]}',
                                  validUntil: '@{item()[8]}',
                                  indicatorId: '@{item()[12]}'
                                }
                              }
                            }
                          }
                        }
                      },
                      default: {
                        actions: {
                          Log_Unsupported_Platform: {
                            type: 'ApiConnection',
                            inputs: {
                              host: {
                                connection: {
                                  name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                                }
                              },
                              method: 'post',
                              body: '@{utcNow()},@{guid()},@{item()[12]},,,@{item()[1]},@{item()[2]},@{items(\'For_Each_Target_Platform\')},AutoDistribute,Warning,Unsupported platform type,@{utcNow()}',
                              headers: {
                                'Log-Type': 'CTI_DistributionHistory_CL'
                              },
                              path: '/api/logs'
                            }
                          }
                        }
                      }
                    }
                  }
                },
                Update_Indicator_Status: {
                  runAfter: {
                    For_Each_Target_Platform: [
                      'Succeeded'
                    ]
                  },
                  type: 'ApiConnection',
                  inputs: {
                    body: 'let indicatorId = "@{item()[12]}";\nlet now = now();\nCTI_ThreatIntelIndicator_CL\n| where IndicatorId_g == indicatorId\n| extend EnforcementStatus_s = "Distributed"\n| extend UpdatedTimeUtc_t = now',
                    host: {
                      connection: {
                        name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                      }
                    },
                    method: 'post',
                    path: '/api/logs'
                  }
                }
              },
              else: {
                actions: {
                  // Tier 2: Medium Confidence (60-84) OR TLP:AMBER → Approval Workflow
                  Process_Tier2_Indicators: {
                    type: 'If',
                    expression: {
                      or: [
                        {
                          and: [
                            { greaterOrEquals: ['@item()[6]', 60] },
                            { less: ['@item()[6]', 85] }
                          ]
                        },
                        { equals: ['@item()[9]', 'TLP:AMBER'] }
                      ]
                    },
                    actions: {
                      Set_Enforcement_Status_ApprovalNeeded: {
                        runAfter: {},
                        type: 'ApiConnection',
                        inputs: {
                          body: 'let indicatorId = "@{item()[12]}";\nlet now = now();\nCTI_ThreatIntelIndicator_CL\n| where IndicatorId_g == indicatorId\n| extend EnforcementStatus_s = "ApprovalNeeded"\n| extend UpdatedTimeUtc_t = now',
                          host: {
                            connection: {
                              name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                            }
                          },
                          method: 'post',
                          path: '/api/logs'
                        }
                      },
                      Create_Approval_Task: {
                        runAfter: {
                          Set_Enforcement_Status_ApprovalNeeded: [
                            'Succeeded'
                          ]
                        },
                        type: 'ApiConnection',
                        inputs: {
                          host: {
                            connection: {
                              name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                            }
                          },
                          method: 'post',
                          body: '@{item()[0]},@{guid()},@{item()[12]},,,@{item()[1]},@{item()[2]},@{item()[11]},NeedsApproval,Pending,Medium confidence or TLP:AMBER = Needs approval,@{utcNow()}',
                          headers: {
                            'Log-Type': 'CTI_DistributionHistory_CL'
                          },
                          path: '/api/logs'
                        }
                      }
                    },
                    else: {
                      actions: {
                        // Tier 3: Low Confidence (<60) or TLP:RED → Monitor Only
                        Process_Tier3_Indicators: {
                          type: 'If',
                          expression: {
                            or: [
                              { less: ['@item()[6]', 60] },
                              { equals: ['@item()[9]', 'TLP:RED'] }
                            ]
                          },
                          actions: {
                            Set_Enforcement_Status_Monitoring: {
                              runAfter: {},
                              type: 'ApiConnection',
                              inputs: {
                                body: 'let indicatorId = "@{item()[12]}";\nlet now = now();\nCTI_ThreatIntelIndicator_CL\n| where IndicatorId_g == indicatorId\n| extend EnforcementStatus_s = "Monitoring"\n| extend UpdatedTimeUtc_t = now',
                                host: {
                                  connection: {
                                    name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                                  }
                                },
                                method: 'post',
                                path: '/api/logs'
                              }
                            },
                            Log_Monitoring_Only: {
                              runAfter: {
                                Set_Enforcement_Status_Monitoring: [
                                  'Succeeded'
                                ]
                              },
                              type: 'ApiConnection',
                              inputs: {
                                host: {
                                  connection: {
                                    name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                                  }
                                },
                                method: 'post',
                                body: '@{item()[0]},@{guid()},@{item()[12]},,,@{item()[1]},@{item()[2]},@{item()[11]},MonitorOnly,Success,Low confidence or TLP:RED = Monitor only,@{utcNow()}',
                                headers: {
                                  'Log-Type': 'CTI_DistributionHistory_CL'
                                },
                                path: '/api/logs'
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          },
          runAfter: {
            Get_New_Indicators: [
              'Succeeded'
            ]
          },
          type: 'Foreach'
        }
      }
    },
    parameters: {
      '$connections': {
        value: {
          azureloganalyticsdatacollector: {
            connectionId: logAnalyticsConnectionId
            connectionName: 'azureloganalyticsdatacollector'
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azureloganalyticsdatacollector')
          }
          azuremonitorlogs: {
            connectionId: logAnalyticsQueryConnectionId
            connectionName: 'azuremonitorlogs'
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuremonitorlogs')
          }
        }
      }
    }
  }
}

// Approval process workflow for Tier 2 indicators
resource approvalWorkflow 'Microsoft.Logic/workflows@2019-05-01' = {
  name: '${prefix}-IndicatorApproval-${environment}'
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentityId}': {}
    }
  }
  properties: {
    state: 'Enabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft/Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {
        '$connections': {
          defaultValue: {}
          type: 'Object'
        }
        workspaceName: {
          defaultValue: ctiWorkspaceName
          type: 'String'
        }
      }
      triggers: {
        Recurrence: {
          recurrence: {
            frequency: 'Minute',
            interval: 10
          },
          type: 'Recurrence'
        }
      },
      actions: {
        Get_Pending_Approvals: {
          runAfter: {},
          type: 'ApiConnection',
          inputs: {
            body: 'CTI_ThreatIntelIndicator_CL \n| where EnforcementStatus_s == "ApprovalNeeded"\n| project TimeGenerated, Type_s, Value_s, Name_s, Description_s, Action_s, Confidence_d, \nValidFrom_t, ValidUntil_t, TLP_s, ThreatType_s, DistributionTargets_s, IndicatorId_g, \nRiskScore_d, EnforcementStatus_s',
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuremonitorlogs\'][\'connectionId\']'
              }
            },
            method: 'post',
            path: '/queryData',
            queries: {
              resourcegroups: '@resourceGroup().name',
              resourcename: '@{parameters(\'workspaceName\')}',
              resourcetype: 'Log Analytics Workspace',
              subscriptions: '@{subscription().subscriptionId}',
              timerange: 'Last 24 hours'
            }
          }
        },
        For_Each_Approval: {
          foreach: '@body(\'Get_Pending_Approvals\').tables[0].rows',
          actions: {
            Send_Email_For_Approval: {
              runAfter: {},
              type: 'ApiConnection',
              inputs: {
                host: {
                  connection: {
                    name: '@parameters(\'$connections\')[\'office365\'][\'connectionId\']'
                  }
                },
                method: 'post',
                path: '/v2/Mail',
                body: {
                  To: 'security-team@contoso.com',
                  Subject: 'CTI Indicator Approval Required: @{item()[2]} (@{item()[1]})',
                  Body: '<p>A new threat intelligence indicator requires approval:</p><table><tr><th>Type</th><td>@{item()[1]}</td></tr><tr><th>Value</th><td>@{item()[2]}</td></tr><tr><th>Name</th><td>@{item()[3]}</td></tr><tr><th>Description</th><td>@{item()[4]}</td></tr><tr><th>Action</th><td>@{item()[5]}</td></tr><tr><th>Confidence</th><td>@{item()[6]}</td></tr><tr><th>TLP</th><td>@{item()[9]}</td></tr><tr><th>Threat Type</th><td>@{item()[10]}</td></tr><tr><th>Distribution Targets</th><td>@{item()[11]}</td></tr></table><p>Click to approve or reject:</p><p><a href="https://cti-portal.contoso.com/approve?id=@{item()[12]}&action=approve">Approve</a> | <a href="https://cti-portal.contoso.com/approve?id=@{item()[12]}&action=reject">Reject</a></p>',
                  Importance: 'High'
                }
              }
            }
          },
          runAfter: {
            Get_Pending_Approvals: [
              'Succeeded'
            ]
          },
          type: 'Foreach'
        }
      }
    },
    parameters: {
      '$connections': {
        value: {
          azureloganalyticsdatacollector: {
            connectionId: logAnalyticsConnectionId
            connectionName: 'azureloganalyticsdatacollector'
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azureloganalyticsdatacollector')
          }
          azuremonitorlogs: {
            connectionId: logAnalyticsQueryConnectionId
            connectionName: 'azuremonitorlogs'
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuremonitorlogs')
          }
          office365: {
            connectionId: resourceId('Microsoft.Web/connections', 'office365'),
            connectionName: 'office365',
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'office365')
          }
        }
      }
    }
  }
}

output inoculationEngineId string = inoculationEngine.id
output inoculationEngineName string = inoculationEngine.name
output approvalWorkflowId string = approvalWorkflow.id
