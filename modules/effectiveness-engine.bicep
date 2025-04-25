// modules/effectiveness-engine.bicep
param location string
param managedIdentityId string
param logAnalyticsConnectionId string
param logAnalyticsQueryConnectionId string
param ctiWorkspaceName string
param ctiWorkspaceId string
param keyVaultName string
param tags object = {}

// Effectiveness Measurement Engine
resource effectivenessEngine 'Microsoft.Logic/workflows@2019-05-01' = {
  name: 'CTI-Effectiveness-Engine'
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
        Daily_Assessment: {
          recurrence: {
            frequency: 'Day',
            interval: 1,
            schedule: {
              hours: [
                1
              ],
              minutes: [
                0
              ]
            }
          },
          type: 'Recurrence'
        }
      },
      actions: {
        // 1. Get active indicators
        Get_Active_Indicators: {
          runAfter: {},
          type: 'ApiConnection',
          inputs: {
            body: 'CTI_ThreatIntelIndicator_CL \n| where Active_b == true\n| project IndicatorId_g, Type_s, Value_s, ThreatType_s, DistributionTargets_s, RiskScore_d, Confidence_d, EnforcementStatus_s, EffectivenessScore_d',
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
              timerange: 'Last 90 days'
            }
          }
        },
        
        // 2. For each distributed indicator, check for matches
        For_Each_Indicator: {
          foreach: '@body(\'Get_Active_Indicators\').tables[0].rows',
          actions: {
            // Check if indicator has been distributed
            Is_Indicator_Distributed: {
              runAfter: {},
              type: 'If',
              expression: {
                and: [
                  {
                    equals: [
                      '@item()[7]',
                      'Distributed'
                    ]
                  },
                  {
                    not: {
                      equals: [
                        '@item()[4]',
                        ''
                      ]
                    }
                  }
                ]
              },
              actions: {
                // Initialize metrics tracking
                Initialize_Metrics: {
                  runAfter: {},
                  type: 'InitializeVariable',
                  inputs: {
                    variables: [
                      {
                        name: 'matchCount',
                        type: 'integer',
                        value: 0
                      },
                      {
                        name: 'effectivenessScore',
                        type: 'float',
                        value: 0
                      },
                      {
                        name: 'matchSources',
                        type: 'array',
                        value: []
                      }
                    ]
                  }
                },
                
                // Check for matches in Microsoft Defender logs
                Check_Defender_Matches: {
                  runAfter: {
                    Initialize_Metrics: [
                      'Succeeded'
                    ]
                  },
                  type: 'ApiConnection',
                  inputs: {
                    body: 'let value = "@{item()[2]}";\nlet indicatorType = "@{item()[1]}";\nlet searchColumn = case(\n  indicatorType == "ip-addr", "RemoteIP", \n  indicatorType == "domain-name", "RemoteUrl", \n  indicatorType == "url", "RemoteUrl", \n  indicatorType startswith "file", "SHA256", \n  "Unknown"\n);\n\nlet query = strcat("SecurityAlert\n| where TimeGenerated > ago(7d)\n| where ", searchColumn, " == \'", value, "\'\n| summarize count()");\n\nprint query;\nlet results = evaluate employer_database(query);\nresults',
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
                      timerange: 'Last 7 days'
                    }
                  }
                },
                
                // Update match count if found
                Update_Defender_Matches: {
                  runAfter: {
                    Check_Defender_Matches: [
                      'Succeeded'
                    ]
                  },
                  type: 'If',
                  expression: {
                    and: [
                      {
                        greater: [
                          '@length(body(\'Check_Defender_Matches\').tables[0].rows)',
                          0
                        ]
                      },
                      {
                        greater: [
                          '@int(body(\'Check_Defender_Matches\').tables[0].rows[0][0])',
                          0
                        ]
                      }
                    ]
                  },
                  actions: {
                    Increment_Match_Count: {
                      runAfter: {},
                      type: 'SetVariable',
                      inputs: {
                        name: 'matchCount',
                        value: '@add(variables(\'matchCount\'), int(body(\'Check_Defender_Matches\').tables[0].rows[0][0]))'
                      }
                    },
                    Add_Defender_To_Sources: {
                      runAfter: {
                        Increment_Match_Count: [
                          'Succeeded'
                        ]
                      },
                      type: 'AppendToArrayVariable',
                      inputs: {
                        name: 'matchSources',
                        value: 'Defender'
                      }
                    }
                  }
                },
                
                // Similar checks would be done for other platforms
                // Check_Sentinel_Matches, Check_AWS_Matches, etc.
                // ...
                
                // For brevity, I'll skip ahead to the effectiveness calculation
                Calculate_Effectiveness_Score: {
                  runAfter: {
                    Update_Defender_Matches: [
                      'Succeeded'
                    ]
                    // In a real implementation, we'd wait for all checks
                  },
                  type: 'SetVariable',
                  inputs: {
                    name: 'effectivenessScore',
                    value: '@{if(greater(variables(\'matchCount\'), 0), min(100, 50 + (variables(\'matchCount\') * 10)), max(0, sub(float(item()[6]), 20)))}'
                  }
                },
                
                // Log effectiveness metrics to a new table
                Log_Effectiveness_Metrics: {
                  runAfter: {
                    Calculate_Effectiveness_Score: [
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
                    body: '@{utcNow()},@{guid()},@{item()[0]},,,Effectiveness,@{variables(\'effectivenessScore\')},Daily,CTI-Effectiveness-Engine,@{item()[1]},@{item()[3]},@{string(variables(\'matchSources\'))}',
                    headers: {
                      'Log-Type': 'CTI_EffectivenessMetrics_CL'
                    },
                    path: '/api/logs'
                  }
                },
                
                // Update the indicator with effectiveness metrics
                Update_Indicator_Effectiveness: {
                  runAfter: {
                    Log_Effectiveness_Metrics: [
                      'Succeeded'
                    ]
                  },
                  type: 'ApiConnection',
                  inputs: {
                    body: 'let indicatorId = "@{item()[0]}";\nlet now = now();\nCTI_ThreatIntelIndicator_CL\n| where IndicatorId_g == indicatorId\n| extend EffectivenessScore_d = @{variables(\'effectivenessScore\')}\n| extend MatchCount_d = @{variables(\'matchCount\')}\n| extend LastMatchTime_t = iff(@{variables(\'matchCount\')} > 0, now, LastMatchTime_t)\n| extend UpdatedTimeUtc_t = now',
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
                  // For indicators not distributed, track that in metrics
                  Log_Not_Distributed: {
                    runAfter: {},
                    type: 'ApiConnection',
                    inputs: {
                      host: {
                        connection: {
                          name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                        }
                      },
                      method: 'post',
                      body: '@{utcNow()},@{guid()},@{item()[0]},,,Utilization,0,Daily,CTI-Effectiveness-Engine,@{item()[1]},@{item()[3]},Not distributed',
                      headers: {
                        'Log-Type': 'CTI_EffectivenessMetrics_CL'
                      },
                      path: '/api/logs'
                    }
                  }
                }
              }
            }
          },
          runAfter: {
            Get_Active_Indicators: [
              'Succeeded'
            ]
          },
          type: 'Foreach'
        },
        
        // 3. Generate dashboard data
        Generate_Dashboard_Data: {
          runAfter: {
            For_Each_Indicator: [
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
            body: '@{utcNow()},@{guid()},System,DashboardUpdate,@{utcNow()},@{body(\'Get_Active_Indicators\').tables[0].rows}',
            headers: {
              'Log-Type': 'CTI_SystemActivity_CL'
            },
            path: '/api/logs'
          }
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

output effectivenessEngineId string = effectivenessEngine.id
output effectivenessEngineName string = effectivenessEngine.name
