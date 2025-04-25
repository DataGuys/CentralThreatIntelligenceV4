// modules/microsoft-connectors.bicep
param location string
param managedIdentityId string
param logAnalyticsConnectionId string
param logAnalyticsQueryConnectionId string
param microsoftGraphConnectionId string
param ctiWorkspaceName string
param ctiWorkspaceId string
param keyVaultName string
param clientSecretName string
param appClientId string
param tenantId string
param tags object = {}

// Microsoft Defender XDR connector
resource defenderConnector 'Microsoft.Logic/workflows@2019-05-01' = {
  name: 'CTI-DefenderXDR-Connector'
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
        tenantId: {
          defaultValue: tenantId
          type: 'String'
        }
        clientId: {
          defaultValue: appClientId
          type: 'String'
        }
      }
      triggers: {
        When_a_HTTP_request_is_received: {
          type: 'Request',
          kind: 'Http',
          inputs: {
            schema: {
              type: 'object',
              properties: {
                indicatorType: {
                  type: 'string'
                },
                indicatorValue: {
                  type: 'string'
                },
                action: {
                  type: 'string'
                },
                title: {
                  type: 'string'
                },
                description: {
                  type: 'string'
                },
                confidenceScore: {
                  type: 'number'
                },
                tlp: {
                  type: 'string'
                },
                threatType: {
                  type: 'string'
                },
                validFrom: {
                  type: 'string'
                },
                validUntil: {
                  type: 'string'
                },
                indicatorId: {
                  type: 'string'
                }
              }
            }
          }
        }
      },
      actions: {
        // Map STIX indicator types to Defender API types
        Set_Defender_Type: {
          runAfter: {},
          type: 'InitializeVariable',
          inputs: {
            variableName: 'defenderType',
            type: 'string',
            value: '@{if(equals(triggerBody().indicatorType, \'ip-addr\'), \'IpAddress\', if(equals(triggerBody().indicatorType, \'domain-name\'), \'DomainName\', if(equals(triggerBody().indicatorType, \'url\'), \'Url\', if(equals(triggerBody().indicatorType, \'file-sha256\'), \'FileSha256\', if(equals(triggerBody().indicatorType, \'file-sha1\'), \'FileSha1\', if(equals(triggerBody().indicatorType, \'file-md5\'), \'FileMd5\', \'unknown\'))))))}'
          }
        },
        // Map actions to Defender actions
        Set_Defender_Action: {
          runAfter: {
            Set_Defender_Type: [
              'Succeeded'
            ]
          },
          type: 'InitializeVariable',
          inputs: {
            variableName: 'defenderAction',
            type: 'string',
            value: '@{if(equals(triggerBody().action, \'block\'), \'BlockAndAlert\', if(equals(triggerBody().action, \'alert\'), \'Alert\', \'Audit\'))}'
          }
        },
        // Get authentication token
        Get_Authentication_Token: {
          runAfter: {
            Set_Defender_Action: [
              'Succeeded'
            ]
          },
          type: 'Http',
          inputs: {
            method: 'POST',
            uri: 'https://login.microsoftonline.com/@{parameters(\'tenantId\')}/oauth2/token',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: 'grant_type=client_credentials&client_id=@{parameters(\'clientId\')}&client_secret=@{listSecrets(resourceId(\'Microsoft.KeyVault/vaults/secrets\', keyVaultName, clientSecretName), \'2023-02-01\').value}&resource=https://api.securitycenter.microsoft.com/'
          }
        },
        // Validate indicator type compatibility
        Check_Indicator_Type: {
          runAfter: {
            Get_Authentication_Token: [
              'Succeeded'
            ]
          },
          type: 'If',
          expression: {
            not: {
              equals: [
                '@variables(\'defenderType\')',
                'unknown'
              ]
            }
          },
          actions: {
            Submit_to_Defender_API: {
              runAfter: {},
              type: 'Http',
              inputs: {
                method: 'POST',
                uri: 'https://api.securitycenter.microsoft.com/api/indicators',
                headers: {
                  'Content-Type': 'application/json',
                  'Authorization': 'Bearer @{body(\'Get_Authentication_Token\').access_token}'
                },
                body: {
                  indicatorValue: '@triggerBody().indicatorValue',
                  indicatorType: '@variables(\'defenderType\')',
                  title: '@triggerBody().title',
                  description: '@triggerBody().description',
                  action: '@variables(\'defenderAction\')',
                  severity: '@{if(greater(triggerBody().confidenceScore, 80), \'High\', if(greater(triggerBody().confidenceScore, 60), \'Medium\', \'Low\'))}',
                  tlpLevel: '@{replace(triggerBody().tlp, \'TLP:\', \'\')}',
                  tags: [
                    'CTI-InoculationEngine',
                    '@{triggerBody().threatType}'
                  ],
                  targetProduct: 'Microsoft Defender ATP',
                  expirationDateTime: '@{triggerBody().validUntil}',
                  rbacGroups: [],
                  generateAlert: true
                }
              }
            },
            // Log success
            Log_Successful_Submission: {
              runAfter: {
                Submit_to_Defender_API: [
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
                body: '@{utcNow()},@{guid()},@{triggerBody().indicatorId},@{guid()},Microsoft Defender XDR,@{triggerBody().indicatorType},@{triggerBody().indicatorValue},@{variables(\'defenderAction\')},Success,@{body(\'Submit_to_Defender_API\')},@{utcNow()}',
                headers: {
                  'Log-Type': 'CTI_DistributionHistory_CL'
                },
                path: '/api/logs'
              }
            }
          },
          else: {
            actions: {
              // Log unsupported indicator type
              Log_Unsupported_Type: {
                type: 'ApiConnection',
                inputs: {
                  host: {
                    connection: {
                      name: '@parameters(\'$connections\')[\'azureloganalyticsdatacollector\'][\'connectionId\']'
                    }
                  },
                  method: 'post',
                  body: '@{utcNow()},@{guid()},@{triggerBody().indicatorId},@{guid()},Microsoft Defender XDR,@{triggerBody().indicatorType},@{triggerBody().indicatorValue},None,Error,Unsupported indicator type,@{utcNow()}',
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

// You would have similar logic for other Microsoft connectors
// Such as Microsoft Sentinel, Exchange Online, and Microsoft Entra ID
// But I'll move on to other components for brevity

output defenderConnectorId string = defenderConnector.id
output defenderConnectorName string = defenderConnector.name
