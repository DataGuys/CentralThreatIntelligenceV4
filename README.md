# Central Threat Intelligence V4: Inoculation Engine

A comprehensive threat intelligence platform that protects your entire digital estate against emerging threats by automatically distributing indicators across your security systems based on risk assessment and confidence scores.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FYourOrg%2FCTI-V4%2Fmain%2Fazuredeploy.json)

## Architecture Overview

![CTI-V4 Architecture](https://raw.githubusercontent.com/DataGuys/CentralThreatIntelligenceV4/refs/heads/main/images/architecture-diagram1.svg)

### Key Architectural Principles

1. **Universal Protection**: Covers all digital assets across platforms (Microsoft, AWS, GCP, network, endpoints)
2. **Dynamic Risk Assessment**: Automatically evaluates indicator confidence, severity, and relevance
3. **Tiered Response**: Implements different actions based on confidence/TLP combinations
4. **Zero-Touch Operations**: Fully automated for high-confidence indicators with manual approval workflows
5. **Audit & Measurement**: Tracks effectiveness with feedback loops to improve detection

## Core Components

### 1. Unified Indicator Store

The solution uses a consolidated schema in Log Analytics that can store any indicator type:

- IP Addresses
- Domain Names
- URLs
- File Hashes (MD5, SHA1, SHA256)
- Email Addresses
- Other STIX/TAXII supported objects

### 2. Inoculation Engine

The heart of the system - decides where and how indicators are distributed:

- **Tier 1**: High confidence (85%+) + TLP:GREEN/WHITE → Auto-distribute everywhere
- **Tier 2**: Medium confidence (60-84%) or TLP:AMBER → Approval workflow
- **Tier 3**: Low confidence (<60%) or TLP:RED → Monitor only

### 3. Risk Assessment Engine

Enhances indicators with additional context to improve confidence scoring:

- **Reputation Services**: Checks external reputation databases (VirusTotal, AbuseIPDB, etc.)
- **Internal Telemetry**: Analyzes your security logs for previous occurrences
- **Contextual Relevance**: Evaluates how relevant the indicator is to your environment
- **Composite Scoring**: Generates a risk score based on weighted factors

### 4. Multi-Platform Connectors

Distributes indicators to various security platforms:

- **Microsoft**: Defender XDR, Sentinel, Exchange Online, Entra ID
- **AWS**: Security Hub, Network Firewall, WAF
- **GCP**: Security Command Center, Cloud Armor
- **Network**: Palo Alto, Cisco, Fortinet, Check Point
- **Endpoints**: CrowdStrike, Carbon Black, SentinelOne

### 5. Effectiveness Measurement

Tracks how indicators perform in your environment:

- Monitors when indicators match actual threats
- Adjusts confidence scores based on real-world effectiveness
- Generates metrics on indicator quality and value

## Getting Started

### Prerequisites

- Azure subscription with Contributor role
- Application registration in Azure AD with appropriate permissions
- Optional: AWS/GCP accounts for cross-cloud protection
- Optional: Management access to network/EDR systems

### Quick Deployment

For a one-click deployment experience, use this command in Azure Cloud Shell:

```bash
curl -sL https://raw.githubusercontent.com/YourOrg/CTI-V4/main/deploy.sh | bash -s -- -l eastus -p cti -e prod
```

### Configuration Options

| Parameter | Description | Default |
|-----------|-------------|---------|
| -l | Azure region | eastus |
| -p | Resource prefix | cti |
| -e | Environment tag | prod |
| -t | Table plan (Analytics/Basic/Standard) | Analytics |
| -c | Enable cross-cloud protection | true |
| -n | Enable network protection | true |
| -d | Enable endpoint protection | true |

### Post-Deployment Steps

1. **Add API Keys**: Store third-party API keys in the Key Vault
2. **Connect Platforms**: Configure connection details for security systems
3. **Configure Approval Workflow**: Set up email notifications for approval requests
4. **Review Default Settings**: Adjust confidence thresholds and distribution rules

## Security Dashboard

The solution includes comprehensive dashboards:

- Active indicator metrics by type and target system
- Recent high-confidence indicators
- Expiring indicators that need renewal
- System health status and connection monitoring
- Effectiveness metrics and match rates

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
