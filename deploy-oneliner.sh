#!/bin/bash
# One-liner deployment script for CTI V4 Inoculation Engine
# Usage: curl -sL https://raw.githubusercontent.com/YourOrg/CTI-V4/main/deploy-oneliner.sh | bash -s

# Colorized output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m'

# Print banner
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                                                               ║${NC}"
echo -e "${BLUE}║   Central Threat Intelligence V4 - Inoculation Engine         ║${NC}"
echo -e "${BLUE}║                                                               ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}"

# Set default parameters
LOCATION="eastus"
PREFIX="cti"
ENVIRONMENT="prod"
TABLE_PLAN="Analytics"
ENABLE_CROSS_CLOUD=true
ENABLE_NETWORK=true
ENABLE_ENDPOINT=true
DEPLOYMENT_NAME="cti-v4-$(date +%Y%m%d%H%M%S)"

# Parse command line arguments
while getopts "l:p:e:t:c:n:d:h" opt; do
  case "$opt" in
    l) LOCATION="$OPTARG" ;;
    p) PREFIX="$OPTARG" ;;
    e) ENVIRONMENT="$OPTARG" ;;
    t) TABLE_PLAN="$OPTARG" ;;
    c) ENABLE_CROSS_CLOUD="$OPTARG" ;;
    n) ENABLE_NETWORK="$OPTARG" ;;
    d) ENABLE_ENDPOINT="$OPTARG" ;;
    h)
      echo -e "Usage: $0 [-l location] [-p prefix] [-e environment] [-t table_plan] [-c enable_cross_cloud] [-n enable_network] [-d enable_endpoint]"
      echo -e "  -l  Azure region                    (default: eastus)"
      echo -e "  -p  Resource name prefix            (default: cti)"
      echo -e "  -e  Environment tag                 (default: prod)"
      echo -e "  -t  Table plan: Analytics|Basic|Aux (default: Analytics)"
      echo -e "  -c  Enable cross-cloud protection   (default: true)"
      echo -e "  -n  Enable network protection       (default: true)"
      echo -e "  -d  Enable endpoint protection      (default: true)"
      exit 0
      ;;
    *) echo "Invalid option: -$OPTARG" >&2; exit 1 ;;
  esac
done

# Create temporary directory
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

# Check if logged in to Azure
if ! az account show &>/dev/null; then
  echo -e "${YELLOW}You're not logged in to Azure. Initiating login...${NC}"
  az login --only-show-errors
fi

# Display current subscription
CURRENT_SUB=$(az account show --query name -o tsv)
CURRENT_SUB_ID=$(az account show --query id -o tsv)
echo -e "\n${GREEN}Using Azure subscription: ${CURRENT_SUB} (${CURRENT_SUB_ID})${NC}"

# Download required files to temporary directory
echo -e "\n${BLUE}Downloading deployment files...${NC}"

# URLs to download files from GitHub
REPO_URL="https://raw.githubusercontent.com/YourOrg/CTI-V4/main"
FILES=(
  "main.bicep"
  "modules/core-resources.bicep"
  "modules/cti-tables.bicep"
  "modules/inoculation-engine.bicep"
  "modules/risk-assessment-engine.bicep"
  "modules/effectiveness-engine.bicep"
  "modules/microsoft-connectors.bicep"
)

if [ "$ENABLE_CROSS_CLOUD" = "true" ]; then
  FILES+=(
    "modules/aws-connectors.bicep"
    "modules/gcp-connectors.bicep"
  )
fi

if [ "$ENABLE_NETWORK" = "true" ]; then
  FILES+=("modules/network-connectors.bicep")
fi

if [ "$ENABLE_ENDPOINT" = "true" ]; then
  FILES+=("modules/edr-connectors.bicep")
fi

FILES+=(
  "modules/dashboards.bicep"
)

# Create directory structure
for file in "${FILES[@]}"; do
  mkdir -p "$TEMP_DIR/$(dirname "$file")"
  curl -s "$REPO_URL/$file" -o "$TEMP_DIR/$file"
  if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to download $file${NC}"
    exit 1
  fi
done

# Step 1: Create app registration
echo -e "\n${BLUE}Step 1: Creating Azure AD application registration...${NC}"
APP_NAME="${PREFIX}-solution-${ENVIRONMENT}"

# Create the application
APP_JSON=$(az ad app create --display-name "$APP_NAME" -o json)
APP_ID=$(echo "$APP_JSON" | jq -r '.appId')
OBJECT_ID=$(echo "$APP_JSON" | jq -r '.id')

echo -e "${GREEN}✓ Created app registration: $APP_NAME ($APP_ID)${NC}"

# Create service principal
az ad sp create --id "$APP_ID" > /dev/null

# Create client secret
SECRET_YEARS=2
CLIENT_SECRET=$(az ad app credential reset --id "$APP_ID" --years "$SECRET_YEARS" --query password -o tsv)

# Add required permissions
echo -e "${YELLOW}Adding required API permissions...${NC}"

# Microsoft Defender XDR permissions
az ad app permission add --id "$APP_ID" --api 00000003-0000-0000-c000-000000000000 --api-permissions "ThreatIndicators.ReadWrite.OwnedBy=Role" &> /dev/null
az ad app permission add --id "$APP_ID" --api 00000003-0000-0000-c000-000000000000 --api-permissions "User.Read.All=Role" &> /dev/null

# Step 2: Deploy core infrastructure
echo -e "\n${BLUE}Step 2: Deploying core infrastructure...${NC}"

# Create resource group
RG_NAME="${PREFIX}-${ENVIRONMENT}-rg"
az group create --name "$RG_NAME" --location "$LOCATION" --tags Environment="$ENVIRONMENT" Project="CTI-Inoculation-Engine" > /dev/null

# Deploy main template
echo -e "${YELLOW}Starting deployment... (this may take several minutes)${NC}"
cd "$TEMP_DIR"

DEPLOYMENT_RESULT=$(az deployment sub create \
  --name "$DEPLOYMENT_NAME" \
  --location "$LOCATION" \
  --template-file "main.bicep" \
  --parameters prefix="$PREFIX" \
    environment="$ENVIRONMENT" \
    location="$LOCATION" \
    enableCrossCloudProtection="$ENABLE_CROSS_CLOUD" \
    enableNetworkProtection="$ENABLE_NETWORK" \
    enableEndpointProtection="$ENABLE_ENDPOINT" \
    tablePlan="$TABLE_PLAN" \
  --query "properties.outputs" -o json)

# Extract outputs
WORKSPACE_NAME=$(echo "$DEPLOYMENT_RESULT" | jq -r '.workspaceName.value')
KEYVAULT_NAME=$(echo "$DEPLOYMENT_RESULT" | jq -r '.keyVaultName.value')
MANAGED_IDENTITY=$(echo "$DEPLOYMENT_RESULT" | jq -r '.managedIdentityName.value')

echo -e "${GREEN}✓ Deployment complete!${NC}"
echo -e "${GREEN}✓ Resource Group: $RG_NAME${NC}"
echo -e "${GREEN}✓ Log Analytics Workspace: $WORKSPACE_NAME${NC}"
echo -e "${GREEN}✓ Key Vault: $KEYVAULT_NAME${NC}"
echo -e "${GREEN}✓ Managed Identity: $MANAGED_IDENTITY${NC}"

# Store client secret in Key Vault
echo -e "\n${BLUE}Step 3: Storing credentials in Key Vault...${NC}"
az keyvault secret set --vault-name "$KEYVAULT_NAME" --name "CTI-APP-SECRET" --value "$CLIENT_SECRET" > /dev/null
echo -e "${GREEN}✓ Stored client secret in Key Vault${NC}"

# Next steps
echo -e "\n${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                       NEXT STEPS                              ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo -e "1. ${YELLOW}Grant admin consent for API permissions:${NC}"
echo -e "   - Go to Azure Portal > Microsoft Entra ID > App registrations"
echo -e "   - Select app: ${APP_NAME}"
echo -e "   - Go to 'API permissions' and click 'Grant admin consent for <tenant>'"
echo -e ""
echo -e "2. ${YELLOW}Add API keys for third-party services:${NC}"
echo -e "   - Add keys for VirusTotal, AbuseIPDB, etc. to the Key Vault"
echo -e ""
echo -e "3. ${YELLOW}Access dashboards:${NC}"
echo -e "   - Go to Azure Portal > Resource Group: ${RG_NAME} > Log Analytics workspace"
echo -e "   - Open 'Workbooks' to access the CTI dashboards"
echo -e ""
echo -e "Detailed documentation: https://github.com/YourOrg/CTI-V4"
echo -e "${GREEN}Deployment completed successfully!${NC}"
