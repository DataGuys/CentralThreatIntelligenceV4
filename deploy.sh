#!/bin/bash
# Central Threat Intelligence V4 - Full Deployment Script
# This script creates the app registration, deploys the inoculation engine, and configures all connectors

set -e

# Color definitions for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

REPO_BRANCH="${REPO_BRANCH:-main}"
RAW_BASE="https://raw.githubusercontent.com/Dataguys/CentralThreatIntelligenceV4/${REPO_BRANCH}"
DEPLOY_NAME="cti-v4-$(date +%Y%m%d%H%M%S)"

echo -e "\n${BLUE}============================================================${NC}"
echo -e "${BLUE}    Central Threat Intelligence V4 - Inoculation Engine    ${NC}"
echo -e "${BLUE}============================================================${NC}"

# Parse command line arguments
LOCATION="westus2"
PREFIX="cti"
ENVIRONMENT="prod"
TABLE_PLAN="Analytics"
ENABLE_CROSS_CLOUD=true
ENABLE_NETWORK=true
ENABLE_ENDPOINT=true

usage() {
    echo -e "Usage: $0 [-l location] [-p prefix] [-e environment] [-t table_plan] [-c enable_cross_cloud] [-n enable_network] [-d enable_endpoint]"
    echo -e "  -l  Azure region                    (default: eastus)"
    echo -e "  -p  Resource name prefix            (default: cti)"
    echo -e "  -e  Environment tag                 (default: prod)"
    echo -e "  -t  Table plan: Analytics|Basic|Aux (default: Analytics)"
    echo -e "  -c  Enable cross-cloud protection   (default: true)"
    echo -e "  -n  Enable network protection       (default: true)"
    echo -e "  -d  Enable endpoint protection      (default: true)"
    echo -e "  -h  Help"
    exit 1
}

while getopts "l:p:e:t:c:n:d:h" opt; do
    case "$opt" in
        l) LOCATION="$OPTARG" ;;
        p) PREFIX="$OPTARG" ;;
        e) ENVIRONMENT="$OPTARG" ;;
        t) TABLE_PLAN="$OPTARG" ;;
        c) ENABLE_CROSS_CLOUD="$OPTARG" ;;
        n) ENABLE_NETWORK="$OPTARG" ;;
        d) ENABLE_ENDPOINT="$OPTARG" ;;
        h|*) usage ;;
    esac
done

# Resolve default location if not provided
if [[ -z "$LOCATION" ]]; then
    LOCATION="eastus"
fi

# Validate table plan
case "${TABLE_PLAN,,}" in
    analytics|basic|auxiliary) TABLE_PLAN="$(tr '[:lower:]' '[:upper:]' <<< "${TABLE_PLAN:0:1}")${TABLE_PLAN:1}" ;;
    *) echo -e "${RED}❌ Invalid table plan. Use Analytics | Basic | Auxiliary${NC}"; exit 1 ;;
esac

echo -e "\n${BLUE}======================= Configuration =======================${NC}"
echo -e " Location     : ${LOCATION}"
echo -e " Prefix       : ${PREFIX}"
echo -e " Environment  : ${ENVIRONMENT}"
echo -e " Table plan   : ${TABLE_PLAN}"
echo -e " Cross-Cloud  : ${ENABLE_CROSS_CLOUD}"
echo -e " Network      : ${ENABLE_NETWORK}"
echo -e " Endpoint     : ${ENABLE_ENDPOINT}"
echo -e " Deployment   : ${DEPLOY_NAME}"
echo -e "${BLUE}============================================================${NC}"

# Azure login check
if ! az account show &>/dev/null; then
    echo -e "${YELLOW}Not logged in to Azure. Initiating login...${NC}"
    az login
fi

# Get current subscription
SUB_NAME=$(az account show --query name -o tsv)
SUB_ID=$(az account show --query id -o tsv)
echo -e "${GREEN}Using subscription: ${SUB_NAME} (${SUB_ID})${NC}"

# Step 1: Create app registration
echo -e "\n${BLUE}Step 1: Creating app registration...${NC}"
APP_NAME="${PREFIX}-solution-${ENVIRONMENT}"
echo "Creating app registration: ${APP_NAME}..."

APP_CREATE=$(az ad app create --display-name "${APP_NAME}")
APP_ID=$(echo "$APP_CREATE" | jq -r '.appId // .id')
OBJECT_ID=$(echo "$APP_CREATE" | jq -r '.id // .objectId')

if [ -z "$APP_ID" ]; then
    echo -e "${RED}Failed to retrieve Application ID.${NC}"
    exit 1
fi

echo -e "${GREEN}Application successfully created.${NC}"
echo -e "${GREEN}Application (Client) ID: ${APP_ID}${NC}"

echo "Creating service principal for the application..."
az ad sp create --id "$APP_ID" || {
    echo -e "${RED}Failed to create service principal.${NC}"
    exit 1
}
echo -e "${GREEN}Service principal created successfully.${NC}"

# Create client secret
echo -e "${BLUE}Creating client secret...${NC}"
SECRET_YEARS=2
echo "Creating client secret with ${SECRET_YEARS} year(s) duration..."
SECRET_RESULT=$(az ad app credential reset --id "$APP_ID" --years "$SECRET_YEARS" --query password -o tsv)

if [ -z "$SECRET_RESULT" ]; then
    echo -e "${RED}Failed to create client secret.${NC}"
    exit 1
fi

# Save credentials to a file
echo "CLIENT_ID=${APP_ID}" > cti-app-credentials.env
echo "APP_OBJECT_ID=${OBJECT_ID}" >> cti-app-credentials.env
echo "APP_NAME=${APP_NAME}" >> cti-app-credentials.env
echo "CLIENT_SECRET=${SECRET_RESULT}" >> cti-app-credentials.env

echo -e "${GREEN}Client secret created successfully and saved to cti-app-credentials.env${NC}"

# Add required API permissions
echo -e "${BLUE}Adding required permissions...${NC}"

# Microsoft Defender XDR
az ad app permission add --id "$APP_ID" --api 00000003-0000-0000-c000-000000000000 --api-permissions "ThreatIndicators.ReadWrite.OwnedBy=Role"

# Microsoft Graph
az ad app permission add --id "$APP_ID" --api 00000003-0000-0000-c000-000000000000 --api-permissions "User.Read.All=Role"

# Microsoft Sentinel
az ad app permission add --id "$APP_ID" --api 9ec59623-ce40-4dc8-a635-ed0275b5d58a --api-permissions "7e2fc5f2-d647-4926-89f6-f13ad2950560=Role"

# Step 2: Deploy the main solution
echo -e "\n${BLUE}Step 2: Deploying the inoculation engine solution...${NC}"

# Create resource group
RG_NAME="${PREFIX}-${ENVIRONMENT}-rg"
echo -e "${YELLOW}Creating resource group ${RG_NAME}...${NC}"
az group create --name "${RG_NAME}" --location "${LOCATION}" --tags "project=CentralThreatIntelligence" "environment=${ENVIRONMENT}"

# Deploy the solution
echo -e "${YELLOW}Deploying the core solution...${NC}"
DEPLOY_RESULT=$(az deployment sub create \
    --name "$DEPLOY_NAME" \
    --location "$LOCATION" \
    --template-file "./main.bicep" \
    --parameters prefix="$PREFIX" environment="$ENVIRONMENT" location="$LOCATION" \
    --parameters enableCrossCloudProtection="$ENABLE_CROSS_CLOUD" enableNetworkProtection="$ENABLE_NETWORK" enableEndpointProtection="$ENABLE_ENDPOINT" \
    --parameters tablePlan="$TABLE_PLAN" \
    --query "properties.outputs" -o json)

# Extract key output values
WORKSPACE_NAME=$(echo "$DEPLOY_RESULT" | jq -r '.workspaceName.value')
KEYVAULT_NAME=$(echo "$DEPLOY_RESULT" | jq -r '.keyVaultName.value')

if [[ -z "$WORKSPACE_NAME" ]]; then
    echo -e "${RED}❌ Failed to retrieve workspace name from deployment${NC}"
    exit 1
fi

# Store client secret in Key Vault
echo -e "${YELLOW}Storing app registration client secret in Key Vault...${NC}"
az keyvault secret set \
    --vault-name "$KEYVAULT_NAME" \
    --name "ctiappsecret" \
    --value "$SECRET_RESULT" \
    --output none

echo -e "${GREEN}✓ Client secret stored in Key Vault successfully${NC}"

# Step 3: Configure required API keys
echo -e "\n${BLUE}Step 3: Configuring additional API keys...${NC}"
echo -e "${YELLOW}Please enter API keys for third-party services (press Enter to skip)${NC}"

read -p "VirusTotal API Key: " VIRUSTOTAL_APIKEY
if [[ -n "$VIRUSTOTAL_APIKEY" ]]; then
    az keyvault secret set --vault-name "$KEYVAULT_NAME" --name "VirusTotal-ApiKey" --value "$VIRUSTOTAL_APIKEY" --output none
    echo -e "${GREEN}✓ VirusTotal API Key stored${NC}"
fi

read -p "AbuseIPDB API Key: " ABUSEIPDB_APIKEY
if [[ -n "$ABUSEIPDB_APIKEY" ]]; then
    az keyvault secret set --vault-name "$KEYVAULT_NAME" --name "AbuseIPDB-ApiKey" --value "$ABUSEIPDB_APIKEY" --output none
    echo -e "${GREEN}✓ AbuseIPDB API Key stored${NC}"
fi

if [[ "$ENABLE_CROSS_CLOUD" == "true" ]]; then
    echo -e "${YELLOW}Enter AWS credentials for cross-cloud protection${NC}"
    read -p "AWS Access Key ID: " AWS_ACCESS_KEY
    read -p "AWS Secret Access Key: " AWS_SECRET_KEY
    read -p "AWS Region: " AWS_REGION
    
    if [[ -n "$AWS_ACCESS_KEY" && -n "$AWS_SECRET_KEY" ]]; then
        AWS_CREDS="{\"aws_access_key_id\":\"$AWS_ACCESS_KEY\",\"aws_secret_access_key\":\"$AWS_SECRET_KEY\",\"aws_region\":\"$AWS_REGION\"}"
        az keyvault secret set --vault-name "$KEYVAULT_NAME" --name "AWS-CREDENTIALS" --value "$AWS_CREDS" --output none
        echo -e "${GREEN}✓ AWS credentials stored${NC}"
    fi
    
    echo -e "${YELLOW}Enter GCP credentials for cross-cloud protection${NC}"
    read -p "GCP Service Account Key (paste JSON, then press Ctrl+D): " GCP_CREDENTIALS
    
    if [[ -n "$GCP_CREDENTIALS" ]]; then
        az keyvault secret set --vault-name "$KEYVAULT_NAME" --name "GCP-CREDENTIALS" --value "$GCP_CREDENTIALS" --output none
        echo -e "${GREEN}✓ GCP credentials stored${NC}"
    fi
fi

# Step 4: Grant admin consent for API permissions
echo -e "\n${BLUE}Step 4: Finishing configuration${NC}"
echo -e "${YELLOW}IMPORTANT: You need to grant admin consent for API permissions:${NC}"
echo "1. Navigate to: Microsoft Entra ID > App registrations"
echo "2. Select your app: ${APP_NAME}"
echo "3. Go to 'API permissions'"
echo "4. Click 'Grant admin consent for <your-tenant>'"

echo -e "\n${GREEN}🎉 Central Threat Intelligence V4 deployment complete!${NC}"
echo -e "Access the CTI dashboard in Azure Portal > Log Analytics Workspace > Workbooks"
