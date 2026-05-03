#!/usr/bin/env bash
# setup-container-app.sh
# ──────────────────────────────────────────────────────────────────────────────
# ONE-TIME script to provision Azure infrastructure and deploy Sentinel Vigil.
# After running this, future deploys happen automatically via GitHub Actions
# (push to main → .github/workflows/deploy.yml).
#
# Prerequisites:
#   • Azure CLI installed + logged in  (az login --tenant <your-tenant-id>)
#   • Subscription set                 (az account set --subscription <id>)
#   • Fill in every variable below
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ════════════════════════════════════════════════════════════════════════════
# FILL IN YOUR VALUES BEFORE RUNNING
# ════════════════════════════════════════════════════════════════════════════

SUBSCRIPTION_ID=""          # az account show --query id -o tsv
RESOURCE_GROUP="Infosec-Infra"
LOCATION="eastus"           # az account list-locations -o table

# ACR — name must be globally unique, lowercase letters + numbers only
ACR_NAME=""                 # e.g. "sentinelvigilacr"

# Container Apps (must match deploy.yml)
CONTAINER_APP="sentinel-vigil"
CONTAINER_ENV="sentinel-vigil-env"
IMAGE_NAME="sentinel-vigil"

# ── Azure identity for the container (service principal) ──────────────────
AZURE_TENANT_ID=""
AZURE_CLIENT_ID=""
AZURE_CLIENT_SECRET=""

# ── Sentinel workspace ────────────────────────────────────────────────────
SENTINEL_WORKSPACE_ID=""
SENTINEL_WORKSPACE_NAME=""
SENTINEL_RESOURCE_GROUP="$RESOURCE_GROUP"    # override if workspace is in a different RG

# ── App settings ──────────────────────────────────────────────────────────
SETTINGS_PASSWORD=""        # password for the Settings page in the UI

# ── LLM — Azure OpenAI (leave blank if using Azure Anthropic instead) ─────
AZURE_OPENAI_ENDPOINT=""    # https://your-resource.openai.azure.com/
AZURE_OPENAI_API_KEY=""
AZURE_OPENAI_DEPLOYMENT="gpt-4o"
AZURE_OPENAI_API_VERSION="2024-02-01"

# ── LLM — Azure Anthropic (leave blank if using Azure OpenAI instead) ─────
AZURE_ANTHROPIC_ENDPOINT=""
AZURE_ANTHROPIC_API_KEY=""
AZURE_ANTHROPIC_MODEL="claude-sonnet-4-6"

# ── Optional threat-intel tokens ─────────────────────────────────────────
IPINFO_TOKEN=""
ABUSEIPDB_TOKEN=""
VPNAPI_TOKEN=""
SHODAN_TOKEN=""

# ════════════════════════════════════════════════════════════════════════════
# VALIDATION
# ════════════════════════════════════════════════════════════════════════════

_require() { [[ -n "${!1}" ]] || { echo "❌  $1 is required — fill it in at the top of this script."; exit 1; }; }
_require SUBSCRIPTION_ID
_require ACR_NAME
_require AZURE_TENANT_ID
_require AZURE_CLIENT_ID
_require AZURE_CLIENT_SECRET
_require SENTINEL_WORKSPACE_ID
_require SENTINEL_WORKSPACE_NAME
_require SETTINGS_PASSWORD

command -v az  >/dev/null 2>&1 || { echo "❌  Azure CLI not found. Install: https://aka.ms/installazurecli"; exit 1; }

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   Sentinel Vigil — Azure Container Apps Setup        ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ════════════════════════════════════════════════════════════════════════════
# 1. SUBSCRIPTION + RESOURCE GROUP
# ════════════════════════════════════════════════════════════════════════════

echo "▶  Setting subscription: $SUBSCRIPTION_ID"
az account set --subscription "$SUBSCRIPTION_ID"

echo "▶  Resource group: $RESOURCE_GROUP ($LOCATION)"
az group create \
  --name "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --output none

# ════════════════════════════════════════════════════════════════════════════
# 2. AZURE CONTAINER REGISTRY
# ════════════════════════════════════════════════════════════════════════════

echo "▶  Creating ACR: $ACR_NAME"
az acr create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$ACR_NAME" \
  --sku Basic \
  --admin-enabled true \
  --output none

ACR_LOGIN_SERVER=$(az acr show --name "$ACR_NAME" --query loginServer -o tsv)
ACR_USERNAME=$(az acr credential show --name "$ACR_NAME" --query username -o tsv)
ACR_PASSWORD=$(az acr credential show --name "$ACR_NAME" --query "passwords[0].value" -o tsv)

echo "   Registry: $ACR_LOGIN_SERVER"

# ════════════════════════════════════════════════════════════════════════════
# 3. BUILD + PUSH IMAGE  (cloud build via ACR — no local Docker daemon needed)
# ════════════════════════════════════════════════════════════════════════════

echo "▶  Building image in ACR (uploads local context → builds in the cloud)..."
az acr build \
  --registry "$ACR_NAME" \
  --image "$IMAGE_NAME:latest" \
  .

echo "   Image: $ACR_LOGIN_SERVER/$IMAGE_NAME:latest"

# ════════════════════════════════════════════════════════════════════════════
# 4. CONTAINER APPS ENVIRONMENT
# ════════════════════════════════════════════════════════════════════════════

echo "▶  Installing containerapp extension (if needed)..."
az extension add --name containerapp --upgrade --output none 2>/dev/null || true
az provider register --namespace Microsoft.App                --wait --output none 2>/dev/null || true
az provider register --namespace Microsoft.OperationalInsights --wait --output none 2>/dev/null || true

echo "▶  Creating Container Apps environment: $CONTAINER_ENV"
az containerapp env create \
  --name "$CONTAINER_ENV" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --output none

# ════════════════════════════════════════════════════════════════════════════
# 5. CONTAINER APP (first-time creation)
# ════════════════════════════════════════════════════════════════════════════

echo "▶  Creating Container App: $CONTAINER_APP"

# Build the --secrets argument list (only include non-empty optional secrets)
SECRETS=(
  "azure-client-secret=$AZURE_CLIENT_SECRET"
  "settings-password=$SETTINGS_PASSWORD"
)
[[ -n "$AZURE_OPENAI_API_KEY"     ]] && SECRETS+=("openai-api-key=$AZURE_OPENAI_API_KEY")
[[ -n "$AZURE_ANTHROPIC_API_KEY"  ]] && SECRETS+=("anthropic-api-key=$AZURE_ANTHROPIC_API_KEY")

# Build the --env-vars list
ENV_VARS=(
  "AZURE_TENANT_ID=$AZURE_TENANT_ID"
  "TENANT_ID=$AZURE_TENANT_ID"
  "AZURE_CLIENT_ID=$AZURE_CLIENT_ID"
  "AZURE_CLIENT_SECRET=secretref:azure-client-secret"
  "SUBSCRIPTION_ID=$SUBSCRIPTION_ID"
  "RESOURCE_GROUP=$SENTINEL_RESOURCE_GROUP"
  "SENTINEL_WORKSPACE_ID=$SENTINEL_WORKSPACE_ID"
  "WORKSPACE_NAME=$SENTINEL_WORKSPACE_NAME"
  "SETTINGS_PASSWORD=secretref:settings-password"
  "AZURE_OPENAI_DEPLOYMENT=$AZURE_OPENAI_DEPLOYMENT"
  "AZURE_OPENAI_API_VERSION=$AZURE_OPENAI_API_VERSION"
)
[[ -n "$AZURE_OPENAI_ENDPOINT"    ]] && ENV_VARS+=("AZURE_OPENAI_ENDPOINT=$AZURE_OPENAI_ENDPOINT")
[[ -n "$AZURE_OPENAI_API_KEY"     ]] && ENV_VARS+=("AZURE_OPENAI_API_KEY=secretref:openai-api-key")
[[ -n "$AZURE_ANTHROPIC_ENDPOINT" ]] && ENV_VARS+=("AZURE_ANTHROPIC_ENDPOINT=$AZURE_ANTHROPIC_ENDPOINT")
[[ -n "$AZURE_ANTHROPIC_API_KEY"  ]] && ENV_VARS+=("AZURE_ANTHROPIC_API_KEY=secretref:anthropic-api-key")
[[ -n "$AZURE_ANTHROPIC_MODEL"    ]] && ENV_VARS+=("AZURE_ANTHROPIC_MODEL=$AZURE_ANTHROPIC_MODEL")
[[ -n "$IPINFO_TOKEN"             ]] && ENV_VARS+=("IPINFO_TOKEN=$IPINFO_TOKEN")
[[ -n "$ABUSEIPDB_TOKEN"          ]] && ENV_VARS+=("ABUSEIPDB_TOKEN=$ABUSEIPDB_TOKEN")
[[ -n "$VPNAPI_TOKEN"             ]] && ENV_VARS+=("VPNAPI_TOKEN=$VPNAPI_TOKEN")
[[ -n "$SHODAN_TOKEN"             ]] && ENV_VARS+=("SHODAN_TOKEN=$SHODAN_TOKEN")

az containerapp create \
  --name            "$CONTAINER_APP" \
  --resource-group  "$RESOURCE_GROUP" \
  --environment     "$CONTAINER_ENV" \
  --image           "$ACR_LOGIN_SERVER/$IMAGE_NAME:latest" \
  --registry-server   "$ACR_LOGIN_SERVER" \
  --registry-username "$ACR_USERNAME" \
  --registry-password "$ACR_PASSWORD" \
  --target-port 8000 \
  --ingress external \
  --transport http \
  --min-replicas 1 \
  --max-replicas 3 \
  --cpu    1.0 \
  --memory 2.0Gi \
  --secrets  "${SECRETS[@]}" \
  --env-vars "${ENV_VARS[@]}" \
  --output none

# ════════════════════════════════════════════════════════════════════════════
# 6. CREATE SERVICE PRINCIPAL FOR GITHUB ACTIONS CI/CD
# ════════════════════════════════════════════════════════════════════════════

echo ""
echo "▶  Creating GitHub Actions service principal..."
SP_JSON=$(az ad sp create-for-rbac \
  --name "sentinel-vigil-deploy" \
  --role contributor \
  --scopes "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP" \
  --sdk-auth \
  --output json 2>/dev/null)

# ════════════════════════════════════════════════════════════════════════════
# 7. RESULTS
# ════════════════════════════════════════════════════════════════════════════

APP_URL=$(az containerapp show \
  --name "$CONTAINER_APP" \
  --resource-group "$RESOURCE_GROUP" \
  --query properties.configuration.ingress.fqdn \
  -o tsv)

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   ✅  Deployment Complete                             ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "  App URL:  https://$APP_URL"
echo "  Health:   https://$APP_URL/api/health"
echo "  API docs: https://$APP_URL/api/docs"
echo ""
echo "────────────────────────────────────────────────────────"
echo "  GitHub Secrets — add these in:"
echo "  Repo → Settings → Secrets and variables → Actions"
echo "────────────────────────────────────────────────────────"
echo ""
echo "  AZURE_CREDENTIALS:"
echo "$SP_JSON"
echo ""
echo "  ACR_LOGIN_SERVER:  $ACR_LOGIN_SERVER"
echo "  ACR_USERNAME:      $ACR_USERNAME"
echo "  ACR_PASSWORD:      $ACR_PASSWORD"
echo ""
echo "  After adding the secrets, push to main to trigger"
echo "  automatic redeploys via .github/workflows/deploy.yml"
echo ""
