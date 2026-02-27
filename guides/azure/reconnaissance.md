# Azure Reconnaissance

Comprehensive enumeration of Azure tenants, users, resources, and configurations. This guide covers both passive discovery and authenticated scanning techniques for building a complete picture of target Azure infrastructure.

## Phases of Azure Reconnaissance

### 1. Passive Discovery Phase
Gathering information without any authentication or direct interaction with Azure services.

### 2. Active Probing Phase  
Identifying valid Azure resources and properties without authentication.

### 3. Authenticated Enumeration Phase
Exploring Azure infrastructure using valid credentials with varying privilege levels.

### 4. Advanced Mapping Phase
Building complete infrastructure models, trust relationships, and access chains.

---

## Remote Reconnaissance (Unauthenticated)

### Tenant Discovery

Azure tenant discovery without authentication:

```bash
# Find tenant ID using domain
curl -s https://login.microsoft.com/{domain}/.well-known/openid-configuration | jq .

# Enumerate common Azure domains
for domain in company company.onmicrosoft.com company.mail.onmicrosoft.com; do
  curl -s -o /dev/null -w "%{http_code}" "https://login.microsoft.com/$domain/.well-known/openid-configuration"
done

# Tenant ID from URL parameter
curl "https://login.microsoft.com/common/discovery/v2.0/keys" | jq .
```

### User Enumeration

Enumerate valid users without authentication:

```bash
# Test if user exists using AAD login page
curl -s -X POST https://login.microsoft.com/common/GetCredentialType \
  -H "Content-Type: application/json" \
  -d '{"username":"user@company.com"}' | jq .

# Batch enumeration
while IFS= read -r email; do
  curl -s -X POST https://login.microsoft.com/common/GetCredentialType \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$email\"}" | jq '.IfExistsResult'
done < email_list.txt
```

### Application Discovery

Find registered applications and service principals:

```bash
# Enumerate Azure AD applications
curl -s https://graph.microsoft.com/v1.0/applications \
  -H "Authorization: Bearer $TOKEN" | jq '.value[] | {appId, displayName, replyUrls}'

# Find OAuth redirect URIs
curl -s https://graph.microsoft.com/v1.0/applications?$select=appId,displayName,replyUrls \
  -H "Authorization: Bearer $TOKEN" | jq .
```

### Certificate Transparency Logs

Find subdomains and service endpoints:

```bash
# Query CT logs for Azure subdomains
curl -s 'https://crt.sh/?q=%25.azurewebsites.net&output=json' | \
  jq -r '.[].name_value' | sort -u

# Common Azure endpoints to check
for subdomain in $(curl -s 'https://crt.sh/?q=%25.azurewebsites.net&output=json' | jq -r '.[].name_value' | sort -u); do
  echo "Checking $subdomain"
  curl -s -I "https://$subdomain" | head -1
done
```

## Authenticated Reconnaissance

### User and Group Enumeration

```bash
# Enumerate all users
az ad user list --output table

# Enumerate group members
az ad group member list --group "Group Name" --output table

# Find privileged users (Global Admins)
az ad role member list --role "Global Administrator"

# Get user properties
az ad user show --id user@company.com --output json | jq .
```

### Application & Service Principal Enumeration

```bash
# List all applications
az ad app list --output table

# List service principals
az ad sp list --output table

# Get application details including credentials
az ad app credential list --id {appId}

# Check service principal role assignments
az role assignment list --assignee {servicePrincipalId}
```

### Resource Enumeration

```bash
# List all subscriptions
az account list --output table

# Switch context to subscription
az account set --subscription {subscriptionId}

# List all resources
az resource list --output table

# List by resource type
az resource list --resource-type "Microsoft.Compute/virtualMachines" --output table

# Find public IPs
az resource list --resource-type "Microsoft.Network/publicIPAddresses" --output json | \
  jq '.[] | {name, id, ipAddress: .properties.ipAddress}'
```

### Storage Account Enumeration

```bash
# List storage accounts
az storage account list --output table

# Enumerate blob containers
az storage container list --account-name {accountName} --output table

# Check container public access level
az storage container show --name {containerName} --account-name {accountName}

# List blobs in container
az storage blob list --container-name {containerName} --account-name {accountName} --output table

# Find publicly accessible blobs
for account in $(az storage account list --query '[].name' -o tsv); do
  for container in $(az storage container list --account-name "$account" --query '[].name' -o tsv); do
    public_level=$(az storage container show --name "$container" --account-name "$account" --query 'properties.publicAccess' -o tsv)
    if [ "$public_level" != "None" ]; then
      echo "$account/$container is publicly accessible: $public_level"
    fi
  done
done
```

### Network Configuration

```bash
# List virtual networks
az network vnet list --output table

# Get network security groups
az network nsg list --output table

# Examine NSG rules
az network nsg rule list --nsg-name {nsgName} --resource-group {rg} --output table

# Check firewall rules
az network firewall list --output table

# Find private endpoints
az network private-endpoint list --output table
```

### Key Vault Enumeration

```bash
# List key vaults
az keyvault list --output table

# Try to access secrets (requires permissions)
az keyvault secret list --vault-name {vaultName}

# Get secret value
az keyvault secret show --vault-name {vaultName} --name {secretName}

# List certificates
az keyvault certificate list --vault-name {vaultName}

# Check access policies
az keyvault show --name {vaultName} --query 'properties.accessPolicies'
```

### Managed Identity Discovery

```bash
# Find managed identities
az identity list --output table

# Get managed identity details
az identity show --resource-group {rg} --name {identityName}

# Check role assignments for managed identity
az role assignment list --assignee {principalId}
```

### API Endpoint Discovery

```bash
# Find Azure App Services
az appservice plan list --output table

# Enumerate web apps
az webapp list --output table

# Get app configuration
az webapp show --name {appName} --resource-group {rg}

# Check app authentication settings
az webapp auth show --name {appName} --resource-group {rg}

# List Function Apps
az functionapp list --output table

# Get function app configuration
az functionapp show --name {functionAppName} --resource-group {rg}
```

### Database Enumeration

```bash
# List SQL servers
az sql server list --output table

# List databases
az sql db list --server {serverName} --resource-group {rg} --output table

# Get SQL database connection details
az sql db show --name {dbName} --server {serverName} --resource-group {rg}

# List SQL firewall rules
az sql server firewall-rule list --server {serverName} --resource-group {rg}

# Find databases with public endpoints
az sql server list --query '[].{Name:name, PublicNetworkAccess:publicNetworkAccess}' -o table

# List Cosmos DB accounts
az cosmosdb list --output table

# Get Cosmos DB connection strings
az cosmosdb keys list --name {accountName} --resource-group {rg}

# List SQL Managed Instances
az sql mi list --output table

# Check database connection policies
az sql db show --name {dbName} --server {serverName} --resource-group {rg} --query 'connectionPolicy'
```

### Cache and Data Services

```bash
# List Redis Cache instances
az redis list --output table

# Get Redis access keys
az redis list-keys --name {cacheName} --resource-group {rg}

# List Elastic databases
az postgres server list --output table

# List MySQL servers
az mysql server list --output table

# Get MySQL firewall rules
az mysql server firewall-rule list --server-name {serverName} --resource-group {rg}

# List MariaDB servers
az mariadb server list --output table

# Check connection string format
az postgres server show --name {serverName} --resource-group {rg} --query 'fullyQualifiedDomainName'
```

### Messaging and Event Services

```bash
# List service buses
az servicebus namespace list --output table

# Get service bus keys
az servicebus namespace authorization-rule keys list --namespace-name {namespace} --name RootManageSharedAccessKey --resource-group {rg}

# List queues
az servicebus queue list --namespace-name {namespace} --resource-group {rg}

# List topics
az servicebus topic list --namespace-name {namespace} --resource-group {rg}

# List event grids
az eventgrid topic list --output table

# List event hubs
az eventhub namespace list --output table

# Get event hub keys
az eventhub namespace authorization-rule keys list --namespace-name {namespace} --name RootManageSharedAccessKey --resource-group {rg}
```

### Logic Apps and Automation

```bash
# List logic apps
az logic workflow list --output table

# Get logic app details
az logic workflow show --name {workflowName} --resource-group {rg}

# List automation accounts
az automation account list --output table

# List runbooks
az automation runbook list --automation-account-name {accountName} --resource-group {rg}

# Get runbook content
az automation runbook export --automation-account-name {accountName} --name {runbookName} --resource-group {rg}

# List webhooks
az automation webhook list --automation-account-name {accountName} --resource-group {rg}

# Check webhook details
az automation webhook show --automation-account-name {accountName} --name {webhookName} --resource-group {rg}
```

## Authenticated Reconnaissance (Elevated Privilege)

- Use dedicated Azure CLI profiles for testing
- Run reconnaissance commands from approved network ranges
- Monitor Azure Activity Log for suspicious queries
- Avoid bulk queries during business hours
- Document all enumeration activities

## Common Information Sources

- Azure Portal publicly visible information
- Azure AD login page (user enumeration)
- Azure Services API documentation
- Public GitHub repositories with .env or config files
- Azure Storage Explorer with SAS URLs found online
- Corporate websites disclosing infrastructure details
