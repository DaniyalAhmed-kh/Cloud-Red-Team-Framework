# AWS Reconnaissance

Reconnaissance in AWS involves enumerating accounts, IAM configuration, and discovering accessible resources through both public and authenticated scanning.

## Account Discovery

### Finding AWS Accounts

```bash
# DNS-based account discovery
nslookup s3.amazonaws.com

# Certificate Transparency logs for AWS endpoints
curl -s 'https://crt.sh/?q=%25.amazonaws.com&output=json' | jq -r '.[].name_value' | sort -u

# Organization-specific bucket enumeration
for i in {1..1000}; do
  aws s3 ls s3://company-$i 2>/dev/null && echo "Found: company-$i"
done

# Common naming patterns
for pattern in prod staging dev backup logs archive; do
  aws s3 ls s3://company-$pattern 2>/dev/null && echo "Found: company-$pattern"
done
```

### Account ID Enumeration

```bash
# If you have any credentials, get account ID
aws sts get-caller-identity

# Try to find related accounts
# AWS account IDs follow patterns from same organization

# Check for linked accounts
aws organizations list-accounts --query 'Accounts[].Id' -o tsv

# Cross-account role enumeration
# Assume role to find related accounts
aws sts assume-role --role-arn "arn:aws:iam::{targetAccountId}:role/{roleName}"
```

## IAM Enumeration

### User and Role Discovery

```bash
# List all users (requires appropriate permissions)
aws iam list-users --output table

# List all roles
aws iam list-roles --output table

# Enumerate role trust relationships
aws iam get-role --role-name {roleName} | jq '.Role.AssumeRolePolicyDocument'

# Find roles assumable by external accounts
aws iam list-roles --query 'Roles[?AssumeRolePolicyDocument.Statement[?Effect==`Allow`&&Principal.AWS]].RoleName' -o tsv
```

### Permission Discovery

```bash
# List policies attached to user
aws iam list-user-policies --user-name {userName}

# Get inline policies
aws iam get-user-policy --user-name {userName} --policy-name {policyName}

# List attached managed policies
aws iam list-attached-user-policies --user-name {userName}

# Get managed policy version
aws iam get-policy-version --policy-arn {policyArn} --version-id {versionId}

# Find overpermissioned identities
aws iam list-users --query 'Users[].UserName' -o tsv | while read user; do
  policies=$(aws iam list-attached-user-policies --user-name "$user" --query 'AttachedPolicies[?PolicyName==`AdministratorAccess`]' -o tsv)
  [ -n "$policies" ] && echo "ADMIN: $user"
done
```

### Service Principal Enumeration

```bash
# List access keys for users
aws iam list-access-keys --user-name {userName}

# Check access key age
aws iam get-access-key-last-used --access-key-id {accessKeyId}

# List temporary security credentials
aws iam list-users | jq '.Users[] | {UserName, .}'

# Enumerate STS AssumeRole usage
aws cloudtrail lookup-events --event-name AssumeRole --max-results 10
```

## Resource Enumeration

### Compute

```bash
# List EC2 instances
aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,PrivateIpAddress,PublicIpAddress,State.Name]' -o table

# Find instances with public IP
aws ec2 describe-instances --query 'Reservations[].Instances[?PublicIpAddress!=null].[InstanceId,PublicIpAddress]' -o table

# List Lambda functions
aws lambda list-functions --query 'Functions[].[FunctionName,Runtime,LastModified]' -o table

# Check Lambda environment variables
aws lambda get-function-configuration --function-name {functionName} | jq '.Environment'

# List elastic container registry
aws ecr describe-repositories --query 'repositories[].[repositoryName,repositoryUri]' -o table
```

### Storage

```bash
# List S3 buckets
aws s3 ls

# Check bucket ACL and policy for public access
aws s3api get-bucket-acl --bucket {bucketName}
aws s3api get-bucket-policy --bucket {bucketName}

# List objects in bucket
aws s3 ls s3://{bucketName}/ --recursive --human-readable --summarize

# Check bucket versioning
aws s3api get-bucket-versioning --bucket {bucketName}

# Find publicly readable buckets
for bucket in $(aws s3 ls | awk '{print $3}'); do
  public=$(aws s3api get-bucket-acl --bucket "$bucket" 2>/dev/null | grep -q "AllUsers" && echo "PUBLIC" || echo "PRIVATE")
  echo "$bucket: $public"
done
```

### Database

```bash
# List RDS instances
aws rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,DBInstanceStatus,MasterUsername]' -o table

# Check RDS public accessibility
aws rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,PubliclyAccessible]' -o table

# List security groups for database access
aws rds describe-db-security-groups

# Check database backups
aws rds describe-db-snapshots
```

### Networking

```bash
# List VPCs
aws ec2 describe-vpcs --query 'Vpcs[].[VpcId,CidrBlock]' -o table

# List security groups
aws ec2 describe-security-groups --query 'SecurityGroups[].[GroupId,GroupName,IpPermissions]' -o table

# Check for overpermissive security groups (0.0.0.0/0)
aws ec2 describe-security-groups --query 'SecurityGroups[].IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]' -o json

# List network ACLs
aws ec2 describe-network-acls

# Find Elastic IPs
aws ec2 describe-addresses --query 'Addresses[].[PublicIp,AssociationId]' -o table
```

### Secrets & Configuration

```bash
# List secrets
aws secretsmanager list-secrets --query 'SecretList[].[Name,LastAccessedDate]' -o table

# Get secret value
aws secretsmanager get-secret-value --secret-id {secretName} --query 'SecretString' -o text

# List parameter store
aws ssm describe-parameters --query 'Parameters[].[Name,Type]' -o table

# Get parameter value
aws ssm get-parameter --name {parameterName} --with-decryption --query 'Parameter.Value'
```

## CloudTrail & Audit

```bash
# List CloudTrail trails
aws cloudtrail describe-trails --query 'trailList[].[Name,S3BucketName,IsMultiRegionTrail]' -o table

# Check if logging is enabled
aws cloudtrail get-trail-status --name {trailName}

# Look for disabled trails (may indicate cover-up)
aws cloudtrail describe-trails --include-shadow-trails | jq '.trailList[] | select(.HasCustomEventSelectors==false)'

# Get recent API calls
aws cloudtrail lookup-events --max-results 50 --query 'Events[].[EventTime,EventName,Username]' -o table
```

## Public Access Scanning

```bash
# Check for public S3 buckets
aws s3 ls s3://{bucketName} --no-sign-request 2>&1 | head -20

# Find misconfigured CloudFront distributions
aws cloudfront list-distributions --query 'DistributionList.Items[].[Id,DomainName,DefaultCacheBehavior.ViewerProtocolPolicy]' -o table

# Check API Gateway configurations
aws apigateway get-rest-apis --query 'items[].[name,id]' -o table

# Test API Gateway without credentials
curl -s https://{apiId}.execute-api.{region}.amazonaws.com/{stage}/{resource}
```

## Configuration Assessment

```bash
# List Config rules
aws configservice describe-config-rules --query 'ConfigRules[].[ConfigRuleName,ConfigRuleState]' -o table

# Check compliance status
aws configservice describe-compliance-by-config-rule

# List Config snapshots (may reveal configuration changes)
aws configservice list-config-snapshots
```

## Key Findings to Report

- Overpermissioned IAM users and roles
- Access keys with excessive permissions
- Public S3 buckets containing data
- Unencrypted RDS instances with public access
- Security groups allowing 0.0.0.0/0 access
- Disabled CloudTrail logging
- Exposed secrets in Parameter Store
- Lambda functions with overpermissioned execution roles
