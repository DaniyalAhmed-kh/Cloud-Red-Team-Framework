# Cloud Security Hardening Guide

## AWS Hardening Baseline

### Identity & Access Management (IAM)

#### Principle of Least Privilege
```bash
# Review all user permissions
aws iam get-user-policy {user-name}
aws iam list-attached-user-policies --user-name {user-name}

# Remove unnecessary policies
aws iam detach-user-policy \
  --user-name {user-name} \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Create least-privilege policies instead
cat > least-privilege.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::specific-bucket/*"
    },
    {
      "Effect": "Allow",
      "Action": "logs:PutLogEvents",
      "Resource": "arn:aws:logs:*:*:*"
    }
  ]
}
EOF
```

#### Enable MFA
```bash
# Enforce MFA for all users
aws iam create-account-password-policy \
  --minimum-password-length 14 \
  --require-symbols \
  --require-numbers \
  --require-uppercase-characters \
  --require-lowercase-characters \
  --allow-users-to-change-password

# Check for users without MFA
aws iam get-credential-report | grep -v "true$"
```

#### Rotate Keys Regularly
```bash
# Identify old access keys (>90 days)
aws iam list-access-keys --user-name {user-name} \
  --query 'AccessKeyMetadata[?CreateDate < `'"$(date -u -d '90 days ago' +%Y-%m-%d)"'`]'

# Deactivate and replace
aws iam delete-access-key --user-name {user-name} --access-key-id {key-id}
```

#### Remove Unused Accounts
```bash
# Find unused users (no access in 30 days)
aws iam list-users --query 'Users[].UserName' --output text | while read user; do
  LAST_USED=$(aws iam get-user --user-name $user | jq '.User.CreateDate')
  # Compare and remove if old
done
```

### Networking Security

#### VPC Configuration
```bash
# Disable public IP on subnets
aws ec2 modify-subnet-attribute \
  --subnet-id {subnet-id} \
  --no-map-public-ip-on-launch

# Create VPC with private subnets only
aws ec2 create-vpc --cidr-block 10.0.0.0/16

# Enable VPC Flow Logs
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids {vpc-id} \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name /aws/vpc/flow-logs
```

#### Security Groups
```bash
# Restrict ingress (deny all by default)
aws ec2 revoke-security-group-ingress \
  --group-id {sg-id} \
  --protocol all \
  --cidr 0.0.0.0/0

# Only allow necessary ports
aws ec2 authorize-security-group-ingress \
  --group-id {sg-id} \
  --protocol tcp \
  --port 443 \
  --cidr 203.0.113.0/24  # Your IP range

# Audit all inbound rules
aws ec2 describe-security-groups \
  --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].GroupId'
```

#### NACLs
```bash
# Create restrictive NACL
aws ec2 create-network-acl-entry \
  --network-acl-id {nacl-id} \
  --rule-number 100 \
  --protocol tcp \
  --port-range From=443,To=443 \
  --cidr-block 203.0.113.0/24 \
  --ingress

# Deny all else
aws ec2 create-network-acl-entry \
  --network-acl-id {nacl-id} \
  --rule-number 32767 \
  --protocol -1 \
  --cidr-block 0.0.0.0/0 \
  --ingress
```

### Data Protection

#### S3 Security
```bash
# Block public access on all buckets
aws s3api put-public-access-block \
  --bucket {bucket-name} \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Enable encryption
aws s3api put-bucket-encryption \
  --bucket {bucket-name} \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}
    }]
  }'

# Enable versioning (for recovery)
aws s3api put-bucket-versioning \
  --bucket {bucket-name} \
  --versioning-configuration Status=Enabled

# Enable logging
aws s3api put-bucket-logging \
  --bucket {bucket-name} \
  --bucket-logging-status 'LoggingEnabled={TargetBucket={bucket-name}-logs,TargetPrefix=s3-logs/}'

# Disable ACLs (use policies instead)
aws s3api put-bucket-acl \
  --bucket {bucket-name} \
  --acl private

# Enforce HTTPS
aws s3api put-bucket-policy \
  --bucket {bucket-name} \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::{bucket-name}/*", "arn:aws:s3:::{bucket-name}"],
      "Condition": {"Bool": {"aws:SecureTransport": "false"}}
    }]
  }'
```

#### RDS Security
```bash
# Enable encryption at rest
aws rds modify-db-instance \
  --db-instance-identifier {db-name} \
  --storage-encrypted \
  --apply-immediately

# Use customer-managed KMS keys
aws rds modify-db-instance \
  --db-instance-identifier {db-name} \
  --kms-key-id arn:aws:kms:region:account:key/id \
  --apply-immediately

# Disable public accessibility
aws rds modify-db-instance \
  --db-instance-identifier {db-name} \
  --no-publicly-accessible

# Enable backup encryption
aws rds modify-db-instance \
  --db-instance-identifier {db-name} \
  --storage-encrypted \
  --backup-retention-period 30

# Create snapshot on delete
aws rds modify-db-instance \
  --db-instance-identifier {db-name} \
  --skip-final-snapshot false \
  --final-db-snapshot-identifier {db-name}-final-snapshot
```

### Monitoring & Logging

#### CloudTrail Configuration
```bash
# Enable CloudTrail logging
aws cloudtrail create-trail \
  --name organization-trail \
  --s3-bucket-name {bucket-name} \
  --is-multi-region-trail \
  --include-global-service-events

# Start logging
aws cloudtrail start-logging --trail-name organization-trail

# Validate log file integrity
aws cloudtrail validate-logs \
  --trail-name organization-trail \
  --start-time 2024-01-01 \
  --end-time 2024-01-31

# Encrypt logs with KMS
aws cloudtrail create-trail \
  --name secure-trail \
  --s3-bucket-name {bucket-name} \
  --kms-key-id arn:aws:kms:region:account:key/id
```

#### CloudWatch Alarms
```bash
# Alert on unauthorized API calls
aws cloudwatch put-metric-alarm \
  --alarm-name UnauthorizedAPICallsAlarm \
  --alarm-description "Alert on unauthorized API calls" \
  --metric-name UnauthorizedOperationCount \
  --namespace CloudTrailMetrics \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold

# Alert on root account usage
aws cloudwatch put-metric-alarm \
  --alarm-name RootAccountUsageAlarm \
  --metric-name RootAccountLoginCount \
  --namespace CloudTrailMetrics \
  --statistic Sum \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold
```

#### Config Rules
```bash
# Enable AWS Config
aws configservice put-config-aggregator \
  --config-aggregator-name organization-aggregator \
  --account-aggregation-sources AccountIds=123456789012,AwsRegions=us-east-1

# Enable specific rules
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "s3-bucket-public-read-prohibited",
    "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"}
  }'
```

---

## Azure Hardening Baseline

### Identity & Access Management

#### Conditional Access
```bash
# Create policy for MFA requirement
az ad conditional-access policy create \
  --display-name "Require MFA for all users" \
  --conditions users.include.all=true \
  --grant-controls require.grant_controls=mfa \
  --state enabled
```

#### RBAC Best Practices
```bash
# Remove Owner roles (use Contributor instead)
az role assignment delete \
  --assignee {user-id} \
  --role Owner

# Use managed identities instead of service principals
az identity create \
  --resource-group {rg} \
  --name app-identity

# Assign specific roles
az role assignment create \
  --assignee-object-id {identity-id} \
  --role "Storage Blob Data Reader" \
  --scope /subscriptions/{sub-id}
```

### Networking

#### Network Security Groups
```bash
# Create restrictive NSG
az network nsg create --resource-group {rg} --name secure-nsg

# Allow only HTTPS inbound
az network nsg rule create \
  --resource-group {rg} \
  --nsg-name secure-nsg \
  --name AllowHTTPS \
  --priority 100 \
  --protocol Tcp \
  --direction Inbound \
  --destination-port-ranges 443 \
  --access Allow \
  --source-address-prefixes 203.0.113.0/24

# Deny all else
az network nsg rule create \
  --resource-group {rg} \
  --nsg-name secure-nsg \
  --name DenyAll \
  --priority 4096 \
  --protocol '*' \
  --direction Inbound \
  --access Deny
```

#### Azure Firewall
```bash
# Deploy Azure Firewall
az network firewall create \
  --resource-group {rg} \
  --name enterprise-firewall

# Create application rules (whitelist traffic)
az network firewall application-rule create \
  --resource-group {rg} \
  --firewall-name enterprise-firewall \
  --collection-name AllowAppServices \
  --action Allow \
  --protocols http=80 https=443 \
  --target-fqdns "*azure.microsoft.com"
```

### Data Security

#### Storage Account Protection
```bash
# Enable encryption
az storage account update \
  --resource-group {rg} \
  --name {account-name} \
  --encryption-key-type-for-queue {key-type}

# Disable public access
az storage account update \
  --resource-group {rg} \
  --name {account-name} \
  --default-action Deny

# Whitelist only trusted networks
az storage account network-rule add \
  --resource-group {rg} \
  --account-name {account-name} \
  --ip-address 203.0.113.0/24
```

#### SQL Database Security
```bash
# Enable Transparent Data Encryption (TDE)
az sql db update \
  --resource-group {rg} \
  --server {server-name} \
  --database {db-name} \
  --encryption-protector /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults/{vault}/keys/{key}/versions/{version}

# Disable public endpoint
az sql server firewall-rule create \
  --resource-group {rg} \
  --server {server-name} \
  --name AllowVNetRule \
  --start-ip-address 10.0.0.0 \
  --end-ip-address 10.255.255.255

# Enable advanced threat protection
az sql db threat-policy update \
  --resource-group {rg} \
  --server {server-name} \
  --database {db-name} \
  --state Enabled
```

### Monitoring

#### Azure Monitor Configuration
```bash
# Create Log Analytics workspace
az monitor log-analytics workspace create \
  --resource-group {rg} \
  --workspace-name secure-workspace

# Enable diagnostics for all resources
az monitor diagnostic-settings create \
  --name {setting-name} \
  --resource {resource-id} \
  --logs '[{"category":"Administrative","enabled":true}]' \
  --workspace {workspace-id}

# Create alert rule
az monitor metrics alert create \
  --name HighCPUAlert \
  --resource-group {rg} \
  --scopes {vm-id} \
  --condition "avg Percentage CPU > 80" \
  --description "Alert when CPU exceeds 80%"
```

---

## GCP Hardening Baseline

### Identity & Access Management

#### Service Account Security
```bash
# Create service account with minimal permissions
gcloud iam service-accounts create app-sa \
  --project={project-id} \
  --display-name="Application Service Account"

# Grant only necessary roles
gcloud projects add-iam-policy-binding {project-id} \
  --member=serviceAccount:app-sa@{project-id}.iam.gserviceaccount.com \
  --role=roles/storage.objectViewer

# Rotate keys regularly
gcloud iam service-accounts keys list \
  --iam-account=app-sa@{project-id}.iam.gserviceaccount.com
```

#### Organization Policy
```bash
# Enforce MFA
gcloud resource-manager org-policies create --parent=organizations/{org-id} \
  --file=mfa-policy.yaml

# Restrict public IP access
gcloud resource-manager org-policies create --parent=organizations/{org-id} \
  --file=no-public-ip-policy.yaml

# Enforce encryption
gcloud resource-manager org-policies create --parent=organizations/{org-id} \
  --file=cmek-policy.yaml
```

### Networking

#### VPC Configuration
```bash
# Create VPC with custom subnet (private)
gcloud compute networks create secure-network \
  --subnet-mode=custom

gcloud compute networks subnets create secure-subnet \
  --network=secure-network \
  --range=10.0.1.0/24 \
  --enable-flow-logs \
  --enable-private-ip-google-access

# Create firewall rules (allow internally only)
gcloud compute firewall-rules create allow-internal \
  --network=secure-network \
  --allow=tcp,udp,icmp \
  --source-ranges=10.0.0.0/8
```

#### Cloud Armor
```bash
# Create security policy
gcloud compute security-policies create secure-policy

# Add rule to block suspicious traffic
gcloud compute security-policies rules create 100 \
  --security-policy=secure-policy \
  --action=deny-403 \
  --expression="origin.region_code == 'CN'"

# Apply to load balancer
gcloud compute backend-services update {service-name} \
  --security-policy=secure-policy \
  --global
```

### Data Security

#### Cloud Storage
```bash
# Enable uniform bucket-level access
gsutil uniformbucketlevelaccess set on gs://{bucket-name}

# Enable encryption with CMEK
gcloud storage buckets update gs://{bucket-name} \
  --default-encryption-key=projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}

# Enable versioning
gsutil versioning set on gs://{bucket-name}

# Enable logging
gsutil logging set on -b gs://{log-bucket} gs://{bucket-name}
```

#### Cloud SQL
```bash
# Create instance with private IP only
gcloud sql instances create secure-instance \
  --database-version=MYSQL_8_0 \
  --network=secure-network \
  --no-assign-ip \
  --require-ssl \
  --region={region}

# Enable automated backups
gcloud sql backups create --instance=secure-instance \
  --description="Daily backup"

# Enforce SSL connections
gcloud sql instances patch secure-instance \
  --require-ssl
```

### Monitoring

#### Cloud Audit Logs
```bash
# Enable audit logs on all resources
gcloud projects update {project-id} \
  --enable-cloud-audit-logs

# Export audit logs to BigQuery
gcloud logging sinks create audit-logs-sink \
  bigquery.googleapis.com/projects/{project-id}/datasets/audit_logs \
  --log-filter='resource.type="gce_instance"'
```

#### Cloud Security Command Center
```bash
# Enable SCC
gcloud beta scc settings update --enable-security-command-center

# Create custom finding
gcloud beta scc findings create \
  --source={source-id} \
  --resource-name=//compute.googleapis.com/projects/{project-id}/zones/{zone}/instances/{instance} \
  --category=UNENCRYPTED_DATA
```

---

## Kubernetes Hardening

### RBAC Hardening
```bash
# Remove default admin binding
kubectl delete clusterrolebinding cluster-admin

# Create minimal roles
cat > minimal-role.yaml << 'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: minimal-role
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
EOF

kubectl apply -f minimal-role.yaml
```

### Network Policies
```bash
# Deny all traffic by default
cat > deny-all.yaml << 'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
EOF

# Allow only necessary traffic
cat > allow-traffic.yaml << 'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-web
spec:
  podSelector:
    matchLabels:
      app: web
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: default
    ports:
    - protocol: TCP
      port: 80
EOF
```

### Pod Security Policies
```bash
cat > restricted-psp.yaml << 'EOF'
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
  - ALL
  volumes:
  - 'configMap'
  - 'emptyDir'
  - 'projected'
  - 'secret'
  - 'downwardAPI'
  - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
  fsGroup:
    rule: 'RunAsAny'
  readOnlyRootFilesystem: true
EOF

kubectl apply -f restricted-psp.yaml
```

---

## Security Audit Checklist

- [ ] All users have MFA enabled
- [ ] IAM policies follow least privilege principle
- [ ] No AdministratorAccess policies attached to users/roles
- [ ] CloudTrail logging enabled and protected
- [ ] S3 buckets have public access blocked
- [ ] All databases have encryption enabled
- [ ] VPC Flow Logs enabled
- [ ] Security Groups have restrictive rules
- [ ] Unused IAM users removed
- [ ] Access keys rotated regularly (< 90 days)
- [ ] Config Rules enabled with remediation
- [ ] CloudWatch alarms configured
- [ ] VPN/private connectivity for all management access
- [ ] Backup policies configured
- [ ] Disaster recovery plan tested
- [ ] Security group rules audited for 0.0.0.0/0
- [ ] DDoS protection enabled (AWS Shield Advanced/Azure DDoS Protection)
- [ ] WAF enabled on public endpoints
- [ ] Encryption in transit (TLS/SSL) enforced
- [ ] Encryption at rest with customer-managed keys
- [ ] Compliance monitoring enabled
- [ ] Incident response plan documented
- [ ] Security training completed for all users

