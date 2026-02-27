# GCP Reconnaissance

Reconnaissance in GCP environments involves enumerating projects, service accounts, and resources through API queries.

## Project Discovery

```bash
# Find accessible projects
gcloud projects list --format="table(projectId,name,projectNumber)"

# Get current project info
gcloud config get-value project

# Find projects by organization
gcloud projects list --filter='parent.id={organizationId}'

# Check project quotas and limits
gcloud compute project-info describe --project={projectId}
```

## Service Account Enumeration

```bash
# List service accounts in project
gcloud iam service-accounts list --project={projectId}

# Get service account details
gcloud iam service-accounts describe {serviceAccountEmail} --project={projectId}

# List service account keys
gcloud iam service-accounts keys list --iam-account={serviceAccountEmail}

# Check service account impersonation permissions
gcloud iam service-accounts get-iam-policy {serviceAccountEmail}
```

## IAM Role Enumeration

```bash
# List custom roles
gcloud iam roles list --project={projectId}

# Get role permissions
gcloud iam roles describe {roleId} --project={projectId}

# List IAM policy bindings
gcloud projects get-iam-policy {projectId}

# Find service accounts with high privileges
gcloud projects get-iam-policy {projectId} | grep -A 5 "roles/owner\|roles/editor"
```

## Compute Resources

```bash
# List Compute Engine instances
gcloud compute instances list --project={projectId}

# Get instance details including service account
gcloud compute instances describe {instanceName} --zone={zone} --project={projectId}

# List instance templates
gcloud compute instance-templates list --project={projectId}

# Check instance startup scripts
gcloud compute instances describe {instanceName} --zone={zone} --project={projectId} | grep -A 10 "startup-script"

# List Cloud Functions
gcloud functions list --project={projectId}

# Get function configuration
gcloud functions describe {functionName} --project={projectId} --region={region}
```

## Storage Resources

```bash
# List Cloud Storage buckets
gsutil ls

# Check bucket permissions
gsutil iam get gs://{bucketName}

# List objects in bucket
gsutil ls -r gs://{bucketName}/

# Check bucket-level public access
gcloud storage buckets describe gs://{bucketName} --project={projectId}

# Find publicly accessible buckets
gsutil ls -L gs://{bucketName}/ 2>/dev/null | grep -i "public\|allUsers"
```

## Database Enumeration

```bash
# List Cloud SQL instances
gcloud sql instances list --project={projectId}

# Get instance details
gcloud sql instances describe {instanceName} --project={projectId}

# List database users
gcloud sql users list --instance={instanceName}

# Check firewall rules
gcloud sql instances describe {instanceName} --project={projectId} | jq '.ipAddresses[] | select(.type=="PRIVATE" or .type=="PUBLIC")'

# List Datastore entities
gcloud datastore export gs://{backupBucket}/ --kinds=Entity --project={projectId}

# BigQuery dataset enumeration
bq ls --project-id={projectId}
bq show --project-id={projectId} {datasetId}
```

## Network Resources

```bash
# List VPCs
gcloud compute networks list --project={projectId}

# List firewall rules
gcloud compute firewall-rules list --project={projectId}

# Check routes
gcloud compute routes list --project={projectId}

# List subnets
gcloud compute networks list --format="table(name)"

# For each network, list subnets
for network in $(gcloud compute networks list --format="value(name)"); do
  gcloud compute networks subnets list --network=$network --project={projectId}
done
```

## Kubernetes Cluster Discovery

```bash
# List GKE clusters
gcloud container clusters list --project={projectId}

# Get cluster credentials
gcloud container clusters get-credentials {clusterName} --zone={zone} --project={projectId}

# Check cluster-level RBAC
gcloud container clusters describe {clusterName} --zone={zone} --project={projectId} | grep -i "rbac\|networkPolicy"

# List workload identities
kubectl describe sa --all-namespaces | grep -i "workload"
```

## Secret & Configuration Discovery

```bash
# List secrets in Secret Manager
gcloud secrets list --project={projectId}

# Get secret value
gcloud secrets versions access latest --secret={secretName} --project={projectId}

# List runtime config
gcloud runtime-config configs list --project={projectId}
```

## Audit & Logging

```bash
# List Cloud Audit Logs
gcloud logging read "resource.type=gce_instance" --limit=50 --project={projectId}

# Check logging sinks
gcloud logging sinks list --project={projectId}

# Get log bucket retention
gcloud logging buckets list --location=global --project={projectId}

# Check if Cloud Audit Logs are enabled
gcloud logging buckets describe _Default --location=global --project={projectId}
```

## External Identities

```bash
# Check for Workload Identity Federation
gcloud iam workload-identity-pools list --location=global --project={projectId}

# Check external account configurations
gcloud iam workload-identity-pools describe {poolId} --location=global --project={projectId}

# Enumerate SAML/OIDC providers
gcloud iam workload-identity-pools providers list --location=global --workload-identity-pool={poolId}
```

## DNS & Certificates

```bash
# List Cloud DNS zones
gcloud dns managed-zones list --project={projectId}

# List DNS records
gcloud dns record-sets list --zone={zoneName} --project={projectId}

# Enumerate SSL/TLS certificates
gcloud compute ssl-certificates list --project={projectId}

# Check certificate details
gcloud compute ssl-certificates describe {certificateName} --project={projectId}
```

## Metadata Server Enumeration

```bash
# From GCP instance, query metadata service
curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/

# Get service account email
curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email

# Get service account identity token
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience={audience}"

# Get service account access token
curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

## Key Findings

- Service accounts with excessive permissions
- Public Cloud Storage buckets with data exposure
- Publicly accessible Cloud SQL instances
- Overpermissioned Compute instances
- Disabled Cloud Audit Logs
- Exposed secrets in Secret Manager
- Firewall rules allowing unrestricted access
- Workload identities with broad permissions
