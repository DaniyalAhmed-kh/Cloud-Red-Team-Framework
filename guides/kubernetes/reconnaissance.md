# Kubernetes Reconnaissance

Reconnaissance in Kubernetes involves enumerating cluster components, RBAC configuration, and workload security posture.

## API Server Access

### Discover and Connect

```bash
# Find Kubernetes API server
# From within cluster
KUBE_API="https://kubernetes.default.svc.cluster.local:443"

# From outside cluster (if exposed)
kubectl cluster-info

# Get API server endpoint
kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}'

# Test unauthenticated access
curl -s https://{api-server}:6443/api/v1/namespaces
# If returns 401, authentication required
```

### Service Account Token Extraction

```bash
# From running pod
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

# Use token to query API
curl -s https://kubernetes.default.svc.cluster.local:443/api/v1/namespaces \
  -H "Authorization: Bearer $TOKEN" \
  -k

# Token often has broader access than expected
# Test access to secrets, configmaps, etc.
```

## RBAC Enumeration

```bash
# List all roles
kubectl get roles --all-namespaces

# List all cluster roles
kubectl get clusterroles

# Get specific role details
kubectl get clusterrole admin -o yaml

# Check role bindings
kubectl get rolebindings --all-namespaces

# Check cluster role bindings
kubectl get clusterrolebindings

# Find roles accessible to current service account
kubectl auth can-i --list

# Check what service account can do
kubectl auth can-i get pods --as=system:serviceaccount:default:default
```

## Service Account Discovery

```bash
# List service accounts
kubectl get serviceaccounts --all-namespaces

# Get service account details
kubectl get serviceaccount -n {namespace} {saName} -o yaml

# Check service account token mount location
kubectl get secret -n {namespace} {saTokenSecretName} -o yaml

# Find service accounts with privileged access
kubectl get clusterrolebinding -o json | jq '.items[] | select(.roleRef.name=="cluster-admin") | .subjects'

# Check for service account token automounting
kubectl get sa --all-namespaces -o json | jq '.items[] | select(.automountServiceAccountToken==true)'
```

## Workload Enumeration

```bash
# List all pods
kubectl get pods --all-namespaces -o wide

# Get pod details including volumes and security context
kubectl get pod {podName} -n {namespace} -o yaml

# Find pods running as root
kubectl get pods --all-namespaces -o json | \
  jq '.items[] | select(.spec.containers[].securityContext.runAsUser==0) | .metadata.name'

# List deployments
kubectl get deployments --all-namespaces

# List DaemonSets
kubectl get daemonsets --all-namespaces

# List StatefulSets
kubectl get statefulsets --all-namespaces

# Check init containers
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.initContainers!=null)'
```

## Secret & ConfigMap Discovery

```bash
# List secrets
kubectl get secrets --all-namespaces

# Get secret content
kubectl get secret {secretName} -n {namespace} -o yaml

# Decode base64 secret
kubectl get secret {secretName} -n {namespace} -o jsonpath='{.data.password}' | base64 -d

# List configmaps
kubectl get configmaps --all-namespaces

# Get configmap content
kubectl get configmap {configmapName} -n {namespace} -o yaml

# Search for secrets containing credentials
kubectl get secrets --all-namespaces -o json | jq '.items[] | select(.data.password!=null or .data.token!=null or .data."api-key"!=null)'
```

## Network Policy and Security

```bash
# List network policies
kubectl get networkpolicies --all-namespaces

# Check network policy details
kubectl get networkpolicy -n {namespace} {policyName} -o yaml

# If no network policies, cluster-wide east-west traffic allowed

# Check Pod Security Policy
kubectl get psp

# Check Pod Security Standards
kubectl label namespace {namespace} pod-security.kubernetes.io/enforce=restricted --dry-run

# Check network plugin
kubectl get daemonsets -n kube-system | grep -i "calico\|flannel\|weave"

# Check ingress controllers
kubectl get ingress --all-namespaces

# Examine ingress configuration
kubectl get ingress {ingressName} -n {namespace} -o yaml
```

## Storage Enumeration

```bash
# List persistent volumes
kubectl get pv

# Check PV details including access modes
kubectl get pv -o yaml

# List persistent volume claims
kubectl get pvc --all-namespaces

# Check storage classes
kubectl get storageclass

# Find volumes with sensitive data
kubectl get pvc --all-namespaces -o json | jq '.items[] | {name: .metadata.name, namespace: .metadata.namespace, size: .spec.resources.requests.storage}'

# Check for accessible host paths
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.volumes[]?.hostPath!=null) | {pod: .metadata.name, path: .spec.volumes[].hostPath.path}'
```

## Node Enumeration

```bash
# List all nodes
kubectl get nodes -o wide

# Get node details
kubectl describe node {nodeName}

# Check kubelet configuration
curl -s http://localhost:10250/pods | jq '.items[] | .metadata.name'

# Check node resource usage
kubectl top nodes

# Find unschedulable nodes (may indicate issues)
kubectl get nodes --field-selector=spec.unschedulable=true

# Check for exposed kubelet API
# Common ports: 10250 (kubelet), 10255 (read-only API)
```

## ETCD Access

```bash
# Check if etcd is accessible
kubectl get endpoints etcd-servers -n kube-system

# If etcd pod running in cluster
kubectl exec -it {etcdPod} -n kube-system -- sh

# From etcd pod, access database
etcdctl --endpoints=http://localhost:2379 get / --prefix

# Dump all keys
etcdctl --endpoints=http://localhost:2379 get / --prefix --keys-only
```

## Addon & Extension Enumeration

```bash
# List kube-system pods
kubectl get pods -n kube-system

# Check API server configuration
kubectl get pod apiserver -n kube-system -o yaml | grep -i "admission\|authorization"

# List webhook configurations
kubectl get validatingwebhookconfigurations
kubectl get mutatingwebhookconfigurations

# Check for privilege escalation via webhooks
# Webhooks can modify resources before admission
```

## Control Plane Access

```bash
# Check if control plane components exposed
# kube-controller-manager, kube-scheduler ports

# Common ports:
# kube-apiserver: 6443 (secured) or 8080 (unsecured)
# kube-controller-manager: 10252 (unsecured)
# kube-scheduler: 10251 (unsecured)

netstat -tulnp | grep -E "(6443|8080|10252|10251)"

# If unsecured ports accessible
curl -s http://localhost:10252/metrics | head -20

# kube-scheduler metrics may reveal workload information
```

## Key Findings

- Service accounts with cluster-admin role
- Pods running as root
- Service accounts with overpermissioned roles
- Secrets containing credentials stored in plain YAML
- Missing network policies (lateral movement possible)
- Disabled Pod Security Policies
- Exposed kubelet API
- Accessible etcd database
- Unsecured control plane components
