# Cloud Attack Surface Mapping

Understanding the attack surface is critical for comprehensive security assessment. Cloud environments present unique attack vectors not found in traditional infrastructure.

## Azure Attack Surface

### Authentication & Authorization
- **Entra ID (Azure AD)**
  - User account compromise
  - Service principal credential theft
  - Managed identity token extraction
  - MFA bypass
  - Conditional access bypass
  - B2B guest account abuse
  
- **Application Authentication**
  - OIDC/OAuth misconfiguration
  - Token validation bypass
  - Scope elevation
  - Client credential exposure

### Compute
- **Virtual Machines**
  - OS vulnerability exploitation
  - VM metadata service abuse
  - Managed identity token theft
  - Extension execution
  - Serial console access
  
- **App Service**
  - Application source code access
  - Configuration file exposure
  - Managed identity token extraction
  - SCM endpoint abuse
  - FTP credential exposure

- **Azure Functions**
  - Runtime environment variable exposure
  - Connection string theft
  - Managed identity impersonation
  - Code injection

- **Container Instances**
  - Container escape
  - Environment variable exposure
  - Volume mount abuse
  - Managed identity access

### Storage
- **Blob Storage**
  - Anonymous public access
  - SAS token exposure
  - Shared Key abuse
  - Unencrypted data at rest
  - Soft delete bypass

- **File Shares**
  - SMB protocol weaknesses
  - Share enumeration
  - Anonymous access
  - Credential exposure

- **Tables & Queues**
  - Anonymous access
  - Queue poisoning
  - Data exfiltration

### Database
- **SQL Database**
  - Default credentials
  - Firewall bypass
  - Transparent data encryption bypass
  - Connection string exposure
  - Database user privilege escalation

- **Cosmos DB**
  - Primary key exposure
  - Firewall bypass
  - Unauthorized document access

### Networking
- **Virtual Networks**
  - NSG bypass
  - Private endpoint abuse
  - Service endpoint misconfiguration
  - Network watcher abuse

- **Application Gateway**
  - Backend selection manipulation
  - SSL/TLS termination bypass
  - WAF bypass

### Management & Governance
- **Azure RBAC**
  - Overpermissioned roles
  - Service principal impersonation
  - Delegated administration abuse
  - Temporary access elevation

- **Policy & Compliance**
  - Policy bypass
  - Audit trail deletion
  - Compliance report manipulation

---

## AWS Attack Surface

### Authentication & Authorization
- **IAM**
  - Access key credential theft
  - STS token impersonation
  - Cross-account role assumption
  - Principal policy confusion
  - Permission boundaries bypass
  - Resource-based policy abuse

- **Cognito**
  - ID token forgery
  - MFA bypass
  - User pool misconfiguration
  - Cross-user identity confusion

### Compute
- **EC2**
  - Instance metadata service (IMDSv2 bypass)
  - IAM instance profile credential extraction
  - Runaway instance creation
  - Security group bypass
  - EBS volume attachment
  - AMI backdooring

- **Lambda**
  - Environment variable exposure
  - Layer injection
  - Concurrency limits abuse
  - VPC endpoint misconfiguration
  - Container image tampering

- **Elastic Beanstalk**
  - Configuration exposure
  - Platform hook execution
  - Auto-scaling abuse

### Storage
- **S3**
  - Bucket policy misconfiguration
  - ACL abuse
  - Object Lock bypass
  - Server-side encryption key abuse
  - Unencrypted object access
  - Bucket versioning exploitation
  - CloudFront cache poisoning

- **EBS**
  - Snapshot sharing
  - Volume cloning
  - Encryption key access

- **EFS**
  - Mount target abuse
  - Access point misconfiguration

### Database
- **RDS**
  - Enhanced monitoring bypass
  - Database user privilege escalation
  - Backup access
  - Parameter group manipulation
  - Multi-AZ failover exploitation

- **DynamoDB**
  - Global secondary index abuse
  - Streams data extraction
  - TTL manipulation

### Management & Governance
- **CloudTrail**
  - Logging bypass
  - Trail deletion
  - Multi-region trail manipulation

- **CloudWatch**
  - Log group access
  - Metric manipulation
  - Alarm configuration abuse

- **Organizations**
  - Cross-account access
  - Service control policy bypass
  - Account assumption

---

## GCP Attack Surface

### Authentication & Authorization
- **Cloud Identity**
  - User account compromise
  - Service account key theft
  - Workload identity federation bypass
  - SAML assertion forgery
  - OAuth scope elevation

- **IAM**
  - Custom role abuse
  - Role assumption
  - Service account impersonation
  - Organization policy bypass
  - Resource hierarchy confusion

### Compute
- **Compute Engine**
  - VM metadata service abuse
  - Service account token extraction
  - SSH key access
  - Startup scripts execution
  - Instance template backdooring

- **Cloud Functions**
  - Environment variable exposure
  - Runtime environment access
  - Default service account abuse
  - Source code extraction

- **Cloud Run**
  - Container image access
  - Environment variable exposure
  - Service account token extraction
  - Invoker permission abuse

- **GKE (Google Kubernetes Engine)**
  - Cluster metadata exposure
  - Node credential theft
  - RBAC misconfiguration
  - Workload identity abuse

### Storage
- **Cloud Storage**
  - Bucket public access
  - Uniform bucket-level access bypass
  - Signed URL expiration issues
  - Object versioning abuse
  - Lifecycle rule manipulation

- **Cloud SQL**
  - Auth proxy bypass
  - Database user privilege escalation
  - Backup access
  - Private IP exposure

### Data & Analytics
- **BigQuery**
  - Dataset public access
  - Table data extraction
  - Service account impersonation
  - Query job enumeration

- **Cloud Dataflow**
  - Worker node access
  - Temporary storage access
  - Credentials in environment

### Management & Governance
- **Cloud Audit Logs**
  - Log exclusion filters
  - Log bucket deletion
  - Sink manipulation

- **Security Command Center**
  - Finding manipulation
  - Custom module abuse

---

## Kubernetes Attack Surface

### Authentication
- **API Server**
  - Default service accounts
  - Bearer token exposure
  - Client certificate misuse
  - Webhook misconfiguration

- **Kubelet**
  - Unauthenticated API access
  - Anonymous authorization
  - Token review bypass

### Authorization
- **RBAC**
  - Wildcard permission usage
  - Role escalation
  - ClusterRole abuse
  - RoleBinding misconfiguration
  - Service account token access

- **Pod Security**
  - Privileged containers
  - Host network access
  - Host PID namespace access
  - Unrestricted capabilities

### Container Runtime
- **Docker**
  - Container escape
  - Volume mount abuse
  - Privileged mode exploitation
  - Runtime configuration bypass

- **containerd/CRI-O**
  - Similar escape vectors
  - Configuration file access
  - Runtime socket exposure

### Storage
- **Secrets**
  - Unencrypted etcd access
  - Secret YAML exposure
  - Default encryption bypass
  - Secret volume mount abuse

- **ConfigMaps**
  - Sensitive data storage
  - Mount point access

### Networking
- **Network Policies**
  - Misconfiguration allowing unauthorized traffic
  - Calico policy bypass
  - CNI plugin weaknesses

- **Ingress**
  - Controller misconfiguration
  - Cross-namespace access
  - TLS termination bypass

- **Service Mesh**
  - mTLS bypass
  - Authorization policy misconfiguration
  - Sidecar injection abuse

### Cluster Management
- **ETCD**
  - Unauthenticated access
  - Encryption key exposure
  - Backup file access

- **Control Plane Components**
  - Scheduler information disclosure
  - Controller manager credential access
  - API server audit bypass

---

## Multi-Cloud Attack Vectors

### Cross-Account/Cross-Project Movement
- Trust relationship exploitation
- Shared resource access
- Cross-cloud service principal linking

### Supply Chain Attacks
- Container registry poisoning
- Helm chart tampering
- Dependency injection in CI/CD

### Credential Centralization
- Secrets manager compromise
- Configuration service abuse
- Shared identity platform exploitation

### Data Exfiltration Paths
- Cross-region data movement
- Backup service abuse
- Replication configuration misuse
