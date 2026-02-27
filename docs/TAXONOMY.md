# Cloud Security Vulnerability Taxonomy

Classification and severity framework for cloud security findings.

## Classification System

### Attack Vector
- **Network** - Accessible over network without authentication
- **Adjacent** - Requires network access within same VPC/region
- **Local** - Requires local access to compute resource
- **Physical** - Requires physical access

### Attack Complexity
- **Low** - Standard exploitation, minimal prerequisites
- **High** - Complex attack chain, multiple conditions required

### Privileges Required
- **None** - No authentication required
- **Low** - Basic user privileges sufficient
- **High** - Administrative/privileged access needed

### User Interaction
- **None** - Attack succeeds without user participation
- **Required** - User action necessary (e.g., credential theft)

## Cloud-Specific Severity Ratings

### Critical
- Unauthorized access to production data
- Account takeover
- Privilege escalation to admin
- Data exfiltration capability
- Complete infrastructure compromise
- Ransomware/destruction capability

Example: Public S3 bucket containing unencrypted customer database

### High
- Privilege escalation (non-admin)
- Unauthorized resource modification
- Partial data exposure
- Service disruption capability
- Compliance violation
- Supply chain attack vector

Example: Service principal with excessive permissions on data storage

### Medium
- Information disclosure (non-sensitive)
- Lateral movement enabler
- Configuration weakness
- Defense evasion
- Audit trail manipulation

Example: Overpermissioned IAM role not directly accessing data

### Low
- Minor misconfiguration
- Hardened attack prerequisite
- Non-critical system exposure
- Limited impact information disclosure

Example: Public API with rate limiting

## Vulnerability Categories

### Identity & Access Management

| Category | Description | Typical Severity |
|----------|-------------|-----------------|
| Overpermissioned Identities | Users/roles with excessive privileges | High |
| Default Credentials | Unchanged default passwords/keys | Critical |
| Credential Exposure | Secrets in code/logs/storage | Critical |
| Multi-account Access | Excessive cross-account permissions | High |
| Privilege Escalation | IAM abuse enabling admin access | Critical |
| MFA Bypass | Circumventing multi-factor authentication | Critical |

### Data Security

| Category | Description | Typical Severity |
|----------|-------------|-----------------|
| Unencrypted Data at Rest | Plaintext sensitive data in storage | Critical |
| Unencrypted Data in Transit | Network traffic without TLS | High |
| Public Data Exposure | Accessible to any internet user | Critical |
| Overshared Access | Resource accessible beyond intended users | High |
| Backup Exposure | Unprotected database/storage backups | Critical |
| Data Retention | Unnecessary data retention periods | High |

### Network Security

| Category | Description | Typical Severity |
|----------|-------------|-----------------|
| Overpermissive Firewall | NSG/SG allowing 0.0.0.0/0 | High |
| VPC Misconfiguration | Weak network segmentation | High |
| DNS Misuse | DNS hijacking/spoofing capability | High |
| DDoS Exposure | Susceptible to denial of service | Medium |
| Lateral Movement Paths | Uncontrolled east-west traffic | Medium |

### Application Security

| Category | Description | Typical Severity |
|----------|-------------|-----------------|
| Authentication Bypass | Circumventing authentication | Critical |
| Authorization Bypass | Accessing unauthorized resources | Critical |
| Injection Attacks | Code/command injection capability | High |
| API Exposure | Unauthenticated API endpoints | High |
| Session Hijacking | Stealing/reusing session tokens | High |

### Container/Kubernetes Security

| Category | Description | Typical Severity |
|----------|-------------|-----------------|
| Privilege Escalation | Container escape or RBAC bypass | Critical |
| Secret Exposure | Kubernetes secrets in memory/storage | Critical |
| Pod Escape | Breaking container boundaries | Critical |
| RBAC Misconfiguration | Overpermissioned service accounts | High |
| Image Vulnerabilities | Known CVEs in container images | High |
| Network Policy Weakness | Unrestricted pod-to-pod communication | Medium |

### Compliance & Audit

| Category | Description | Typical Severity |
|----------|-------------|-----------------|
| Audit Disabled | Logging/monitoring not enabled | High |
| Audit Trail Manipulation | Logs deleted/modified | High |
| Compliance Violation | Breach of regulatory requirement | High |
| Backup Failure | No recovery capability | High |
| Change Tracking | Untracked infrastructure changes | Medium |

## Exploitability Assessment

### Easily Exploitable
- Public POC available
- Single attack step
- No special tools needed
- No user interaction required

Example: Public S3 bucket

### Moderately Exploitable  
- Known attack technique
- Requires tool/script
- Multiple attack steps
- Requires specific environment

Example: Service principal privilege escalation

### Difficult to Exploit
- Complex attack chain
- Custom tooling required
- Environment-specific
- Requires multiple prerequisites

Example: Chained privilege escalation across services

## Impact Assessment

### Confidentiality
- **None** - No information disclosed
- **Low** - Limited non-sensitive data exposure
- **Medium** - Sensitive data partial exposure
- **High** - Critical data exposure
- **Maximum** - Complete data compromise

### Integrity
- **None** - No modification capability
- **Low** - Minor non-critical modification
- **Medium** - Modification of application data
- **High** - Modification of system/configuration
- **Maximum** - Complete system compromise

### Availability
- **None** - No service disruption
- **Low** - Temporary/limited disruption
- **Medium** - Service degradation
- **High** - Service unavailability
- **Maximum** - Extended service loss

## Reporting Template

### Finding Report

```
Title: [Vulnerability Name]

Severity: [Critical|High|Medium|Low]

CVSS Score: [3.9]

Affected Assets:
- [Resource 1]
- [Resource 2]

Description:
[Clear explanation of vulnerability]

Prerequisites:
- [Prerequisite 1]
- [Prerequisite 2]

Impact:
- Confidentiality: [High]
- Integrity: [Medium]
- Availability: [Low]

Attack Scenario:
1. [Step 1]
2. [Step 2]
3. [Outcome]

Evidence:
[Screenshot/log/command output]

Remediation:
1. [Specific configuration change]
2. [Implementation steps]
3. [Verification]

Timeline:
- Discovered: [Date]
- Reported: [Date]
- Patched: [Date]
```

## Cloud-Specific Considerations

### Shared Responsibility Model
- Rate infrastructure vulnerabilities as lower severity (AWS/Azure/GCP responsibility)
- Rate customer configuration issues as higher severity
- Distinguish between platform features and misuse

### Multi-Tenancy
- Increase severity if affecting cross-tenant security
- Rate tenant isolation bypass as critical

### Compliance Requirements
- HIPAA, PCI-DSS, SOC 2 violations increase severity
- Audit/logging impact ratings differ by regulation

### Scale & Blast Radius
- Cloud vulnerabilities often have organization-wide impact
- Rate accordingly based on scope
