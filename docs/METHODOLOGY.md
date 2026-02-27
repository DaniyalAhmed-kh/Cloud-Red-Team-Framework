# Cloud Security Assessment Methodology

This document describes the systematic approach to cloud security penetration testing, adapted for Azure, AWS, GCP, and Kubernetes environments.

## Assessment Framework

### Phase 1: Scoping & Authorization

Define the scope explicitly:
- Cloud tenants/accounts in scope
- Subscription/project identifiers
- Resource types included (compute, storage, database, networking, identity)
- Time windows and business constraints
- Rules of engagement (data access restrictions, availability impact)
- Escalation contacts

Document baseline:
- Cloud provider versions
- Identity provider configuration
- Network architecture
- Authentication mechanisms in use

### Phase 2: Reconnaissance

Gather information about the target cloud infrastructure without exploiting vulnerabilities.

#### Remote Reconnaissance
- Cloud provider metadata endpoints
- DNS enumeration (subdomain discovery)
- HTTP header analysis
- Certificate transparency logs
- Public GitHub repositories and commits
- Cloud resource exposure scanning

#### Local Reconnaissance (if initial access obtained)
- Cloud metadata service queries
- Configuration file inspection
- Environment variable analysis
- Service principal/role discovery
- Network connectivity mapping

#### Documentation
- Create attack surface map
- Identify trust boundaries
- Document authentication methods
- Map data flows

### Phase 3: Vulnerability Assessment

Identify weaknesses in cloud configuration and deployment:

#### Identity & Access
- Overpermissioned identities
- Unused service accounts
- Credential exposure
- MFA bypass opportunities
- Inheritance-based permission chains

#### Resource Configuration
- Public accessibility settings
- Network security group/firewall rules
- Encryption status
- Logging and auditing gaps
- Default configurations

#### Application Layer
- Authentication flaws
- API authorization bypass
- Injection vulnerabilities
- Token handling issues
- Secrets in code or logs

#### Infrastructure
- Outdated runtimes and dependencies
- Container escape vectors
- Kubernetes RBAC misconfigurations
- Orchestration platform weaknesses

### Phase 4: Exploitation

Validate identified vulnerabilities through controlled exploitation:

#### Initial Access
- Abuse identified entry points
- Obtain credentials or tokens
- Gain shell access or command execution

#### Persistence
- Install persistent mechanisms
- Maintain access across service restarts
- Secure backup access methods

#### Privilege Escalation
- Move from initial identity to higher-privileged identity
- Abuse misconfigurations
- Exploit platform features

#### Lateral Movement
- Enumerate accessible resources from current position
- Move between subscriptions/accounts/projects
- Access data across trust boundaries

#### Data Collection
- Locate sensitive data
- Extract or exfiltrate
- Document findings

### Phase 5: Reporting

Document findings with:
- Clear impact assessment
- Reproducible steps
- Proof-of-concept evidence
- Remediation recommendations
- Timeline and complexity rating

Rating Framework:
- **Critical** - Unauthorized data access, account takeover, infrastructure compromise
- **High** - Privilege escalation, unauthorized resource access, compliance violation
- **Medium** - Information disclosure, misconfiguration, attack chain enabler
- **Low** - Defense evasion, minor information disclosure, non-critical misconfiguration

## Key Differences from Traditional Pentesting

### Shared Responsibility Model
Cloud providers maintain infrastructure security. Assessment focuses on customer-controlled elements:
- Identity and access management
- Application configuration
- Data protection
- Network segmentation
- Logging and monitoring

### Identity-Centric Attacks
Cloud security is often compromised through identity abuse rather than network-level compromise:
- Service principal credentials
- Personal user credentials
- API keys and tokens
- Authentication tokens in memory
- Session hijacking

### Blast Radius
Actions in cloud environments may have broad impact:
- Subscription-wide resource access
- Tenant-wide role assignments
- Data replication across regions
- Cross-service dependencies

Always evaluate impact before exploitation.

### Audit Trail Generation
Cloud platforms generate extensive audit logs:
- All API calls are logged
- Timestamped with identity
- Often centralized in SIEM
- Use this to your advantage during reporting

## Documentation Standards

For each finding:
1. **Vulnerability Type** - Map to CWE/CVSS
2. **Affected Resources** - Specific identifiers
3. **Attack Prerequisites** - What must be true to exploit
4. **Impact** - What an attacker could achieve
5. **Evidence** - Screenshots, command output, logs
6. **Remediation** - Specific configuration changes
7. **Detection** - How to identify if exploitation occurred

## Operational Security

- Use dedicated cloud accounts for assessments
- Isolate lab environments
- Don't persist personal tooling in target environments
- Clean up test data and temporary identities
- Document all changes for cleanup verification
- Maintain separate audit trails
- Use VPN/approved networks only
- Avoid account takeover during business hours unless approved

## Escalation Procedures

Establish clear escalation protocols:
- Critical findings require immediate notification
- Pre-arranged out-of-band communication channels
- Incident response contact information
- Rollback procedures for access restoration

## Continuous Reassessment

Cloud infrastructure changes rapidly:
- Re-evaluate scope quarterly
- Test new services and integrations
- Verify remediation of previous findings
- Update tooling and techniques based on platform changes
