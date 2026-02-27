#!/usr/bin/env python3
"""
Cloud Enumeration Tool - Reconnaissance across AWS, Azure, GCP

Usage:
    ./cloud-enum.py --platform aws --profile default
    ./cloud-enum.py --platform azure --tenant-id {tenantId}
    ./cloud-enum.py --platform gcp --project {projectId}
"""

import argparse
import json
import subprocess
import sys
from typing import List, Dict, Any
from dataclasses import dataclass, asdict
from datetime import datetime


@dataclass
class Finding:
    timestamp: str
    platform: str
    category: str
    resource_type: str
    resource_id: str
    risk_level: str
    description: str
    details: Dict[str, Any]


class CloudEnumerator:
    def __init__(self, platform: str):
        self.platform = platform
        self.findings: List[Finding] = []
    
    def run_command(self, cmd: str) -> str:
        """Execute shell command and return output."""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            print(f"[!] Command timeout: {cmd}", file=sys.stderr)
            return ""
        except Exception as e:
            print(f"[!] Command failed: {e}", file=sys.stderr)
            return ""
    
    def add_finding(self, category: str, resource_type: str, resource_id: str, 
                    risk_level: str, description: str, details: Dict[str, Any] = None):
        """Add finding to report."""
        finding = Finding(
            timestamp=datetime.now().isoformat(),
            platform=self.platform,
            category=category,
            resource_type=resource_type,
            resource_id=resource_id,
            risk_level=risk_level,
            description=description,
            details=details or {}
        )
        self.findings.append(finding)
    
    def report(self) -> str:
        """Generate findings report."""
        if not self.findings:
            return "No findings discovered."
        
        output = f"\n[*] {len(self.findings)} findings discovered\n"
        
        # Group by risk level
        critical = [f for f in self.findings if f.risk_level == "CRITICAL"]
        high = [f for f in self.findings if f.risk_level == "HIGH"]
        medium = [f for f in self.findings if f.risk_level == "MEDIUM"]
        
        if critical:
            output += f"\n[!] CRITICAL ({len(critical)}):\n"
            for f in critical:
                output += f"  - {f.resource_type}: {f.resource_id}\n    {f.description}\n"
        
        if high:
            output += f"\n[!] HIGH ({len(high)}):\n"
            for f in high:
                output += f"  - {f.resource_type}: {f.resource_id}\n    {f.description}\n"
        
        if medium:
            output += f"\n[*] MEDIUM ({len(medium)}):\n"
            for f in medium:
                output += f"  - {f.resource_type}: {f.resource_id}\n    {f.description}\n"
        
        return output


class AWSEnumerator(CloudEnumerator):
    def __init__(self, profile: str = "default"):
        super().__init__("AWS")
        self.profile = profile
        self.account_id = self._get_account_id()
    
    def _get_account_id(self) -> str:
        """Get AWS account ID."""
        cmd = f"aws sts get-caller-identity --profile {self.profile} --query 'Account' -o text"
        return self.run_command(cmd)
    
    def enumerate_iam(self):
        """Enumerate IAM configuration."""
        print("[*] Enumerating IAM...")
        
        # Check for overpermissioned users
        cmd = f"aws iam list-users --profile {self.profile} --query 'Users[].UserName' -o json"
        users = json.loads(self.run_command(cmd) or "[]")
        
        for user in users:
            # Check attached policies
            cmd = f"aws iam list-attached-user-policies --user-name {user} --profile {self.profile} --query 'AttachedPolicies[].PolicyName' -o json"
            policies = json.loads(self.run_command(cmd) or "[]")
            
            if "AdministratorAccess" in policies:
                self.add_finding(
                    category="IAM",
                    resource_type="User",
                    resource_id=user,
                    risk_level="CRITICAL",
                    description="User has AdministratorAccess policy",
                    details={"policies": policies}
                )
    
    def enumerate_s3(self):
        """Enumerate S3 buckets."""
        print("[*] Enumerating S3...")
        
        cmd = f"aws s3 ls --profile {self.profile} --output json"
        output = self.run_command(cmd)
        
        # Parse bucket names and check permissions
        for line in output.split('\n'):
            if not line:
                continue
            
            bucket_name = line.split()[-1] if line.split() else None
            if not bucket_name:
                continue
            
            # Check ACL
            cmd = f"aws s3api get-bucket-acl --bucket {bucket_name} --profile {self.profile} --query 'Grants[?Grantee.Type==`Group`]' -o json"
            grants = json.loads(self.run_command(cmd) or "[]")
            
            if grants:
                self.add_finding(
                    category="Storage",
                    resource_type="S3 Bucket",
                    resource_id=bucket_name,
                    risk_level="HIGH",
                    description="Bucket has public ACLs",
                    details={"grants": grants}
                )
    
    def enumerate_ec2(self):
        """Enumerate EC2 security groups."""
        print("[*] Enumerating EC2...")
        
        cmd = f"aws ec2 describe-security-groups --profile {self.profile} --query 'SecurityGroups[]' -o json"
        sgs = json.loads(self.run_command(cmd) or "[]")
        
        for sg in sgs:
            # Check for 0.0.0.0/0 rules
            for rule in sg.get('IpPermissions', []):
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        self.add_finding(
                            category="Network",
                            resource_type="Security Group",
                            resource_id=sg['GroupId'],
                            risk_level="MEDIUM",
                            description=f"Allows unrestricted inbound access on port {rule.get('FromPort')}",
                            details={"group_name": sg['GroupName']}
                        )
    
    def enumerate(self):
        """Run full enumeration."""
        print(f"[*] Enumerating AWS (Account: {self.account_id})...")
        self.enumerate_iam()
        self.enumerate_s3()
        self.enumerate_ec2()


class AzureEnumerator(CloudEnumerator):
    def __init__(self, tenant_id: str):
        super().__init__("Azure")
        self.tenant_id = tenant_id
    
    def enumerate_rbac(self):
        """Enumerate RBAC configuration."""
        print("[*] Enumerating RBAC...")
        
        cmd = f"az role assignment list --all --output json"
        assignments = json.loads(self.run_command(cmd) or "[]")
        
        for assignment in assignments:
            role_name = assignment.get('roleDefinitionName', '')
            
            if 'Owner' in role_name or 'Administrator' in role_name:
                principal = assignment.get('principalName', assignment.get('principalId', ''))
                self.add_finding(
                    category="IAM",
                    resource_type="Role Assignment",
                    resource_id=principal,
                    risk_level="HIGH",
                    description=f"Principal has {role_name} role",
                    details={"scope": assignment.get('scope')}
                )
    
    def enumerate_storage(self):
        """Enumerate storage accounts."""
        print("[*] Enumerating Storage...")
        
        cmd = "az storage account list --output json"
        accounts = json.loads(self.run_command(cmd) or "[]")
        
        for account in accounts:
            account_name = account.get('name', '')
            
            # Check for public access
            cmd = f"az storage container list --account-name {account_name} --output json 2>/dev/null"
            containers = json.loads(self.run_command(cmd) or "[]")
            
            for container in containers:
                public_access = container.get('properties', {}).get('publicAccess')
                if public_access and public_access != 'None':
                    self.add_finding(
                        category="Storage",
                        resource_type="Storage Container",
                        resource_id=f"{account_name}/{container.get('name')}",
                        risk_level="CRITICAL",
                        description=f"Container publicly accessible ({public_access})"
                    )
    
    def enumerate(self):
        """Run full enumeration."""
        print(f"[*] Enumerating Azure (Tenant: {self.tenant_id})...")
        self.enumerate_rbac()
        self.enumerate_storage()


class GCPEnumerator(CloudEnumerator):
    def __init__(self, project_id: str):
        super().__init__("GCP")
        self.project_id = project_id
    
    def enumerate_iam(self):
        """Enumerate IAM configuration."""
        print("[*] Enumerating IAM...")
        
        cmd = f"gcloud projects get-iam-policy {self.project_id} --flatten='bindings[].members' --format='table(bindings.role,bindings.members)'"
        output = self.run_command(cmd)
        
        # Check for overpermissioned service accounts
        for line in output.split('\n'):
            if 'roles/owner' in line.lower() or 'roles/editor' in line.lower():
                self.add_finding(
                    category="IAM",
                    resource_type="IAM Binding",
                    resource_id=self.project_id,
                    risk_level="CRITICAL",
                    description=f"High privilege role assigned: {line}",
                    details={"project": self.project_id}
                )
    
    def enumerate_storage(self):
        """Enumerate Cloud Storage."""
        print("[*] Enumerating Storage...")
        
        cmd = f"gsutil ls -p {self.project_id}"
        buckets = self.run_command(cmd).split('\n')
        
        for bucket in buckets:
            if not bucket:
                continue
            
            # Check IAM policy
            cmd = f"gsutil iam get {bucket} 2>/dev/null | grep -i 'allUsers\\|allAuthenticatedUsers'"
            result = self.run_command(cmd)
            
            if result:
                self.add_finding(
                    category="Storage",
                    resource_type="GCS Bucket",
                    resource_id=bucket,
                    risk_level="CRITICAL",
                    description="Bucket is publicly accessible"
                )
    
    def enumerate(self):
        """Run full enumeration."""
        print(f"[*] Enumerating GCP (Project: {self.project_id})...")
        self.enumerate_iam()
        self.enumerate_storage()


def main():
    parser = argparse.ArgumentParser(description="Cloud Enumeration Tool")
    parser.add_argument("--platform", choices=["aws", "azure", "gcp"], required=True)
    parser.add_argument("--profile", default="default", help="AWS profile name")
    parser.add_argument("--tenant-id", help="Azure tenant ID")
    parser.add_argument("--project", help="GCP project ID")
    parser.add_argument("--output", help="Output file (JSON)")
    
    args = parser.parse_args()
    
    # Create appropriate enumerator
    if args.platform == "aws":
        enumerator = AWSEnumerator(args.profile)
    elif args.platform == "azure":
        if not args.tenant_id:
            print("[!] --tenant-id required for Azure")
            sys.exit(1)
        enumerator = AzureEnumerator(args.tenant_id)
    elif args.platform == "gcp":
        if not args.project:
            print("[!] --project required for GCP")
            sys.exit(1)
        enumerator = GCPEnumerator(args.project)
    
    # Run enumeration
    enumerator.enumerate()
    
    # Output report
    print(enumerator.report())
    
    # Save JSON if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump([asdict(f) for f in enumerator.findings], f, indent=2)
        print(f"\n[+] Findings saved to {args.output}")


if __name__ == "__main__":
    main()
