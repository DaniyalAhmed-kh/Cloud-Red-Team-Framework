#!/usr/bin/env python3
"""
Comprehensive Cloud Infrastructure Scanner
Performs deep enumeration across all four cloud platforms in a single pass.
Generates comprehensive risk assessment report.
"""

import subprocess
import json
import sys
from datetime import datetime
from pathlib import Path

class ComprehensiveCloudScanner:
    def __init__(self, output_file="cloud_assessment.json"):
        self.output_file = output_file
        self.findings = {
            "scan_date": datetime.now().isoformat(),
            "azure": {"resources": [], "risks": []},
            "aws": {"resources": [], "risks": []},
            "gcp": {"resources": [], "risks": []},
            "kubernetes": {"resources": [], "risks": []}
        }
    
    def scan_azure(self):
        """Comprehensive Azure enumeration"""
        print("[*] Scanning Azure infrastructure...")
        
        try:
            # Get subscriptions
            result = subprocess.run(
                ["az", "account", "list", "--output", "json"],
                capture_output=True, text=True, timeout=30
            )
            subscriptions = json.loads(result.stdout)
            
            for sub in subscriptions:
                sub_id = sub['id']
                print(f"  [+] Scanning subscription: {sub['name']}")
                
                subprocess.run(["az", "account", "set", "--subscription", sub_id],
                              capture_output=True, timeout=10)
                
                # Get resources
                resources_result = subprocess.run(
                    ["az", "resource", "list", "--output", "json"],
                    capture_output=True, text=True, timeout=60
                )
                resources = json.loads(resources_result.stdout)
                
                for resource in resources:
                    self.findings["azure"]["resources"].append({
                        "name": resource.get('name'),
                        "type": resource.get('type'),
                        "id": resource.get('id'),
                        "location": resource.get('location')
                    })
                
                # Get role assignments
                roles_result = subprocess.run(
                    ["az", "role", "assignment", "list", "--output", "json"],
                    capture_output=True, text=True, timeout=60
                )
                roles = json.loads(roles_result.stdout)
                
                # Flag high-privilege roles
                for role in roles:
                    if any(x in role.get('roleDefinitionName', '') 
                           for x in ['Owner', 'Contributor', 'Administrator']):
                        self.findings["azure"]["risks"].append({
                            "type": "High Privilege Role",
                            "principal": role.get('principalName'),
                            "role": role.get('roleDefinitionName'),
                            "scope": role.get('scope')
                        })
                
                # Check storage accounts
                storage_result = subprocess.run(
                    ["az", "storage", "account", "list", "--output", "json"],
                    capture_output=True, text=True, timeout=60
                )
                
                if storage_result.returncode == 0:
                    storage_accounts = json.loads(storage_result.stdout)
                    for account in storage_accounts:
                        # Check if public access enabled
                        if account.get('allowBlobPublicAccess'):
                            self.findings["azure"]["risks"].append({
                                "type": "Public Blob Access Enabled",
                                "storage_account": account.get('name'),
                                "severity": "HIGH"
                            })
                
        except Exception as e:
            print(f"  [-] Azure scan error: {str(e)}")
    
    def scan_aws(self):
        """Comprehensive AWS enumeration"""
        print("[*] Scanning AWS infrastructure...")
        
        try:
            # Get account info
            account_result = subprocess.run(
                ["aws", "sts", "get-caller-identity", "--output", "json"],
                capture_output=True, text=True, timeout=30
            )
            
            if account_result.returncode != 0:
                print("  [-] AWS credentials not configured")
                return
            
            account_info = json.loads(account_result.stdout)
            print(f"  [+] Account: {account_info['Account']}")
            
            # Get IAM users
            users_result = subprocess.run(
                ["aws", "iam", "list-users", "--output", "json"],
                capture_output=True, text=True, timeout=60
            )
            
            if users_result.returncode == 0:
                users = json.loads(users_result.stdout)
                for user in users.get('Users', []):
                    self.findings["aws"]["resources"].append({
                        "type": "IAM User",
                        "name": user.get('UserName'),
                        "created": user.get('CreateDate').isoformat()
                    })
                    
                    # Check access keys
                    keys_result = subprocess.run(
                        ["aws", "iam", "list-access-keys", "--user-name", user['UserName']],
                        capture_output=True, text=True, timeout=30
                    )
                    
                    if keys_result.returncode == 0:
                        keys = json.loads(keys_result.stdout)
                        if len(keys.get('AccessKeyMetadata', [])) > 1:
                            self.findings["aws"]["risks"].append({
                                "type": "Multiple Access Keys",
                                "user": user.get('UserName'),
                                "key_count": len(keys['AccessKeyMetadata']),
                                "severity": "MEDIUM"
                            })
            
            # Get EC2 instances with public IPs
            ec2_result = subprocess.run(
                ["aws", "ec2", "describe-instances", "--output", "json"],
                capture_output=True, text=True, timeout=60
            )
            
            if ec2_result.returncode == 0:
                reservations = json.loads(ec2_result.stdout)
                for reservation in reservations.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        self.findings["aws"]["resources"].append({
                            "type": "EC2 Instance",
                            "instance_id": instance.get('InstanceId'),
                            "state": instance.get('State', {}).get('Name'),
                            "public_ip": instance.get('PublicIpAddress')
                        })
            
            # Get S3 buckets
            buckets_result = subprocess.run(
                ["aws", "s3", "ls", "--output", "json"],
                capture_output=True, text=True, timeout=60
            )
            
        except Exception as e:
            print(f"  [-] AWS scan error: {str(e)}")
    
    def scan_gcp(self):
        """Comprehensive GCP enumeration"""
        print("[*] Scanning GCP infrastructure...")
        
        try:
            # Get projects
            projects_result = subprocess.run(
                ["gcloud", "projects", "list", "--format=json"],
                capture_output=True, text=True, timeout=60
            )
            
            if projects_result.returncode != 0:
                print("  [-] GCP not configured")
                return
            
            projects = json.loads(projects_result.stdout)
            
            for project in projects:
                project_id = project['projectId']
                print(f"  [+] Scanning project: {project_id}")
                
                # Set current project
                subprocess.run(
                    ["gcloud", "config", "set", "project", project_id],
                    capture_output=True, timeout=10
                )
                
                # Get service accounts
                sa_result = subprocess.run(
                    ["gcloud", "iam", "service-accounts", "list", "--format=json"],
                    capture_output=True, text=True, timeout=60
                )
                
                if sa_result.returncode == 0:
                    service_accounts = json.loads(sa_result.stdout)
                    for sa in service_accounts:
                        self.findings["gcp"]["resources"].append({
                            "type": "Service Account",
                            "email": sa.get('email'),
                            "display_name": sa.get('displayName')
                        })
                        
                        # Check keys
                        keys_result = subprocess.run(
                            ["gcloud", "iam", "service-accounts", "keys", "list",
                             f"--iam-account={sa['email']}", "--format=json"],
                            capture_output=True, text=True, timeout=30
                        )
                        
                        if keys_result.returncode == 0:
                            keys = json.loads(keys_result.stdout)
                            # Flag user-managed keys
                            for key in keys:
                                if key.get('keyType') == 'USER_MANAGED':
                                    self.findings["gcp"]["risks"].append({
                                        "type": "User-Managed Service Account Key",
                                        "service_account": sa['email'],
                                        "key_id": key.get('name'),
                                        "severity": "HIGH"
                                    })
                
                # Get IAM policy
                policy_result = subprocess.run(
                    ["gcloud", "projects", "get-iam-policy", project_id, "--format=json"],
                    capture_output=True, text=True, timeout=30
                )
                
                if policy_result.returncode == 0:
                    policy = json.loads(policy_result.stdout)
                    for binding in policy.get('bindings', []):
                        if 'admin' in binding.get('role', '').lower():
                            for member in binding.get('members', []):
                                self.findings["gcp"]["risks"].append({
                                    "type": "Admin Role Binding",
                                    "member": member,
                                    "role": binding['role'],
                                    "severity": "HIGH"
                                })
        
        except Exception as e:
            print(f"  [-] GCP scan error: {str(e)}")
    
    def scan_kubernetes(self):
        """Comprehensive Kubernetes enumeration"""
        print("[*] Scanning Kubernetes cluster...")
        
        try:
            # Get current context
            context_result = subprocess.run(
                ["kubectl", "config", "current-context"],
                capture_output=True, text=True, timeout=10
            )
            
            if context_result.returncode != 0:
                print("  [-] kubectl not configured")
                return
            
            context = context_result.stdout.strip()
            print(f"  [+] Current context: {context}")
            
            # Get nodes
            nodes_result = subprocess.run(
                ["kubectl", "get", "nodes", "-o", "json"],
                capture_output=True, text=True, timeout=30
            )
            
            if nodes_result.returncode == 0:
                nodes = json.loads(nodes_result.stdout)
                for node in nodes.get('items', []):
                    self.findings["kubernetes"]["resources"].append({
                        "type": "Node",
                        "name": node['metadata']['name'],
                        "status": node['status']['conditions'][-1]['type']
                    })
            
            # Check RBAC
            roles_result = subprocess.run(
                ["kubectl", "get", "clusterroles", "-o", "json"],
                capture_output=True, text=True, timeout=30
            )
            
            if roles_result.returncode == 0:
                roles = json.loads(roles_result.stdout)
                for role in roles.get('items', []):
                    rules = role['rules']
                    # Check for dangerous permissions
                    for rule in rules:
                        if '*' in rule.get('verbs', []) and '*' in rule.get('resources', []):
                            self.findings["kubernetes"]["risks"].append({
                                "type": "Overly Permissive Role",
                                "role": role['metadata']['name'],
                                "permissions": "Full Access",
                                "severity": "CRITICAL"
                            })
            
            # Get service accounts with tokens
            sa_result = subprocess.run(
                ["kubectl", "get", "serviceaccount", "-A", "-o", "json"],
                capture_output=True, text=True, timeout=30
            )
            
            if sa_result.returncode == 0:
                service_accounts = json.loads(sa_result.stdout)
                for sa in service_accounts.get('items', []):
                    self.findings["kubernetes"]["resources"].append({
                        "type": "Service Account",
                        "namespace": sa['metadata']['namespace'],
                        "name": sa['metadata']['name']
                    })
        
        except Exception as e:
            print(f"  [-] Kubernetes scan error: {str(e)}")
    
    def run_scan(self):
        """Execute comprehensive scan"""
        print("[*] Starting comprehensive cloud infrastructure scan")
        print(f"[*] Output file: {self.output_file}")
        
        self.scan_azure()
        self.scan_aws()
        self.scan_gcp()
        self.scan_kubernetes()
        
        # Write results
        with open(self.output_file, 'w') as f:
            json.dump(self.findings, f, indent=2)
        
        # Print summary
        print("\n[*] Scan Summary:")
        print(f"  Azure: {len(self.findings['azure']['resources'])} resources, {len(self.findings['azure']['risks'])} risks")
        print(f"  AWS: {len(self.findings['aws']['resources'])} resources, {len(self.findings['aws']['risks'])} risks")
        print(f"  GCP: {len(self.findings['gcp']['resources'])} resources, {len(self.findings['gcp']['risks'])} risks")
        print(f"  Kubernetes: {len(self.findings['kubernetes']['resources'])} resources, {len(self.findings['kubernetes']['risks'])} risks")
        
        total_risks = (
            len(self.findings['azure']['risks']) +
            len(self.findings['aws']['risks']) +
            len(self.findings['gcp']['risks']) +
            len(self.findings['kubernetes']['risks'])
        )
        
        print(f"\n[!] Total risks identified: {total_risks}")
        print(f"[+] Results saved to: {self.output_file}")

if __name__ == "__main__":
    output_file = sys.argv[1] if len(sys.argv) > 1 else "cloud_assessment.json"
    scanner = ComprehensiveCloudScanner(output_file)
    scanner.run_scan()
