#!/usr/bin/env python3
"""
Kubernetes RBAC Analyzer - Identify overpermissioned roles and bindings

Usage:
    ./k8s-rbac-analyzer.py --kubeconfig ~/.kube/config
    ./k8s-rbac-analyzer.py --kubeconfig ~/.kube/config --audit
"""

import argparse
import json
import subprocess
import sys
from typing import List, Dict, Any
from collections import defaultdict


class RBACAnalyzer:
    def __init__(self, kubeconfig: str = None):
        self.kubeconfig = kubeconfig
        self.findings = []
    
    def kubectl(self, args: str) -> str:
        """Execute kubectl command."""
        cmd = f"kubectl {args}"
        if self.kubeconfig:
            cmd = f"kubectl --kubeconfig {self.kubeconfig} {args}"
        
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            return result.stdout.strip()
        except Exception as e:
            print(f"[!] Command failed: {e}", file=sys.stderr)
            return ""
    
    def get_roles(self) -> List[Dict[str, Any]]:
        """Get all cluster roles and roles."""
        # Cluster roles
        output = self.kubectl("get clusterroles -o json")
        cluster_roles = json.loads(output or "{}")
        
        roles = []
        for role in cluster_roles.get('items', []):
            roles.append({
                'type': 'ClusterRole',
                'name': role['metadata']['name'],
                'namespace': None,
                'rules': role.get('rules', [])
            })
        
        # Namespaced roles
        output = self.kubectl("get roles --all-namespaces -o json")
        ns_roles = json.loads(output or "{}")
        
        for role in ns_roles.get('items', []):
            roles.append({
                'type': 'Role',
                'name': role['metadata']['name'],
                'namespace': role['metadata']['namespace'],
                'rules': role.get('rules', [])
            })
        
        return roles
    
    def get_bindings(self) -> List[Dict[str, Any]]:
        """Get all role bindings."""
        bindings = []
        
        # Cluster role bindings
        output = self.kubectl("get clusterrolebindings -o json")
        crbs = json.loads(output or "{}")
        
        for binding in crbs.get('items', []):
            bindings.append({
                'type': 'ClusterRoleBinding',
                'name': binding['metadata']['name'],
                'namespace': None,
                'roleRef': binding['roleRef'],
                'subjects': binding.get('subjects', [])
            })
        
        # Role bindings
        output = self.kubectl("get rolebindings --all-namespaces -o json")
        rbs = json.loads(output or "{}")
        
        for binding in rbs.get('items', []):
            bindings.append({
                'type': 'RoleBinding',
                'name': binding['metadata']['name'],
                'namespace': binding['metadata']['namespace'],
                'roleRef': binding['roleRef'],
                'subjects': binding.get('subjects', [])
            })
        
        return bindings
    
    def check_dangerous_permissions(self, rules: List[Dict]) -> bool:
        """Check if rules contain dangerous permissions."""
        dangerous_verbs = ['*', 'create', 'delete', 'patch', 'update']
        dangerous_resources = ['clusterroles', 'clusterrolebindings', 'roles', 'rolebindings', 'secrets', '*']
        
        for rule in rules:
            verbs = rule.get('verbs', [])
            resources = rule.get('resources', [])
            
            # Wildcard permissions
            if '*' in verbs or '*' in resources:
                return True
            
            # Check for dangerous combinations
            for verb in verbs:
                if verb in dangerous_verbs:
                    for resource in resources:
                        if resource in dangerous_resources:
                            return True
        
        return False
    
    def analyze(self):
        """Analyze RBAC configuration."""
        print("[*] Analyzing RBAC configuration...")
        
        roles = self.get_roles()
        bindings = self.get_bindings()
        
        # Check roles
        dangerous_roles = []
        for role in roles:
            if self.check_dangerous_permissions(role['rules']):
                dangerous_roles.append(role)
        
        if dangerous_roles:
            print(f"\n[!] Found {len(dangerous_roles)} roles with dangerous permissions:")
            for role in dangerous_roles:
                location = f"{role['namespace']}/{role['name']}" if role['namespace'] else role['name']
                print(f"  - {role['type']}: {location}")
                self.findings.append({
                    'type': 'DangerousRole',
                    'role': role
                })
        
        # Check service accounts
        output = self.kubectl("get serviceaccounts --all-namespaces -o json")
        sas = json.loads(output or "{}")
        
        print(f"\n[*] Analyzing {len(sas.get('items', []))} service accounts...")
        
        for sa in sas.get('items', []):
            sa_name = sa['metadata']['name']
            namespace = sa['metadata']['namespace']
            
            # Find bindings for this service account
            sa_bindings = [b for b in bindings 
                          if any(s['kind'] == 'ServiceAccount' and 
                                s['name'] == sa_name and 
                                s.get('namespace', namespace) == namespace 
                                for s in b['subjects'])]
            
            # Check if service account has dangerous roles
            for binding in sa_bindings:
                role_name = binding['roleRef']['name']
                matching_roles = [r for r in roles 
                                 if r['name'] == role_name and 
                                 (r['namespace'] == namespace or binding['type'] == 'ClusterRoleBinding')]
                
                for role in matching_roles:
                    if self.check_dangerous_permissions(role['rules']):
                        print(f"  [!] {namespace}/{sa_name} has dangerous role: {role_name}")
                        self.findings.append({
                            'type': 'DangerousServiceAccount',
                            'namespace': namespace,
                            'service_account': sa_name,
                            'role': role_name,
                            'binding': binding['name']
                        })
        
        # Check automount
        print(f"\n[*] Checking service account token automount...")
        for sa in sas.get('items', []):
            if sa.get('automountServiceAccountToken', True):
                namespace = sa['metadata']['namespace']
                sa_name = sa['metadata']['name']
                print(f"  [*] {namespace}/{sa_name} has token automount enabled")
    
    def audit(self):
        """Generate audit report."""
        print(f"\n[*] Generated {len(self.findings)} findings")
        for i, finding in enumerate(self.findings, 1):
            print(f"\n[{i}] {finding['type']}")
            if finding['type'] == 'DangerousServiceAccount':
                print(f"    Service Account: {finding['namespace']}/{finding['service_account']}")
                print(f"    Role: {finding['role']}")
                print(f"    Binding: {finding['binding']}")


def main():
    parser = argparse.ArgumentParser(description="Kubernetes RBAC Analyzer")
    parser.add_argument("--kubeconfig", help="Path to kubeconfig file")
    parser.add_argument("--audit", action="store_true", help="Generate audit report")
    
    args = parser.parse_args()
    
    analyzer = RBACAnalyzer(args.kubeconfig)
    analyzer.analyze()
    
    if args.audit:
        analyzer.audit()


if __name__ == "__main__":
    main()
