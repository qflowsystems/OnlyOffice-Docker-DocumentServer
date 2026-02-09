#!/usr/bin/env python3
"""
Convert Trivy scan results to AWS Security Hub findings format.
Adapted for DocumentServer Docker image scanning.
"""
import json
import sys
import uuid
from datetime import datetime, timezone
import os

def convert_trivy_to_security_hub(trivy_file, repo_name, image_tag, commit_sha):
    """
    Convert Trivy JSON output to AWS Security Hub findings format.

    Args:
        trivy_file: Path to Trivy JSON results file
        repo_name: Repository name (e.g., 'staging/onlyoffice-documentserver')
        image_tag: Image tag (e.g., 'v1.0.0')
        commit_sha: Git commit SHA

    Returns:
        List of Security Hub findings
    """
    with open(trivy_file, 'r') as f:
        trivy_data = json.load(f)

    findings = []

    # Process each result (usually one per target)
    for result in trivy_data.get('Results', []):
        target = result.get('Target', 'unknown')

        # Process vulnerabilities
        for vuln in result.get('Vulnerabilities', []):
            finding_id = f"trivy-documentserver-{vuln.get('VulnerabilityID', 'unknown')}-{uuid.uuid4().hex[:8]}"

            # Map Trivy severity to Security Hub
            severity_map = {
                'CRITICAL': {'Label': 'CRITICAL', 'Normalized': 90},
                'HIGH': {'Label': 'HIGH', 'Normalized': 70},
                'MEDIUM': {'Label': 'MEDIUM', 'Normalized': 50},
                'LOW': {'Label': 'LOW', 'Normalized': 30},
                'UNKNOWN': {'Label': 'INFORMATIONAL', 'Normalized': 10}
            }

            severity = severity_map.get(vuln.get('Severity', 'UNKNOWN'), severity_map['UNKNOWN'])

            finding = {
                'SchemaVersion': '2018-10-08',
                'Id': finding_id,
                'ProductArn': f'arn:aws:securityhub:us-east-1::product/aquasecurity/aquasecurity',
                'GeneratorId': 'trivy-github-action-documentserver',
                'AwsAccountId': '397666958145',
                'Types': ['Software and Configuration Checks/Vulnerabilities/CVE'],
                'CreatedAt': datetime.now(timezone.utc).isoformat(),
                'UpdatedAt': datetime.now(timezone.utc).isoformat(),
                'Severity': severity,
                'Title': f"Vulnerability {vuln.get('VulnerabilityID', 'Unknown')} in {vuln.get('PkgName', 'unknown package')}",
                'Description': vuln.get('Description', 'No description available')[:1024],  # Security Hub limit
                'Resources': [{
                    'Type': 'Container',
                    'Id': f"arn:aws:ecr:us-east-1:397666958145:repository/{repo_name}:{image_tag}",
                    'Region': 'us-east-1',
                    'Details': {
                        'Container': {
                            'ImageId': image_tag,
                            'ImageName': f"{repo_name}:{image_tag}"
                        }
                    }
                }],
                'SourceUrl': vuln.get('PrimaryURL', ''),
                'RecordState': 'ACTIVE',
                'WorkflowState': 'NEW',
                'Compliance': {
                    'Status': 'FAILED'
                },
                'Remediation': {
                    'Recommendation': {
                        'Text': f"Update {vuln.get('PkgName', 'package')} from {vuln.get('InstalledVersion', 'unknown')} to {vuln.get('FixedVersion', 'latest available version')}" if vuln.get('FixedVersion') else f"Monitor {vuln.get('PkgName', 'package')} for security updates"
                    }
                }
            }

            # Add CVE information if available
            if vuln.get('VulnerabilityID', '').startswith('CVE-'):
                finding['ProductFields'] = {
                    'CVE': vuln.get('VulnerabilityID'),
                    'Package': vuln.get('PkgName', ''),
                    'InstalledVersion': vuln.get('InstalledVersion', ''),
                    'FixedVersion': vuln.get('FixedVersion', ''),
                    'Target': target,
                    'GitCommit': commit_sha,
                    'Application': 'DocumentServer'
                }

            findings.append(finding)

    return findings

if __name__ == '__main__':
    if len(sys.argv) != 5:
        print("Usage: python convert_to_security_hub.py <trivy_file> <repo_name> <image_tag> <commit_sha>")
        print("Example: python convert_to_security_hub.py trivy-results.json staging/onlyoffice-documentserver v1.0.0 abc123")
        sys.exit(1)

    trivy_file = sys.argv[1]
    repo_name = sys.argv[2]
    image_tag = sys.argv[3]
    commit_sha = sys.argv[4]

    if not os.path.exists(trivy_file):
        print(f"Error: Trivy results file not found: {trivy_file}")
        sys.exit(1)

    findings = convert_trivy_to_security_hub(trivy_file, repo_name, image_tag, commit_sha)

    # Save findings to file
    output_file = 'security-hub-findings.json'
    with open(output_file, 'w') as f:
        json.dump(findings, f, indent=2)

    print(f"✅ Converted {len(findings)} findings to Security Hub format")
    print(f"📄 Output saved to: {output_file}")
