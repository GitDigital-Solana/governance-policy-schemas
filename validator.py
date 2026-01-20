governance-policy-schemas/validator.py

```python
#!/usr/bin/env python3
"""
Policy Schema Validator
Validates policies against JSON schemas and performs semantic validation.
"""

import json
import yaml
import jsonschema
from jsonschema import validate, ValidationError
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import importlib.resources


class Severity(Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class ValidationIssue:
    severity: Severity
    message: str
    path: str
    schema_path: Optional[str] = None
    detail: Optional[str] = None


class PolicyValidator:
    def __init__(self, schema_dir: Optional[str] = None):
        self.schema_dir = Path(schema_dir) if schema_dir else Path(__file__).parent / "schemas"
        self.schemas = {}
        self.load_schemas()
        
    def load_schemas(self):
        """Load all available schemas from the schema directory."""
        for version_dir in self.schema_dir.iterdir():
            if version_dir.is_dir() and version_dir.name.startswith('v'):
                schema_file = version_dir / "policy.schema.json"
                if schema_file.exists():
                    with open(schema_file, 'r') as f:
                        self.schemas[version_dir.name] = json.load(f)
    
    def validate(self, policy_content: Dict, schema_version: str = "latest") -> Tuple[bool, List[ValidationIssue]]:
        """Validate policy against specified schema version."""
        issues = []
        
        # Determine schema version
        if schema_version == "latest":
            schema_version = max(self.schemas.keys())
        
        if schema_version not in self.schemas:
            issues.append(ValidationIssue(
                severity=Severity.ERROR,
                message=f"Schema version {schema_version} not found",
                path="",
                detail=f"Available versions: {list(self.schemas.keys())}"
            ))
            return False, issues
        
        schema = self.schemas[schema_version]
        
        # Validate against JSON schema
        try:
            validate(instance=policy_content, schema=schema)
        except ValidationError as e:
            issues.append(ValidationIssue(
                severity=Severity.ERROR,
                message="Schema validation failed",
                path=e.path if e.path else "",
                schema_path=e.schema_path if e.schema_path else "",
                detail=e.message
            ))
            return False, issues
        
        # Perform semantic validation
        semantic_issues = self.semantic_validation(policy_content)
        issues.extend(semantic_issues)
        
        # Check for deprecated features
        deprecation_issues = self.check_deprecations(policy_content, schema_version)
        issues.extend(deprecation_issues)
        
        # Check for best practices
        best_practice_issues = self.check_best_practices(policy_content)
        issues.extend(best_practice_issues)
        
        is_valid = all(issue.severity != Severity.ERROR for issue in issues)
        return is_valid, issues
    
    def semantic_validation(self, policy: Dict) -> List[ValidationIssue]:
        """Perform semantic validation beyond JSON schema."""
        issues = []
        
        # Check that rule names are unique
        if 'spec' in policy and 'rules' in policy['spec']:
            rule_names = []
            for i, rule in enumerate(policy['spec']['rules']):
                if 'name' in rule:
                    if rule['name'] in rule_names:
                        issues.append(ValidationIssue(
                            severity=Severity.ERROR,
                            message=f"Duplicate rule name: {rule['name']}",
                            path=f".spec.rules[{i}].name",
                            detail="Rule names must be unique within a policy"
                        ))
                    rule_names.append(rule['name'])
                
                # Validate condition syntax
                if 'condition' in rule:
                    condition = rule['condition']
                    if not self._is_valid_jsonpath(condition):
                        issues.append(ValidationIssue(
                            severity=Severity.ERROR,
                            message=f"Invalid JSONPath expression",
                            path=f".spec.rules[{i}].condition",
                            detail=f"Expression: {condition}"
                        ))
        
        # Check severity consistency
        if 'metadata' in policy and 'severity' in policy['metadata']:
            severity = policy['metadata']['severity']
            if severity not in ['low', 'medium', 'high', 'critical']:
                issues.append(ValidationIssue(
                    severity=Severity.WARNING,
                    message=f"Unusual severity value: {severity}",
                    path=".metadata.severity",
                    detail="Expected values: low, medium, high, critical"
                ))
        
        return issues
    
    def _is_valid_jsonpath(self, expression: str) -> bool:
        """Validate JSONPath expression syntax."""
        # Basic validation - in production, use a JSONPath parser
        if not expression:
            return False
        
        # Must start with valid characters
        if not expression.startswith(('$', '@', '[')):
            return False
        
        # Check for common syntax errors
        if '..' in expression and expression.count('..') > 1:
            return False
        
        return True
    
    def check_deprecations(self, policy: Dict, schema_version: str) -> List[ValidationIssue]:
        """Check for deprecated features."""
        issues = []
        
        # Check for deprecated fields based on schema version
        if schema_version == "v1.1.0":
            if 'legacyField' in policy:
                issues.append(ValidationIssue(
                    severity=Severity.WARNING,
                    message="Deprecated field used",
                    path=".legacyField",
                    detail="This field is deprecated in v1.1.0 and will be removed in v2.0.0"
                ))
        
        return issues
    
    def check_best_practices(self, policy: Dict) -> List[ValidationIssue]:
        """Check for best practice recommendations."""
        issues = []
        
        # Recommend including description
        if 'metadata' in policy and 'description' not in policy['metadata']:
            issues.append(ValidationIssue(
                severity=Severity.INFO,
                message="Policy missing description",
                path=".metadata",
                detail="Consider adding a description for better documentation"
            ))
        
        # Recommend severity for rules
        if 'spec' in policy and 'rules' in policy['spec']:
            for i, rule in enumerate(policy['spec']['rules']):
                if 'severity' not in rule:
                    issues.append(ValidationIssue(
                        severity=Severity.INFO,
                        message="Rule missing severity",
                        path=f".spec.rules[{i}]",
                        detail="Consider adding severity to help prioritize violations"
                    ))
        
        return issues
    
    def validate_file(self, file_path: str, schema_version: str = "latest") -> Dict[str, Any]:
        """Validate a policy file."""
        with open(file_path, 'r') as f:
            if file_path.endswith(('.yaml', '.yml')):
                content = yaml.safe_load(f)
            else:
                content = json.load(f)
        
        is_valid, issues = self.validate(content, schema_version)
        
        return {
            "valid": is_valid,
            "file": file_path,
            "policy_name": content.get('metadata', {}).get('name', 'unknown'),
            "schema_version": schema_version,
            "issues": [
                {
                    "severity": issue.severity.value,
                    "message": issue.message,
                    "path": issue.path,
                    "detail": issue.detail
                }
                for issue in issues
            ]
        }


class SchemaMigrator:
    """Migrate policies between schema versions."""
    
    def __init__(self):
        self.migrations = {
            "v1.0.0_to_v1.1.0": self._migrate_1_0_to_1_1,
            "v1.1.0_to_v1.2.0": self._migrate_1_1_to_1_2,
        }
    
    def migrate(self, policy: Dict, from_version: str, to_version: str) -> Dict:
        """Migrate policy from one version to another."""
        migration_key = f"{from_version}_to_{to_version}"
        
        if migration_key not in self.migrations:
            raise ValueError(f"No migration path from {from_version} to {to_version}")
        
        return self.migrations[migration_key](policy)
    
    def _migrate_1_0_to_1_1(self, policy: Dict) -> Dict:
        """Migrate from v1.0.0 to v1.1.0."""
        migrated = policy.copy()
        
        # Add new required field with default
        if 'spec' in migrated:
            migrated['spec']['enforcement'] = migrated['spec'].get('enforcement', 'enforce')
        
        # Rename field
        if 'metadata' in migrated and 'labels' in migrated['metadata']:
            migrated['metadata']['tags'] = migrated['metadata'].pop('labels')
        
        return migrated
    
    def _migrate_1_1_to_1_2(self, policy: Dict) -> Dict:
        """Migrate from v1.1.0 to v1.2.0."""
        migrated = policy.copy()
        # Add migration logic here
        return migrated


def main():
    """CLI interface for policy validation."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Validate governance policies')
    parser.add_argument('files', nargs='+', help='Policy files to validate')
    parser.add_argument('--schema', default='latest', help='Schema version to validate against')
    parser.add_argument('--output', choices=['text', 'json', 'yaml'], default='text',
                       help='Output format')
    parser.add_argument('--fix', action='store_true', help='Try to auto-fix issues')
    
    args = parser.parse_args()
    
    validator = PolicyValidator()
    
    results = []
    all_valid = True
    
    for file_path in args.files:
        result = validator.validate_file(file_path, args.schema)
        results.append(result)
        
        if not result['valid']:
            all_valid = False
    
    # Output results
    if args.output == 'json':
        print(json.dumps(results, indent=2))
    elif args.output == 'yaml':
        print(yaml.dump(results, default_flow_style=False))
    else:
        for result in results:
            print(f"\n{'✅' if result['valid'] else '❌'} {result['file']}")
            print(f"  Policy: {result['policy_name']}")
            print(f"  Schema: {result['schema_version']}")
            
            for issue in result['issues']:
                icon = {
                    'error': '❌',
                    'warning': '⚠️',
                    'info': 'ℹ️'
                }.get(issue['severity'], ' ')
                print(f"  {icon} [{issue['severity'].upper()}] {issue['message']}")
                if issue['path']:
                    print(f"       Path: {issue['path']}")
                if issue['detail']:
                    print(f"       Detail: {issue['detail']}")
    
    exit(0 if all_valid else 1)


if __name__ == "__main__":
    main()
