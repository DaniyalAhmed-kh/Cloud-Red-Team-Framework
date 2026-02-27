# Contributing to Cloud Security Pentesting Codex

We welcome contributions from security researchers and practitioners. This document outlines contribution guidelines.

## Reporting Findings

Report new attack techniques, vulnerabilities, or misconfigurations through:

1. **GitHub Issues** - For discussion and community feedback
2. **Security Advisory** - For sensitive vulnerabilities requiring disclosure coordination
3. **Pull Request** - For documented techniques and playbooks

## Adding New Guides

### Structure

Each platform guide should follow the kill chain:
1. Reconnaissance
2. Initial Access
3. Privilege Escalation
4. Lateral Movement
5. Persistence
6. Data Exfiltration

### Format

- Use practical command examples
- Include both offensive and defensive perspectives
- Provide clear explanation of attack prerequisites
- Note detection opportunities

### Example

```markdown
# Attack Title

## Prerequisites
- [List requirements]

## Attack Steps
\`\`\`bash
# Command example
command --flag
\`\`\`

## Detection
- Log sources that would capture this activity
- Indicators of compromise

## Mitigation
- Configuration changes
- Detection controls
```

## Tool Contributions

Tools should:
- Be written in Python 3 or shell script
- Include usage documentation
- Have minimal external dependencies
- Be compatible with Unix/Linux environments

### Tool Template

```python
#!/usr/bin/env python3
"""
Tool Name - Brief description

Usage:
    ./tool.py --help
"""

import argparse
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--option", help="Description")
    args = parser.parse_args()
    
    # Implementation


if __name__ == "__main__":
    main()
```

## Lab Environment Templates

Terraform templates for vulnerable environments should:
- Use free tier resources where possible
- Include clear variable definitions
- Have documentation on access
- Include cleanup instructions

## Code of Conduct

- Respect responsible disclosure timelines
- Provide evidence for reported vulnerabilities
- Avoid posting active exploits without context
- Test contributions before submission
- Document limitations and prerequisites

## Pull Request Process

1. Fork repository
2. Create branch: `git checkout -b feature/description`
3. Make changes following guidelines
4. Test thoroughly
5. Commit with clear messages: `git commit -m "Add X technique for Azure"`
6. Push and create pull request
7. Respond to review feedback

## Citation

If you use this resource in research or publications, please cite:

```bibtex
@online{codex-gigas,
  title={Cloud Security Pentesting Codex},
  url={https://github.com/your-username/cloud-security-pentesting},
  year={2024}
}
```

## Disclaimer

This resource is for authorized security professionals only. All activities must comply with applicable laws and organizational policies. Unauthorized access is illegal.

---

Questions? Open an issue or reach out to the community.
