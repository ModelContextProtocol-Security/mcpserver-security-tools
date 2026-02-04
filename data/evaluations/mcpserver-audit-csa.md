---
name: mcpserver-audit (CSA)
url: https://github.com/ModelContextProtocol-Security/mcpserver-audit
evaluated: 2026-02-04
---

# mcpserver-audit (CSA)

## One-liner
AI-assisted security audit tool for MCP servers that emphasizes education and community knowledge sharing over pure automation.

## Who's behind it
- **Organization**: Model Context Protocol Security initiative
- **Sponsor**: Cloud Security Alliance (CSA)
- **Maintained by**: MCP Security Working Group
- **License**: Apache-2.0
- **Part of broader ecosystem**: mcpserver-finder, MCP Inspector, audit-db, vulnerability-db

## Problems it claims to solve
- Checking if MCP servers are safe before use
- Security vulnerability detection in MCP server source code
- Building security awareness and skills in users
- Community knowledge sharing about MCP security

## Key differentiator: Education over automation
Unlike other tools that focus purely on automated scanning, mcpserver-audit emphasizes:
- Teaching users to evaluate tools themselves
- Security awareness training
- Interactive threat modeling guidance
- Systematic audit methodology training

## Four-phase workflow
1. **Security Education & Threat Modeling** - Builds awareness of MCP-specific threats
2. **Guided Security Analysis** - Conducts systematic code evaluation
3. **Risk Evaluation & Prioritization** - Assesses and scores findings using AIVSS
4. **Remediation Guidance** - Develops mitigation strategies

## What it analyzes
- Static code vulnerability scanning
- Dependency security assessment
- Configuration security review
- MCP protocol compliance verification
- Permission and access control analysis

## Threat knowledge areas
- Prompt injection and indirect attacks
- Confused deputy and privilege escalation
- Token theft and credential security
- Data exfiltration risks
- Model manipulation vulnerabilities
- Training data poisoning
- Privacy extraction attacks

## How it works
- Prompt-driven interaction (prompts in `prompts/` directory)
- Requires Claude Desktop or MCP-compatible AI client
- Uses file system access to read source code
- Optional internet for vulnerability database lookups
- Different prompts for different audit depths (comprehensive, targeted, specific checks)

## Ecosystem integration
- **audit-db**: Publish general audit results
- **vulnerability-db**: Publish specific vulnerability discoveries
- **mcpserver-builder**: Handoff for implementing fixes
- **mcpserver-operator**: Deployment security coordination
- **mcpserver-finder**: Finding servers to audit

## AIVSS scoring
Uses AI Vulnerability Scoring System to rate severity of security issues found - standardized scoring framework.

## Limitations acknowledged
- "Limited fix guidance" - detailed recommendations delegated to mcpserver-builder
- Framework-based analysis rather than exhaustive automated scanning
- Educational focus requiring user engagement
- Expert guidance over comprehensive automation

## Interesting observations
- **Philosophy is different**: Education-first vs automation-first
- **Ecosystem thinking**: Not standalone, designed to work with companion tools
- **Community contribution model**: Findings go back to shared databases
- **Prompt-based architecture**: Uses prompts rather than traditional CLI
- **AIVSS is notable**: Standardized vulnerability scoring for AI systems
- **CSA backing**: Credibility from established security organization

## Maturity signals
- Part of established CSA project
- Has companion website (modelcontextprotocol-security.io)
- Documentation and step-by-step guides
- Multiple related tools in ecosystem
- Working group maintenance model

## Questions raised
- How does AIVSS compare to CVSS?
- What's the quality/coverage of audit-db and vulnerability-db?
- How effective is education-first approach vs automation-first?
- What's the learning curve for the prompt-based workflow?
