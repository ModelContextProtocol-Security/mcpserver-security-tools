---
name: mcp-security-scanner (AWS)
url: https://github.com/aws-samples/sample-mcp-security-scanner
evaluated: 2026-02-04
---

# mcp-security-scanner (AWS)

## One-liner
MCP server that integrates Checkov, Semgrep, and Bandit for real-time security scanning within AI coding assistants.

## Who's behind it
- **Creator**: AWS (aws-samples)
- **License**: MIT-0 (very permissive, no attribution required)
- **Type**: MCP server (not a scanner OF MCP, but security tools VIA MCP)

## Important distinction
This is **NOT** a tool that scans MCP servers for vulnerabilities. It's an MCP server that exposes traditional security scanning tools TO AI coding assistants. It's in the "security tools via MCP" category.

## What it does
Enables AI coding assistants (Amazon Q Developer, Kiro) to perform security scans on code during development.

## Integrated tools

### Checkov
- Infrastructure as Code scanning
- Terraform, CloudFormation, Kubernetes, Dockerfiles
- Security misconfigurations and compliance violations

### Semgrep
- Source code analysis
- Multi-language: Python, JavaScript, Java, Go, C/C++, C#, Ruby, PHP, Scala, Kotlin, Rust
- Security vulnerabilities and bugs

### Bandit
- Python-specific security scanning
- Insecure functions, hardcoded secrets, injection vulnerabilities

## Key features
- **Delta scanning**: Only scan new code segments to reduce overhead
- **Isolated environments**: Prevent cross-tool contamination
- **Real-time feedback**: During code generation
- **Customizable rules**: Organizational compliance
- **Standardized output**: Check IDs, severity, descriptions, line numbers

## Interesting observations
- **Inverse category**: Uses MCP to do security, not securing MCP
- **AWS backing**: Enterprise credibility
- **MIT-0 license**: Maximally permissive
- **Delta scanning**: Practical for real-time use in IDEs
- **Multi-tool unification**: Single interface for three different scanners

## Use case
Developer writes code with AI assistant → Assistant calls this MCP server → Gets security feedback → Can fix issues in real-time

## Questions raised
- How does this compare to running Checkov/Semgrep/Bandit directly?
- What's the latency impact on code generation?
- Are there other MCP servers wrapping security tools?
