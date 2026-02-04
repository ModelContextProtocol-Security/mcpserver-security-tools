---
name: MCPScan.ai
url: https://mcpscan.ai/
evaluated: 2026-02-04
---

# MCPScan.ai

## One-liner
Web-based MCP security scanner with specialized LLM classifier for detecting tool poisoning in MCP tool definitions.

## Who's behind it
- **Creator**: Not clearly identified on website
- **Type**: Web service (SaaS)
- **Pricing**: Free tier available, Enterprise tier for private server scanning

## Problems it claims to solve
- Tool poisoning attacks (malicious instructions in tool metadata)
- Command injection (string concatenation in shell commands)
- Code injection (eval, exec usage)
- Path traversal attacks
- IDOR (Insecure Direct Object References)
- Resource exhaustion risks
- Authentication/authorization deficiencies
- Confused deputy attacks
- Indirect prompt injection

## How it works
1. Enter GitHub repository URL containing MCP server
2. Scanner analyzes code for vulnerability patterns
3. Results provided with findings

## Key differentiator: LLM Classifier for Tool Poisoning
- "Advanced Tool Metadata Scanner"
- Specialized LLM classifier to detect poisoning attempts
- Scans across all MCP tool definitions
- Targets instructions invisible to users but visible to AI models

## What it detects
- **LLM-specific vulnerabilities** that traditional scanners miss
- **Tool poisoning** - malicious instructions embedded in tool metadata
- **Confused deputy attacks** - exploiting trust relationships
- **Indirect prompt injection** - attacks via tool outputs

## Scanning recommendations they provide
- After every significant code change
- Monthly minimum for production servers
- Weekly for high-security environments
- More frequent for servers with sensitive data access

## Example repos for testing
- BlenderMCP
- Grafana MCP
- Crypto News MCP

## Interesting observations
- **Anonymous creator**: Unusual not to identify who's behind it
- **Web-only**: No CLI or local option mentioned - requires sending code to their service
- **LLM classifier angle**: Using AI to detect AI-specific attacks
- **GitHub-focused**: Input is GitHub repo URL, not local code
- **Simple UX**: Enter URL, get results - very low friction

## Limitations
- Only scans GitHub repositories (not local code, npm packages, etc.)
- Creator identity unknown - trust implications
- Enterprise tier details not disclosed
- No mention of CI/CD integration

## Maturity signals
- Working web service
- Example repos provided
- Enterprise tier exists
- But: anonymous creator, limited documentation

## Questions raised
- Who operates this service?
- Where does the code go when scanned?
- How does their LLM classifier compare to Cisco/Invariant approaches?
- Why no creator identification?
- What's in the Enterprise tier?
