# MCP Security Tools Research Notes

Research conducted: 2026-02-04

## Emerging Categories

Based on the tools found, several distinct categories are emerging:

### 1. MCP Server Scanners/Auditors
Tools that analyze MCP servers for vulnerabilities before deployment or integration.
- Static analysis of tool definitions, prompts, resources
- Detection of prompt injection, tool poisoning, command injection
- Examples: mcp-scan, Cisco mcp-scanner, Proximity, MCP-Shield, mcpserver-audit

### 2. MCP Gateways
Proxy/middleware that sits between AI agents and MCP servers, providing runtime security.
- Real-time filtering and guardrailing
- Authentication, authorization, rate limiting
- PII detection and redaction
- Audit logging
- Examples: Lasso MCP Gateway, MintMCP Gateway, Pangea AI Guard

### 3. Security Tools Exposed via MCP
MCP servers that wrap traditional security tools, enabling AI assistants to perform security work.
- Pentesting tools (SQLMap, Nmap, Nuclei)
- Code analysis (Semgrep, Bandit, Checkov)
- Binary analysis (Ghidra)
- This is the inverse - using MCP to DO security, not securing MCP
- Examples: mcp-security-hub, mcp-for-security, AWS mcp-security-scanner

### 4. Directories/Verification Services
Sites that catalog and potentially verify MCP servers.
- Examples: MCPVerified, MCPScan.ai (has both scanner and directory aspects)

## Patterns Noticed

### Commercial vs Open Source Split
- Several commercial offerings emerging (Enkrypt AI, MintMCP, Lasso has both)
- Strong open source presence on GitHub
- Enterprise features (SOC2, SSO) driving commercial differentiation

### Multiple Scanning Approaches
- Static analysis of tool definitions/descriptions
- LLM-as-a-judge (using AI to detect malicious AI content)
- YARA rules (traditional pattern matching)
- Runtime monitoring/proxy mode
- Rego policies for runtime enforcement

### Key Vulnerabilities Being Targeted
- Tool poisoning (malicious instructions hidden in tool descriptions)
- Prompt injection (direct and indirect)
- Data exfiltration
- Command/code injection
- Cross-origin escalation
- PII/secret leakage

### Gateway Pattern Emerging
The "MCP Gateway" as a category is solidifying - acts as:
- Reverse proxy for MCP traffic
- Policy enforcement point
- Audit logging
- Authentication layer

## Gaps Observed

### Detection Tools
- No clear tools for detecting MCP servers/clients already deployed in enterprise environments
- Code scanning to find MCP implementations in repos mentioned as a need but not clearly addressed

### Supply Chain
- Limited tooling around verifying MCP server provenance
- No SBOM-style approaches for MCP dependencies yet

### Standards Alignment
- Tools mention OWASP, SOC2, ISO 27001 but unclear how consistently
- No MCP-specific security standard yet (opportunity?)

### Client-Side Security
- Most tools focus on server security
- Less attention to securing MCP clients/hosts

## Questions for Further Research

1. How do these tools compare in detection accuracy?
2. What's the performance overhead of gateway approaches?
3. Are there tools specifically for MCP marketplace security?
4. How do runtime guardrails handle false positives?
5. What's the coverage of "security tools via MCP" - are there gaps in what security workflows are available?

## Notable Players

- **Invariant Labs** - Strong presence with mcp-scan, seems focused on this space
- **Cisco** - Enterprise credibility with mcp-scanner
- **Lasso Security** - First open-source security gateway claim
- **Cloud Security Alliance** - mcpserver-audit, broader initiative
- **Enkrypt AI** - Commercial automated scanning

## Sources

- https://github.com/invariantlabs-ai/mcp-scan
- https://github.com/cisco-ai-defense/mcp-scanner
- https://www.enkryptai.com/mcp-scan
- https://mcpscan.ai/
- https://www.helpnetsecurity.com/2025/10/29/proximity-open-source-mcp-security-scanner/
- https://github.com/lasso-security/mcp-gateway
- https://www.mintmcp.com/mcp-gateway
- https://pangea.cloud/blog/secure-mcp-servers-with-ai-guardrails/
- https://www.akto.io/blog/mcp-security-tools
- https://www.integrate.io/blog/best-mcp-gateways-and-ai-agent-security-tools/

---

## Evaluation Log

Raw observations from individual tool evaluations. This captures dimensions and patterns as we discover them.

### 2026-02-04: mcp-scan (Invariant Labs)

**New dimensions identified:**
- Operating modes: static scan vs runtime proxy (tools may have multiple modes)
- Hybrid architecture: local analysis + cloud API (where does processing happen?)
- Business model: free tool as funnel to paid platform
- Privacy tradeoffs: what data leaves your machine and goes to vendor?
- Platform support: which MCP clients does it work with?
- Anti-tampering: tool pinning/hashing to detect changes after approval

**Interesting observations:**
- "Rug pull" terminology borrowed from crypto - effective framing
- Research angle visible: anonymous IDs suggest building a dataset
- Explicit about limitations and privacy implications (refreshing)
- Company vs side project distinction matters for maturity assessment
- Closed to contributions but accepts bug reports (middle ground on open source)

**Questions raised:**
- What's the false positive rate?
- How does detection compare to alternatives?
- What happens if their API is down?
- What's in premium vs free?
