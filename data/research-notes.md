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

### 2026-02-04: mcp-scanner (Cisco)

**New dimensions identified:**
- Multi-engine approach: Combining different detection methods (pattern, semantic, API)
- CI/CD integration: Static/offline scanning mode for pipelines
- Behavioral code analysis: Detecting mismatches between docs and implementation
- Multiple deployment modes: CLI, REST API server, Python SDK
- Enterprise ecosystem fit: Standalone tool that feeds into larger platform

**Interesting observations:**
- Explicit competitor critique in marketing ("existing tools focus narrowly on static code scanning")
- Three-engine design hedges bets: fast pattern matching + semantic LLM + proprietary API
- Enterprise credibility via Cisco brand - appeals to security-conscious orgs
- YARA-only mode allows use without vendor lock-in
- "Supply chain" framing aligns with existing enterprise security concerns (SBOMs, etc.)

**Questions raised:**
- How do YARA rules get updated? Community contributed?
- What's the pricing/access model for Cisco AI Defense API?
- How does LLM-as-judge compare to Invariant's approach?
- Timeout issues mentioned - how does this affect production use?

### 2026-02-04: mcpserver-audit (CSA)

**New dimensions identified:**
- Philosophy: Education-first vs automation-first approaches
- Ecosystem design: Tools designed to work together (audit, builder, operator, finder)
- Community contribution: Findings published to shared databases
- Prompt-based architecture: Using prompts rather than traditional CLI
- Vulnerability scoring: AIVSS as standardized scoring for AI systems
- Organizational backing: CSA/working group vs company vs individual

**Interesting observations:**
- Deliberately limits automation to encourage learning
- Four-phase workflow is more methodical than "run scanner, get results"
- Ecosystem thinking is rare - most tools are standalone
- AIVSS could become important standard (like CVSS for traditional vulns)
- Working group model for maintenance vs single company

**Questions raised:**
- How does AIVSS compare to CVSS?
- Is education-first approach more effective long-term?
- What's the adoption of audit-db and vulnerability-db?
- How do prompt-based tools compare to CLI for user adoption?

### 2026-02-04: Enkrypt AI MCP Scan

**New dimensions identified:**
- Research-backed credibility: Publishing vulnerability studies establishes expertise
- Public results model: Scan results visible to community (transparency vs privacy tradeoff)
- Multi-layer analysis: Config + code + tool + network as distinct layers
- Input flexibility: GitHub repo, npm package, or remote endpoint
- Freemium model: Free for public repos, paid for CI/CD and enterprise

**Interesting observations:**
- Research as marketing is effective strategy - 1000-server study gets attention
- "Zero security documentation" finding is damning for ecosystem maturity
- Authorization bypass (41%) most common - basic access control often missing
- Claims traditional scanners miss MCP-specific vulns - recurring theme
- Public-by-default results is bold choice - good for community, maybe not for enterprise

**Questions raised:**
- How is 98% detection rate validated?
- What are privacy implications of public scan results?
- How does "agentic static analysis" differ from other AI-based approaches?
- Do enterprises want their results public?

### 2026-02-04: MCPScan.ai

**New dimensions identified:**
- Creator transparency: Anonymous operators raise trust questions
- Input method: GitHub URL only vs local code vs multiple options
- Scanning frequency guidance: Recommendations for how often to scan

**Interesting observations:**
- Anonymous creator is unusual and concerning for security tool
- Web-only, no CLI - simplest UX but least flexible
- LLM classifier for detecting AI-specific attacks - using AI to find AI vulnerabilities
- Very focused on tool poisoning specifically

**Questions raised:**
- Who operates this and where does code go?
- Why no creator identification for a security tool?
- Is web-only acceptable for enterprise use?

### 2026-02-04: Proximity

**New dimensions identified:**
- Rule engine approach: NOVA as separate, reusable detection component
- Agent Skills scanning: Beyond just MCP servers to broader agent ecosystem
- Local LLM support: Ollama option avoids cloud API dependencies
- License implications: GPL-3.0 vs Apache-2.0 affects enterprise adoption
- Individual vs company: Known security researcher as creator

**Interesting observations:**
- GPL-3.0 is notable choice - copyleft may limit enterprise adoption
- LLM-powered rules can do semantic analysis, not just pattern matching
- Scans both MCP servers AND Agent Skills - broader scope
- Ollama support means fully local operation possible

**Questions raised:**
- How do NOVA rules compare to YARA?
- Performance implications of LLM-powered rule evaluation?
- GPL-3.0 enterprise adoption barriers?

### 2026-02-04: Remaining Tools (Batch Summary)

Evaluated: MCP-Shield, AWS mcp-security-scanner, sidhpurwala scanner, FuzzingLabs hub, cyproxio, mcp-vulnerability-scanner, Lasso Gateway, MintMCP Gateway, TrueFoundry Gateway, Pangea, Acuvity, MCPVerified, Teleport

**New dimensions identified:**
- Tool inspiration chains: MCP-Shield credits Invariant Labs research
- Deliberately vulnerable test servers: Educational value (sidhpurwala)
- Security tools VIA MCP vs scanning OF MCP: Important category distinction
- Gateway tiering: Free/basic vs premium plugins (Lasso)
- Natural language policies: New UX pattern for security rules
- Identity-first approach: Treating AI agents as infrastructure identities (Teleport)
- Curated server repositories: Pre-validated MCP servers (Acuvity 100+)
- Directory vs tool: MCPVerified aggregates, doesn't scan

**Patterns across gateways:**
- SOC 2 certification as enterprise differentiator
- OAuth/SSO/SAML integration standard
- PII detection/redaction common feature
- Audit logging universal
- Multi-compliance (SOC2 + HIPAA + GDPR) for enterprise

**Security tools via MCP observations:**
- FuzzingLabs: 163+ tools, Docker-first, massive scope
- cyproxio: 24 tools, TypeScript, mobile security unique
- AWS: Checkov/Semgrep/Bandit unified, delta scanning for real-time
- Different category than MCP security scanners

**Questions raised across batch:**
- What makes a tool "verified" on MCPVerified?
- How do Rego policies (Acuvity) compare to YARA (Cisco) compare to NOVA (Proximity)?
- Enterprise gateway pricing models?
- Can Teleport be used for MCP-only without full platform?
