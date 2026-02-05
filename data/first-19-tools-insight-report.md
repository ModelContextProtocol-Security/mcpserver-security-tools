# Insight Report: First 19 MCP Security Tools

**Date:** 2026-02-04
**Tools Evaluated:** 19 tools across scanners, gateways, and security toolkits

---

## Key Findings

### 1. Four Distinct Categories Have Emerged

**MCP Server Scanners/Auditors (8 tools)**
Static and dynamic analysis of MCP servers before deployment. Focus on tool poisoning, prompt injection, command injection.
- mcp-scan (Invariant Labs), Cisco mcp-scanner, mcpserver-audit (CSA), Enkrypt AI, MCPScan.ai, Proximity, MCP-Shield, sidhpurwala scanner

**MCP Gateways (5 tools)**
Runtime proxy/middleware providing security enforcement between AI agents and MCP servers.
- Lasso Gateway, MintMCP Gateway, TrueFoundry Gateway, Pangea AI Guard, Acuvity

**Security Tools via MCP (4 tools)**
MCP servers wrapping traditional security tools - enabling AI assistants to perform security work. This is the inverse: using MCP to DO security, not securing MCP.
- FuzzingLabs hub (163+ tools), cyproxio (24 tools), AWS scanner, mcp-vulnerability-scanner

**Directories/Aggregators (2 tools)**
Catalogs and verification services for MCP servers.
- MCPVerified, Teleport (also provides infrastructure identity)

### 2. Multiple Detection Approaches Coexist

No consensus on best detection method. Tools use various approaches:

| Approach | Tools Using It | Strengths | Weaknesses |
|----------|----------------|-----------|------------|
| Static pattern matching (YARA) | Cisco | Fast, no external deps | Limited to known patterns |
| LLM-as-a-judge | Cisco, MCPScan.ai, Invariant | Semantic understanding | Slower, API costs |
| Rule engine (NOVA, Rego) | Proximity, Acuvity | Customizable, local | Requires rule writing |
| Behavioral code analysis | Cisco, Enkrypt | Detects doc/impl mismatch | Complex to implement |
| Runtime proxy monitoring | Invariant, Lasso, Pangea | Catches runtime attacks | Performance overhead |

Most sophisticated tools combine multiple approaches.

### 3. Commercial vs. Open Source Split

**Commercial/Enterprise-Focused:**
- Enkrypt AI, MintMCP, TrueFoundry, Pangea, Acuvity, Teleport
- Differentiated by: SOC 2 certification, SSO/OAuth, compliance (HIPAA, GDPR), support

**Open Source:**
- Invariant mcp-scan, Cisco mcp-scanner, CSA mcpserver-audit, Proximity, MCP-Shield, Lasso
- Range from permissive (Apache 2.0) to copyleft (GPL-3.0)
- Some open source with commercial upsell (Invariant, Lasso)

**Enterprise features driving commercial differentiation:**
- SOC 2 Type II certification
- SSO/SAML integration
- Audit logging and compliance reporting
- SLA and support

### 4. Tool Poisoning Dominates Scanner Focus

Almost every scanner prioritizes detecting malicious tool descriptions. Less coverage of:
- **Prompts:** Few tools explicitly scan MCP prompts for injection
- **Resources:** Resource content scanning underrepresented
- **Cross-server attacks:** Most tools analyze servers in isolation

This mirrors academic research findings - tool poisoning is well-understood, other vectors less so.

### 5. Gateway Pattern Is Solidifying

MCP Gateways share common features:
- Reverse proxy for MCP traffic
- Policy enforcement point (allow/deny tool invocations)
- PII detection and redaction
- Audit logging
- Authentication layer (OAuth, API keys)
- Rate limiting

Differentiation comes from:
- Policy language (natural language vs. Rego vs. custom)
- Pre-built rule libraries
- Compliance certifications
- Integration breadth

### 6. "Security via MCP" Is a Distinct Category

FuzzingLabs, cyproxio, and AWS scanner aren't securing MCP - they're exposing security tools through MCP. This enables:
- AI assistants performing penetration testing
- Automated security workflows via natural language
- Integration of security into AI-assisted development

FuzzingLabs alone wraps 163+ tools (Nmap, Ghidra, Nuclei, SQLMap, Hashcat, etc.).

This category will likely grow as AI-assisted security operations expand.

---

## Patterns Across Tools

### Operating Modes

Most scanners support multiple modes:
- **CLI:** One-time scans, CI/CD integration
- **Proxy/Runtime:** Continuous monitoring
- **API/SDK:** Integration into larger platforms

### Privacy Considerations

Tools vary in data handling:
- **Fully local:** Proximity (with Ollama), CSA tools
- **Local analysis + cloud API:** Cisco (optional), Invariant
- **Cloud-first:** Enkrypt AI, MCPScan.ai

Enterprise deployments will care about where code/configs are sent.

### Transparency and Learning

Tools differ in how much they explain:
- **Black box:** Scan, get results, no explanation
- **Educational:** CSA tools deliberately limit automation to encourage learning
- **Transparent:** Invariant shows exactly what triggered detection

For building organizational security capability, educational tools may have longer-term value.

---

## Gaps Observed

### Detection Gaps
- No tools for discovering MCP servers/clients already deployed in enterprise environments
- Limited scanning of MCP prompts and resources (vs. tools)
- Cross-server attack detection largely absent

### Supply Chain Gaps
- Limited tooling for verifying MCP server provenance
- No SBOM-style approaches for MCP dependencies
- Rug pull detection (post-install malicious updates) underserved

### Standards Gaps
- Tools mention OWASP, SOC 2, ISO 27001 inconsistently
- No MCP-specific security standard exists
- Scoring varies (some use CVSS-style, CSA proposes AIVSS)

### Client-Side Gaps
- Most tools focus on server security
- MCP client/host security underserved
- Configuration drift detection limited

---

## Notable Observations

### Tool Inspiration Chains
MCP-Shield explicitly credits Invariant Labs research. The field is building on itself.

### Research as Marketing
Enkrypt AI's 1000-server vulnerability study drives credibility. Academic-style research is effective marketing for security tools.

### Identity-First Approaches
Teleport treats AI agents as infrastructure identities requiring zero-trust controls. This framing (AI agents as principals, not just software) may become important.

### Curated Server Repositories
Acuvity maintains 100+ pre-validated MCP servers. As the ecosystem grows, curation/verification services will matter.

---

## Questions for Further Research

1. How do detection approaches compare in accuracy? (No head-to-head benchmarks exist)
2. What's the performance overhead of gateway approaches in production?
3. How do enterprises handle the privacy tradeoffs of cloud-based scanning?
4. What's the false positive rate across different tools?
5. How will tools evolve as MCP protocol itself adds security features?

---

## Tool Selection Guidance

**For quick, free scanning:**
- mcp-scan (Invariant) - good baseline, active development
- Proximity - fully local option with Ollama

**For enterprise/compliance:**
- MintMCP Gateway - SOC 2 Type II, SSO
- Cisco mcp-scanner - enterprise credibility, multi-engine

**For learning/education:**
- mcpserver-audit (CSA) - designed for understanding, not just detection

**For CI/CD integration:**
- Enkrypt AI - GitHub/npm input, automation-friendly
- Cisco - offline mode for pipelines

**For AI-assisted security operations:**
- FuzzingLabs hub - broadest tool coverage (163+)
- AWS scanner - focused on code analysis tools
