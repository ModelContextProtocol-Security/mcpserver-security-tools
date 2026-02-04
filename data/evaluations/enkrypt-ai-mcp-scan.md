---
name: Enkrypt AI MCP Scan
url: https://www.enkryptai.com/mcp-scan
evaluated: 2026-02-04
---

# Enkrypt AI MCP Scan

## One-liner
Commercial MCP security scanner with free tier, backed by research showing 33% of MCP servers have critical vulnerabilities.

## Who's behind it
- **Company**: Enkrypt AI, Inc.
- **Location**: Brighton, MA
- **Status**: Venture-backed startup (featured in Forbes, VentureBeat, Financial Times)
- **Certifications**: SOC 2 certified
- **Contact**: hello@enkryptai.com

## Problems it claims to solve
- Command injection in MCP servers
- Prompt injection vulnerabilities
- Path traversal attacks
- Authorization bypass issues
- Resource exhaustion / DoS
- Network security issues (SSRF, weak TLS)
- Configuration problems (missing sandboxing, timeouts, auth)

## How it works
1. Submit MCP server source via GitHub repo, npm package, or remote endpoint
2. Automated analysis runs (~5 minutes)
3. Get detailed report with severity ratings, line numbers, remediation recommendations
4. Results published to MCP Hub for community visibility

## Four-layer analysis
1. **Configuration assessment** - Least-privilege, sandboxing, timeouts, auth
2. **Code security scanning** - Injection, traversal, IDOR, DoS vulnerabilities
3. **Tool-level assessment** - Hidden injections, prompt injection, suspicious patterns
4. **Network security evaluation** - SSRF, TLS, open ports, timeouts

## Key metrics they claim
- 98% detection rate
- Under 5 minutes scan time
- 1000+ MCP servers scanned
- 4000+ tools analyzed
- 1000+ vulnerabilities identified

## Their research findings (1000 server study)
- **32%** had at least one critical vulnerability
- **5.2** vulnerabilities per server on average
- **0%** had security documentation
- **Authorization bypass (41%)** most common
- **Prompt injection (35%)** second most common
- **Command injection (28%)** third

## Pricing model
- **Free tier**: Public repositories and npm packages
- **Paid plans**: CI/CD integration, bulk scanning, dedicated support
- Enterprise support available

## Unique aspects
- **Public results**: Scan results display in MCP Hub for community
- **Research-backed**: Published study gives credibility
- **CI/CD integration**: Automated scanning on commits/releases
- **Agentic static analysis**: Uses AI for analysis, not just pattern matching

## Positioning
- "Most advanced comprehensive security platform built specifically for MCP"
- Claims traditional code scanners miss MCP-specific vulnerabilities
- Emphasizes LLM-driven exploits that semantic analysis catches

## Interesting observations
- **Research as marketing**: 1000-server study is great content marketing and establishes expertise
- **Public by default**: Unusual choice to publish results to MCP Hub
- **Free tier strategy**: Lower barrier to entry, upsell to enterprise
- **"92% exploit probability" stat**: Cites external research on chained MCP plugins
- **Zero security documentation finding**: Damning for the ecosystem

## Maturity signals
- SOC 2 certified (enterprise-ready)
- Press coverage in major publications
- Published research
- Clear pricing tiers

## Also offers
- Secure MCP Gateway (separate product for runtime protection)
- Broader AI security platform

## Questions raised
- What's their detection methodology vs Invariant/Cisco?
- How do they validate the 98% detection rate claim?
- What happens to scan data - privacy implications?
- Is public-by-default a feature or concern for enterprises?
