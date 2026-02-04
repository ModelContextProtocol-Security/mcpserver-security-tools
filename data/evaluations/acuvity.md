---
name: Acuvity
url: https://acuvity.ai/
evaluated: 2026-02-04
---

# Acuvity

## One-liner
Open source MCP security framework with Rego-based threat detection, sandboxed execution, and MiniBridge runtime proxy.

## Who's behind it
- **Company**: Acuvity (The AI Security Company)
- **CEO**: Satyam Sinha
- **Location**: Sunnyvale, California
- **Type**: Open source framework + commercial platform
- **GitHub**: github.com/acuvity

## Problems it claims to solve
- Tool poisoning attacks
- Cross-server tool shadowing
- Rug pull attacks
- Secrets leakage
- Supply chain attacks
- Insecure MCP server deployments

## Key components

### Security & Isolation
- Sandboxed container execution
- Non-root-by-default enforcement
- Immutable runtime with read-only filesystems
- Version pinning and CVE scanning
- TLS support with threat detection

### MiniBridge Runtime Proxy
- Authentication
- Content filtering
- Policy enforcement via Rego

### Rego-Based Threat Detection
- Built-in policy suite
- Scans and validates tool metadata
- Runtime behavior validation
- Custom policy support via Open Policy Agent

## Deployment support
- Kubernetes
- Helm
- Docker
- IDE integration (VS Code, Windsurf, Cursor, Claude Desktop)

## Additional features
- OAuth 2.1 authorization (via Descope)
- OpenTelemetry (OTEL) integration for tracing
- Curated repository of 100+ secure containerized MCP server builds

## Interesting observations
- **Rego/OPA choice**: Open Policy Agent for policy enforcement - well-established in cloud-native
- **Curated 100+ servers**: Pre-validated MCP servers reduce risk
- **Non-root-by-default**: Security-first container approach
- **CVE scanning**: Supply chain security built-in
- **MiniBridge**: Clever naming for the proxy component
- **Research-heavy**: Multiple blog posts on MCP vulnerabilities

## Maturity signals
- Open source on GitHub
- Press release (PRNewswire)
- CEO identified
- Multiple technical blog posts
- Curated server repository

## Questions raised
- How does Rego policy writing work for non-experts?
- What's commercial vs open source?
- How does performance compare to other proxies?
- Is 100+ curated servers enough coverage?
