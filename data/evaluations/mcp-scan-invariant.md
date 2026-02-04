---
name: mcp-scan (Invariant Labs)
url: https://github.com/invariantlabs-ai/mcp-scan
evaluated: 2026-02-04
---

# mcp-scan (Invariant Labs)

## One-liner
Security scanner for MCP connections that detects vulnerabilities in tool descriptions and can monitor MCP traffic in real-time.

## Who's behind it
- **Company**: Invariant Labs, based in Zurich, Switzerland
- **Authors**: Luca Beurer-Kellner and Marc Fischer
- **Focus**: Agentic AI safety
- **License**: Apache-2.0
- **Open source**: Yes, but currently closed to external contributions (accepts bug reports/feature requests)

## Problems it claims to solve
- Prompt injection attacks hidden in MCP tool descriptions
- Tool poisoning attacks (malicious instructions concealed in tool descriptions)
- MCP "rug pulls" (unauthorized modifications to tools after user approval)
- Cross-origin escalations / tool shadowing attacks
- Sensitive data exposure in tool definitions
- Hardcoded secrets in skill definitions

## Two operating modes

### 1. Static Scanning (`mcp-scan scan`)
- On-demand scanning of configured MCP servers
- Auto-discovers configurations across Claude, Cursor, Windsurf
- Generates hash-based signatures to detect tool changes
- Supports local STDIO servers and remote HTTP/SSE connections

### 2. Runtime Monitoring (`mcp-scan proxy`)
- Real-time traffic interception via local gateway proxy
- Enforces guardrailing policies (PII detection, secrets blocking, tool restrictions)
- Logs all MCP interactions for audit
- Injects Invariant Gateway component temporarily into configs

## How it works under the hood
- Combines local pattern matching with external API analysis
- Tool descriptions are sent to invariantlabs.ai for analysis via "Invariant Guardrails"
- Tool pinning uses hash-based integrity verification
- Guardrailing operates locally (doesn't require external API calls for that part)

## Notable features highlighted
- **Tool pinning**: Hash tools to detect changes (anti-rug-pull)
- **Single command install**: `uvx mcp-scan@latest`
- **No configuration required** for basic scanning
- **JSON output** for automation/parsing
- **Custom guardrailing policies** configurable
- **Whitelist management** for approved tools

## Platforms supported
- Claude Desktop
- Cursor
- Windsurf
- Any file-based MCP client configuration

## Caveats and limitations they acknowledge
- Requires sharing tool names/descriptions with invariantlabs.ai servers
- Must accept their terms of use and privacy policy
- Assigns persistent anonymous ID for research purposes (opt-out available via `--opt-out`)
- Proxy mode requires optional dependency installation
- Not accepting external code contributions currently

## Positioning
- Entry point to broader Invariant security platform
- Frames scanning as complementary to their premium "Invariant Guardrails" offering
- Emphasizes ease of use as differentiator
- No direct competitor comparisons in their materials

## Maturity signals
- Active development (v0.2 announced with significant updates)
- Has documentation site
- Has blog posts explaining the tool
- Part of a company with broader AI security focus (not a side project)

## Interesting observations
- **Hybrid approach**: Local analysis + cloud API gives them flexibility
- **Business model visible**: Free scanner feeds into paid guardrails platform
- **Tool pinning is clever**: Addresses the "things change after you approve them" attack
- **Privacy tradeoff explicit**: They're upfront that tool descriptions go to their servers
- **Research angle**: Anonymous ID for scans suggests they're building a dataset
- **"Rug pull" terminology**: Borrowed from crypto, effective framing for the attack type

## Questions raised
- What's the false positive rate?
- How does their detection compare to alternatives like Cisco's scanner?
- What happens if their API is down - does local scanning still work?
- What's in the "premium" guardrails vs the free version?
