---
name: mcp-scanner (Cisco)
url: https://github.com/cisco-ai-defense/mcp-scanner
evaluated: 2026-02-04
---

# mcp-scanner (Cisco)

## One-liner
Enterprise-grade MCP server scanner using three engines (YARA, LLM-as-judge, Cisco AI Defense API) to detect supply chain threats.

## Who's behind it
- **Company**: Cisco, via the Cisco AI Defense organization
- **License**: Apache License 2.0
- **Open source**: Yes, standalone tool that complements their commercial AI Defense platform
- **Announced**: October 23, 2025

## Problems it claims to solve
- **Tool poisoning attacks** - Malicious code in tool descriptions/metadata
- **Rug pull attacks** - Legitimate tools updated with malicious code after adoption
- **Over-privileged permissions** - Excessive filesystem/network/system access
- Supply chain vulnerabilities from public MCP registries

## Three scanning engines

### 1. Cisco AI Defense API
- Uses Cisco's inspection API for threat analysis
- Part of their broader AI Defense ecosystem

### 2. YARA Rules
- Pattern-based threat detection
- Customizable rules
- Can run standalone without API keys

### 3. LLM-as-Judge
- Semantic analysis using LLMs
- Supports multiple providers (OpenAI, AWS Bedrock, etc.)
- Detects things pattern matching would miss

## Key capabilities
- **Multiple modes**: CLI tool, REST API server, Python SDK
- **Static/offline scanning**: For CI/CD pipelines without live server connections
- **OAuth and custom auth support**
- **Behavioral code analysis**: Detects mismatches between documentation and implementation
- **Comprehensive coverage**: Tools, prompts, resources, and server instructions

## Positioning
- Explicitly critiques existing approaches: "Most existing tools focus narrowly on static code scanning"
- Claims contextual and semantic awareness that SaaS tools lack
- Part of broader Cisco AI Defense ecosystem but usable standalone
- Enterprise credibility play - Cisco brand for security-conscious orgs

## Installation
- Python 3.11+
- `uv pip install cisco-ai-mcp-scanner`
- PyPI package

## Limitations acknowledged
- Requires API keys for Cisco AI Defense (optional for YARA-only)
- LLM scanning needs external provider credentials
- Some analyzers may timeout on extended thinking operations

## Interesting observations
- **Three-engine approach is clever**: Pattern matching (fast, known threats) + LLM (semantic, unknown threats) + Cisco API (enterprise integration)
- **Standalone vs ecosystem**: Can use independently but clearly designed to funnel into paid AI Defense platform
- **Behavioral code analysis**: Detecting doc/implementation mismatches is a unique angle
- **CI/CD focus**: Static scanning mode suggests DevSecOps integration priority
- **Explicit competitor positioning**: Unusual to directly critique "existing tools" in announcement

## Maturity signals
- Cisco enterprise backing
- Multiple blog posts explaining features
- Active releases on GitHub
- Part of broader announced AI security framework

## Questions raised
- How does the Cisco AI Defense API compare to Invariant's API?
- What's the false positive rate of LLM-as-judge?
- How do YARA rules get updated? Community contributed?
- What's the pricing for the Cisco AI Defense API?
