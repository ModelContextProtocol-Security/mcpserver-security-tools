---
name: Lasso MCP Gateway
url: https://github.com/lasso-security/mcp-gateway
evaluated: 2026-02-04
---

# Lasso MCP Gateway

## One-liner
Open-source security gateway that sits between LLMs and MCP servers, providing triple-gate security pattern with scanning, guardrails, and custom policies.

## Who's behind it
- **Company**: Lasso Security
- **License**: MIT
- **Type**: MCP Gateway (security middleware)

## Problems it claims to solve
- Centralizing MCP infrastructure management
- Preventing sensitive data leakage (tokens, PII, credentials)
- Blocking risky MCP servers before they're loaded
- Detecting injection attacks
- Custom security policies

## Triple-Gate Security Pattern

### Gate 1: Scanner (Initial)
- Evaluates server reputation via marketplace and GitHub data
- Blocks risky MCPs based on reputation scores
- Tool description scanning for hidden instructions
- Auto-updates configuration files

### Gate 2: Guardrails (Request/Response)
- Masks sensitive data before processing
- Multiple plugin options (Basic, Presidio, Lasso)
- Token masking, PII masking
- Content safety checks

### Gate 3: Custom Policies (Application)
- Natural language-based security rules
- Tailored to specific business needs

## Guardrail plugin comparison

| Plugin | PII Masking | Token Masking | Custom Policy | Injection Detection | Content Safety |
|--------|-------------|---------------|---------------|-------------------|-----------------|
| Basic | ❌ | ✅ | ❌ | ❌ | ❌ |
| Presidio | ✅ | ❌ | ❌ | ❌ | ❌ |
| Lasso | ✅ | ✅ | ✅ | ✅ | ✅ |

## How it works
- Reads server configs from `mcp.json` files
- Manages lifecycle of configured MCP servers
- Intercepts all requests/responses
- Exposes two tools: `get_metadata` and `run_tool`
- Automatically sanitizes data passing through

## Key example
When agent reads a file containing a Hugging Face token, gateway masks the token value while returning file content.

## Installation
```bash
pip install mcp-gateway
mcp-gateway --mcp-json-path ~/.cursor/mcp.json -p basic -p xetrack
```

## Additional features
- **Xetrack integration**: Experiment tracking with SQLite/DuckDB
- **Reputation scoring**: GitHub stars, marketplace presence
- **Configuration auto-updates**: Can modify mcp.json to block risky servers

## Interesting observations
- **Tiered plugins**: Free/basic vs full-featured Lasso plugin
- **Natural language policies**: Interesting UX for custom rules
- **Reputation-based blocking**: Uses marketplace/GitHub signals
- **Auto-update configs**: Can automatically block servers
- **Enterprise design**: Clearly built for organizational use
- **Open source + commercial**: MIT license but Lasso plugin has more features

## Maturity signals
- Company-backed
- Published Python package
- Docker support
- Multiple plugin options
- Clear documentation

## Questions raised
- What's in Lasso plugin vs open source?
- How accurate is reputation scoring?
- Performance overhead of interception?
- How do natural language policies work technically?
