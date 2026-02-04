---
name: Proximity
url: https://github.com/fr0gger/proximity
evaluated: 2026-02-04
---

# Proximity (Nova Proximity)

## One-liner
Open-source MCP and Agent Skills security scanner with NOVA rule engine for pattern-based threat detection.

## Who's behind it
- **Creator**: Thomas Roccia (@fr0gger_)
- **License**: GPL-3.0
- **Open source**: Yes, fully open
- **GitHub stars**: 277
- **Contributions**: Welcomes community contributions

## Problems it claims to solve
- Pre-deployment security assessment of MCP servers
- Agent Skills security evaluation
- Prompt injection detection
- Jailbreak attempt detection
- Tool poisoning identification
- Data exfiltration vector detection

## What it scans
### MCP Servers
- Tools, prompts, and resources
- Parameter analysis
- Server capabilities enumeration

### Agent Skills
- Skill metadata and structure
- Permissions analysis
- Security posture evaluation

## NOVA Rule Engine
- Pattern-based threat detection
- Custom rule files (.nov format)
- Combines keyword matching + semantic analysis + LLM evaluation
- Requires API credentials (OpenAI, Groq, Anthropic, Azure, or Ollama)
- Example rule: Detects jailbreaking by identifying phrases like "previous instructions"

## Detection capabilities
- Dynamic code execution (eval, exec, subprocess)
- Data exfiltration vectors (encoded HTTP requests, shell pipes)
- Unsafe deserialization methods
- Undeclared tool permissions
- Unauthorized environment variable access

## How to use
```bash
# MCP server via HTTP
python novaprox.py http://localhost:8000/mcp

# MCP server via stdio
python novaprox.py "python server.py"

# Agent Skills scan
python novaprox.py --skill /path/to/skill

# With NOVA security rules
python novaprox.py -n -r rulefile.nov
```

## Output formats
- Console display
- JSON exports
- Markdown reports
- Includes remediation guidance

## Notable features
- **MCP Spec 2025-11-25 compatible**: Streamable HTTP, session tracking, tool annotations
- **Contextual remediation**: Specific guidance for identified issues
- **Recursive scanning**: Can scan entire skills repositories
- **Multiple transport support**: HTTP endpoints and stdio commands

## Interesting observations
- **Individual creator**: Not a company, but well-known security researcher
- **GPL-3.0 license**: Copyleft, requires derivative works to be open source
- **NOVA as separate component**: Rule engine can be used independently
- **Agent Skills focus**: Not just MCP servers but broader agent ecosystem
- **LLM-powered rules**: Rules can use AI for semantic analysis, not just pattern matching
- **Ollama support**: Can run locally without cloud API dependencies

## Maturity signals
- 277 GitHub stars
- Active development
- Press coverage (Help Net Security)
- Clear documentation
- Multiple output formats

## Questions raised
- How do NOVA rules compare to YARA rules (Cisco)?
- What's the performance with LLM-powered rule evaluation?
- How comprehensive is the rule library?
- GPL-3.0 implications for enterprise use?
