---
name: MCP-Shield
url: https://github.com/riseandignite/mcp-shield
evaluated: 2026-02-04
---

# MCP-Shield

## One-liner
npm-based MCP security scanner focusing on tool poisoning, shadowing, and cross-origin attacks with optional Claude API integration.

## Who's behind it
- **Creator**: Rise and Ignite
- **License**: MIT
- **Inspired by**: Invariant Labs security research
- **Installation**: npm (`npx mcp-shield`)

## Problems it claims to solve
- Tool poisoning attacks (hidden instructions in descriptions)
- Tool shadowing (one tool manipulating another's behavior)
- Data exfiltration via suspicious optional parameters
- Cross-origin violations (intercepting communications between services)
- Sensitive file access attempts

## Vulnerability categories

### 1. Tool Poisoning
Hidden instructions within tool descriptions that attempt covert actions

### 2. Tool Shadowing
One tool's description contains instructions to "modify the behavior of" other tools

### 3. Data Exfiltration
Suspicious optional parameters designed to collect sensitive information

### 4. Cross-Origin Violations
Tools attempting to intercept and redirect communications between other services

## How it works
- Connects to installed MCP servers
- Analyzes tool descriptions for suspicious patterns
- Generates risk reports
- Optional AI-powered deeper analysis via Claude API

## Platform support
- Cursor
- Claude Desktop
- Windsurf
- VSCode
- Codeium

## Usage
```bash
npx mcp-shield
npx mcp-shield --path /path/to/config
npx mcp-shield --claude-api-key sk-xxx  # AI analysis
npx mcp-shield --identify-as cursor     # Test client-specific behavior
npx mcp-shield --safe-list server1,server2
```

## Notable features
- **Safe list**: Exclude trusted servers from scanning
- **Client identity testing**: `--identify-as` flag tests if servers behave differently for different clients
- **Optional AI analysis**: Can work without API key, enhanced with Claude
- **npm distribution**: Very easy to run (`npx`)

## Interesting observations
- **MIT license**: Most permissive, enterprise-friendly
- **npm distribution**: JavaScript ecosystem, easy adoption
- **Credits Invariant Labs**: Acknowledges prior research
- **Tool shadowing concept**: Interesting attack vector - one tool poisoning another
- **Client identity testing**: Clever idea - does server behave differently based on who's asking?
- **Optional AI**: Works standalone, AI is enhancement not requirement

## Maturity signals
- Clear documentation
- npm package published
- Covers multiple platforms
- But: unclear how active development is

## Questions raised
- How comprehensive is the pattern detection vs AI-powered analysis?
- What's the false positive rate?
- Is it actively maintained?
- How does it compare to Invariant's mcp-scan it was inspired by?
