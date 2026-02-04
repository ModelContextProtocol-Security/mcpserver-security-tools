---
name: mcp-security-scanner (sidhpurwala)
url: https://github.com/sidhpurwala-huzaifa/mcp-security-scanner
evaluated: 2026-02-04
---

# mcp-security-scanner (sidhpurwala)

## One-liner
Python penetration testing tool for MCP servers with comprehensive transport support and a deliberately vulnerable test server for learning.

## Who's behind it
- **Author**: Huzaifa Sidhpurwala
- **Contributor**: Ye Wang (Red Hat) - helped resolve initialization issues
- **License**: Apache-2.0
- **Inspired by**: "Damn Vulnerable MCP Server" project

## Problems it claims to solve
- Identifying vulnerabilities and misconfigurations in MCP servers
- Generating actionable security reports
- Testing across different transport types

## Transport support
- **HTTP** JSON-RPC endpoints
- **Stdio** (local process communication)
- **SSE** (Server-Sent Events) - experimental, deprecated in latest MCP

## Security check categories
1. **Authentication mechanisms**
2. **Transport security**
3. **Tool exposure**
4. **Prompt integrity**
5. **Resource access**

## Output formats
- Human-readable text reports
- JSON for programmatic processing
- Verbose tracing with real-time feedback

## Key features
- RPC passthrough for direct method invocation
- Health checks without full scanning
- Bearer token and OAuth2 Client Credentials auth
- Customizable timeouts and session management
- `--explain <ID>` for detailed finding explanations

## Deliberately Insecure Test Server
Included for learning/testing - simulates real vulnerabilities:
- Test 0: Basic insecure setup
- Test 1: Prompt injection vulnerabilities
- Test 2: Tool poisoning attacks
- Test 3: Tool mutation ("rug-pull")
- Test 4: Excessive permissions and private resource leakage
- Test 5: Token theft scenarios
- Test 6: Indirect prompt injection via external resources
- Test 7: Unauthenticated remote access exposure

## Installation
Python 3.10+, pip install from cloned repo

## Interesting observations
- **Educational focus**: Vulnerable test server is great for learning
- **Comprehensive transport coverage**: HTTP, stdio, SSE all supported
- **Red Hat contributor**: Enterprise connection
- **Pentest framing**: Positioned as penetration testing tool
- **Explain feature**: Can explain individual findings, good for learning
- **"Damn Vulnerable" inspiration**: Security community pattern (like DVWA)

## Maturity signals
- Clear documentation
- Test server for validation
- Multiple output formats
- Apache-2.0 license

## Questions raised
- How does this compare to Invariant/Cisco scanners?
- Is it actively maintained?
- Could the vulnerable test server become a standard testing target?
