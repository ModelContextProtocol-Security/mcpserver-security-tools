---
name: Pangea AI Guard
url: https://pangea.cloud/blog/secure-mcp-servers-with-ai-guardrails/
evaluated: 2026-02-04
---

# Pangea AI Guard

## One-liner
MCP proxy and security services for AI guardrails - protects against prompt injection, PII leakage, and provides audit logging without code changes.

## Who's behind it
- **Company**: Pangea
- **Type**: Security platform with MCP-specific offerings
- **Approach**: Both proxy and MCP server components

## Two components

### 1. MCP Proxy
- Wraps existing MCP servers without code modifications
- Sanitizes tool inputs and outputs via AI Guard
- Protects against prompt injection attacks
- Prevents PII leakage
- Implements content moderation

### 2. MCP Server (Direct Tools)
Exposes security services as MCP tools:
- Prompt injection detection
- Sensitive information redaction
- Malicious reputation checking (IPs, domains)
- WHOIS and geolocation lookups
- Secure audit logging

## How it works
1. Configure security policies in Pangea Console (no code)
2. Wrap target MCP command with Pangea proxy
3. All traffic passes through guardrails at runtime
4. Credentials managed via Pangea Vault with rotation

## Key features
- No code changes to agents or MCP servers
- Multi-step attack detection
- Configurable policies via console
- API key rotation via Vault service
- Content moderation based on policies

## Interesting observations
- **Dual approach**: Proxy for wrapping + MCP server for direct tools
- **No-code configuration**: Console-based policy setup
- **Vault integration**: Credential management built-in
- **Multi-step attack awareness**: Not just single-request detection
- **Platform play**: MCP is part of broader Pangea security platform

## Questions raised
- How does pricing work?
- What's the latency overhead?
- How comprehensive is prompt injection detection?
- Can it work fully offline?
