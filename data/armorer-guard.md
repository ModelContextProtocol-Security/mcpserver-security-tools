# Armorer Guard

Source: https://github.com/ArmorerLabs/Armorer-Guard

Armorer Guard is an MIT-licensed local Rust scanner for AI-agent security. For MCP use cases, it includes an `mcp-proxy` mode that wraps stdio MCP servers and inspects `tools/call` arguments before forwarding them to the underlying server.

## Relevant MCP Security Capabilities

- Runtime proxy for stdio MCP servers.
- Local detection of prompt injection, credential leakage, data exfiltration requests, and risky tool-call arguments.
- Structured JSON scan output with reasons, confidence, sanitized text, and scan IDs.
- Local feedback/learning overlay for deployment-specific allow/block corrections without silent cloud upload.

## Evaluation Notes

- Best categorized as an MCP gateway/runtime guardrail rather than a static server scanner.
- Primary evaluation should focus on whether unsafe `tools/call` arguments are blocked while benign tool calls pass through unchanged.
- Further evaluation could compare latency, false positives, and coverage against existing MCP gateway and proxy tools in this catalog.
