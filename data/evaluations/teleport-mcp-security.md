---
name: Teleport MCP Security
url: https://goteleport.com/
evaluated: 2026-02-04
---

# Teleport MCP Security

## One-liner
Zero-trust infrastructure identity platform extended to MCP, treating AI agents as first-class identities with granular access control.

## Who's behind it
- **Company**: Teleport
- **Type**: Established infrastructure security company
- **Focus**: Identity and access management for infrastructure
- **MCP addition**: Extended existing platform to support MCP

## What Teleport is
Teleport is an existing infrastructure identity platform that provides zero-trust access to:
- SSH
- RDP
- Databases
- Kubernetes
- Clouds
- And now: Model Context Protocol (MCP)

## MCP-specific features

### Access Control
- Deny new tools by default
- Granular control down to individual tool invocations
- Role-based access control scoped to actual needs
- Just-in-time (JIT) access requests for high-risk tools

### Identity Management
- Treats AI agents as infrastructure identities
- Every actor (agents, LLM tools, bots, MCP tools, digital twins) as first-class identity
- "Turns agentic AI from uncontrolled automation into trustworthy, governed automation"

### Audit and Compliance
- Logs every action with full identity context
- Captures: who, what, when, where, why, how
- Comprehensive audit trails

### Security Architecture
- Ephemeral privileges via short-lived certificates
- Replaces passwords, SSH keys, API tokens, database credentials
- Certificates bound to biometric devices and secure enclaves
- Built-in certificate authority

## Positioning
- "Zero-code MCP" security
- Automatic security enforcement (no manual work)
- Enterprise infrastructure security extended to AI

## Interesting observations
- **Platform extension**: Not MCP-native, added to existing infra platform
- **Identity-first**: Treats AI agents like any other infrastructure identity
- **Enterprise-grade**: JIT access, audit trails, RBAC
- **Certificate-based**: Modern approach vs tokens/credentials
- **Deny-by-default**: Strict security posture
- **AWS Marketplace presence**: Listed in AI Agents and Tools category

## Maturity signals
- Established company
- Existing customer base for infrastructure security
- AWS Marketplace listing
- Multiple MCP-specific pages/blog posts

## Questions raised
- How complex is setup for MCP-only use cases?
- Pricing model?
- Can it be used standalone for MCP or requires full Teleport?
- How does it compare to MCP-native gateways?
