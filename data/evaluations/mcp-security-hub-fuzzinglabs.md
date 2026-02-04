---
name: mcp-security-hub (FuzzingLabs)
url: https://github.com/FuzzingLabs/mcp-security-hub
evaluated: 2026-02-04
---

# mcp-security-hub (FuzzingLabs)

## One-liner
Production-ready collection of 28 MCP servers wrapping 163+ offensive security tools for AI-assisted security testing.

## Who's behind it
- **Creator**: FuzzingLabs (security research organization)
- **License**: MIT
- **Type**: Security tools VIA MCP (not scanning MCP)

## Important distinction
This is NOT a tool for securing MCP servers. It's a collection of MCP servers that expose security/pentesting tools TO AI assistants. Inverse category.

## Scale
- 28 MCP servers
- 163+ security tools
- 11 categories

## Tool categories

### Reconnaissance
Nmap, Shodan, ProjectDiscovery tools, WhatWeb, Masscan, ZoomEye

### Web Security
Nuclei, SQLMap, Nikto, FFUF, Wayback URLs, Burp Suite

### Binary Analysis
Radare2, Binwalk, YARA, Capa, Ghidra, IDA Pro

### Cloud Security
Trivy, Prowler

### Secrets Detection
Gitleaks

### Exploitation
SearchSploit

### OSINT
Maigret, DNSTwist

### Threat Intel
VirusTotal, AlienVault OTX

### Active Directory
BloodHound

### Password Cracking
Hashcat

## How it works
- Each MCP server wraps a security tool in Docker container
- Standardized interfaces for all tools
- Natural language interaction via Claude
- Docker Compose for multi-tool orchestration
- Results returned to AI assistant

## Installation
```bash
git clone https://github.com/FuzzingLabs/mcp-security-hub
cd mcp-security-hub
docker-compose build
docker-compose up [server-name] -d
```

## Interesting observations
- **Massive scope**: 163+ tools is impressive coverage
- **Docker-first**: Each tool containerized for isolation
- **Authorization warning**: Emphasizes authorized testing only
- **Production-ready claim**: Suggests stability focus
- **Binary analysis inclusion**: Ghidra, IDA Pro, Radare2 - not just web tools
- **Cloud security**: Trivy, Prowler for cloud-native environments

## Use case
Security professional wants to use Claude for pentesting → Configure these MCP servers → Ask Claude to "scan this network with nmap" or "analyze this binary with Ghidra"

## Questions raised
- How well do complex tools like Burp Suite work via MCP?
- What's the latency for heavy tools?
- How do you handle tool output that's too large for context?
- Legal implications of AI-assisted pentesting?
