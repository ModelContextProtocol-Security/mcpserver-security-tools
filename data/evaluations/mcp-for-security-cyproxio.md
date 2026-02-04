---
name: mcp-for-security (cyproxio)
url: https://github.com/cyproxio/mcp-for-security
evaluated: 2026-02-04
---

# mcp-for-security (cyproxio)

## One-liner
Collection of 24 MCP servers for penetration testing tools, integrating security workflows with AI assistants.

## Who's behind it
- **Creator**: Cyprox (AI-driven cybersecurity company)
- **Tagline**: "Humans and AI, Working Together"
- **License**: MIT
- **Type**: Security tools VIA MCP (not scanning MCP)

## Important distinction
This is NOT a tool for securing MCP servers. It exposes security/pentesting tools TO AI assistants. Inverse category.

## Scale
- 24 operational MCP servers
- More in development

## Tool categories

### Reconnaissance
Amass, Alterx, Assetfinder, Cero, crt.sh, shuffledns, Waybackurls

### Web Testing
FFUF, Arjun, Katana, httpx, Gowitness, Smuggler

### Network Scanning
Nmap, Masscan

### Vulnerability Detection
Nuclei, SQLmap, WPScan, SSLScan

### Specialized Analysis
- HTTP Headers Security analyzer
- MobSF (mobile security)
- Scout Suite (cloud auditing)

### In Development
Commix, Corsy, CrackMapExec, feroxbuster, gobuster, and others

## Architecture
- TypeScript + MCP SDK
- Docker-based deployment
- Cyprox platform integration

## Installation
```bash
# Docker
docker pull cyprox/mcp-for-security

# Manual
./start.sh [tool-name]
```

## Interesting observations
- **Company-backed**: Cyprox is building a commercial platform around this
- **TypeScript**: Different tech stack from FuzzingLabs (Python/Docker)
- **Mobile security**: MobSF inclusion is unique
- **Cloud auditing**: Scout Suite for cloud security
- **In-development section**: Transparent about what's coming
- **Cyprox platform tie-in**: Open source feeds commercial product

## Comparison to FuzzingLabs
- Smaller tool count (24 vs 163+)
- TypeScript vs Python
- More focused on web/recon tools
- Includes mobile security (MobSF)
- Company-backed vs security research org

## Questions raised
- How does Cyprox platform build on this?
- What's the business model?
- Why TypeScript when Python dominates security tooling?
- How does tool coverage compare long-term?
