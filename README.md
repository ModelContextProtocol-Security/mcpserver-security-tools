# MCP Server Security Tools

A catalog of tools, projects, and resources for securing MCP (Model Context Protocol) servers and implementations.

Part of the [Model Context Protocol Security](https://modelcontextprotocol-security.io/) initiative, a Cloud Security Alliance project.

## Current Status: Discovery Phase

This repository is in the **discovery and sense-making phase**. We're actively researching what tools exist, understanding the landscape, and identifying patterns and categories.

There is no fixed schema yet - we're learning what matters as we go.

## What's Here

- `data/mcp-security-tools.csv` - Inventory of MCP security tools (name, url, description)
- `data/research-notes.md` - Observations, patterns, emerging categories, gaps
- `prompts/` - AI prompts used for research

## What Belongs Here

This repository catalogs **anything that helps secure MCP implementations**, including:

- **Traditional software tools** - Scanners, gateways, proxies
- **Academic research papers** - Methodologies, benchmarks, attack taxonomies
- **Frameworks and benchmarks** - Testing suites, vulnerable-by-design servers
- **Prompts and prompt-based tools** - AI-assisted security workflows

**Why include papers?** In the AI era, the line between documentation and executable software has blurred. A paper describing a security methodology can be turned into a working tool by having an AI read and implement it. Papers that describe attack taxonomies, defense frameworks, or evaluation methodologies are effectively "software that runs in an AI runtime." We include them because they're actionable - you can use them.

## Emerging Categories

Based on initial research, we're seeing these types:

1. **MCP Server Scanners/Auditors** - Analyze MCP servers for vulnerabilities before deployment
2. **MCP Gateways** - Runtime security proxies between AI agents and MCP servers
3. **Security Tools via MCP** - Traditional security tools exposed as MCP servers (inverse - using MCP to do security)
4. **Directories/Verification** - Catalogs of MCP servers with security verification
5. **Academic Research** - Papers with methodologies, benchmarks, and attack/defense frameworks

See `data/research-notes.md` for detailed observations.

## Future Work

- Detection tools for finding MCP servers/clients in enterprise environments
- Deeper evaluation of individual tools
- Integration with modelcontextprotocol-security.io website
- Contributing guidelines

## Contributing

This is early stage. If you know of MCP security tools not listed, open an issue or PR adding to the CSV.

## Related

- [mcpserver-audit](https://github.com/ModelContextProtocol-Security/mcpserver-audit) - CSA's MCP server auditing tool
- [Model Context Protocol Security](https://modelcontextprotocol-security.io/) - Main initiative site
