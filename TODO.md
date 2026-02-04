# TODO - Deferred Decisions and Open Questions

## Decisions Needed

### Data Schema
- [ ] Define structured schema for tool entries once patterns are clearer
- [ ] Decide on evaluation criteria / what capabilities to track systematically
- [ ] Format for deeper tool evaluations (obsidian-style yaml+md likely)

### Categories/Taxonomy
- [ ] Finalize tool categories (scanners, gateways, security-via-MCP, directories)
- [ ] Decide if categories are flat or hierarchical
- [ ] How to handle tools that span categories

### Evaluation Methodology
- [ ] Self-reported features vs actual testing?
- [ ] Community reviews?
- [ ] Comparative testing against same malicious MCP server?

### Contributing
- [ ] Formal contributing guidelines
- [ ] Review process for submissions
- [ ] Quality bar for inclusion

## Deferred Work

### Detection Tools
- Research tools for detecting MCP servers/clients in enterprise environments
- Code scanning to find MCP implementations in repos
- Runtime detection approaches
- (Discussed in working group meeting - important use case, not addressed yet)

### Malicious Content Warning
- Standardized warning statement for repos containing malicious AI prompts
- Something like: "This repository may contain malicious AI prompts for security research purposes. While we attempt to label them and make them relatively safe, we cannot guarantee safety for all models and processing pipelines. Use at your own risk."
- Where to put it (README, separate file, both)
- How to label malicious content within files

### Website Integration
- How to integrate this content into modelcontextprotocol-security.io
- Build process to generate pages from data?
- Manual sync?
- Which pages/sections on main site

### Scorecards
- Discussed in working group: useful for managers, less for technical evaluation
- If we do scorecards, what criteria?
- How to avoid false precision

## Open Questions

1. How do we encourage tool vendors to help users fix vulnerabilities AND report upstream?
2. Should we track which tools align with which standards (OWASP, Linux Foundation, etc)?
3. How to handle commercial vs open source fairly?
4. Do we want to track MCP marketplaces in this repo or separately?
5. What's the relationship between this repo and mcpserver-audit?

## From Working Group Meeting (2026-02-04)

Key points raised:
- Need definitive resource that Google/ChatGPT will point to
- Want to enable ecosystem, not do all the work ourselves
- Detection of MCP in enterprise is a gap
- Malicious prompts in audit reports are a concern
- Consider fingerprinting MCP servers/clients in code
