# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Purpose

**mcpserver-security-tools** is a **catalog of tools, projects, papers, and resources for securing MCP implementations** — part of the CSA Model Context Protocol Security initiative.

It is explicitly in a **discovery / sense-making phase**: there is *no fixed schema yet*, and the structure is expected to evolve as the landscape is understood. Don't impose rigid formats — the point is to learn what matters.

A defining editorial stance: **academic papers are catalogued alongside software tools.** The rationale (from the README) is that in the AI era a paper describing an attack taxonomy, defense framework, or evaluation methodology is "software that runs in an AI runtime" — an AI can read and enact it — so papers are treated as actionable tools, not just references.

## Layout

```
data/
  mcp-security-tools.csv        # The core inventory (name, url, description)
  research-notes.md             # Observations, emerging categories, gaps
  first-*-insight-report.md     # Synthesized findings from batches of tools/papers
  evaluations/                  # Per-tool evaluations
  paper-analyses/               # Per-paper analyses
prompts/                        # The AI research workflows (see below)
resources/papers/{arxiv-id}/    # Downloaded papers converted to Markdown (+ attribution README)
scripts/download_papers.py      # arXiv PDF -> Markdown fetcher
```

## Research workflow (prompt-driven)

The actual work is done by running the prompts in `prompts/` with an AI:
- **`discover-mcp-security-tools.md`** — research/find new tools to add to the inventory
- **`evaluate-mcp-security-tool.md`** — evaluate a specific tool
- **`analyze-mcp-security-paper.md`** — analyze a security paper
- **`workflow-log.md`** — running log of research activity

Emerging tool categories identified so far: MCP server scanners/auditors, MCP gateways (runtime proxies), security tools *exposed via* MCP, directories/verification, and academic research. See `data/research-notes.md`.

## The one script

`scripts/download_papers.py` downloads papers from arXiv and converts them to Markdown using **markitdown** (a pip dependency — install it before running). For each paper it creates `resources/papers/{arxiv-id}/`, downloads the PDF, converts it, and writes an attribution README. It is idempotent/ctrl-c-safe (skips already-completed papers).

```bash
python scripts/download_papers.py                  # process all pending papers
python scripts/download_papers.py --paper 2512.06556   # a specific arXiv ID
```

There is otherwise no build/test/lint system — this is a research/data repository.

## Contributing & ecosystem

Early stage: to add a tool, open an issue or a PR adding a row to `data/mcp-security-tools.csv`. Related siblings include `mcpserver-audit` (CSA's auditing tool) and the main site `modelcontextprotocol-security.io`. `main` is protected via pull request.
