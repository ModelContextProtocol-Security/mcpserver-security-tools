# MCP Security Tool Evaluation Prompt

## Goal
Evaluate a single MCP security tool in depth to understand what it is, what it claims to do, and what it emphasizes. We're discovering what dimensions matter by seeing what tools actually built.

## Process

1. Read `data/mcp-security-tools.csv`
2. Pick a tool that doesn't have an evaluation file yet (no entry in the `evaluation_file` column, or column is empty)
3. Research that tool broadly
4. Write evaluation to `data/evaluations/{tool-slug}.md`
5. Update the CSV to add the evaluation filename
6. **Append to the Evaluation Log** in `data/research-notes.md` with meta-observations

## What to research
Cast a broad net - look at whatever you can find:
- GitHub repo (README, code structure, issues)
- Documentation
- Marketing materials, landing pages
- Blog posts, announcements
- Comparisons to other tools
- User discussions, reviews

## What to capture in the evaluation file
Freeform markdown - capture what seems relevant or interesting:

- What is it? (one-liner)
- What problems does it claim to solve?
- What features/capabilities does it highlight?
- What does it compare itself to or position against?
- Who's behind it? (company, individual, community)
- Open source or commercial? Licensing?
- For open source: what's the general approach under the hood?
  - Does it use AI/LLM for analysis?
  - Static analysis? Runtime? Both?
  - What does it actually scan/check?
- What standards or frameworks does it reference?
- Maturity signals (age, activity, users, stars)
- Anything surprising, interesting, or potentially useful
- Gaps or limitations they acknowledge

### Coverage scope (important - tool poisoning gets most attention, but what about prompts/resources?)
- Does it scan tools only, or also prompts and resources?
- Does it check server instructions/metadata?
- What's explicitly in scope vs out of scope?

### Learning & transparency
- Does it explain findings (why something is bad, not just that it is)?
- Does it help users understand MCP security concepts?
- Is there educational content, or just scan results?
- Can you learn from using it, or is it a black box?
- Does it have an `--explain` or similar feature?

### Remediation
- Does it suggest how to fix issues?
- Does it help report vulnerabilities upstream?
- Just detection, or detection + guidance?

Don't worry about being comprehensive or structured - we're learning what matters.

## Output

### 1. Evaluation file
`data/evaluations/{tool-slug}.md` with YAML frontmatter:

```yaml
---
name: Tool Name
url: https://...
evaluated: YYYY-MM-DD
---
```

Followed by freeform notes.

### 2. CSV update
Add evaluation filename to the `evaluation_file` column for that row.

### 3. Research notes update
Append an entry to the **Evaluation Log** section at the bottom of `data/research-notes.md`:

```markdown
### YYYY-MM-DD: Tool Name

**New dimensions identified:**
- Any new aspects/dimensions this tool reveals that we hadn't considered before
- Things that might become schema fields later

**Interesting observations:**
- Notable patterns, approaches, or choices
- Things that surprised you
- Effective framing or terminology

**Questions raised:**
- New questions this evaluation surfaced
- Things to investigate across other tools
```

This log captures our learning as we go - raw material for later schema development.
