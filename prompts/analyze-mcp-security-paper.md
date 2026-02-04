# MCP Security Paper Analysis Prompt

## Goal
Analyze an academic paper about MCP security to:
1. Extract knowledge that helps us understand MCP security
2. Discover tools, papers, or resources we should add to our inventory
3. Identify reusable assets (prompts, taxonomies, methodologies)

Papers are "software that runs in an AI runtime" - we want to make them actionable.

## Process

1. Read `data/mcp-security-tools.csv` to see which papers exist
2. Pick a paper that doesn't have an analysis file yet
3. Read the paper markdown from `resources/papers/{arxiv-id}/paper.md`
4. Write analysis to `data/paper-analyses/{arxiv-id}.md`
5. Update the CSV `evaluation_file` column
6. **Append discoveries** to `data/research-notes.md`

## What to extract

### 1. Paper summary
- What's the core contribution? (one paragraph)
- What problem does it address?
- What's the key finding or proposal?

### 2. Attack/threat coverage
- What attacks does it describe or demonstrate?
- What threat model does it assume?
- Attack success rates, if measured
- Which MCP components are in scope (tools, prompts, resources, transport)?

### 3. Defense/mitigation proposals
- What defenses does it propose?
- What's the claimed effectiveness?
- Implementation complexity?
- Are there reference implementations?

### 4. Discoveries (ADD TO INVENTORY)
Look for things we should add to `mcp-security-tools.csv`:

**Tools mentioned:**
- Security tools the paper references or compares against
- Tools the paper implements or releases
- Tools used in evaluation

**Other papers:**
- Papers cited that we should read
- Related work that covers MCP security

**Datasets/benchmarks:**
- Evaluation datasets released
- Benchmark frameworks
- Vulnerable-by-design servers for testing

**Companies/projects:**
- Organizations working on MCP security
- Research groups

### 5. Extractable assets
Things we could use directly:

**Prompts:**
- Detection prompts used in the paper
- Attack prompts demonstrated
- Defense prompts proposed

**Taxonomies:**
- Attack classifications
- Threat categories
- Vulnerability types

**Methodologies:**
- Evaluation frameworks
- Testing approaches
- Security assessment checklists

**Metrics:**
- How they measure success/failure
- Useful benchmarks

### 6. Limitations & gaps
- What does the paper acknowledge it doesn't cover?
- What assumptions might not hold?
- What's missing from their threat model?

## Output

### 1. Analysis file
`data/paper-analyses/{arxiv-id}.md` with YAML frontmatter:

```yaml
---
arxiv_id: "2512.06556"
title: Paper Title
authors: [First Author, et al.]
analyzed: YYYY-MM-DD
---
```

Then sections for each extraction area above.

### 2. CSV update
Add analysis filename to the `evaluation_file` column for the paper row.

### 3. Discovery additions
For each tool/paper/resource discovered:
- If it seems relevant, add a new row to `mcp-security-tools.csv`
- Note in the analysis which items were added

### 4. Research notes update
Append to **Evaluation Log** in `data/research-notes.md`:

```markdown
### YYYY-MM-DD: [Paper] Paper Title

**Discoveries added to inventory:**
- List any new tools/papers/resources added to CSV

**Key insights:**
- Most important findings for MCP security practitioners
- Things that change how we think about MCP security

**Extractable assets:**
- Prompts, taxonomies, or methodologies that could be reused
- Note if you saved any to a separate file

**Gaps identified:**
- What this paper doesn't cover that we should look for elsewhere
```

## Notes

- Papers often have supplementary materials (GitHub repos, datasets) - look for those
- Check if the paper has an associated tool we should evaluate separately
- Some papers are more theoretical, others more practical - note which
- Look for evaluation code or prompts in paper appendices
