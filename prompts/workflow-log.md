# Workflow Log

How we built this research repository using AI-assisted discovery.

## Approach

We're in the **discovery phase** - no fixed schema, learning what matters by looking at what exists. The workflow is:

1. Create prompts that guide research
2. Run them to gather data
3. Capture meta-observations about what dimensions emerge
4. Iterate on the prompts based on what we learn

## Writing the Prompts

The prompts themselves were written collaboratively with AI. The process:

1. **Start with goals** - "We need a prompt to find MCP security tools" or "We need to evaluate individual tools"
2. **Discuss structure** - Talk through what the output should look like (CSV? Markdown? Both?), what to capture, what not to worry about yet
3. **AI drafts the prompt** - Based on the discussion, AI proposes a prompt structure
4. **Iterate** - Review, adjust, simplify. We cut a template because we realized we don't want rigid structure yet. We added the Evaluation Log after realizing we should capture meta-learning.
5. **Run it and refine** - After running a prompt, we noticed things to add (like "check marketing materials") and updated the prompt

This took maybe 10 minutes of back-and-forth per prompt. The conversation surfaced things we hadn't initially considered - like using the CSV for checkpointing, or capturing "what dimensions emerged" as a separate concern from the evaluation itself.

**Key insight:** Don't try to write the perfect prompt upfront. Start with goals, draft something, run it, learn, iterate.

## Step 1: Initial Discovery

**Goal:** Find what MCP security tools exist and get a broad inventory.

**Prompt:** [discover-mcp-security-tools.md](./discover-mcp-security-tools.md)

**Process:**
- Used web search to find MCP security tools, scanners, gateways
- Cast a broad net: GitHub repos, product pages, blog posts, "top 10" lists
- Captured results in a simple CSV (name, url, description)
- Wrote freeform observations about patterns and categories

**Output:**
- [data/mcp-security-tools.csv](../data/mcp-security-tools.csv) - 19 tools inventoried
- [data/research-notes.md](../data/research-notes.md) - patterns, categories, gaps

**Time:** ~15 minutes

## Step 2: Individual Tool Evaluation

**Goal:** Go deeper on individual tools to understand what they emphasize, which reveals what dimensions people care about.

**Prompt:** [evaluate-mcp-security-tool.md](./evaluate-mcp-security-tool.md)

**Process:**
- Pick a tool from CSV that hasn't been evaluated
- Research broadly: repo, docs, marketing materials, blog posts
- Write freeform evaluation capturing what seems relevant
- Update CSV with evaluation filename (checkpointing)
- Append to Evaluation Log with meta-observations (new dimensions, interesting patterns, questions)

**Output:**
- [data/evaluations/](../data/evaluations/) - one file per tool evaluated
- Evaluation Log section in research-notes.md - raw learning captured

**Time:** ~10-15 minutes per tool

## Key Design Decisions

**Why CSV for the inventory?**
Simple, easy to read, good for checkpointing (empty `evaluation_file` = not done yet).

**Why freeform evaluations?**
We don't know what matters yet. Rigid schemas would force us to guess. Instead, we capture what each tool emphasizes and let patterns emerge.

**Why an Evaluation Log?**
Each evaluation teaches us something. The log captures "new dimensions identified" and "interesting observations" as raw material for eventual schema development.

**Why YAML+markdown (obsidian-style)?**
AI-friendly format. Structured enough to parse, flexible enough for freeform content.

## Step 3: Post-Evaluation Iteration

After completing all 19 evaluations, we reviewed what we learned and updated the prompt.

**What we noticed:**
- **Tool poisoning dominates**: Almost every scanner focuses on malicious tool descriptions. But what about prompts and resources? Few tools explicitly cover those.
- **Learning/transparency gap**: Some tools just give results (black box). Others explain findings and teach you about MCP security. This matters.
- **Remediation varies**: Some tools help you fix issues and report upstream. Others just detect.

**Prompt updates made:**
- Added "Coverage scope" section: Does it scan tools only, or also prompts and resources?
- Added "Learning & transparency" section: Does it explain why something is bad? Can you learn from it?
- Added "Remediation" section: Does it help fix issues or just detect them?

**Key insight:** Run the evaluations first, THEN update the prompt based on what you learned. The first pass reveals what dimensions actually matter in practice.

## Step 4: Adding Academic Papers

**Goal:** Include academic research as "tools" since papers with methodologies can be implemented by AI.

**Rationale:**
In the AI era, the line between documentation and executable software has blurred. A paper describing a security methodology can be turned into a working tool by having an AI read and implement it. Papers that describe attack taxonomies, defense frameworks, or evaluation methodologies are effectively "software that runs in an AI runtime."

**Process:**
- Searched arXiv for MCP security papers
- Added papers to CSV with `[Paper]` prefix in name field
- Created script to download PDFs and convert to markdown using [marker](https://github.com/datalab-to/marker)

**Script:** [scripts/download_papers.py](../scripts/download_papers.py)

```bash
# List papers from CSV
python scripts/download_papers.py --list

# Download all papers
python scripts/download_papers.py

# Download specific paper
python scripts/download_papers.py --paper 2512.06556
```

**Output structure:**
```
resources/papers/{arxiv-id}/
├── paper.md     # Markdown conversion
├── images/      # Extracted figures
└── README.md    # Attribution and source info
```

**Why convert to markdown?**
- Makes papers AI-readable in context windows
- Preserves figures for visual reference
- Enables semantic search across paper content
- Allows AI to implement methodologies described in papers

## Reproducing This

1. Read the discovery prompt, run web searches, populate the CSV
2. Pick a tool, read the evaluation prompt, research it, write the evaluation
3. Note what new dimensions you discovered in the Evaluation Log
4. Repeat until patterns solidify into a schema
5. **After a batch of evaluations**: Review findings, identify gaps in the prompt, update it
6. **For papers**: Run the download script to convert PDFs to markdown

The prompts guide the work but don't constrain it. Adapt as you learn.
