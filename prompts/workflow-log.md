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

## Reproducing This

1. Read the discovery prompt, run web searches, populate the CSV
2. Pick a tool, read the evaluation prompt, research it, write the evaluation
3. Note what new dimensions you discovered in the Evaluation Log
4. Repeat until patterns solidify into a schema

The prompts guide the work but don't constrain it. Adapt as you learn.
