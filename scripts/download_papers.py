#!/usr/bin/env python3
"""
Download academic papers from arXiv and convert to markdown using markitdown.

For each paper:
1. Creates resources/papers/{arxiv-id}/ directory
2. Downloads PDF from arXiv
3. Converts to markdown using markitdown
4. Creates README.md with attribution

Usage:
    python scripts/download_papers.py [--paper ARXIV_ID]

    # Process all papers (skips completed ones, ctrl+c safe)
    python scripts/download_papers.py

    # Download specific paper
    python scripts/download_papers.py --paper 2512.06556

    # Show status of all papers
    python scripts/download_papers.py --status

    # Reprocess a specific paper
    python scripts/download_papers.py --paper 2512.06556 --force
"""

import argparse
import csv
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path


def get_arxiv_id_from_url(url: str) -> str | None:
    """Extract arXiv ID from URL like https://arxiv.org/abs/2512.06556"""
    match = re.search(r'arxiv\.org/abs/(\d+\.\d+)', url)
    if match:
        return match.group(1)
    return None


def get_papers_from_csv(csv_path: Path) -> list[dict]:
    """Read CSV and return list of paper entries."""
    papers = []
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['name'].startswith('[Paper]'):
                arxiv_id = get_arxiv_id_from_url(row['url'])
                if arxiv_id:
                    papers.append({
                        'name': row['name'].replace('[Paper] ', ''),
                        'url': row['url'],
                        'arxiv_id': arxiv_id,
                        'description': row['description']
                    })
    return papers


def is_paper_complete(paper_dir: Path) -> bool:
    """Check if a paper has been fully processed."""
    if not paper_dir.exists():
        return False
    arxiv_id = paper_dir.name
    paper_md = paper_dir / f'{arxiv_id}.md'
    readme_md = paper_dir / 'README.md'
    return paper_md.exists() and readme_md.exists()


def download_pdf(arxiv_id: str, output_path: Path) -> bool:
    """Download PDF from arXiv."""
    pdf_url = f"https://arxiv.org/pdf/{arxiv_id}.pdf"
    print(f"  Downloading from {pdf_url}")
    try:
        urllib.request.urlretrieve(pdf_url, output_path)
        print(f"  Downloaded {output_path.stat().st_size / 1024:.1f} KB")
        return True
    except Exception as e:
        print(f"  Error downloading: {e}")
        return False


def convert_with_markitdown(pdf_path: Path, output_path: Path) -> bool:
    """Convert PDF to markdown using markitdown."""
    print(f"  Converting with markitdown...")
    try:
        result = subprocess.run(
            ['markitdown', str(pdf_path), '-o', str(output_path)],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            print(f"  markitdown error: {result.stderr}")
            return False
        print(f"  Created {output_path.name} ({output_path.stat().st_size / 1024:.1f} KB)")
        return True
    except Exception as e:
        print(f"  Error running markitdown: {e}")
        return False


def create_readme(paper_dir: Path, paper: dict, md_filename: str):
    """Create README.md with paper attribution."""
    readme_content = f"""# {paper['name']}

## Source

- **arXiv**: [{paper['arxiv_id']}]({paper['url']})
- **PDF**: https://arxiv.org/pdf/{paper['arxiv_id']}.pdf

## Description

{paper['description']}

## Contents

- `{md_filename}` - Markdown conversion of the paper

## Conversion notes

Converted using [markitdown](https://github.com/microsoft/markitdown). Limitations:
- **No images** - figures/diagrams not extracted, refer to PDF for visuals
- **Tables may be imperfect** - complex tables might not render correctly
- **Equations** - may appear as plain text rather than LaTeX

For authoritative content, always refer to the original PDF.

## License

This paper was obtained from arXiv. Please refer to the original paper for licensing terms.
The markdown conversion is provided for research and accessibility purposes.

## Citation

Please cite the original paper when using this content.
Visit {paper['url']} for citation information.
"""
    readme_path = paper_dir / 'README.md'
    with open(readme_path, 'w') as f:
        f.write(readme_content)
    print(f"  Created README.md")


def process_paper(paper: dict, resources_dir: Path, force: bool = False) -> bool:
    """Process a single paper: download, convert, create README."""
    arxiv_id = paper['arxiv_id']
    paper_dir = resources_dir / 'papers' / arxiv_id

    # Check if already processed
    if is_paper_complete(paper_dir) and not force:
        print(f"  Already processed, skipping (use --force to reprocess)")
        return True

    # Clean up any partial download
    if paper_dir.exists():
        print(f"  Cleaning up partial download...")
        shutil.rmtree(paper_dir)

    # Create directory
    paper_dir.mkdir(parents=True, exist_ok=True)

    # Download PDF to temp location
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / f"{arxiv_id}.pdf"

        if not download_pdf(arxiv_id, pdf_path):
            return False

        # Convert with markitdown
        paper_md = paper_dir / f'{arxiv_id}.md'
        if not convert_with_markitdown(pdf_path, paper_md):
            return False

    # Create README
    create_readme(paper_dir, paper, f'{arxiv_id}.md')

    return True


def main():
    parser = argparse.ArgumentParser(description='Download and convert arXiv papers')
    parser.add_argument('--paper', help='Specific arXiv ID to download (e.g., 2512.06556)')
    parser.add_argument('--force', action='store_true', help='Reprocess existing papers')
    parser.add_argument('--list', action='store_true', help='List papers from CSV without downloading')
    parser.add_argument('--status', action='store_true', help='Show status of all papers')
    args = parser.parse_args()

    # Find repo root
    script_dir = Path(__file__).parent
    repo_root = script_dir.parent
    csv_path = repo_root / 'data' / 'mcp-security-tools.csv'
    resources_dir = repo_root / 'resources'

    if not csv_path.exists():
        print(f"Error: CSV not found at {csv_path}")
        sys.exit(1)

    # Get papers from CSV
    papers = get_papers_from_csv(csv_path)

    if args.list:
        print(f"Found {len(papers)} papers in CSV:\n")
        for p in papers:
            print(f"  {p['arxiv_id']}: {p['name']}")
        sys.exit(0)

    # Show status
    if args.status:
        complete = 0
        incomplete = []
        for p in papers:
            paper_dir = resources_dir / 'papers' / p['arxiv_id']
            if is_paper_complete(paper_dir):
                print(f"  ✓ {p['arxiv_id']}: {p['name']}")
                complete += 1
            else:
                print(f"  ✗ {p['arxiv_id']}: {p['name']}")
                incomplete.append(p)
        print(f"\n{complete}/{len(papers)} complete")
        if incomplete:
            print(f"\nNext up: {incomplete[0]['arxiv_id']} - {incomplete[0]['name']}")
        sys.exit(0)

    # Filter to specific paper if requested
    if args.paper:
        papers = [p for p in papers if p['arxiv_id'] == args.paper]
        if not papers:
            print(f"Error: Paper {args.paper} not found in CSV")
            sys.exit(1)

    # Count current status
    complete_count = sum(1 for p in papers if is_paper_complete(resources_dir / 'papers' / p['arxiv_id']))
    print(f"Papers: {complete_count}/{len(papers)} complete\n")

    # Process papers one at a time
    success = 0
    failed = 0
    skipped = 0

    for i, paper in enumerate(papers):
        paper_dir = resources_dir / 'papers' / paper['arxiv_id']

        # Skip if already complete (unless --force)
        if is_paper_complete(paper_dir) and not args.force:
            skipped += 1
            continue

        remaining = len(papers) - i - skipped
        print(f"[{i+1}/{len(papers)}] Processing: {paper['name']} ({paper['arxiv_id']})")

        if process_paper(paper, resources_dir, force=args.force):
            success += 1
            print(f"  ✓ Complete\n")
        else:
            failed += 1
            print(f"  ✗ Failed\n")

    print(f"Session: {success} processed, {skipped} skipped, {failed} failed")

    # Final status
    final_complete = sum(1 for p in get_papers_from_csv(csv_path)
                        if is_paper_complete(resources_dir / 'papers' / p['arxiv_id']))
    total = len(get_papers_from_csv(csv_path))
    print(f"Overall: {final_complete}/{total} papers complete")


if __name__ == '__main__':
    main()
