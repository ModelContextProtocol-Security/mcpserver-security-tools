#!/usr/bin/env python3
"""
Download academic papers from arXiv and convert to markdown using marker.

For each paper:
1. Creates resources/papers/{arxiv-id}/ directory
2. Downloads PDF from arXiv
3. Converts to markdown using marker_single (preserves images)
4. Creates README.md with attribution

Usage:
    python scripts/download_papers.py [--paper ARXIV_ID]

    # Download all papers from CSV
    python scripts/download_papers.py

    # Download specific paper
    python scripts/download_papers.py --paper 2512.06556
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


def download_pdf(arxiv_id: str, output_path: Path) -> bool:
    """Download PDF from arXiv."""
    pdf_url = f"https://arxiv.org/pdf/{arxiv_id}.pdf"
    print(f"  Downloading from {pdf_url}")
    try:
        urllib.request.urlretrieve(pdf_url, output_path)
        return True
    except Exception as e:
        print(f"  Error downloading: {e}")
        return False


def convert_with_marker(pdf_path: Path, output_dir: Path) -> bool:
    """Convert PDF to markdown using marker_single."""
    print(f"  Converting with marker...")
    try:
        result = subprocess.run(
            [
                'marker_single',
                str(pdf_path),
                '--output_dir', str(output_dir),
                '--output_format', 'markdown'
            ],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            print(f"  Marker error: {result.stderr}")
            return False
        return True
    except Exception as e:
        print(f"  Error running marker: {e}")
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
- `images/` - Extracted figures (if any)

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
    if paper_dir.exists() and not force:
        md_files = list(paper_dir.glob('*.md'))
        if len(md_files) > 1:  # README.md + content
            print(f"  Already processed, skipping (use --force to reprocess)")
            return True

    # Create directory
    paper_dir.mkdir(parents=True, exist_ok=True)

    # Download PDF to temp location
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / f"{arxiv_id}.pdf"

        if not download_pdf(arxiv_id, pdf_path):
            return False

        # Convert with marker
        if not convert_with_marker(pdf_path, paper_dir):
            return False

    # Marker creates a nested subdirectory with the PDF name
    # Structure: paper_dir/{arxiv_id}/{arxiv_id}.md + images
    marker_subdir = paper_dir / arxiv_id

    if marker_subdir.exists() and marker_subdir.is_dir():
        # Find markdown file in subdirectory
        md_files = list(marker_subdir.glob('*.md'))
        if md_files:
            # Move markdown to paper.md
            src_md = md_files[0]
            dst_md = paper_dir / 'paper.md'
            shutil.move(str(src_md), str(dst_md))
            print(f"  Created paper.md")

            # Move images to images/ subdirectory
            image_files = list(marker_subdir.glob('*.jpeg')) + list(marker_subdir.glob('*.png'))
            if image_files:
                images_dir = paper_dir / 'images'
                images_dir.mkdir(exist_ok=True)
                for img in image_files:
                    shutil.move(str(img), str(images_dir / img.name))
                print(f"  Moved {len(image_files)} images to images/")

            # Remove the now-empty marker subdirectory (and any leftover files like meta.json)
            shutil.rmtree(marker_subdir)
        else:
            print(f"  Warning: No markdown file found in marker output")
    else:
        # Fallback: check for markdown directly in paper_dir
        md_files = [f for f in paper_dir.glob('*.md') if f.name != 'README.md']
        if md_files:
            new_md_path = paper_dir / 'paper.md'
            if md_files[0] != new_md_path:
                md_files[0].rename(new_md_path)
            print(f"  Created paper.md")
        else:
            print(f"  Warning: No markdown file generated")

    # Create README
    create_readme(paper_dir, paper, 'paper.md')

    return True


def main():
    parser = argparse.ArgumentParser(description='Download and convert arXiv papers')
    parser.add_argument('--paper', help='Specific arXiv ID to download (e.g., 2512.06556)')
    parser.add_argument('--force', action='store_true', help='Reprocess existing papers')
    parser.add_argument('--list', action='store_true', help='List papers from CSV without downloading')
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
    print(f"Found {len(papers)} papers in CSV\n")

    if args.list:
        for p in papers:
            print(f"  {p['arxiv_id']}: {p['name']}")
        sys.exit(0)

    # Filter to specific paper if requested
    if args.paper:
        papers = [p for p in papers if p['arxiv_id'] == args.paper]
        if not papers:
            print(f"Error: Paper {args.paper} not found in CSV")
            sys.exit(1)

    # Process papers
    success = 0
    failed = 0
    for paper in papers:
        print(f"Processing: {paper['name']} ({paper['arxiv_id']})")
        if process_paper(paper, resources_dir, force=args.force):
            success += 1
        else:
            failed += 1
        print()

    print(f"Done: {success} successful, {failed} failed")


if __name__ == '__main__':
    main()
