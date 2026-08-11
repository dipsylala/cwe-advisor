#!/usr/bin/env python3
"""Deterministic structural lint for the CWE knowledge base.

Pure static checks against CLAUDE.md's authoring spec - no network calls, no LLM calls.
Run: python scripts/lint.py
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

ROOT_REQUIRED_HEADINGS = ["## LLM Guidance", "## Key Principles"]
LANG_REQUIRED_HEADINGS = ["## LLM Guidance", "## Key Principles", "## Taint Sinks", "## Safe Pattern"]
STEPS_HEADINGS = ["## Remediation Steps", "## Actionable Steps"]

ROOT_WORD_LIMIT = 500
ROOT_WORD_WARN_AT = 650
LANG_WORD_LIMIT = 800
LANG_WORD_WARN_AT = 950

errors = []
warnings = []


def word_count(text):
    # Strip code fences so embedded code doesn't inflate the prose count.
    return len(re.sub(r"```.*?```", "", text, flags=re.S).split())


def rel(path):
    return path.relative_to(ROOT).as_posix()


def check_h1(path, text, cwe_id, is_language):
    first_line = text.splitlines()[0] if text.splitlines() else ""
    expected_prefix = f"# CWE-{cwe_id}:"
    if not first_line.startswith(expected_prefix):
        errors.append(f"{rel(path)}: H1 does not start with '{expected_prefix}' (found: {first_line!r})")
    if is_language and " - " not in first_line:
        warnings.append(f"{rel(path)}: H1 missing a ' - {{Language}}' suffix")


def check_steps_heading(path, text):
    if not any(h in text for h in STEPS_HEADINGS):
        errors.append(f"{rel(path)}: missing '## Remediation Steps' (or legacy '## Actionable Steps')")


def check_root_file(cwe_dir, cwe_id):
    path = cwe_dir / "INDEX.md"
    if not path.exists():
        errors.append(f"{rel(cwe_dir)}: missing INDEX.md")
        return
    text = path.read_text(encoding="utf-8")
    missing = [h for h in ROOT_REQUIRED_HEADINGS if h not in text]
    if missing:
        errors.append(f"{rel(path)}: missing heading(s) {missing}")
    check_steps_heading(path, text)
    check_h1(path, text, cwe_id, is_language=False)
    if "```" in text:
        errors.append(f"{rel(path)}: root guidance should not include code fences")
    wc = word_count(text)
    if wc > ROOT_WORD_WARN_AT:
        warnings.append(f"{rel(path)}: {wc} words, over the ~{ROOT_WORD_LIMIT} word guideline")


def check_language_file(lang_dir, cwe_id):
    path = lang_dir / "INDEX.md"
    if not path.exists():
        errors.append(f"{rel(lang_dir)}: missing INDEX.md")
        return
    text = path.read_text(encoding="utf-8")
    missing = [h for h in LANG_REQUIRED_HEADINGS if h not in text]
    if missing:
        errors.append(f"{rel(path)}: missing heading(s) {missing}")
    check_steps_heading(path, text)
    check_h1(path, text, cwe_id, is_language=True)
    if "```" not in text:
        warnings.append(f"{rel(path)}: no code fence found (Safe Pattern should show one)")
    wc = word_count(text)
    if wc > LANG_WORD_WARN_AT:
        warnings.append(f"{rel(path)}: {wc} words, over the ~{LANG_WORD_LIMIT} word guideline")


def check_links(path):
    text = path.read_text(encoding="utf-8")
    # Strip fenced code so code-syntax like `foo[x](y)` isn't parsed as a markdown link.
    prose = re.sub(r"```.*?```", "", text, flags=re.S)
    for match in re.finditer(r"]\(([^)]+)\)", prose):
        target = match.group(1)
        if target.startswith(("http://", "https://", "#", "mailto:")):
            continue
        target_path = (path.parent / target).resolve()
        if not target_path.exists():
            errors.append(f"{rel(path)}: broken link -> {target}")


def parse_alias_ids():
    path = ROOT / "aliases.md"
    ids = set()
    if not path.exists():
        errors.append("aliases.md is missing")
        return ids
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            continue
        cols = [c.strip() for c in line.strip("|").split("|")]
        if len(cols) < 2 or not cols[0].isdigit():
            continue
        ids.add(cols[0])
    return ids


def main():
    cwe_dirs = sorted(
        (p for p in ROOT.iterdir() if p.is_dir() and p.name.isdigit()),
        key=lambda p: int(p.name),
    )
    cwe_ids = {p.name for p in cwe_dirs}

    for cwe_dir in cwe_dirs:
        cwe_id = cwe_dir.name
        check_root_file(cwe_dir, cwe_id)
        for sub in sorted(cwe_dir.iterdir()):
            if sub.is_dir():
                check_language_file(sub, cwe_id)

    for md_file in ROOT.rglob("*.md"):
        if ".git" in md_file.parts:
            continue
        check_links(md_file)

    alias_ids = parse_alias_ids()
    for cwe_id in sorted(cwe_ids - alias_ids, key=int):
        errors.append(f"aliases.md: missing row for CWE-{cwe_id}")
    for cwe_id in sorted(alias_ids - cwe_ids, key=int):
        errors.append(f"aliases.md: row for CWE-{cwe_id} has no matching directory")

    print(f"Checked {len(cwe_dirs)} CWE directories.")

    if warnings:
        print(f"\n{len(warnings)} warning(s):")
        for w in warnings:
            print(f"  WARN  {w}")

    if errors:
        print(f"\n{len(errors)} error(s):")
        for e in errors:
            print(f"  ERROR {e}")
        return 1

    print("\nNo errors found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
