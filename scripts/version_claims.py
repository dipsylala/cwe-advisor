#!/usr/bin/env python3
"""Surface version/advisory claims for re-verification prioritization.

This tool does NOT judge whether any claim is still correct - that requires the
same vendor-source-tracing a manual review does. What it does:

  1. Extract every line that looks like it makes a version, CVE/GHSA, or
     spec-number claim (a version floor, a fix release, an advisory ID, a JEP/PEP
     number, an obsoletion code, ...), across every cwe/{ID}/INDEX.md and
     cwe/{ID}/{language}/INDEX.md file.
  2. Look up, from git history, the date each file was last substantively
     edited by any commit - used as a staleness proxy, not a "last verified"
     guarantee (see caveat below).
  3. Rank files oldest-edited-first, so the next re-verification pass has a
     generated worklist instead of a manual grep-and-guess.

CAVEAT: "last edited" is a proxy, not a guarantee. A file that was reviewed
and found correct, and that nothing has touched since, still ranks as if it
were stale - there's no way to tell "never looked at" apart from "looked at,
confirmed correct" from git history alone. Treat the ranking as a starting
point to read from, not as ground truth about what's actually wrong.

Regex extraction is necessarily approximate: expect some false positives
(a byte count, a CVSS score) and some misses (an unusually-phrased claim).
That's fine for a worklist - a human still reads and judges each line; this
tool only decides what order to look at files in.

Usage:
  python scripts/version_claims.py                  # summary, oldest-edited first
  python scripts/version_claims.py --limit 20        # top 20 oldest
  python scripts/version_claims.py --file cwe/89/php/INDEX.md   # one file's claims
  python scripts/version_claims.py --claims           # full worklist: every claim line, grouped by file
  python scripts/version_claims.py --claims --limit 20  # claim lines for the 20 oldest-edited files only
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CWE_ROOT = ROOT / "cwe"

ECOSYSTEM_WORDS = (
    r"(?:PHP|Python|Java(?:Script)?|JDK|JRE|JVM|OpenJDK|Node(?:\.js)?|"
    r"Go(?:lang)?|Ruby(?:\s+on\s+Rails)?|Rails|\.NET(?:\s+Core|\s+Framework|\s+Standard)?|"
    r"ASP\.NET(?:\s+Core)?|C#|Servlet|Jakarta\s+EE|Java\s+EE|"
    r"Spring(?:\s+Security|\s+Boot)?|Django|Flask|Laravel|Express|"
    r"Android|iOS|Chrome|Firefox|Safari|MySQL|PostgreSQL|MariaDB|"
    r"OpenSSL|TLS|SSL|GCC|Clang|glibc|Xcode|Swift|Kotlin|Perl)"
)
VERSION_NUM = r"v?\d+(?:\.\d+){0,3}\+?"

PATTERNS = {
    "ecosystem-version": re.compile(rf"\b{ECOSYSTEM_WORDS}\s+{VERSION_NUM}\b"),
    "semver": re.compile(r"\bv\d+\.\d+(?:\.\d+)?\b|\b\d+\.\d+\.\d+\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b"),
    "ghsa": re.compile(r"\bGHSA-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}\b"),
    "jep": re.compile(r"\bJEP\s+\d+\b"),
    "pep": re.compile(r"\bPEP\s+\d+\b"),
    "syslib": re.compile(r"\bSYSLIB\d+\b"),
    "api-level": re.compile(r"\bAPI\s+(?:level\s+)?\d+\b"),
}


def rel(path):
    return path.relative_to(ROOT).as_posix()


def iter_target_files():
    if not CWE_ROOT.is_dir():
        return
    for cwe_dir in sorted((p for p in CWE_ROOT.iterdir() if p.is_dir() and p.name.isdigit()), key=lambda p: int(p.name)):
        root_file = cwe_dir / "INDEX.md"
        if root_file.exists():
            yield root_file
        for sub in sorted(cwe_dir.iterdir()):
            if sub.is_dir():
                lang_file = sub / "INDEX.md"
                if lang_file.exists():
                    yield lang_file


def extract_claims(path):
    text = path.read_text(encoding="utf-8")
    claims = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        matched_kinds = set()
        for kind, pattern in PATTERNS.items():
            if pattern.search(line):
                matched_kinds.add(kind)
        if matched_kinds:
            claims.append((line_no, sorted(matched_kinds), line.strip()))
    return claims


def build_last_edited_map():
    """One git-log pass over full history -> {relpath: (date, hash, subject)} for the
    most recent commit that touched each file, regardless of commit message."""
    result = subprocess.run(
        ["git", "log", "--format=COMMIT|%H|%cI|%s", "--name-only"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    last_edited = {}
    current = None
    for line in result.stdout.splitlines():
        if line.startswith("COMMIT|"):
            _, commit_hash, date, subject = line.split("|", 3)
            current = (date, commit_hash, subject)
            continue
        if not line.strip() or current is None:
            continue
        # First commit touching a file in log order is the most recent one (git log is newest-first).
        last_edited.setdefault(line.strip(), current)
    return last_edited


def format_row(relpath, edited):
    if edited is None:
        return f"{'NEVER':<10}  {'-':<50}  {relpath}"
    edit_date, _hash, subject = edited
    edit_date = edit_date.split("T", 1)[0]
    short_subject = subject if len(subject) <= 50 else subject[:47] + "..."
    return f"{edit_date:<10}  {short_subject:<50}  {relpath}"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--limit", type=int, default=None, help="only show the N oldest-edited files")
    parser.add_argument("--file", type=str, default=None, help="show claim lines for one file only")
    parser.add_argument("--claims", action="store_true", help="dump every matched claim line, grouped by file")
    args = parser.parse_args()

    if args.file:
        path = ROOT / args.file
        if not path.exists():
            print(f"No such file: {args.file}", file=sys.stderr)
            return 1
        claims = extract_claims(path)
        if not claims:
            print(f"No version-shaped claims found in {args.file}")
            return 0
        for line_no, kinds, text in claims:
            print(f"{line_no:>4}  [{','.join(kinds)}]  {text}")
        return 0

    last_edited = build_last_edited_map()
    files = list(iter_target_files())

    def sort_key(path):
        edited = last_edited.get(rel(path))
        # None (no history at all - shouldn't happen for a tracked file) sorts first; else oldest first.
        return (edited is not None, edited[0] if edited else "")

    files.sort(key=sort_key)
    if args.limit:
        files = files[: args.limit]

    if args.claims:
        for path in files:
            claims = extract_claims(path)
            if not claims:
                continue
            edited = last_edited.get(rel(path))
            header_date = edited[0].split("T", 1)[0] if edited else "NEVER"
            print(f"\n=== {rel(path)}  (last edited: {header_date}) ===")
            for line_no, kinds, text in claims:
                print(f"{line_no:>4}  [{','.join(kinds)}]  {text}")
        return 0

    print(f"{'LAST EDITED':<10}  {'LAST COMMIT':<50}  FILE")
    for path in files:
        edited = last_edited.get(rel(path))
        print(format_row(rel(path), edited))
    return 0


if __name__ == "__main__":
    sys.exit(main())
