#!/usr/bin/env python3
"""Surface version/advisory claims for re-verification prioritization.

This tool does NOT judge whether any claim is still correct - that requires the
same vendor-source-tracing an LLM sweep batch does (see TODO.md's per-batch
method). What it does:

  1. Extract every line that looks like it makes a version, CVE/GHSA, or
     spec-number claim (a version floor, a fix release, an advisory ID, a JEP/PEP
     number, an obsoletion code, ...), across every cwe/{ID}/INDEX.md and
     cwe/{ID}/{language}/INDEX.md file.
  2. Look up, from git history, the date each file was last substantively
     edited by ANY commit - used as a staleness proxy, not a "last verified"
     guarantee (see caveat below) - plus, separately, the most recent commit
     whose message names a sweep batch (e.g. "Sweep batch 27"), shown for
     context when one exists.
  3. Rank files oldest-edited-first (never-touched-since-authoring files sort
     first), so the next targeted sweep has a generated worklist instead of a
     manual grep-and-guess.

CAVEAT - this was tested against the repo's own history and found wanting in
one specific way, worth knowing before trusting the ranking: an earlier
version of this tool filtered to commits whose *message* names a batch, and
that undercounted badly. A repo-wide directory rename ("Move CWE directories
under cwe/") silently dropped content from several files; the follow-up
commit that restored it ("Restore operational detail the compression to
cwe/ had dropped") touched files across four already-swept batches' worth of
CWEs but doesn't say "batch" anywhere in its message - so those files looked
"never verified" under that filter even though they'd been through the
sweep. Falling back to "last edited by any commit" fixes that specific case,
but the general problem doesn't fully go away: a file the sweep reviewed and
found clean, and that nothing has touched since, will still rank as if it
were stale, when it was actually just confirmed correct. Cross-check
anything this tool ranks as a top priority against TODO.md's "Clean-
language-file count" list before assuming it's genuinely unreviewed.

Regex extraction is necessarily approximate: expect some false positives
(a byte count, a CVSS score) and some misses (an unusually-phrased claim).
That's fine for a worklist - a human or sweep agent still reads and judges
each line; this tool only decides what order to look at files in.

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

BATCH_COMMIT_RE = re.compile(r"\bbatch\s+\d+", re.IGNORECASE)

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


def build_history_maps():
    """One git-log pass over full history -> two dicts keyed by relpath:
    last_edited:    (date, hash, subject) of the most recent commit touching the file, any message.
    last_batch:     same, but only among commits whose message names a sweep batch (may be absent
                    even for a genuinely-reviewed file - see the CAVEAT in the module docstring).
    """
    result = subprocess.run(
        ["git", "log", "--format=COMMIT|%H|%cI|%s", "--name-only"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    last_edited = {}
    last_batch = {}
    current = None
    current_is_batch = False
    for line in result.stdout.splitlines():
        if line.startswith("COMMIT|"):
            _, commit_hash, date, subject = line.split("|", 3)
            current = (date, commit_hash, subject)
            current_is_batch = bool(BATCH_COMMIT_RE.search(subject))
            continue
        if not line.strip() or current is None:
            continue
        # First commit touching a file in log order is the most recent one (git log is newest-first).
        path = line.strip()
        last_edited.setdefault(path, current)
        if current_is_batch:
            last_batch.setdefault(path, current)
    return last_edited, last_batch


def format_row(relpath, edited, batch):
    if edited is None:
        return f"{'NEVER':<10}  {'-':<40}  {relpath}"
    edit_date = edited[0].split("T", 1)[0]
    if batch is None:
        batch_note = "(no batch-labeled commit)"
    else:
        subject = batch[2]
        batch_note = subject if len(subject) <= 40 else subject[:37] + "..."
    return f"{edit_date:<10}  {batch_note:<40}  {relpath}"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--limit", type=int, default=None, help="only show the N oldest-verified files")
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

    last_edited, last_batch = build_history_maps()
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

    print(f"{'LAST EDITED':<10}  {'LAST BATCH COMMIT':<40}  FILE")
    for path in files:
        edited = last_edited.get(rel(path))
        batch = last_batch.get(rel(path))
        print(format_row(rel(path), edited, batch))
    return 0


if __name__ == "__main__":
    sys.exit(main())
