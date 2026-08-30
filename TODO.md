# TODO

Tracks the live state of the language-file triage sweep: a batch-by-batch vendor-fact review of
every `cwe/{ID}/{language}/INDEX.md` file, checking claims against primary sources rather than
rereading for plausibility. Durable lessons that generalize across batches live in `CLAUDE.md`
(see "Version and Advisory Claims" and "Remediation Claims") so any authoring or editing session
inherits them without reading this file. What stays here is live state only: counts, the queue,
the per-batch method, and findings not yet proven to recur.

Full per-batch findings are not preserved here - `git log` carries them in each batch's commit
message. Do not re-derive detail from this file; if you need a past batch's reasoning, read its
commit.

`docs/` is a gitignored, human-readable parent corpus this skill was originally derived from,
maintained elsewhere via actor/critic review across two model families, and it has since drifted -
this repo toward LLM-facing remediation, `docs/` toward human explanation. It mirrors the tree as
`docs/CWE-{ID}/{language}/index.md`. Not every language file has a `docs/` counterpart; anything
authored directly in this repo (rather than derived from `docs/`) has none.

## Sweep status

**253 of 301 language files reviewed. 48 remain.** (The population was originally miscounted as
287; a full directory diff against every batch's actual commits, not its self-reported count, found
14 hidden gaps - see batch 19's commit for how. Root files are out of scope by default: they rarely
carry falsifiable claims, but check before skipping if a root names specific APIs or versions -
`cwe/88` and `cwe/113` both did, and both were wrong.)

Remaining, grouped for batching at the ~9-12 entry size used throughout:

- C dangerous/obsolete-function and format-string (11): `242/c, 243/c, 364/c, 479/c, 477/c,
  477/python, 676/c, 676/python, 134/c, 134/java, 134/python`
- Config/allowlist/path-control injection (10): `15/csharp, 15/java, 15/javascript, 15/python,
  183/java, 183/javascript, 183/python, 73/csharp, 73/java, 73/python`
- LLM/AI, timing, cert, multi-byte string (11, loosely themed): `1426/javascript, 1426/python,
  1427/javascript, 1427/python, 208/csharp, 208/java, 208/javascript, 208/python, 299/java,
  135/c, 135/php`
- Mass assignment and process control (10): `915/csharp, 915/java, 915/javascript, 915/php,
  915/python, 915/ruby, 114/c, 114/java, 114/javascript, 114/python`
- Small platform-specific leftovers, undersized alone (6): `382/java, 498/java, 597/csharp,
  597/java, 597/php, 926/android` - merge into an adjacent batch if preferred

## Per-batch method

1. One subagent per language entry, briefed for **evidence only**: claim quoted verbatim, vendor
   sentence quoted verbatim with URL, when the behavior was introduced/in which release, what the
   vendor does *not* say, whether a stated mechanism is vendor-supported or only its outcome is. No
   verdicts - "is this true?" answers yes for a claim that is true and still broken, which is the
   dominant failure mode. Give each brief the language's own vendor sources and, where known, a
   specific trap to check.
2. Judge the evidence yourself; re-verify directly anything that would reverse a claim or delete a
   recommendation.
3. Patch, then re-read each patched file end to end - a per-bullet patch is how a file ends up
   arguing with itself, and lint cannot see it.
4. Run the `docs/` reconciliation (below) for each touched file or family.
5. `python scripts/lint.py`, confirm no language file grew past ~950 words, commit per batch.

**Commit each batch's patches with the batch.** A summary of evidence is not evidence - batch 10 had
to be re-gathered from scratch once because its findings were left uncommitted in a session
transcript that was later gone.

## `docs/` reconciliation - reading a disagreement

Neither corpus wins automatically:

- On a *vendor fact* (a version floor, a default, a CVE, documented API behavior), this repo is
  usually ahead - the sweep traces these to primary sources and `docs/` largely does not.
- On *operational detail* (what a fix fails to cover, what a test actually proves, a concrete
  framework trap), `docs/` is usually ahead - compression dropped this from the derived copies.
- A defect **both** corpora carry is the case neither comparison catches - only the vendor pass
  finds it. It has happened at least twice (CWE-287's `store.New` etc. in batch 10; CWE-362/csharp's
  substituted "boxed value" hazard in batch 18c).

File real `docs/` defects (a false claim, not just a gap) to `DOCS_UPDATE.md`.

## Batch log

Batches 1-18d covered the "intended order": authn/authz, crypto/randomness, web hygiene, and
memory/native-and-resource. Batches 19-20 closed gaps the 287-baseline miscount had hidden.

| Batch | CWEs | Entries | Defective |
|---|---|---|---|
| 1 | 89, 78 | 12 | 12/12 |
| 2 | 611, 918 | 11 | 11/11 |
| 3 | 22, 94 | 10 | 10/10 |
| 4 | 79, 943, 502, 90 | 10 | 10/10 |
| 5 | 77, 91, 95 | 11 | 11/11 |
| 6 | 41, 88 (+root) | 9 | 9/9 |
| 7 | 93, 113 (+root) | 9 | 9/9 |
| 8 | 80 | 6 | 6/6 |
| 9 | 862, 863 (+roots) | 12 | 12/12 |
| 10 | 287 | 6 | 6/6 |
| 11 | 306 | 6 | 6/6 |
| 12 | 798, 522 (+roots) | 11 | 11/11 |
| 13 | 285, 566 (+roots) | 8 | 8/8 |
| 14 | 326, 330 (+roots) | 11 | 11/11 |
| 15 | 331, 338 (+331 root) | 11 | 11/11 |
| 16a | 347, 295 | 11 | 10/11 (`347/csharp` clean) |
| 16b | 780, 316 (+780 root) | 10 | 10/10 |
| 17a | 352, 601 (+601 root) | 11 | 8/11 (`352/python`, `601/go`, `601/root` clean) |
| 17b | 614, 434 (+roots) | 14 | 8/14 (`614/root`, `434/root`, `434/go`, `434/javascript`, `434/python` clean) |
| 17c | 942, 209, 201 (+roots) | 9 | 8/9 (`201/python` + all 3 roots clean) |
| 18a | 125, 787, 121 | 6 | 4/6 (`125/cpp`, `121/cpp` clean) |
| 18b | 415, 416, 823, 824 | 8 | 2/8 clear defects (+ `docs/` additions across all 8; root/child contradiction found in `823`) |
| 18c | 401, 362 | 12 | 8/12 (`401/javascript`, `401/python`, `362/java` clean) |
| 18d | 367, 377 | 10 | 5/10 (`367/go`, `367/java`, `367/javascript`, `367/python`, `377/java` clean) |
| 19 | 117 (+root) - never-assigned CWE found by the recount | 5 | 5/5 |
| 20 | Closeout tail: `190/c`, `190/python`, `94/csharp`, `79/python`, `79/perl`, `601/python`, `943/go` | 7 | 6/7 (`79/perl` clean on vendor facts) |
| 21 | C/C++ numeric-conversion group: `170/c`, `170/cpp`, `195/c`, `195/cpp`, `196/c`, `196/cpp`, `197/c`, `197/cpp`, `197/java`, `1105/c` | 10 | 6/10 (`170/cpp`, `195/c`, `195/cpp`, `197/java` clean on vendor facts) |

Clean-language-file count so far: `347/csharp`, `352/python`, `601/go`, `434/go`, `434/javascript`,
`434/python`, `201/python`, `125/cpp`, `121/cpp`, `401/javascript`, `401/python`, `362/java`,
`367/go`, `367/java`, `367/javascript`, `367/python`, `377/java`, `79/perl`, `170/cpp`, `195/c`,
`195/cpp`, `197/java` - 22 of ~260 reviewed files, still consistent with "treat every unreviewed
file as suspect by default."

## Findings not yet promoted to CLAUDE.md

Promote a shape to CLAUDE.md's "Remediation Claims" once it recurs in a second, unrelated batch;
until then it stays here so the next batch can watch for it without over-generalizing from one
instance.

- **Two recommendations that are each correct and jointly fatal.** `cwe/330/java` (batch 14)
  prescribed `SecureRandom.getInstanceStrong()` for key generation and `secureRandom.nextInt(bound)`
  for OTP ranges in separate bullets; together they reproduce JDK-8240296's hang
  (`getInstanceStrong()` resolves to a blocking `/dev/random` reader, and `nextInt`'s rejection loop
  is unbounded). Ask what an entry's recommendations do when applied *together*, not just each in
  isolation.
- **Advice a major library adopted and then reverted.** Also batch 14: Apache Commons Lang's
  `commons-lang3` 3.15.0 moved `RandomStringUtils` onto `getInstanceStrong()`, hit the same hang in
  production (LANG-1748), and reverted it in 3.17.0. Searching an ecosystem's issue tracker for the
  approach an entry recommends is cheap and finds what API docs cannot.
- **A finding naming a dead taint sink.** New in batch 20: `94/csharp` named
  `CSharpCodeProvider.CompileAssemblyFromSource()`, which throws `PlatformNotSupportedException`
  unconditionally on .NET Core/5+ - live only on a .NET Framework target. The mirror image of a
  prescribed *fix* that doesn't run: here the *finding itself* can't execute on the platform most
  code now targets. Worth checking on any legacy-Framework-era API before treating it as a live sink.
- **A cast that unifies operand types silences the diagnostic without validating anything.**
  Four instances in one batch (21): casting both sides of a comparison to `int` in C makes a
  mixed-signedness warning disappear while validating neither operand; a `static_cast<int>` fix
  for a CWE-195 finding is itself a fresh CWE-196 finding; a `static_cast` added only to quiet
  `-Wsign-conversion` in C++ does the same; `int32_t count{static_cast<int32_t>(length)}` defeats
  brace-initialization's narrowing check by making both sides the same type before the compiler
  ever evaluates narrowing. Distinct from "test proves nothing against unfixed code" (already in
  CLAUDE.md) because here the *cast itself* is the fake fix, not a test - check whether a "fix"
  that resolves a compiler warning did anything beyond making the types match.

## Other open work (non-sweep)

- **Eval corpus.** Runs 1-4 established: chain depth is inert (source tracing scores max at every
  depth), every harm in the corpus was sink-local, and the real gap is correct-vs-plausible fixes,
  not fixing-vs-not-fixing. Ten regression cases exist (CWE-326/java, 338/python, 338/go, 117/java,
  190/java, 434/csharp, 434/javascript, 78/php, 347/csharp, 209/javascript) with `trap`/
  `must_preserve` fields - keep them as a regression guard, not a measuring instrument; run 4 showed
  19/20 runs saw through the "trap" so the batch doesn't discriminate arms anymore. Still unresolved:
  the `no_harm` rubric needs the case's `must_preserve` contract passed to the judge (currently
  withheld, so judges apply their own reading and disagree); nothing in the corpus is compiled or
  executed, so a fix is scored on intent, not correctness.
- **CWE-522 has no JWT secret-strength or token-lifetime coverage.** `docs/CWE-522` covers this in
  its root, java, javascript, and python pages; none of the five language entries here do. Whether
  it belongs in 522 or should route to CWE-326/CWE-330 is the open question - 522 already routes
  password hashing elsewhere, so precedent exists either way.
- **MITRE rank is a proxy, not the real signal.** Top 25 rank reflects CVE/KEV exploitation data;
  this skill receives whatever a SAST tool flags in source. If scanner output naming which CWEs
  actually arrive becomes available, it should override rank order for prioritizing remaining work.
