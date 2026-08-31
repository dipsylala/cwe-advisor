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

The initial sweep is complete and batches were a one-off process to get there, not an ongoing
structure - future work is re-verification of specific claims as they age, done directly without
needing a "batch N" label. `python scripts/version_claims.py` generates a worklist for that: it
extracts version/CVE/GHSA-shaped claims from every file and ranks files by how long since they were
last substantively edited, oldest first - a starting point for picking what to re-check next, not a
correctness checker (see the script's own docstring for what it does and does not do). Run
`python scripts/version_claims.py --claims --limit N` to get the actual claim lines for the N
oldest-edited files.

## Sweep status

**All 333 language files reviewed. Verified complete by directory-diff recount, not just by the
batch table's self-reported count** - the same recount method batch 19 and batch 26 each had to
run after a miscount, run pre-emptively here instead of waited for a third one. The recount cross-
references every file the batch table's CWE/file lists actually name against every `INDEX.md`
under `cwe/{id}/{language}/`, so it does not just trust arithmetic - see the "Lesson for next time"
below for why that distinction mattered twice already.

Batches 26-28 closed the gap the 287-to-301 recount had missed: three entirely new CWEs (`328`,
`476`, `501`, `643`, all added 2026-08-28) plus a handful of individual language files added to
already-swept CWEs (`190/csharp`, `190/go`, `190/java`, `114/csharp`, `134/php`) had never entered
the queue. Batch 27 covered `190`'s three new languages, `114/csharp`, `134/php`, `328` (root + all
6 languages), and `476` (`c`/`cpp`/`java`) - 5 of 14 defective. Batch 28 covered `501` (root + all 6
languages) and `643` (root + `csharp`/`java`/`python`) - 3 of 9 defective. Root files are out of
scope by default: they rarely carry falsifiable claims, but check before skipping if a root names
specific APIs or versions - `cwe/88`, `cwe/113`, and `cwe/328` all did, and all three were wrong.

**Lesson for next time:** re-run the directory-diff recount before declaring the sweep closed, not
just when a miscount is suspected - the population moves while the sweep is in progress, since
this repo keeps growing new CWE entries independent of the sweep's own commits. Any future
correctness work on language files is a fresh, targeted pass (e.g. re-verifying a specific claim,
or sweeping a newly-added CWE created after this recount), not a continuation of this batch queue -
but re-run the same directory diff before trusting that "all files are covered" again, since this
is now the second time the tracked total silently fell behind the real one.

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

The Entries column is a per-batch count of files reviewed, language files and root files both -
several rows include a root file's `(+root)`/`(+roots)` review alongside its language files, so
the column does not sum to the language-file population on its own; the "Sweep status" section
above tracks the language-file-only count separately and is the number to trust.

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
| 22 | C dangerous/obsolete-function and format-string: `242/c`, `243/c`, `364/c`, `479/c`, `477/c`, `477/python`, `676/c`, `676/python`, `134/c`, `134/java`, `134/python` | 11 | 6/11 (`243/c`, `477/python`, `676/python`, `134/java`, `134/python` clean on vendor facts) |
| 23 | Config/allowlist/path-control injection: `15/csharp`, `15/java`, `15/javascript`, `15/python`, `183/java`, `183/javascript`, `183/python`, `73/csharp`, `73/java`, `73/python` | 10 | 8/10 (`73/csharp`, `73/python` clean on vendor facts) |
| 24 | LLM/AI, timing, cert, multi-byte string: `1426/javascript`, `1426/python`, `1427/javascript`, `1427/python`, `208/csharp`, `208/java`, `208/javascript`, `208/python`, `299/java`, `135/c`, `135/php` | 11 | 6/11 (`208/csharp`, `208/javascript`, `208/python`, `299/java`, `135/php` clean on vendor facts; `208/java`'s "isEqual() returns early on unequal lengths" claim was true only through JDK 21 - JDK 22 removed the early return, caught only by reading OpenJDK's actual source after a reconciliation agent contradicted the file) |
| 25 | Mass assignment and process control: `915/csharp`, `915/java`, `915/javascript`, `915/php`, `915/python`, `915/ruby`, `114/c`, `114/java`, `114/javascript`, `114/python` | 10 | 6/10 (`915/ruby`, `114/c`, `114/javascript`, `114/python` clean on vendor facts; `915/python` also got a substantial FastAPI/Pydantic expansion since the file previously covered Django/DRF only) |
| 26 | `382/java`, `498/java`, `597/csharp`, `597/java`, `597/php`, `926/android` (queued as a "closeout" batch that turned out not to be one - see Sweep status) | 6 | 4/6 (`498/java`, `597/java` clean on vendor facts; `597/java`'s `MessageDigest.isEqual()` constant-time claim was re-verified directly against tagged OpenJDK source for 8u/11u/17u/21u current branches, not just trusted from batch 24's finding on a different file). User review of this batch's commit caught two agent-evidence errors the human judgment pass missed: `597/csharp`'s `FixedTimeEquals()` bullet omitted that it short-circuits on a length mismatch (needs hashing both sides to a fixed length first, not just byte-encoding), and `926/android`'s manifest-merger fix named the wrong marker (`tools:replace="android:exported"` at the attribute level, not `tools:node`) - both corrected in a follow-up commit. |
| 27 | Newly-discovered files (see batch 26's recount): `190/csharp`, `190/go`, `190/java`, `114/csharp`, `134/php`, `328` root + 6 languages, `476` `c`/`cpp`/`java` | 14 | 5/14 (root's "bcrypt cost 12+" overstated OWASP's actual minimum of 10; `114/csharp` conflated two different `AppDomain.CreateDomain` overloads - one doesn't exist at all on .NET Core/5+, the other compiles and throws; `328/java`'s `BCryptPasswordEncoder` truncation claim was backwards for current/fixed versions - CVE-2025-22228 made it throw `IllegalArgumentException` instead of silently truncating, as of Spring Security 6.4.4/6.3.8 and other patched lines; `328/php`'s `crypt()` DES-fallback claim needed PHP-8.0 version scoping, since the salt parameter became required that release; `328/python`'s "OpenSSL hard requirement in 3.12" was wrong - PEP 644 raised the minimum OpenSSL version in 3.10, and neither version made OpenSSL mandatory for the whole build. `190/csharp`, `190/go`, `190/java`, `134/php`, `328/csharp`, `328/go`, `328/javascript`, `476/c`, `476/cpp`, `476/java` clean on vendor facts) |
| 28 | The last two never-swept CWEs: `501` root + 6 languages, `643` root + `csharp`/`java`/`python` - closeout, verified by a full directory-diff recount, not just the batch table's arithmetic | 9 | 3/9 (`501/csharp` named a nonexistent identifier `SecurityStampValidationInterval` - the real property is `SecurityStampValidatorOptions.ValidationInterval`; `501/php` claimed `session.use_only_cookies` defaults off, but php.net documents its default as on, conflating it with `use_strict_mode`'s correctly-stated off-by-default two bullets earlier; `643/csharp` claimed `XPathDocument` needs `XmlResolver = null` like `XmlDocument`, but `XPathDocument` has no `XmlResolver` property at all - the null-resolver mitigation has to be applied to the `XmlReader` passed into its constructor. `501/go`, `501/java`, `501/javascript`, `501/python`, `643/java` clean on vendor facts; `643/python`'s `no_network=True` recommendation was accurate-but-redundant (already the lxml default) and tightened to name only the setting that actually needs flipping) |

Clean-language-file count: `347/csharp`, `352/python`, `601/go`, `434/go`, `434/javascript`,
`434/python`, `201/python`, `125/cpp`, `121/cpp`, `401/javascript`, `401/python`, `362/java`,
`367/go`, `367/java`, `367/javascript`, `367/python`, `377/java`, `79/perl`, `170/cpp`, `195/c`,
`195/cpp`, `197/java`, `243/c`, `477/python`, `676/python`, `134/java`, `134/python`, `73/csharp`,
`73/python`, `208/csharp`, `208/javascript`, `208/python`, `299/java`, `135/php`, `915/ruby`,
`114/c`, `114/javascript`, `114/python`, `498/java`, `597/java`, `190/csharp`, `190/go`,
`190/java`, `134/php`, `328/csharp`, `328/go`, `328/javascript`, `476/c`, `476/cpp`, `476/java`,
`501/go`, `501/java`, `501/javascript`, `501/python`, `643/java` - 55 of 333 reviewed files (all of
them, as of batch 28), still consistent with "treat every unreviewed file as suspect by default,"
now read as "every file not on this list."

## Findings not yet promoted to CLAUDE.md

Promote a shape to CLAUDE.md's "Remediation Claims" once it recurs in a second, unrelated batch;
until then it stays here so the next batch can watch for it without over-generalizing from one
instance.

- **A library's documented quirk was itself the vulnerability, and a later release fixed it by
  removing the quirk rather than just patching around it.** `328/java` (batch 27) described Spring
  Security's `BCryptPasswordEncoder` as truncating at 72 bytes "like every bcrypt implementation" -
  true historically, but that silent truncation was exactly what CVE-2025-22228 exploited
  (`matches()` treated two different passwords sharing a 72-byte prefix as equal), and the fix
  (6.4.4/6.3.8 and other patched lines) replaced the truncation with a thrown
  `IllegalArgumentException`. An entry that states a library's quirky-but-longstanding behavior as
  a stable fact, without checking whether that behavior has a CVE against it, can describe the
  already-fixed vulnerable behavior as if it were still current. Worth checking, for any claim
  about a library's "known" truncation/coercion/fallback quirk, whether that quirk has its own CVE
  and a release that removed it rather than merely documenting it better.
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
- **A cast that unifies operand types silences the diagnostic without validating anything.**
  Four instances in one batch (21): casting both sides of a comparison to `int` in C makes a
  mixed-signedness warning disappear while validating neither operand; a `static_cast<int>` fix
  for a CWE-195 finding is itself a fresh CWE-196 finding; a `static_cast` added only to quiet
  `-Wsign-conversion` in C++ does the same; `int32_t count{static_cast<int32_t>(length)}` defeats
  brace-initialization's narrowing check by making both sides the same type before the compiler
  ever evaluates narrowing. Distinct from "test proves nothing against unfixed code" (already in
  CLAUDE.md) because here the *cast itself* is the fake fix, not a test - check whether a "fix"
  that resolves a compiler warning did anything beyond making the types match.
- **A framework wrapper's method name gets misattributed to the raw SDK it wraps.** Four instances
  in batch 24, one batch: `withStructuredOutput()`/`with_structured_output()` (`1426/javascript`,
  `1426/python`) and `RunnableConfig` (`1427/javascript`, `1427/python`) all belong to LangChain(.js),
  not the raw `@anthropic-ai/sdk`/`anthropic` packages these files are otherwise scoped to - in each
  case the file's own correctly-named raw-SDK mechanism sat one bullet away from the misattributed
  one. Worth checking, for any entry naming a framework-adjacent ecosystem (LangChain, Spring,
  Express middleware), whether a named method actually lives on the base library the file claims to
  cover or on a wrapper around it.
- **An authorization check can pass honestly while the request is still attacker-induced.**
  `1427/javascript` and `1427/python` both only gated tool actions on "does the caller own this
  resource" - which a prompt injection instructing the model to act on the caller's *own* resource
  (e.g. "refund my own order for $500") satisfies legitimately. The fix is a value/irreversibility
  threshold routed to human approval, independent of and in addition to ownership authorization.
  Ask whether an entry's authorization check would still block an attack that only asks for
  something the legitimate caller was already allowed to have.
- **A language/runtime hardening feature can be named as a fix for a bug class it structurally
  cannot touch.** `597/php` (batch 26) recommended `declare(strict_types=1)` as a fix for
  loose-vs-strict string comparison bugs; php.net's own manual scopes `strict_types` to type
  coercion for typed function/method parameters and return values only - it has no defined effect
  on `==`/`===` at all, in the same file or any other. The claim read as plausible (it is a real,
  security-adjacent hardening flag) and traced cleanly to a real API, which is what let it survive
  a plausibility reread; only checking the vendor doc's stated *scope* of the feature (not just
  whether the feature exists) caught it. Watch for a recommended flag/feature/mode that is real and
  security-relevant but whose documented scope doesn't cover the specific operator or mechanism the
  entry is trying to fix.
- **A numeric identifier is not itself an identity.** `114/javascript` and `114/python` (batch
  25, same batch so far) both needed a correction that validating a PID against a format or
  allowlist proves nothing about *which* process it currently names, since PIDs are small and
  reused - the actual control is resolving identity via an app-maintained registry (or, in
  Python, `psutil.Process(pid).create_time()`) immediately before acting, not at validation time.
  Watch for the same shape wherever a short-lived numeric ID (a PID, a file descriptor, a session
  slot) is checked once and acted on later without re-resolving identity at the point of use.

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
- **Three more authored cases added (2026-08-31), not yet run.** `OrderEventQueueDeserialize`
  (CWE-502/java), `ModelCachePickleLoad` (CWE-502/python), `DeprecatedEntityLoaderGuard`
  (CWE-611/php) - not padding for the existing ten, but targeting the one shape that actually caught
  the guided arm in run 4: an entry's `Remediation Steps` opening with an infrastructure/config
  change (migrate to JSON; call a deprecated no-op loader) ahead of the sink-local fix. Confirmed by
  reading `cwe/502/java`, `cwe/502/python` and `cwe/611/php` directly - none carries the "do not
  offer this as the fix for one finding" caveat that `cwe/117/java` and `cwe/78/java` gained after
  being caught the same way. Needs a run before it tells us anything.
- **Per-language coverage campaign started (2026-08-31), four batches so far.** Goal: at least one
  case per `(CWE, language)` slot that has a language-specific entry (318 slots were missing across
  the 190 CWEs in the repo at the start; root-only CWEs with no language subfolder - 105 of them,
  mostly design-level weaknesses like CWE-16/269/1174 - are out of scope). A `source: "authored"`
  case type was added for this: plain true-positive, no `trap`/`must_preserve`/`origin`, since most
  language slots don't carry the specific "leads with an infra fix" defect the docs-pitfall cases
  target - see `evals/README.md`'s source table. Each case is written by a workflow agent that reads
  the target `cwe/{CWE}/{language}/INDEX.md`'s own `Taint Sinks` list and picks a real API from it,
  then has its `sink_line`/`sink_code` checked against the file it actually wrote.
  Batch 1 (14 cases) completed CWE-90, 117, 209, 338. Batch 2 (16 cases) completed CWE-78, 326, 434,
  502. Batch 3 (15 cases) completed CWE-89, 330, 347. Batch 4 (15 cases) completed CWE-22, 611, 614 -
  all across every language they have. One defect caught in batch 2 and fixed: the
  `434/python/FlaskUploadNoValidation` agent pointed the SAST comment at a `content_type` check
  rather than the actual `file.save()` write two lines down - moved to the write call, matching the
  corpus convention that the comment sits on the dangerous operation itself, not an adjacent check.
  Batch 3's prompt added an explicit instruction against this same mistake plus a rule against
  forcing a fake finding onto an API a language's entry documents as safe-by-default; no further
  instance of either turned up in batches 3 or 4 - e.g. batch 4's Go CWE-611 case correctly used the
  entry's one documented risky pattern (`xml.Decoder.Entity` populated from untrusted input) rather
  than a fake finding on plain `xml.Unmarshal`, which the entry says is safe. Worth keeping both
  instructions in future batches rather than assuming they're now unnecessary.
  Combined cost: ~2.87M subagent tokens for 60 cases (~47.8k/case), 0 agent errors across 60 agents.
  258 `(cwe, language)` slots remain - at the observed rate, finishing all of them is roughly a
  further 12.3M-token campaign; continue in similar-sized batches (~15 cases, one workflow run
  each), checking each batch's output before the next.
- **Top-15 depth campaign started (2026-08-31), two batches so far.** Separate goal from the breadth
  campaign above: for the CWEs this project's own MITRE Top-25 ranks-1-15 review covered (CWE-20,
  22, 77, 78, 79, 89, 94, 125, 269, 287, 352, 416, 434, 787, 862 - 20 and 269 root-only, out of
  scope), reach 3 cases per `(CWE, language)` slot rather than 1, mining `docs/CWE-{ID}/{language}
  /index.md`'s "Common Vulnerable Patterns" section for distinct shapes (adapted into an original
  scenario each time, not copied verbatim). Reaching 3-per-pair across the remaining 11 CWEs is
  roughly 128 more cases at this rate (counted directly against the corpus, not re-estimated from
  batch 1's per-CWE rate).
  Batch 1 (19 cases) completed CWE-79 (XSS): 3 cases each for csharp, go, javascript, perl, php,
  python (all previously at 0) plus one more for java (previously 2, from Benchmark) - all 7
  languages now at the 3-case target. First use of `perl` in the eval corpus. Cost: ~1.09M subagent
  tokens for 19 cases (~57.3k/case - higher than the breadth campaign's ~48k, likely the extra
  `docs/` read step), 0 agent errors. Each of the 3 per-language cases was assigned a specific named
  `docs/` pattern up front (e.g. csharp's "Raw String Concatenation in Razor" vs "HttpResponse.Write
  Without Encoding" vs "JavaScript Context Without Encoding") so they don't converge on the same
  shape - spot-checked several and confirmed genuine variety (e.g. the two Perl cases build the
  tainted HTML differently: inline interpolation vs. assemble-then-print).
  Batch 2 (12 cases) completed CWE-77 (command injection, non-shell interpreters): 3 cases each for
  csharp, java, php, python (its only 4 languages, all previously at 0) - all 4 now at the 3-case
  target. CWE-77 is scoped in this repo to non-shell command interpreters only (`cwe/77/INDEX.md`
  routes shell sinks to CWE-78), so each pattern was checked to avoid any `Process.Start`/
  `Runtime.exec`/`subprocess`/`shell_exec` drift - verified by grepping every file in the batch for
  those patterns after writing, none found. Patterns: csharp/python got Redis-inline-protocol and
  Memcached/multi-arg raw-socket variants; java got SMTP/IMAP/FTP raw-socket command injection (one
  protocol per case); php got the three distinct dynamic-dispatch forms its own entry names
  (`call_user_func()`, `$$cmd()`, `$obj->$method()`). Cost: ~653k subagent tokens for 12 cases
  (~54.4k/case), 0 agent errors. `sink_line`/`sink_code` verified programmatically against every
  written file post-hoc (not just trusted from each agent's self-report) - all 12 correct once
  compared with whitespace-trimming, matching this corpus's existing convention of storing
  `sink_code` de-indented.
  Remaining, in rank order: 78, 89 (both already breadth-complete at 1/language, need 2 more per
  slot to reach 3), 94, 125, 287, 352, 416, 434 (same), 787, 862.
- **Multi-file depth pass (2026-08-31), one batch, first authored multi-file cases in the corpus.**
  Separate from the two campaigns above: every `authored` case so far was single-file (`depth: 1`);
  only `juliet` had multi-file chains, and only in Java. 11 cases, one per language slot across the
  two CWEs already at the 3-case single-file target (CWE-79's 7 languages, CWE-77's 4), `depth`
  varying 2-5 to mirror Juliet's original range. Each case threads untrusted input through genuine
  intermediate logic - a value object, a service layer doing unrelated bookkeeping, a partial
  allowlist that checks one half of a dotted action string but not the other (PHP, depth 5), a
  formatter that correctly escapes one field while leaving a sibling field it also handles
  unescaped (JavaScript, depth 5) - rather than a bare pass-through, so the chain has to be traced
  rather than walked past boilerplate. Cost: ~587k subagent tokens for 11 cases (~53.4k/case), 0
  agent errors. Verified: file count matches declared depth for all 11, `sink_line`/`sink_code`
  correct against the actual last file for all 11, zero CWE-78 shell-pattern drift in the 4 CWE-77
  cases, and the two depth-5 chains read through end to end by hand to confirm the taint survives
  every intermediate file unsanitized. Not yet extended to the other completed/in-progress top-15
  CWEs, or applied as a default going forward - this was a one-off pass over the two CWEs already
  at the single-file target, per the direction that prompted it.
- **Resolved (2026-08-31): JWT secret-strength and token-lifetime coverage.** `docs/CWE-522` covered
  this under Insufficiently Protected Credentials, but MITRE's own definitions say otherwise - 522
  is about an insecure transmission/storage *method*, not a value's strength or a token's lifetime.
  Routed instead to where the definitions actually point: secret-strength bullets added to `330`
  (weak generation) and `798` (hardcoding) across all six languages plus root, verified per-language
  against primary sources - notably that HMAC-key-length enforcement varies by JWT library (jjwt
  throws `WeakKeyException`; PyJWT only warns by default; `jsonwebtoken` and `golang-jwt` enforce
  nothing at all; `Microsoft.IdentityModel.Tokens` enforces 128 bits against RFC 7518's 256-bit
  requirement; `firebase/php-jwt` only started enforcing it in 7.0.0, via a disputed CVE). Token
  lifetime got its own new CWE-613 (Insufficient Session Expiration) entry, root plus all six
  languages - it didn't exist in this repo at all before this pass.
- **MITRE rank is a proxy, not the real signal.** Top 25 rank reflects CVE/KEV exploitation data;
  this skill receives whatever a SAST tool flags in source. If scanner output naming which CWEs
  actually arrive becomes available, it should override rank order for prioritizing remaining work.
