# TODO

Live pending work only. Durable lessons and authoring rules live in `CLAUDE.md`. Completed work's
reasoning lives in `git log` commit messages, not here - do not re-add batch-by-batch history.

## Language-file re-verification

The original vendor-fact sweep (all 333 `cwe/{ID}/{language}/INDEX.md` files) is complete. Future
work is re-verifying specific claims as they age, not resuming a batch queue.

`python scripts/version_claims.py` generates a worklist: it extracts version/CVE/GHSA-shaped claims
from every file and ranks files by how long since they were last substantively edited, oldest
first - a starting point for picking what to re-check next, not a correctness checker (see the
script's own docstring). Run `python scripts/version_claims.py --claims --limit N` for the claim
lines of the N oldest-edited files.

Before trusting "all files are covered," re-run a directory-diff recount of `cwe/{id}/{language}/`
against whatever tracked list you're using - the repo keeps growing new CWE entries independent of
any review pass, so a stale count has silently drifted before.

## Findings not yet promoted to CLAUDE.md

Promote a shape to CLAUDE.md's "Remediation Claims" once it recurs in a second, unrelated instance;
until then it stays here so future work can watch for it without over-generalizing from one case.

- **A library's documented quirk was itself the vulnerability, and a later release fixed it by
  removing the quirk rather than just patching around it.** `328/java` described Spring Security's
  `BCryptPasswordEncoder` as truncating at 72 bytes "like every bcrypt implementation" - true
  historically, but that silent truncation was exactly what CVE-2025-22228 exploited (`matches()`
  treated two different passwords sharing a 72-byte prefix as equal), and the fix (6.4.4/6.3.8 and
  other patched lines) replaced the truncation with a thrown `IllegalArgumentException`. An entry
  that states a library's quirky-but-longstanding behavior as a stable fact, without checking
  whether that behavior has a CVE against it, can describe the already-fixed vulnerable behavior as
  if it were still current. Worth checking, for any claim about a library's "known"
  truncation/coercion/fallback quirk, whether that quirk has its own CVE and a release that removed
  it rather than merely documenting it better.
- **Two recommendations that are each correct and jointly fatal.** `cwe/330/java` prescribed
  `SecureRandom.getInstanceStrong()` for key generation and `secureRandom.nextInt(bound)` for OTP
  ranges in separate bullets; together they reproduce JDK-8240296's hang (`getInstanceStrong()`
  resolves to a blocking `/dev/random` reader, and `nextInt`'s rejection loop is unbounded). Ask
  what an entry's recommendations do when applied *together*, not just each in isolation.
- **Advice a major library adopted and then reverted.** Apache Commons Lang's `commons-lang3`
  3.15.0 moved `RandomStringUtils` onto `getInstanceStrong()`, hit the same hang in production
  (LANG-1748), and reverted it in 3.17.0. Searching an ecosystem's issue tracker for the approach an
  entry recommends is cheap and finds what API docs cannot.
- **A cast that unifies operand types silences the diagnostic without validating anything.**
  Casting both sides of a comparison to `int` in C makes a mixed-signedness warning disappear while
  validating neither operand; a `static_cast<int>` fix for a CWE-195 finding is itself a fresh
  CWE-196 finding; a `static_cast` added only to quiet `-Wsign-conversion` in C++ does the same;
  `int32_t count{static_cast<int32_t>(length)}` defeats brace-initialization's narrowing check by
  making both sides the same type before the compiler ever evaluates narrowing. Distinct from "test
  proves nothing against unfixed code" (already in CLAUDE.md) because here the *cast itself* is the
  fake fix, not a test - check whether a "fix" that resolves a compiler warning did anything beyond
  making the types match.
- **A framework wrapper's method name gets misattributed to the raw SDK it wraps.**
  `withStructuredOutput()`/`with_structured_output()` (`1426/javascript`, `1426/python`) and
  `RunnableConfig` (`1427/javascript`, `1427/python`) all belong to LangChain(.js), not the raw
  `@anthropic-ai/sdk`/`anthropic` packages these files are otherwise scoped to - in each case the
  file's own correctly-named raw-SDK mechanism sat one bullet away from the misattributed one.
  Worth checking, for any entry naming a framework-adjacent ecosystem (LangChain, Spring, Express
  middleware), whether a named method actually lives on the base library the file claims to cover or
  on a wrapper around it.
- **An authorization check can pass honestly while the request is still attacker-induced.**
  `1427/javascript` and `1427/python` both only gated tool actions on "does the caller own this
  resource" - which a prompt injection instructing the model to act on the caller's *own* resource
  (e.g. "refund my own order for $500") satisfies legitimately. The fix is a value/irreversibility
  threshold routed to human approval, independent of and in addition to ownership authorization.
  Ask whether an entry's authorization check would still block an attack that only asks for
  something the legitimate caller was already allowed to have.
- **A language/runtime hardening feature can be named as a fix for a bug class it structurally
  cannot touch.** `597/php` recommended `declare(strict_types=1)` as a fix for loose-vs-strict
  string comparison bugs; php.net's own manual scopes `strict_types` to type coercion for typed
  function/method parameters and return values only - it has no defined effect on `==`/`===` at
  all, in the same file or any other. The claim read as plausible (it is a real, security-adjacent
  hardening flag) and traced cleanly to a real API, which is what let it survive a plausibility
  reread; only checking the vendor doc's stated *scope* of the feature (not just whether the
  feature exists) caught it. Watch for a recommended flag/feature/mode that is real and
  security-relevant but whose documented scope doesn't cover the specific operator or mechanism the
  entry is trying to fix.
- **A numeric identifier is not itself an identity.** `114/javascript` and `114/python` both needed
  a correction that validating a PID against a format or allowlist proves nothing about *which*
  process it currently names, since PIDs are small and reused - the actual control is resolving
  identity via an app-maintained registry (or, in Python, `psutil.Process(pid).create_time()`)
  immediately before acting, not at validation time. Watch for the same shape wherever a
  short-lived numeric ID (a PID, a file descriptor, a session slot) is checked once and acted on
  later without re-resolving identity at the point of use.

## Eval corpus

- `no_harm` rubric needs the case's `must_preserve` contract passed to the judge (currently
  withheld, so judges apply their own reading and disagree).
- Nothing in the corpus is compiled or executed, so a fix is scored on intent, not correctness.
- Three authored cases are written but not yet run: `OrderEventQueueDeserialize` (CWE-502/java),
  `ModelCachePickleLoad` (CWE-502/python), `DeprecatedEntityLoaderGuard` (CWE-611/php).
- Per-language coverage campaign: 258 `(cwe, language)` slots remain out of the original 318
  missing (root-only CWEs with no language subfolder are out of scope). Continue in ~15-case
  batches, one workflow run each, checking each batch's output before the next.
- Top-15 depth campaign: remaining CWEs in rank order: 78, 89 (both need 2 more per slot to reach
  3), 94, 125, 287, 352, 416, 434, 787, 862. The corpus this campaign mined pattern shapes from is
  no longer part of this repo's source - pull patterns from OWASP cheat sheets, framework docs, or
  the language entry's own `Key Principles` instead.
- 2025 Top 15 remediation-quality plan (current MITRE Top 15: CWE-79, 89, 352, 862, 787, 22, 416,
  125, 78, 94, 120, 434, 476, 121, 502): every row now has no open next-pressure item. Full per-CWE
  case lists and per-trap descriptions live in `evals/README.md`'s top-15 table and its
  batch-by-batch prose above that table (see each `evals` commit message for a batch's own detail).
  CWE-120's decision is resolved: `cwe/120/INDEX.md` routes a finding to CWE-121 (stack destination)
  or CWE-787 (every other destination) rather than duplicating either entry's remediation, the same
  pattern `cwe/77` already uses for `cwe/78` - no CWE-120-specific eval fixture was needed as a
  result.
  - A top-15 CWE counts as "hammered" only once it has ordinary true positives plus at least one
    case combining two of: multi-file flow, existing partial mitigation, plausible wrong fix,
    explicit behaviour preservation. Any future batch should still prefer a genuinely distinct
    datapath over padding an already-hammered row.
- Multi-file depth cases exist only for CWE-79 (7 languages) and CWE-77 (4 languages) at the
  3-case single-file target; not extended to other top-15 CWEs or applied as a default - decide if
  wanted.
- MITRE rank is a proxy for exploitation data, not for what a SAST tool actually flags in source. If
  scanner output naming which CWEs actually arrive becomes available, prioritize by that instead of
  rank order.
