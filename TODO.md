# TODO

What remains of the top-15 CWE review (MITRE Top 25 ranks 1-15) and the `Safe Pattern`
retirement. Every graded finding from that review has been applied, along with the sweep audit's
regressions and the version-sensitive items it depended on.

The review's `docs/` process findings have been dropped rather than actioned: `docs/` is the
human-readable guidance and education corpus this knowledge base was originally derived from, kept
here as a working copy and deliberately outside this repository's history. Its being untracked and
skipped by the linter follows from what it is, rather than being a defect. The two have drifted
since the derivation - this repo toward LLM-facing remediation, `docs/` toward human explanation -
so entries here are expected to stand on their own against current sources, which is how this pass
verified them. Where the two disagree, that is a question about which is right, not automatically
a fault here. `docs/` has since been through actor/critic review between two model families
(Claude and Codex), which this repo has not.

**That once made `docs/` the default winner on a factual disagreement. Nine sweep batches have
since retired that rule** - see "The docs/ reconciliation step" below for the split that replaced
it. The short form: on a vendor fact - a version floor, a default, a CVE, an API's documented
behaviour - the skill is now usually ahead, because the sweep traces these to primary sources and
`docs/` largely does not carry them. `docs/` was wrong on CWE-88's `--` support (findutils
documents that `--` does *not* work for `find`, and git needs `--end-of-options`) and on CWE-113's
PHP behaviour (a header whose only newline trails is silently trimmed and sent, not dropped). On
operational detail - what a fix fails to cover, what a test actually proves - `docs/` is still
usually ahead. Check both against the vendor rather than deferring to either.

## 1. Open

### Extend the graded review to the rest of the MITRE Top 25

The first pass was described as covering ranks 1-15. Checked against the list, it actually covered
**ranks 1-14**; CWE-269 was never touched. Two further entries look covered but are not: CWE-918
received one `CURLPROTO_HTTPS` fix from the sweep audit, and CWE-306 gained language entries
without its root being graded.

Remaining, in rank order:

| Rank | CWE | Entry | Language dirs | Status |
|---|---|---|---|---|
| 15 | CWE-269 Improper Privilege Management | yes | 0 | **Reviewed.** Router; all four children it names (250, 272, 273, 274) exist. No changes |
| 16 | CWE-502 Deserialization | yes | 6 | **Reviewed.** Four corrections - see below |
| 17 | CWE-200 Information Exposure | yes | 0 | **Reviewed.** Routes correctly; all seven children exist. Added to SKILL.md's router list |
| 18 | CWE-863 Incorrect Authorization | yes | 6 | **Superseded by batch 9.** This pass read it as sound - "all six language entries carry framework traps, no changes". The evidence pass found all six defective, and the two entries did *not* agree with CWE-862 on the ownership status. Kept as a record of what plausibility review misses |
| 19 | CWE-918 SSRF | yes | 6 | **Reviewed.** Stronger than the note implied. One gap: `python` - see below |
| 20 | CWE-119 Buffer bounds | yes | 0 | **Reviewed.** Read/write split to 125/787 is complete; now also names 121 for a stack buffer |
| 21 | CWE-476 NULL Pointer Dereference | yes | 3 | **Done.** Root reviewed; `c`, `cpp` and `java` entries authored |
| 22 | CWE-798 Hard-coded Credentials | yes | 6 | **Superseded by batch 12.** This pass condensed the entries; the evidence pass found all six defective and the root missing half the CWE. Third time a plausibility read passed a family the evidence pass then failed, after ranks 18 and 25 |
| 23 | CWE-190 Integer Overflow | yes | 5 | **Done.** Root and `java` reviewed; `csharp` and `go` entries authored |
| 24 | CWE-400 Uncontrolled Resource Consumption | yes | 0 | **Done.** Root authored; routes to CWE-1333 and CWE-674 where the finding names a mechanism |
| 25 | CWE-306 Missing Authentication | yes | 6 | **Superseded by batch 11.** This pass read the root as strong and left the language entries alone. The evidence pass found all six defective. Same lesson as CWE-863 at rank 18 |

### Rebuild the eval corpus around incomplete fixes

Runs 1-3 exhausted the original corpus as a measuring instrument. Of 17 run-3 outputs on the
current skill, exactly one scored below the maximum on any criterion, so the remaining headroom
(0.08 on `no_harm`) is smaller than the effect of a single case flipping (0.083). A further change
to the skill would register as nothing whether it helped or not.

What the three runs established about *what* to build instead:

- **Chain depth is inert.** Source tracing scored 2.00 in every arm at depths 2, 4 and 5, unguided
  included. More multi-file cases would buy nothing.
- **Every harm was sink-local.** Output the original discarded, an argument the original left
  `null`, a dropped URI fragment - all fit in one function.
- **The gap is between a correct fix and a plausible one**, not between fixing and not fixing.

Ten cases now cover that axis, drawn from `docs/` `Common Pitfalls` bullets and carrying explicit
`trap` and `must_preserve` fields: CWE-326/java, 338/python, 338/go, 117/java, 190/java,
434/csharp, 434/javascript, 78/php, 347/csharp, 209/javascript.

Open:

- **Run 4 answered this: the traps mostly are not traps.** 19 of 20 runs closed the real vector,
  and all three judges reported independently that both arms saw through the decoy in every case
  but one. Extending the batch in the same style would add cost without adding resolution. The
  ten cases are worth keeping as a regression guard; they are not a measuring instrument.
- **Settle the `no_harm` rubric before using it to compare arms again.** Judges disagreed on 9 of
  20 runs, all on the same question: whether a behaviour change the author declared (a new size
  cap, a filename allowlist, a changed key charset) should cost a point. That is a rubric
  ambiguity, not a model behaviour. Related: `must_preserve` exists in `case.json`, which judges
  are barred from reading, so they applied their own reading of the contract instead. Passing the
  stated contract into the judge prompt without revealing the trap is the fix.
- **True positives only, by decision.** The scenario being measured is a static analysis tool
  having found a real issue and the developer being helped to resolve it, so the arm can be told
  the finding is confirmed rather than asked to adjudicate it. That drops the verdict criterion
  and concentrates scoring on the fix, which is where all three runs found the signal. Note the
  cost: SKILL.md Step 4's no-exploitable-path exit is then exercised by nothing, and the five
  Juliet false-positive cases already in the corpus are the only coverage it has. Both arms
  handled all five correctly in runs 2 and 3, so it is untested rather than unmeasured - but a
  future change to that branch would not be caught.
- **Labels are an authoring claim.** Benchmark and Juliet ship external ground truth; these do not.
  A judge disagreeing with `kind` on one of these is a finding about the case.
- **Nothing is compiled or executed.** `must_preserve` is checked by reading, so a fix that fails
  to compile would be scored on its intent.

### CWE-502 review findings

Four corrections, each traced to a vendor source rather than recall:

- `java` - XStream's operative floor is **1.4.21**, not 1.4.18. 1.4.18 is where the allowlist became
  the default; 1.4.21 (2024-11-07) fixes CVE-2024-47072, a stack-overflow DoS reachable through
  `BinaryStreamDriver`. The entry gave the first fix rather than the floor.
- `csharp` - `BinaryFormatter`'s lifecycle was missing. Obsolete from .NET 5; from .NET 9 the in-box
  implementation throws on use and the switches that previously re-enabled it are removed. On .NET
  9+ the finding is a runtime failure, not a live vulnerability, and re-enabling is not an option to
  offer.
- `python` - PyYAML deprecated the Loader-less `yaml.load` in 5.1 (warns) and made `Loader` required
  in 6.0, so a bare `yaml.load(data)` raises `TypeError` there. Same live-versus-stale distinction
  the go entry already made for `math/rand`.
- `javascript` - **factual error.** `serialize-javascript` was listed as an unsafe deserializer and
  its Taint Sinks line named a `serialize-javascript` "unsafe unserialize". No such function exists;
  it is an output-side serializer whose weakness is injection into the output it writes
  (CVE-2019-16769, CVE-2020-7660). Naming an API that does not exist sends a remediation somewhere
  there is nothing to fix. Replaced with `funcster.deepDeserialize()`, which is a real sink.

The `go` and `php` entries needed no changes; both already carried the version-sensitive detail
(`gopkg.in/yaml.v3` constructing no arbitrary types, and phar deserialization narrowing at PHP 8.0).


### CWE-918 review finding

`cwe/918/python` was thinner than its siblings and recommended a check with a correctness history
the entry did not carry. `ipaddress`'s `is_private`/`is_global` disagreed with the IANA
special-purpose registries on several IPv4 and IPv6 ranges until CPython 3.12.4 (CVE-2024-4032,
backported to the 3.8-3.11 branches), so the recommended classification silently misclassifies
ranges on an unpatched interpreter. Also added the IPv6-spelling-of-IPv4 case the `java` and
`javascript` entries already carried - `ipaddress` normalizes the mapped form via `ipv4_mapped`,
but the compatible form `::7f00:1` is a separate case a mapped-only check misses.

Checked and correct: `918/csharp`'s `IsIPv6UniqueLocal` (.NET 6+) claim, verified against the API
reference, which lists net-6.0 through net-11.0.


### CWE-798 review finding

Every language entry opened with four or five bullets restating that secrets should not be
committed, should come from environment variables or a manager, should be rotated, and should be
least-privileged. That is what CLAUDE.md's quality bar rules out and what runs 1-4 showed
empirically: restating the primary defence bought nothing, while naming a concrete trap prevented
harm. Condensed to one line each in `csharp`, `java`, `javascript`, `php` and `python`, keeping the
language-specific bullets that follow. `go` was left alone - its opening bullets already name the
`.go` declaration forms, an SDK path, a fail-fast startup check and the "`go vet` does not do this"
point.

The root gained two things it lacked: that a hard-coded signing or encryption key makes every token
or record produced with it forgeable, so rotation invalidates all of them at once and the fix has to
say what breaks and whether a dual-key window is needed; and that entropy-based scanning finds long
random strings while missing default passwords, dictionary-word HMAC keys and account numbers used
as API keys.

### Authored this pass (ranks 21, 23, 24)

Six new entries, all built around what a model does not reliably carry rather than around the
primary defence:

- **`cwe/190/csharp`** - C# integral arithmetic is unchecked by default, so the reported overflow
  wraps silently unless `checked` or `<CheckForOverflowUnderflow>` says otherwise. The trap worth
  writing down is that `checked` applies only to what is *textually* inside it: a method called from
  inside a `checked` block does not inherit the context, so a guard placed around the call site does
  nothing. Also that constant expressions are checked by default, so a literal calculation compiling
  proves nothing about the runtime path beside it, and that `decimal` throws in both contexts.
- **`cwe/190/go`** - no checked arithmetic at all, wraparound is defined rather than trapping, and
  `int` is platform-width, so the same expression overflows on a 32-bit target and not on amd64. Use
  `math.MaxInt` (Go 1.17+) rather than a literal bound, and treat unsigned subtraction on a length as
  the dangerous case, since the result cannot be negative to test for.
- **`cwe/476/c`** - the ordering rule: a null check placed *after* the first dereference can be
  deleted as dead code, because the dereference already licensed the assumption that the pointer is
  non-null (CVE-2009-1897 is the canonical instance). Also that `assert` disappears under `NDEBUG`,
  and that `realloc` returning null leaves the original block valid.
- **`cwe/476/cpp`** - defers to `c/` for the shared undefined-behaviour cases and covers what C++
  adds: express absence in the type, `operator*` on an empty `std::optional` is undefined the same
  way a null dereference is while `.value()` throws, `dynamic_cast` reports failure differently for
  pointers and references, and `map::operator[]` inserts rather than reporting absence.
- **`cwe/476/java`** - the Java-specific cases are the ones with no visible dereference: unboxing a
  null wrapper in arithmetic, and the conditional operator unboxing *both* branches when their types
  differ, so `flag ? 0 : nullInteger` throws even when the null branch is not taken. Java 14+ helpful
  NPE messages name the exact subexpression, which is the fastest route to the producer.
- **`cwe/400`** - the one Top 25 entry with no directory. Written around the property that makes it
  different from an injection class: every request is individually legitimate, so the fix is a bound
  at the point of acquisition rather than validation. Routes to CWE-1333 for regex backtracking and
  CWE-674 for recursion where the finding names a mechanism.

**TODO section 1 is complete.** All eleven of MITRE Top 25 ranks 15-25 are now reviewed or authored.

### Verification pass over this session's authored entries - started

The entries written this session are sold on being traced to a vendor rather than recalled, but the
tracing stopped where the authoring began: the `docs/` pitfalls behind them went through actor/critic
across two model families, and the transcriptions and surrounding claims did not. Since the product
is a *nudge*, a wrong entry costs more than a missing one - the eval runs measured a guided arm
scoring below the unguided control on `no_harm` twice - so verifying what is written beats writing
more.

First batch: eight claims checked against vendor sources, chosen by harm potential (would this change
what a developer types?).

**Confirmed correct - 4:**

- XPath 1.0 literals have no escape sequence. The W3C grammar is `'"' [^"]* '"' | "'" [^']* "'"`, so
  the delimiter is excluded with no escape defined. The whole CWE-643 family rests on this.
- Node's `crypto.pbkdf2` default digest was SHA-1, runtime-deprecated in v6 and end-of-life in v8
  (`undefined`) and v14 (`null`) as DEP0009.
- `gorilla/securecookie` with a nil `blockKey` authenticates but does not encrypt, so the value is
  readable by the client.
- Spring MVC `@SessionAttributes` does promote a data-bound `@ModelAttribute` into the session, so
  request data reaches the trusted store with no `setAttribute` in the source.

**Corrected - 4:**

- `cwe/476/java` ternary unboxing: **the mechanism was wrong.** The entry said the conditional
  operator unboxes both branches so `flag ? 0 : nullInteger` throws even when the null branch is not
  taken. The unchosen operand is not evaluated. The real trap is that binary numeric promotion makes
  the whole expression primitive-typed, so the *selected* branch is unboxed even when the assignment
  target is `Integer`.
- `cwe/476/java` JEP 358: claimed helpful NPE messages from Java 14. JDK 14 shipped the feature **off
  by default** behind `-XX:+ShowCodeDetailsInExceptionMessages`; it became the default in JDK 15.
- `cwe/328/java` `MessageDigest`: asserted "instances are not thread-safe" as documented fact. The
  Javadoc states no thread-safety guarantee either way. Restated on the documented basis - mutable
  state between `update()` and `digest()`, no guarantee given, so concurrent use is undefined.
- `cwe/328/javascript` `timingSafeEqual`: asserted it throws a `RangeError`. That it throws rather
  than returning false is confirmed; the error class is not documented in what could be retrieved, so
  it now names `ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH` instead.

**Four wrong out of eight.** That rate is the finding, not the individual fixes: claims written from
recall in entries whose value proposition is that they are not written from recall. It argues for
finishing this pass before authoring anything further.

Second batch - the nine claim groups above, all now checked.

**Confirmed correct - 8:**

- CVE-2009-1897 is exactly as described: `tun_chr_poll` in `drivers/net/tun.c` assigned `sk = tun->sk`
  before the null test, gcc deleted the test as provably true, and the kernel's response was to build
  with `-fno-delete-null-pointer-checks`. Both the citation and the compiler-deletion mechanism hold
- `std::optional::operator*` is undefined on an empty optional and does not check; `.value()` throws
  `std::bad_optional_access`
- `crypto.Hash.New()` - "New panics if the hash function is not linked into the binary", verbatim
- PHP `crypt()`'s DES form "only uses the first eight characters", verbatim from the manual
- `PASSWORD_DEFAULT` is documented as designed to change over time, and `PASSWORD_BCRYPT` truncates at
  72 bytes rather than characters
- `session.use_strict_mode` is still off by default - the RFC to change it is Inactive and was never
  implemented, so the claim has not quietly dated
- `DelegatingPasswordEncoder` prefixes with the encoder id, and `upgradeEncoding()` returns true when
  the stored id differs from `idForEncode`
- `bcrypt.DefaultCost` is 10; `hash('xxh3', ...)` arrived in PHP 8.1

**Corrected - 4:**

- `cwe/328/go` **missing version floor on the entry's whole reason for existing.** The Go-specific
  hook is that bcrypt rejects rather than truncates - but `ErrPasswordTooLong` landed 2022-12-21 and
  first shipped in `x/crypto` v0.5.0. On v0.4.0 and earlier it truncates silently like everyone else,
  so a reader on a pinned older version writes handling for an error that never arrives and keeps the
  truncation they were told they did not have. Floor now stated
- `cwe/643/java` **wrong mechanism, and the wrong one is load-bearing.** The entry said to install the
  resolver "before `compile()` or `evaluate()`". The Javadoc: `compile()` uses the resolver *in effect
  at compile time*. A compiled `XPathExpression` captures it, so the `or evaluate()` reading - compile
  once at startup, install a per-request resolver before evaluating - never resolves the variable
- `cwe/501/csharp` **"readable by the user" was false.** `CookieTempDataProvider` encrypts with
  `IDataProtector`. It is also the framework default outright, not "the default in many templates" as
  written, so the hedge pointed a reader away from checking. Restated on the real reason to keep trust
  decisions out of it: a 4096-byte chunked cookie whose lifetime belongs to the client
- `cwe/501/php` **wrong attribution.** The entry blamed the `APP_KEY` rotation logout on the `cookie`
  session driver. Laravel encrypts the session cookie on *every* driver, so rotation logs everyone out
  regardless - and `APP_PREVIOUS_KEYS` avoids it, which the entry presented as unavoidable. Added
  GHSA-qm5c-m76r-2hfr while there, since it is specifically about the driver the bullet covers

Also tightened `cwe/190/go`, where a trailing "(Go 1.17+)" sat after a list including `math.MaxInt32`,
which predates it by years.

**Pass totals: 17 claims checked, 8 wrong.** The second batch's errors differ in kind from the first.
Batch 1 was recall producing false statements. Batch 2 is mostly true statements that fail anyway -
a correct behaviour with no version floor, a correct instruction with the wrong mechanism behind it,
a correct concern resting on a false premise. Those survive a reread by their author, because the
sentence is not wrong; only tracing each claim to the vendor separately surfaces them.

The nine recorded groups are now closed. What this pass did not cover: the ~160 entries below rank 25
that were never prose-reviewed, and the pre-existing entries this session only modified rather than
authored.

### Sampling the entries nobody reviewed - the error rate is repo-wide

The verification pass only ever looked at entries this session authored, which is the worst-case
population: written fast, under a push to cover the Top 25. So the 47% figure could plausibly have
been an artefact of that. It is not.

Method: 475 entries have neither been authored nor modified this session. Drew a seeded random 12
(`random.seed(20260829)`), took the 8 with language-specific content, and gave each to a subagent
briefed to return **evidence only** - the claim quoted verbatim, the vendor sentence quoted verbatim
with URL, when the behaviour was introduced, and explicitly what the vendor does *not* say. No
verdicts: the batch-2 lesson is that "is this true?" returns "yes" for a claim that is true and still
broken, so the judging stayed here. The highest-harm findings were then re-verified directly before
any edit.

**Seven of the eight entries carried at least one real defect.** The defects, by entry:

- `cwe/114/csharp` - "Sign assemblies and enable strong name verification" is inert. Microsoft's own
  page carries a Warning, "Do not rely on strong names for security. They provide a unique identity
  only", and states that on .NET Core and .NET 5+ "The runtime never validates the strong-name
  signature". A remediation step whose control does not run. Also: `ArgumentList` has no version floor
  stated and does not exist on any .NET Framework; `AppDomain.CreateDomain` was called non-existent on
  Core when it compiles and throws `PlatformNotSupportedException`
- `cwe/331/java` - `setSeed()` described as reducing entropy. The Javadoc says the opposite: "The seed
  supplements, rather than replaces, the existing seed. Thus, repeated calls are guaranteed never to
  reduce randomness." The real documented trap, which the entry missed, is that a PRNG `SecureRandom`
  will not self-seed if `setSeed` is called before any `nextBytes`. Also named the wrong default
  algorithm and gave `"DRBG"` with no JDK 9 floor
- `cwe/125/cpp` - `.subspan()` offered as the bounds-checked alternative to `span[i]`. The standard
  states its offset and count as *preconditions* with no throws clause, so it is exactly as unchecked.
  Also `_LIBCPP_HARDENING_MODE` with no libc++ 18 floor, where the older spelling is silently inert
- `cwe/601/go` - the entry says to reject a target containing a backslash and to verify via `url.Parse`
  that `Scheme` and `Host` are empty. Go does not treat `\` as a separator, so `/\evil.com` passes
  the entry's own check. The recommended test does not catch the case the same bullet says to reject
- `cwe/863/python` - object-level permissions are not applied on create, because `get_object()` is
  never called. An authorization entry whose remediation leaves POST unguarded
- `cwe/79/php` - no version floor on `htmlspecialchars` flags. Before PHP 8.1 the default was
  `ENT_COMPAT`, which leaves the single quote unescaped
- `cwe/134/php` - `%2000000000s` used as the example of the width that throws. It is below `INT_MAX`,
  so it does not; the `ValueError` boundary is above it

The eighth, `cwe/676`, is a root file: no APIs, no versions, nothing falsifiable. That is the one
structural comfort here - root files are low-risk by construction, and the exposure is concentrated in
language files, which is also where the value is.

**Conclusion: the rate is not an artefact of fast authoring.** Entries written slowly, months ago, by
the same process fail at about the same rate. The common thread across both populations is that the
knowledge base was written from model recall about APIs, and recall about API defaults, version floors
and "X does not do Y" is unreliable in a way that is invisible to rereading.

Not yet done: ~467 unreviewed entries remain. At this hit rate a full sweep is the only way to trust
the corpus, and it is a large job - roughly 60 batches of the shape run here.

### Triage sweep - in progress

Scope chosen after the sampling result: language files only, ordered by how often a SAST tool
actually reports the CWE. Root files are excluded because `cwe/676` showed they carry almost nothing
falsifiable - no APIs, no versions - so the exposure sits in language files, which is also where the
value is. 287 untouched language files across 79 CWEs.

**Method per batch** (repeatable from a cold start):

1. One subagent per entry, briefed to return **evidence only** - claim quoted verbatim, vendor
   sentence quoted verbatim with URL, when the behaviour was introduced and in which release, what
   the vendor does *not* say, and whether a stated mechanism is vendor-supported or only its outcome.
2. No verdicts from the agent. "Is this true?" answers yes for a claim that is true and still broken,
   which is the dominant failure mode - so the judging stays with the main model.
3. Re-verify directly any finding that will reverse a claim or delete a recommendation.
4. Patch, `python scripts/lint.py`, commit per batch.

Give each brief the language's own vendor sources and, where known, the specific trap to check. That
targeting is what surfaced the `IsPrivate` and `mysql2` defects; a generic brief would not have.

**Batches done:**

- Batch 1 - CWE-89 and CWE-78, six languages each (12 entries). All 12 defective.
- Batch 2 - CWE-611 and CWE-918 (11 entries). All 11 defective.
- Batch 3 - CWE-22 and CWE-94 (10 entries). All 10 defective.
- Batch 4 - CWE-79, CWE-943, CWE-502, CWE-90 (10 entries). All 10 defective.
- Batch 5 - CWE-77, CWE-91, CWE-95 (11 entries). All 11 defective.
- Batch 6 - CWE-41, CWE-88 (9 entries, plus the CWE-88 root). All 9 defective.
- Batch 7 - CWE-93, CWE-113 (9 entries, plus the CWE-113 root). All 9 defective.
- Batch 8 - CWE-80 (6 entries). All 6 defective.
- Batch 9 - CWE-862, CWE-863 (12 entries, plus both roots). All 12 defective.
- Batch 10 - CWE-287 (6 entries). All 6 defective. Evidence re-gathered from scratch and applied.
- Batch 11 - CWE-306 (6 entries). All 6 defective. Started cold, as the lost batch-10 evidence required.
- Batch 12 - CWE-798 (6 entries) and CWE-522 (5 entries), plus both roots. All 11 defective.
- Batch 13 - CWE-285 and CWE-566 (8 entries, plus both roots). All 8 defective. Completes the authn/authz group.
- Batch 14 - CWE-326 (5 entries) and CWE-330 (6 entries), plus both roots. All 11 defective. Opens the crypto and randomness group.
- Batch 15 - CWE-331 (5 entries) and CWE-338 (6 entries), plus the CWE-331 root (5515d7f). All 11 defective. Most consequential: `cwe/331/java` and `cwe/338/java` both recommended `SecureRandom.getInstanceStrong()` for startup-time key/token generation, which JDK-8240296 already showed hangs when combined with `nextInt()` - this batch found two further production hangs (Apache RANGER-2700, OrientDB #9603) from `nextBytes()` alone, no `nextInt()` involved. The `cwe/331/INDEX.md` root carried the same "use the platform's blocking or entropy-aware source" instinct batch 14 already found wrong for CWE-330, into a second CWE untouched.
- Batch 16a - CWE-347 (6 entries) and CWE-295 (5 entries). **10 of 11 defective; `cwe/347/csharp` was clean** - the first language entry in sixteen batches with no defect found, breaking the streak the running count below used to justify treating every unreviewed entry as suspect by default. Most consequential: `cwe/347/javascript` had the crux of its own LLM Guidance backwards - it named 4.2.2 (CVE-2015-9235) as the version where `jsonwebtoken` started auto-inferring `algorithms` from key type, but that fix only added an opt-in option; the auto-inference is GHSA-hjrf-2m68-5959, fixed in 9.0.0, so the entry's own worked example understated which versions are still exploitable by omission alone. `cwe/347/java`'s jjwt `verifyWith()` guidance pinned the key but not the algorithm, reproducing the exact `docs/CWE-347/java` "RS512 verifies against an RS256-only handler" gap this repo's own parent corpus had already closed. `cwe/347/php` recommended "upgrade to v6+" as if it were a dependency bump; the pre-6.0 three-argument `decode()` call is a compile-time-silent, run-time `Error` on 6.0+ because the third parameter was repurposed to an output reference - an "edit that breaks the application" in CLAUDE.md's terms, not a no-op. `cwe/295/javascript` carried an HSTS remediation step that has no relationship to certificate validation (RFC 6797 governs browser upgrade behavior, not server-cert trust) and named no HTTP-client-specific sinks beyond the raw `https` module. `cwe/295/go` conflated "a weak `VerifyPeerCertificate` callback" with "validation is disabled," when Go only skips its own verification when `InsecureSkipVerify` is also set. `cwe/295/python` had the `server_hostname`/`check_hostname` failure direction backwards - omitting `server_hostname` with `check_hostname=True` raises `ValueError` (fails closed), while the true quiet bypass is `check_hostname=False` regardless of `server_hostname`. Also found and fixed one defect in `cwe/295/INDEX.md` (root): `PYTHONHTTPSVERIFY=0` was listed as a live bypass, but it is a Python-2.7-only relic (PEP 493) with no effect on Python 3's `ssl` module. One `docs/` defect filed (`DOCS_UPDATE.md` #13): `docs/CWE-295/csharp` claims `ServicePointManager` is inert against `HttpClient` "confirmed on .NET 10," contradicted by Microsoft's own page stating the .NET 9 remap onto `SocketsHttpHandler.SslOptions`.

- Batch 16b - CWE-780 (5 entries) and CWE-316 (4 entries), plus the CWE-780 root. All 10 defective. **Completes the crypto and randomness group** (326, 330, 331, 338, 347, 295, 780, 316). Two shapes recurred from earlier batches rather than new ones: a version floor absent everywhere (root and all five CWE-780 language files said "minimum 2048-bit RSA" with no date - `docs/` reconciliation supplied NIST SP 800-57 Part 1's 2030 cutoff for 2048-bit/112-bit strength, fixed uniformly), and the framework's-own-recommended-API-as-taint-sink pattern (`cwe/780/go` listed `rsa.SignPKCS1v15`/`VerifyPKCS1v15` as sinks, but CWE-780 is encryption-specific by MITRE's own definition and Go does not deprecate PKCS1v15 *signing* - it is the undeprecated, standard scheme most X.509/TLS uses). New shape: `cwe/780/javascript` had the "state the default" defect backwards from usual - it told the model to add `RSA_PKCS1_OAEP_PADDING` as if fixing an insecure default, when Node's `publicEncrypt`/`privateDecrypt` already default to it; the live default worth fixing is the OAEP hash (`oaepHash` defaults to `'sha1'`). `cwe/316/javascript` asserted "JavaScript strings are immutable in V8, making them persist in memory" with no supporting V8 documentation found, and separately claimed `libsodium-wrappers` provides "automatic memory protection" when it requires an explicit `sodium.memzero()` call and its WASM sandbox has no OS-level `mlock` access. `cwe/316/java` softened a real fact into a hedge - `BCryptPasswordEncoder.matches()` calls `.toString()` on its `CharSequence` argument internally (confirmed from Spring Security's own source), so the entry's "does not guarantee no copy" should have been "does copy." One `docs/` defect filed (`DOCS_UPDATE.md` #14): `docs/CWE-316/csharp` prescribes `Array.Clear()` throughout - including a "why this works" bullet crediting it - where Microsoft documents `CryptographicOperations.ZeroMemory()` as the one built specifically to resist dead-store elimination.

**Running count: 176 of 287 language files reviewed, 176 carried at least one defect.**

The rate held at 100% for fifteen batches (the whole injection family, the authz pair, CWE-287,
CWE-306, the credential pair, CWE-285/CWE-566, and the first two CWEs of the crypto group), broke
once at batch 16a's `cwe/347/csharp`, then returned to 100% for batch 16b. Treat every unreviewed
language entry as suspect by default, but "every entry in a swept family is defective" is no
longer a safe assumption to state as fact - one clean entry in twenty is enough to disprove it as
a certainty, even though it remains the way to bet.

**The `Safe Pattern` retirement is finished.** Six root files still routed the model to a section
retired across all 307 language files; five were fixed in 2dc5a63 and `cwe/330`'s went with its
rewrite. A grep for `Safe Pattern` across `cwe/` now returns nothing.

**Batch 10 was re-run rather than trusted.** Its first pass gathered evidence for CWE-287 and
CWE-306 but committed none of it, leaving the findings only in a session transcript that was gone by
the next session - so this file's own instruction applied and the batch was re-gathered from a cold
start. CWE-287 was re-run as batch 10 and CWE-306 followed as batch 11. The re-run reproduced
every defect the summary described and added several the summary did not carry, which is the
argument for the rule: a summary of evidence is not evidence. **Commit each batch's patches with the
batch.**

**Two roots turned out to be in scope after all.** The sweep excluded root files on the strength of
`cwe/676` carrying nothing falsifiable. That does not generalise: `cwe/88/INDEX.md` and
`cwe/113/INDEX.md` both named specific third-party options and per-platform behaviours, and both
were wrong - CWE-113's root claimed PHP "drops the header entirely" (true mid-string, but a value
whose only newline trails is silently trimmed and sent) and that Tomcat and Jetty replace CR and LF
(they replace every control character except TAB). Check a root for named APIs before skipping it;
skip it only when it is genuinely vendor-neutral prose.

**The durable half of this list now lives in `CLAUDE.md`**, under `Remediation Claims`, so an
authoring or editing session inherits it without reading this file. What stays here is the
sweep's live state: the instance counts, the per-batch evidence, and the shapes still too thinly
evidenced to promote. When one recurs across batches, move it up rather than lengthening the list
below.

**Recurring defect shapes**, worth briefing future batches on explicitly:

- *A helper offered as the safe one that the vendor says is not.* Go's `net.IP.IsPrivate` carries
  "should not be used for access control" in its own doc and misses `169.254.169.254`; `span.subspan`
  states bounds as preconditions, not checks; .NET strong-name verification is documented as not a
  security control.
- *Defaults never stated, where the default is the whole point.* `AllowAutoRedirect` is true;
  `fetch` follows redirects; `CURLOPT_FOLLOWLOCATION` is already off; `mysql2`'s `?` binds under
  `execute()` and escapes under `query()`.
- *Version floors absent, or naming a superseded fix.* CWE-78/javascript cited Node's incomplete fix
  and named exploitable versions as safe.
- *Guidance that has dated.* CWE-611/python described an XXE that CPython closed in 3.6.8/3.7.1 and
  prescribed a dependency last released in 2021 - a false-positive generator.
- *The case the fix does not cover.* Identifiers in every CWE-89 entry; create in CWE-863/python.
- *A right conclusion resting on wrong reasons.* All four CWE-88 entries argued for a
  first-character allowlist because a denylist "misses `--`, unicode dashes, and leading
  whitespace". `--` does begin with a dash; getopt treats only ASCII 0x2D as an option introducer.
  The advice was right and every stated reason was wrong, so a reread by its author would pass it.
- *A prescribed test that passes against the unfixed code.* CWE-93/javascript told the model to
  confirm no extra header appeared - which it does not, because Nodemailer replaces the CRLF with a
  space; meanwhile the envelope has been rewritten to the attacker alone. CWE-80/javascript tested
  with `<script>`, which `innerHTML` never executes. Check what the payload actually proves.
- *A sanitizer that strips rather than rejects, changing the value into a different valid one.*
  Nodemailer's CRLF-to-space turns an injected recipient into RFC 5322 group syntax. This is the
  concrete form of the root files' "reject rather than strip" principle.
- *A named library that has stopped.* `bleach` ended maintenance in June 2026 with an open advisory
  that can never be fixed. "Use a sanitization library" needs the library checked, not just named.
- *An offered fix that breaks the application.* Worse than a no-op and new in batch 12. `cwe/522/php`
  said to add `Deny from all` to `.htaccess` for `.env`. That is Apache 2.2 syntax, provided in 2.4
  only by `mod_access_compat` (Status: Deprecated, and documented as taking precedence over the
  modern directives when mixed), and `Deny` has no filename scoping of its own - written bare in an
  `.htaccess` it denies the whole directory. Ask not only whether the prescribed edit works, but what
  it does when applied literally to a real tree.
- *A shared constant whose handling differs per ecosystem.* bcrypt's 72-byte ceiling is one fact with
  five behaviours: PHP truncates silently and documents it; Spring throws on encode and skips the
  check on match; Python's `bcrypt` 5.0 turned truncation into a `ValueError`; `bcryptjs` does not
  check but ships `truncates()`; `BCrypt.Net-Next` neither enforces nor documents it. A single
  sentence written once and copied across a family will be wrong in most of them.
- *An offered fix that is a no-op.* CWE-287/go told the model to take the session with
  `gorilla/sessions` `store.New` rather than `store.Get` so a planted cookie is "discarded instead of
  promoted". `New` decodes the request cookie and sets `IsNew = false` exactly as `Get` does; the doc
  comment gives the only difference as decoding twice versus reusing the decoded session. The
  remediation would be applied, reviewed, and change nothing. Distinct from a stale claim - this one
  was never true - and from a wrong reason, because here the reason is the mechanism.
- *Two recommendations that are each correct and jointly fatal.* New in batch 14 and not yet seen
  twice, so it stays here rather than moving to CLAUDE.md. `cwe/330/java` prescribed
  `SecureRandom.getInstanceStrong()` and `secureRandom.nextInt(bound)` in separate bullets; the
  first resolves to a `/dev/random` reader on Linux and the second inherits an unbounded rejection
  loop, so together they hang. Ask what an entry's recommendations do when applied at once.
- *Advice a major library adopted and then reverted.* Also new in batch 14. `commons-lang3` 3.15.0
  moved `RandomStringUtils` onto `getInstanceStrong()`, LANG-1748 reported the resulting production
  timeouts, and 3.17.0 backed it out. Searching an ecosystem's issue tracker for the approach an
  entry recommends is cheap and finds what API documentation cannot.

### Batch 14 - what it changed about the method

**A new shape, and the most expensive one found so far: two bullets that are each defensible and
combine into a failure.** Batch 13 named the seam between two bullets of one file as a
*contradiction* - each bullet wrong about the other. This is different and harder to see, because
neither bullet is wrong. `cwe/330/java` said to use `SecureRandom.getInstanceStrong()` for key
generation, and to use `secureRandom.nextInt(bound)` for OTP ranges. Separately both are ordinary
advice. Together they are JDK-8240296 verbatim: `getInstanceStrong()` resolves through
`securerandom.strongAlgorithms` to `NativePRNGBlocking`, whose `nextBytes()` reads `/dev/random` on
every call; `nextInt(int)` is not overridden by `SecureRandom` but inherited from
`java.util.Random`, whose rejection loop is documented as unbounded in iterations; so each retry is
another blocking read and the program hangs. Reading each bullet against the vendor passes both.
The check that finds it is to ask what the entry's own recommendations do *when applied together*.

**A second new shape, and the cheapest check in the sweep: has the ecosystem already run this
experiment?** The same CWE-330 advice was adopted by Apache Commons Lang in `commons-lang3` 3.15.0,
reported as a production outage in LANG-1748, and reverted in 3.17.0. A major library adopting a
prescribed approach and backing it out is the strongest possible evidence against it, it is
recorded in public issue trackers, and no amount of reading the API documentation surfaces it.
Worth adding to any brief where the entry recommends one API over another on non-obvious grounds.

**The "prescribed test that passes against unfixed code" shape is now the batch's most common
finding, at four instances in eleven entries** - `cwe/326/go` (identical plaintext blocks yield
different ciphertext for RC4, DES-CBC and static-IV CBC, so the ECB test clears three of the four
sinks the same entry names), `cwe/330/INDEX.md` and `cwe/330/java` and `cwe/330/python` (all
variations on "verify the values are not sequential", which Mersenne Twister and a randomly seeded
`java.util.Random` both pass). It is promoted in CLAUDE.md already; what batch 14 adds is that in
a randomness CWE it is close to universal, because *every* weak generator produces output that
looks random. Assume the test bullet is wrong in CWEs 331, 338 and 347 rather than checking whether
it is.

**Two corrections ran the other way, and both were "right conclusion, wrong reason".** `cwe/330/csharp`
said `Guid.NewGuid()` "is not a cryptographically secure random source"; Microsoft documents the
opposite - `CoCreateGuid` on Windows, the OS CSPRNG elsewhere since .NET 6 - and grounds its own
recommendation on the 122-bit ceiling and the fixed version/variant bits instead. `cwe/330/php`
called `uniqid()` a predictable PRNG when it invokes no PRNG at all, its default form being
`sprintf("%08x%05x", sec, usec)`. In both cases the advice to stop using the API survives and every
stated reason had to be replaced - and in the csharp case the correct reasoning exposed a real
version floor (before .NET 6, non-Windows GUID entropy was *not* guaranteed cryptographic) that the
wrong reasoning had hidden.

**Word budget: the constraint bound again, and step 5 is what pushed it over.** The CWE-326 root
finished at 608 words against a ~500 guideline and `cwe/330/INDEX.md` at 573, both because
essentially every sentence is a traced correction and the alternative was dropping one. `cwe/330/java`
reached 906 after reconciliation and had to be trimmed twice to 831. That is batch 12's rule
confirmed for a third time: measure after step 5, not after the vendor pass. Note the linter warns
at 650/950 rather than at the 500/800 guideline, so a file can pass lint and still be over.

**The docs/ yield was high in this family and worth budgeting for in 331 and 338.** Every
`docs/CWE-330/*` page carries both a shared `Considerations` block and a `Common Pitfalls` section,
and the reconciliation produced findings in six of the seven entries - including the one thing six
vendor agents missed on CWE-326, that no entry said data already encrypted under the old algorithm
has to keep decrypting. It also supplied a qualification that *corrected* the vendor evidence:
LANG-1748's "drains the systems entropy pool" framing has itself dated, because since Linux 5.6
drawing bytes depletes nothing. Taking the issue tracker at face value would have shipped a stale
mechanism behind a correct conclusion.

### Batch 10's defect families - the entry frozen at a prior release

CWE-287 and CWE-306 were the strongest entries the sweep has read: several traps came back clean and
306/csharp had six of eight confirmed outright. They still hit 12 of 12, but the defects were almost
all *time* rather than error. **Both halves have since been re-verified against source and applied - CWE-287 in batch 10, CWE-306
in batch 11 - so the examples below are now evidence-backed rather than recalled. Batch 11 confirmed
every CWE-306 example this summary carried.** Three sub-shapes, worth briefing every future batch on:

- **The library absorbed the fix.** `gorilla/sessions` `store.New` (which does not discard a planted
  cookie - `CookieStore.New` decodes it and sets `IsNew = false`); Laravel's `Timebox`, which pads
  every failed `Auth::attempt()` to 200 ms so the timing channel the entry describes is already
  closed; Passport 0.6.0, whose `req.login()` regenerates the session internally, making the entry's
  hand-rolled wrapper a double regeneration.
- **The API moved.** Swashbuckle's `UseSwagger()` dropped from the .NET 9 template in favour of
  `MapOpenApi()`; Laravel 11's skeleton; `middleware.ts` renamed `proxy` in Next.js 16.
- **A behaviour flipped under a correct sentence.** Spring Security 6.0 changed an unmatched
  `authorizeHttpRequests` rule from abstain to `DENY`, so "a request matching no rule is public" was
  true when written and is now false. Spring Boot 3.5 made `heapdump` restricted by default, so
  `include=*` no longer publishes it. Werkzeug 3.0 changed `generate_password_hash` to scrypt,
  creating by default the hash mismatch that entry warns about. This one is the hardest to catch:
  the advice stays right while its justification stops being true, so a reread passes it.

**A fourth pattern, now at eight instances: the entry lists the vendor's own recommended API as a
taint sink.** `user.IsInRole()` (in Microsoft's own handler sample), `@login_not_required` (required
by Django on the login view), `__return_true` (what WordPress core's `_doing_it_wrong` string tells
you to use for public routes), `PASSWORD_HASHERS` "strongest first" (which would flag Django's
shipped default), and `@PreAuthorize` on a Jersey resource. Batch 11 added three more, all in
CWE-306: php naming "`permission_callback` returning true" where core's own notice names
`__return_true` as the fix for a public route, python listing `@login_not_required` a second time,
and java's `@PermitAll` at class level. All eight point the model at correct code.

**The fix for this shape is not always deletion.** Two of batch 11's three were kept in Taint Sinks
with a guard, because grepping for them is how the exceptions get audited - what changed is the
entry now says what the finding is *not*. Only php's was rewritten outright, to the absent
`permission_callback` that is the real defect. Decide per entry whether the name is a bad search
target or a good one described wrongly.

**That briefing note is spent, and was slightly overstated.** `docs/CWE-566/java` does carry the
`@PostAuthorize` transaction-rollback condition that three sibling pages lack, and it was worth
reading before the authz write-ups. But "completely" was wrong: a grep of that file for
`EnableTransactionManagement` returns nothing, so it has the failure condition and neither of the
vendor's two remedies - read first and then write, or order `@EnableTransactionManagement` ahead of
`@EnableMethodSecurity`. `cwe/285/java` now carries both. The same correction applies to the claim
made in `DOCS_UPDATE.md` finding 1.

### The docs/ reconciliation step - now mandatory per batch

After batch 4 the swept CWEs were compared against `docs/`, the human-readable parent corpus this
skill was derived from. That comparison found things four batches of vendor fact-checking had not,
including two corrections that were themselves wrong. It is not optional; run it as step 5 of every
batch.

`docs/` mirrors the tree as `docs/CWE-{ID}/{language}/index.md`, is gitignored (so it is not versioned
here and can change underneath us), and is maintained elsewhere by actor/critic review across two model
families. **Language coverage is not 1:1, and an earlier version of this note said it was.** Checked
across all 333 language directories, 28 have no `docs/` counterpart: all six of `cwe/306` (whose
root `docs/CWE-306/index.md` does exist - the gap is the language tier only, and batch 11 reconciled
the root against it and found nothing in either direction), `cwe/328`
and `cwe/501`; `cwe/476/{c,cpp,java}`; `cwe/643/{csharp,java,python}`; `cwe/190/{csharp,go}`;
`cwe/382/java`; `cwe/926/android`. The rule is not "two exceptions" but "anything authored here has no
parent" - each of those was written in this repository rather than derived from `docs/`, so it has
vendor tracing but never went through the two-model review. Establish coverage before planning a
reconciliation: half of batch 10 had nothing to reconcile against.

**How to read a disagreement.** Neither corpus wins automatically:

- On a *vendor fact* - a version floor, a default, a CVE, an API's documented behaviour - the skill is
  usually ahead, because the sweep traced these to primary sources and `docs/` largely does not carry
  them. `docs/` is sometimes wrong in the false-finding direction - CWE-88's `--` support and
  CWE-113's PHP header behaviour were both wrong this pass, and are recorded with the vendor
  evidence in `DOCS_UPDATE.md`. Two older examples once cited here have since been withdrawn: the
  CWE-943 "never enable" note kept its "derived from user input" qualifier all along, and the
  .NET Framework DTD claim conflated the `XmlResolver` default with DTD parsing and was never
  traced to a primary source.
- On *operational detail* - what a fix fails to cover, what a test actually proves, which precondition
  a defence needs - `docs/` is usually ahead, because compression dropped it. This is where the
  restoration pass in commit d97d283 came from. Confirmed again in the CWE-287 re-run:
  `docs/CWE-287/python:220` states the `PASSWORD_HASHERS` rule correctly - "Django hashes with the
  first entry and can verify against the rest, so a legacy hasher left at the top keeps producing
  weak hashes for every new password" - where this repo had compressed it to "strongest hasher
  first", which would flag Django's shipped default. The right version was in the parent all along.
- A third case the split does not cover: a defect **both** corpora carry, which no comparison can
  find. The CWE-287 re-run produced three (`store.New`, Laravel's Timebox, the Passport wrapper),
  all traced to source. Reconciliation catches divergence; only the vendor pass catches agreement.

**What the reconciliation caught that the vendor pass missed** (all fixed, commit fc9bce0):

- `cwe/22/php` - a *fail-open* claim I introduced was wrong. `str_starts_with` takes the haystack
  first, so a `realpath()` false coerces to `''` as the candidate and the check rejects; under
  `strict_types` it raises. Both fail closed. I had reversed the arguments.
- `cwe/79/java` - `c:out` narrowed to "an HTML-body control"; it escapes both quote characters and so
  covers a quoted attribute too.
- Every CWE-90 file told the model to escape `/` as `\2f` "per RFC 4515". RFC 4515 gives `/` no
  meaning; escaping it corrupts values.
- Every CWE-90 file prescribed `*)(objectClass=*)` as the test payload. Client parsers in JNDI, ldapts,
  ldap3 and .NET reject it before contacting the server, so it raises whether or not the fix works. The
  discriminating payload is a bare `*`.
- Five entries were left arguing with themselves because Key Principles were patched without re-reading
  Remediation Steps in the same file.

**Process rule that follows: after editing a Key Principle, read the whole file before committing.**
A per-bullet patch is how a corpus starts contradicting itself, and lint cannot see it.

### Where to pick up

Batches 1-4 are done and committed (bc14c8d, f4e270a, 39d0b0f, 4118475), then reconciliation
(fc9bce0) and restoration (d97d283). Batches 5-8 completed the injection family (705c76a, 19089d8,
f4cfab2, 4ed535e); batch 9 did CWE-862/863 and the authn/authz doctrine (7c73974).

**The authn/authz group is complete.** CWE-287, CWE-306, CWE-798, CWE-522, CWE-285 and CWE-566 are
all done and committed (batch 10; batch 11 as 79ee709, cf6140d, 083bb0c; batch 12 as 48e46cc,
bcb5cef, aaae74a, 709109c; batch 13 as c2630cc, 6e69b63).

**Batch 14 opened the crypto and randomness group** with CWE-326 and CWE-330 (a8d4630, dda4f12,
90a32f8, 3dd0dbd). **Batch 15 covered CWE-331 and CWE-338** (5515d7f), swept together with CWE-330
in view as planned. All three of the carried-in obligations resolved:

- `cwe/331/java`'s setSeed() framing already matched the corrected `cwe/330/java` (both state the
  Javadoc's actual hazard: no self-seeding if `setSeed` precedes the first `nextBytes`). `cwe/338/java`
  needed the same correction, since its Remediation Steps still said to remove seeding blanket-wide.
- Only `cwe/331/INDEX.md` carried the "platform's blocking or entropy-aware API" instinct -
  `cwe/338/INDEX.md` did not repeat it, so that obligation was narrower than expected. `cwe/331/INDEX.md`
  is now corrected in both directions batch 14 established: Linux 5.6 removed the reason to reach for
  a blocking variant by default, and `cwe/331/java`/`cwe/338/java` both replaced their
  `getInstanceStrong()`-for-startup advice, backed by two further production hangs found this batch
  (Apache RANGER-2700, OrientDB #9603) beyond JDK-8240296.
- `cwe/331/javascript` and `cwe/338/javascript` were read together with the rewritten
  `cwe/330/javascript`; the async-vs-sync entropy claim in 331 turned out to be a fabricated Node
  documentation citation, and 338 had a separate, unrelated defect (a self-contradicted entropy
  floor - 256 bits asserted twice, then "16 bytes" two bullets later).

**Batch 16a covered CWE-347 and CWE-295** (11 entries; 6c1f1d9, a77b31f, c885971, a745c03). Split
from the originally planned batch 16 by user sizing choice, to match the ~9-12 entry size of every
prior batch rather than running all 20 CWE-347/295/780/316 entries in one pass. See the batch 16a
entry above for findings; no cross-CWE doctrine seam was found between 347 and 295 specifically
(the 330/331/338 seam predicted for the wider group didn't have a 347/295-specific instance).

**Batch 16b covered CWE-780 and CWE-316** (10 entries, plus the CWE-780 root; 255b37b, 1dc23f0,
3d2e9ac), completing the crypto and randomness group. No 780/316-specific doctrine seam materialized
either - the shared surface the original plan predicted (RSA-without-OAEP and cert/signature
validation sharing TLS/crypto-library surface) didn't produce a cross-CWE contradiction the way
330/331/338 did; the recurring shapes instead traced back to the two general defect shapes already
in CLAUDE.md (absent version floor, framework's-own-API-as-taint-sink). See the batch 16b entry
above for the per-file findings.

**The crypto and randomness group is complete**: CWE-326, 330, 331, 338, 347, 295, 780, 316.

**Batch 17 opened the web hygiene group.** 32 language entries across CWE-352, 601, 614, 434, 942,
209, 201 - split into sub-batches at the established ~9-12 entry size rather than run in one pass,
matching the batch 16a/16b precedent.

- Batch 17a - CWE-352 (5 entries) and CWE-601 (6 entries), plus the CWE-601 root. 8 of 11 defective;
  `352/python`, `601/go` and `601/root` were clean - the second and third clean language entries the
  sweep has found, after `347/csharp` in batch 16a. Most consequential: `601/java`'s own prescribed
  check was internally broken, not just imprecise - `isAbsolute()`/`getHost()` bucketed a
  scheme-relative value (`//evil.example`, non-absolute yet has a host) and an opaque URI
  (`javascript:alert(1)`, absolute yet null host) into the wrong branch each, the exact trap
  `docs/CWE-601/java`'s Common Pitfalls had already named from the other direction (dropping half
  the check misclassifies the opaque case as safe) - two independent authoring passes reached the
  same broken two-variable check from different starting bugs. `601/javascript`'s prescribed fix
  didn't work at all: `new URL(target)` throws a `TypeError` on any relative input without a `base`
  argument, which is the common case for a `next=`/`redirect=` parameter - an "edit that breaks the
  application" in CLAUDE.md's terms. `352/csharp` had `AntiforgeryOptions.HeaderName`'s default
  backwards (claimed `null`, confirmed `"RequestVerificationToken"` from the aspnetcore source
  directly, current and back to 2.1) and misattributed the framework's constant-time comparison to
  `CryptographicOperations.FixedTimeEquals` alone when that call only covers the per-user claim
  check. `352/java` misattributed token *generation* to `CsrfFilter`/`SecureRandom` when generation
  is `HttpSessionCsrfTokenRepository.createNewToken()` via `UUID.randomUUID()` - `CsrfFilter` only
  compares - and was missing `SpaCsrfTokenRequestHandler`, needed alongside
  `CookieCsrfTokenRepository.withHttpOnlyFalse()` because the default `XorCsrfTokenRequestAttributeHandler`
  (6.0+) BREACH-encodes the token server-side so it no longer matches the plain cookie value a JS
  client reads. `601/php` prescribed two "correct API, wrong problem" fixes: `parse_url()` for
  allowlist validation, against the PHP manual's own caution naming that exact use case as a source
  of vulnerabilities, and Laravel's `'url'` validation rule, which checks well-formedness and scheme
  only and passes `https://evil.com` as readily as a same-site link. `docs/` reconciliation (step 5)
  added two operational-detail items neither corpus had wrong but only `docs/` had at all: PHP's
  browser-side tab/CR/LF-stripping bypass of a `//`-only check (verified on PHP 8.5.8), and
  JavaScript's warning against building the trusted redirect origin from `req.headers.host` behind a
  proxy. No `DOCS_UPDATE.md` finding filed - the `docs/` entries for both CWEs already carried the
  correct, vetted versions of what this pass fixed rather than sharing the defects.
- Batch 17b - CWE-614 (6 entries, plus root) and CWE-434 (6 entries, plus root). 8 of 14 defective;
  `614/root`, `434/root`, `434/go`, `434/javascript` and `434/python` were clean - the largest clean
  count in one batch so far, and both root files confirmed genuinely vendor-neutral. Most
  consequential: `434/java` had three separate gaps in the same bullet - `MimeTypes.forName()` throws
  a checked `MimeTypeException` the one-line call chain didn't account for, `getExtension()` returns
  an empty string rather than throwing for a type with no known extension (an unguarded caller
  produces a bare-dot filename), and `Files.probeContentType()`'s "reads the file name, not the
  bytes" framing is a JDK 9+ fact, not a constant - JDK 8's Linux default chain included a
  libmagic-backed content detector that JDK-8162624 removed. `614/csharp` had `CookieSecurePolicy.None`
  backwards - it isn't a forced clear, it's a no-op that leaves an already-`Secure` cookie secure,
  confirmed against `ResponseCookiesWrapper.ApplyPolicy` source directly - and was missing that
  `UseCookiePolicy()` must be registered before `UseAuthentication()`/session middleware for the
  global policy to reach those cookies at all. `614/java`'s "the Servlet `Cookie` class has no
  SameSite setter" was true once and dated: Jakarta Servlet 6.0 (2022) added
  `Cookie.setAttribute("SameSite", "Strict")`, and JAX-RS 3.1 added `NewCookie.Builder.sameSite(...)`
  - both landed the same Jakarta EE 10 wave the entry never mentioned. `614/php` line 9 wrote
  `secure: true` (JS-style colon) where PHP's `setcookie()` options array requires `'secure' => true`
  - confirmed against the same file's own line 24, which had it right. `614/python`'s Taint Sinks
  listed `session.cookie_secure` (lowercase-dotted) as a Django setting; no such setting exists -
  the real one, `SESSION_COOKIE_SECURE`, was already listed separately in the same line. `docs/`
  reconciliation independently confirmed every fix rather than surfacing new ones - `docs/CWE-614/java`
  already documents `setAttribute` and `NewCookie.Builder` at the same version floors, `docs/CWE-614/go`
  already states the `SameSite=None` without `Secure` rejection, and `docs/CWE-614/php` already uses
  `'secure' => true` - no `DOCS_UPDATE.md` finding filed.
- Batch 17c - CWE-942 (2 entries, plus root), CWE-209 (4 entries, plus root), CWE-201 (3 entries, plus
  root). 8 of 9 language entries defective; `201/python` and all three roots were clean. Most
  consequential: `209/python` had the FastAPI half of a Flask/FastAPI claim backwards - source-traced
  through `applications.py`/`ExceptionMiddleware` to show FastAPI's default `Exception` handler
  cannot see a routing-raised `HTTPException` at all (opposite of the file's claim that it does),
  though `docs/CWE-209/python` (see below) supplied a real, different FastAPI trap in the same
  area to replace it with - registering the handler on `fastapi.HTTPException` rather than
  `starlette.exceptions.HTTPException` misses routing errors, since the router raises the parent
  class. `942/python` had a "check the library version, older releases default to permissive"
  framing that inverted the actual fact: `flask-cors`'s permissive default is version-independent
  (present in v1.1 and today alike), while `django-cors-headers`/FastAPI's `CORSMiddleware` have
  always defaulted restrictive - no version explains either behavior. `209/java` and `201/java`
  share three defects: both name `server.error.*` properties Spring Boot 4.0 renamed to
  `spring.web.error.*`; both conflate `BasicErrorController` (handles all `/error` responses,
  JSON included) with "the whitelabel page" (a separate HTML-only fallback view gated by its own
  `whitelabel.enabled` property); and both prescribe `include-stacktrace=never`/`include-message=never`
  as if unconfigured, when both have defaulted to `never` since Spring Boot 2.3. `209/java` additionally
  named a `web.xml`/`/WEB-INF/error-pages/` pattern absent from any current Spring Boot doc, replaced
  with the vendor-documented `/error`-resource-directory mechanism. `209/javascript` claimed Winston
  and Pino both serialize an `Error`'s `message`/`stack` by default; only Pino does - Winston requires
  explicitly composing `winston.format.errors({ stack: true })` from the separate `logform` package,
  or `logger.error(err)` logs an empty object. `201/javascript`'s Mongoose `.lean()` bullet conflated
  "returns a plain object" with "returns every field" - `.lean()` only changes the return type, field
  selection is entirely the query's own projection. `docs/` reconciliation (step 5) supplied the
  FastAPI `HTTPException` subclass trap above (measured on FastAPI 0.141.1) and confirmed Actuator's
  `/env`/`/configprops` masking is key-name-pattern-based, not blanket - a credential under an
  unexpected key name is returned in full. No `DOCS_UPDATE.md` finding filed; every divergence found
  ran in this repo's favor or added detail rather than surfacing a `docs/` defect.

**The web hygiene group is complete**: CWE-352, 601, 614, 434, 942, 209, 201 (batches 17a-17c).

**Batch 18 opens the memory/native and resource group**, split by user sizing choice rather than run
as one 36-entry pass: CWE-125, 787, 121, 415, 416, 823, 824 (c/cpp, 14 entries) and CWE-401, 362, 367,
377 (six languages each, 22 entries). Least likely of the remaining groups to be handed to this skill
by a web-application scanner, per the original batch-9 ordering rationale.

- Batch 18a - CWE-125, 787, 121 (c and cpp, 6 entries). 4 of 6 defective; `125/cpp` and `121/cpp` were
  clean. The shared defect: `cwe/125/c` and `cwe/787/c` both said `_FORTIFY_SOURCE=3` needs "Clang
  15+" - every source found (glibc's own `features.h` gate, the OpenSSF hardening guide, MaskRay's
  writeup) says Clang 9+, and `docs/CWE-121/c` independently supplied the glibc floor these files
  omitted entirely (2.35+ with GCC, 2.33+ with Clang), now added to all three. A second instance of
  batch 9's "seam between two entries" shape, this time inside one language pair rather than one CWE
  family: `cwe/787/cpp` recommended libc++'s `EXTENSIVE` hardening mode where `cwe/125/cpp` (reviewed
  in the same batch) already had it right at `FAST`, sourced directly from libc++'s own docs showing
  `valid-element-access` - the check `operator[]` needs - is a `fast`-category check, and `extensive`
  adds nothing for it. `docs/CWE-125/cpp` and `docs/CWE-787/cpp` carry the same `EXTENSIVE` defect
  `cwe/787/cpp` did, filed as `DOCS_UPDATE.md` finding 15. `cwe/121/c`'s `fgets` truncation check
  ("no trailing newline means over-long, reject") had a real false-positive: a line landing exactly
  on the buffer's capacity, with only the terminating newline unread, looks identical to the
  genuinely truncated case. `docs/CWE-121/c` already carries the correct fix - peek the next
  character with `getchar()` and check for `EOF`/`'\n'` rather than checking `feof()` - which this
  repo's file didn't have and now does, found only because the reconciliation step compared the two
  patterns rather than treating "not wrong" as "not improvable." `cwe/121/c` also capped
  `_FORTIFY_SOURCE` at `=2` with a rationale (`_FORTIFY_SOURCE` "only helps where the size is
  statically known") that argues for `=2` being sufficient, not for `=3` being wrong to also use -
  `=3` is a strict superset, so the file's own sibling-inconsistent choice had no technical basis;
  brought in line with `125/c`/`787/c` at `=3` with `=2` as the toolchain-floor fallback.

- Batch 18b - CWE-415, 416, 823, 824 (c and cpp, 8 entries), completing the c/cpp memory-native
  subgroup. Lower defect rate than any prior batch - 2 of 8 clear vendor-fact defects, plus small,
  cheap corrections and several worthwhile `docs/` operational-detail additions across all eight -
  consistent with this being the most standard-precise, lowest-API-surface family swept so far
  (mostly ISO C/C++ clauses and sanitizer flags, not framework defaults). The two defects: a third
  instance of the `EXTENSIVE`-vs-`fast` libc++ hardening mistake found in batch 18a, this time in
  `cwe/823/cpp` (confirmed against the same vendor page, `libcxx.llvm.org/Hardening.html`); and
  `cwe/824/c` recommending `-Wmaybe-uninitialized` with no optimization-level requirement, when
  GCC's own manual states the analysis needs `-O1`+ to report anything - a build following the
  bullet as written gets a clean `-O0` run that proves nothing, the same "prescribed check passes
  against unfixed code" shape CLAUDE.md already tracks. The reconciliation step found something more
  consequential than either: **the root file `cwe/823/INDEX.md` contradicted its own child file.**
  Its Key Principles told the model to "check both the offset and... the resulting pointer value
  against the buffer's valid range" - exactly the anti-pattern `cwe/823/c` and `docs/CWE-823` both
  warn against, since a pointer more than one element past the end is already undefined behaviour by
  the time such a comparison runs and the compiler is entitled to delete it. A root file arguing with
  its own children is the same defect class batch 9 found between sibling *entries*; this is the
  first instance found between a root and its own child rather than between two files at the same
  level - worth watching for in future root-inclusive batches. Also fixed on the strength of the
  reconciliation, all confirmed against a live vendor fetch or the C/C++ standard text directly
  rather than taken from `docs/` alone: `cwe/824/c` and `cwe/824/cpp` gained `-O1`+/`--track-origins`
  testing detail and (c only) the `free(NULL)`-safe/`fclose(NULL)`-unsafe asymmetry in a
  `goto cleanup` epilogue; `cwe/824/cpp` gained the "adding an empty `Header() {}` later silently
  breaks a previously-zeroing `new T()`" trap; `cwe/415/c` gained that nulling-before-free is not a
  concurrency fix and that a genuinely multi-owner structure needs reference counting, not nulling;
  `cwe/415/cpp` gained that a constructor throwing mid-construction leaks (CWE-401) rather than
  double-frees, and that owning members extend past `new`/`delete` to `FILE*`/custom deleters;
  `cwe/823/c` gained a `-O2`-not-`-O0` retest note for the pointer-arithmetic guard itself, the
  `offset == size && length == 0` accept case, and a `_FORTIFY_SOURCE=3` mention it had lacked
  entirely; `cwe/823/cpp` gained the inverse of the `.at()`/`span` mixup (a redundant guard ahead of
  `.at()` is dead code) and why ASan alone often misses a `std::vector` off-by-one where the hardened
  mode catches it (the index still lands inside reserved capacity). No `DOCS_UPDATE.md` findings this
  batch - every divergence ran in this repo's favor or added detail rather than surfacing a `docs/`
  defect.

**The c/cpp memory-native subgroup is complete**: CWE-125, 787, 121, 415, 416, 823, 824.

- Batch 18c - CWE-401 (cpp, csharp, go, java, javascript, python) and CWE-362 (csharp, go, java,
  javascript, php, python), 12 entries. 8 of 12 defective; `401/javascript`, `401/python` and
  `362/java` were clean, and `362/csharp` carried a real gap rather than an error (see below) -
  the fourth, fifth and sixth clean language entries the sweep has found. Most consequential:
  `401/java`'s lambda-capture bullet had the mechanism backwards in the shape CLAUDE.md already
  tracks for `476/java`'s ternary defect - it named "the lambda capturing `this`" as if lambdas
  unconditionally retain the enclosing instance the way a non-static inner class does, when
  capture is conditional on the lambda body referencing `this`/an instance member (confirmed
  against Brian Goetz's canonical lambda-translation design doc); a lambda touching only locals or
  static members holds no reference to the enclosing instance at all. `362/go`'s `sync.Map`
  bullet presented it as a co-equal alternative to a mutex-guarded map, where `sync.Map`'s own
  doc recommends it only for two narrower access patterns and states "most code should use a
  plain Go map instead" - the family's recurring "framework's own doc doesn't endorse what the
  entry claims" shape, one level more subtle than a taint-sink instance since the API itself
  isn't wrong, just not the general-purpose tool the entry presented it as. `362/javascript`'s
  Redis lock example (`SET key value NX`) omitted the expiry Redis's own SET/distributed-locks
  docs treat as load-bearing to the pattern - without it a crashed holder locks the resource
  forever - and separately, `async-mutex` (recommended with no caveat) has had no release in
  over two years per Snyk, a milder instance of the "named library can stop" shape since it's a
  small, stable API surface rather than one processing untrusted input. `362/csharp`'s
  three-things-not-to-lock-on list substituted "a boxed value" for Microsoft's own third listed
  case (a `Type` instance via `typeof`/reflection) - both are genuine, distinct hazards (a boxed
  value gives no exclusion at all since each box is a new object; a shared `Type` instance risks
  an accidental cross-code lock and deadlock), and `docs/CWE-362/csharp` carries the identical
  substitution independently, making this the sweep's second confirmed instance of a defect both
  corpora share rather than one reconciliation could catch (the first was the CWE-287 re-run's
  three agreeing defects in batch 10). Two absence-shaped findings rounded out the batch:
  `362/python`'s GIL-atomicity framing had no caveat for CPython's free-threaded build
  (`python3.13t`+, officially supported per PEP 703/779 as of 3.14), whose own docs describe
  built-in container thread-safety there as an implementation detail rather than a guarantee -
  strengthening rather than contradicting the entry's existing advice; and `362/php`'s `flock()`
  bullet lacked the PHP manual's own NFS-unreliability caveat, relevant precisely because CWE-362
  fixes on this CWE often involve a shared/network mount. `401/cpp` had two minor, non-reversing
  corrections (the make_unique/make_shared "exception-safe in argument evaluation" justification
  is explicitly scoped "until C++17" by cppreference's own example; LeakSanitizer has open,
  maintainer-acknowledged macOS gaps) and one hedge (the `unique_ptr<FILE, decltype(&std::fclose)>`
  deleter form isn't the one cppreference's own worked example demonstrates, which uses a small
  wrapper function instead - changed to match the vendor's demonstrated form rather than asserting
  an unverified one compiles). `401/csharp` had a `MemoryCache` gap (`SizeLimit` does nothing for
  an entry with no `Size` set, per the vendor's own remarks) and a docs/-vendor disagreement filed
  below. `401/go` conflated `context.WithCancel` (no timer) and `WithTimeout`/`WithDeadline` (has
  one) under a single "leaks the timer" bullet naming both functions.

  One `DOCS_UPDATE.md` finding filed: `docs/CWE-401/csharp` claims CA2000 and CA1816 are "both in
  the default .NET analyzer set," where Microsoft's own rule reference states CA2000 is not
  enabled by default and CA1816 defaults to suggestion severity - a vendor-fact disagreement,
  which per the reconciliation split this repo's vendor-traced evidence wins on, so this repo's
  `401/csharp` was corrected to say both need enabling rather than merely escalating.

- Batch 18d - CWE-367 (c, go, java, javascript, python) and CWE-377 (csharp, go, java, javascript,
  python), 10 entries, closing out the memory/native and resource group. Both root files
  (`cwe/367/INDEX.md`, `cwe/377/INDEX.md`) are vendor-neutral prose naming no specific APIs, so they
  were excluded from the sweep per the established rule. 5 of 10 language entries carried a defect
  worth a vendor-traced correction; the other 5 (`367/go`, `367/java`, `367/javascript`,
  `367/python`, `377/java`) held up against direct fact-checking. Most consequential:
  `cwe/367/c` bundled three `*at()`-family functions under one flag name that only one of them
  takes - `AT_SYMLINK_NOFOLLOW` is documented for `fstatat` alone; `openat` rejects a symlink via
  `O_NOFOLLOW` in its ordinary `open()`-style flags argument, and `unlinkat`'s only documented flag
  is `AT_REMOVEDIR` (unlink already doesn't follow the final symlink, so no flag is needed there) -
  an instance of the "API named that does not exist for this call" shape, one level more subtle
  since the flag is real, just not accepted by two of the three functions cited. The same file's
  `O_NONBLOCK` bullet overstated protection to "a FIFO or device node," where open(2) explicitly
  states the flag has no effect on block devices or regular files. `cwe/377/javascript` named a
  `cleanupSync()` method on the `tmp` package that does not exist in the current source or README
  (confirmed against `raszi/node-tmp` on GitHub and the unpacked `tmp@0.2.3` source) - the real API
  is `removeCallback()` (returned by the sync `tmp.fileSync()`/`tmp.dirSync()` calls) and the async
  form's `cleanupCallback`, both of which piggyback on the same `process.on('exit')` event whose
  limits the same bullet was already describing. `cwe/377/csharp` had two version floors wrong in
  the same direction - `UnixCreateMode` cited as ".NET 8+" when Microsoft's own API page moniker
  range starts at net-7.0, and the `GetTempFileNameW` 65535-file cap stated as an unqualified fact
  when Microsoft's own page says "Starting in .NET 8, the limitation does not exist on any
  operating system," so the reason given to avoid the API is gone for the versions likeliest to be
  in use - and gained the `FileOptions.Encrypted` caveat it lacked entirely: the .NET runtime docs
  confirm it throws `UnauthorizedAccessException` on any filesystem without NTFS-EFS support,
  which is every non-Windows platform. `cwe/377/go`'s "respects TMPDIR/TEMP/TMP" line flattened
  `os.TempDir()`'s actual per-OS variable set (Unix: `$TMPDIR` only; Windows: `%TMP%`, `%TEMP%`,
  `%USERPROFILE%` in that order) into one undifferentiated list that also reversed the Windows
  TMP/TEMP precedence.

  The `docs/` reconciliation step (step 5) surfaced a cross-language doctrine gap matching CLAUDE.md's
  "sweep the family, not the file" pattern: `docs/CWE-377` warns in its root, Go, and Java pages that
  a "create-if-missing" directory call (`os.MkdirAll`, `Files.createDirectories()`) succeeds silently
  against an attacker-planted existing directory and sets no permissions on it - `cwe/377/python`
  already carried this warning but `cwe/377/go` and `cwe/377/java` did not, despite `docs/` covering
  all three identically. Added to both, plus their Taint Sinks lists. Also added from reconciliation:
  Java's `MultipartFile.transferTo()` deleting-then-recreating its destination (discarding any
  permissions already set on a securely-created temp file); C#'s Unix permission reversal (without
  `UnixCreateMode`, the "more secure" `GetRandomFileName()`+`CreateNew` pattern lands on 0666 reduced
  by umask to 0644, weaker than the `GetTempFileName()` pattern it replaces, which goes through
  `mkstemps` and lands on 0600); JavaScript's sync-only-completes-in-an-exit-handler limit (a
  callback-based `fs.unlink()` never gets its callback there); Python's Windows `PermissionError` on
  `os.unlink()` against an open handle; a `RESOLVE_BENEATH`/`openat2()` (Linux 5.6+) addition to C's
  `*at()` bullet, closing the case the family alone leaves open when an intermediate component is a
  symlink; a CAS-loop starvation bound for Go; the Spring Data exception-translation gap for Java
  (`@Version` conflicts surface as `org.springframework.dao.OptimisticLockingFailureException`, not
  the raw JPA `OptimisticLockException` the entry named, and the check only runs on `saveAndFlush`,
  not `save`); a stale-reference half-fix warning for JavaScript; and an `asyncio.Lock`-vs-
  `threading.Lock` caveat for Python's async path. No factual contradictions between the two corpora
  were found in either CWE - every divergence ran in `docs/`'s favor (operational detail this repo
  had compressed away), consistent with the doctrine. No `DOCS_UPDATE.md` findings filed.

**The memory/native and resource group is complete**: CWE-125, 787, 121, 415, 416, 823, 824, 401, 362,
367, 377. That closes out all four groups named in "the intended order" (authn/authz, crypto/
randomness, web hygiene, memory/native and resource).

**It does not exhaust the full 287-file scope.** Summing the language-entry count recorded in every
batch line from 1 through 18d (12+11+10+10+11+9+9+6+12+6+6+11+8+11+11+11+9+11+12+9+6+8+12+10) gives
**231 of the original 287** in scope when the triage sweep began. **56 language files remain
unreviewed** against that original count. The "intended order" list (authn/authz, crypto/randomness,
web hygiene, memory/native and resource) is now fully worked, so the 56 remaining are files that were
never named in that list at all - the original "79 CWEs" scoping was never fully enumerated in this
file, only discovered batch by batch. Before picking up further batches, identify the 56 by diffing
every language directory under `cwe/` against the CWE numbers this file records as swept (batches 1-18d
plus the pre-sweep Top-25 and coverage-gap authoring), rather than assuming the next unswept family is
obvious.

**What batch 13 changed about the method.** Three of its four CWE-566 entries and two of its four
CWE-285 entries prescribed an edit that *cannot be applied as written* - not a no-op this time but
a hard failure: `.Where()` chained onto a `ValueTask`, a Django sink given a SQLAlchemy expression,
a `queryset` class attribute referencing `request`, `.requestMatchers()` after `anyRequest()`
asserting at startup. The batch-11 check ("does the edit survive being applied to code that already
has the thing?") generalises further than it was written: ask whether the edit *compiles*, then
whether it runs, then whether it enforces anything. Sequelize's `findByPk` is the one that fails at
the third question only, which is why it had survived twelve batches of review.

**A new shape, and it is the cheapest one to find: the defect in the seam between two bullets of
the same file.** Batch 9 named the seam between two *entries*; this is one file arguing with
itself. `cwe/285/javascript` recommended `express-jwt-permissions` in one bullet and noted
express-jwt's `req.auth` rename in another, and the pair as documented reads a property the
verifier never writes. `cwe/566/java` warned against comparing a numeric id to a username string
and then named `@AuthenticationPrincipal`, whose default principal supplies exactly that string.
`cwe/285/python` recommended overriding `get_object()` in one bullet and stated in the next that
overriding it drops the object-permission check. None needs a vendor lookup to find - only reading
the file end to end, which is the process rule already recorded above for Key Principles edits.

**Also new: a fix that is inert under the configuration the same entry recommends.** DRF's shipped
permission classes do not implement `has_object_permission` (its base returns `True`), so
`cwe/285/python`'s prescribed `check_object_permissions` call checked nothing under the
`IsAuthenticated`/`IsAdminUser` the same file recommends. Distinct from batch 10's no-op, where the
API never did the thing; here the API works and the entry's own surrounding advice disables it.

**What batch 12 changed about the method.** The credential pair were the thinnest entries the sweep
has read - 246 to 472 words against a ~800 guideline - and the finding rate held at 11 of 11 anyway.
Thin entries fail differently: almost every defect was an *absence* (no version floor, no named
package, no framework-native mechanism) rather than a false statement, so the rewrites were near
total rather than surgical. Brief a thin family by asking what the entry does not say.

Two further notes. First, **the docs/ yield varies by CWE in a way worth checking before planning
step 5**: `docs/CWE-798/*` carry Common Pitfalls sections and produced six findings including the
one that reshaped the root, while `docs/CWE-522/*` are worked-example pages with no Common Pitfalls
at all and produced almost nothing at the language tier - the value was entirely in its root. Look
at the section headings before budgeting time for the comparison. Second, batch 12 produced **no
`DOCS_UPDATE.md` entries**: every divergence ran the other way. One candidate was checked and
dropped rather than filed, since its enclosing sentence was accurate; that file's own ratio of two
withdrawn false positives to three confirmed defects is the reason not to file a weak one.

**Batch 11 landed in three commits rather than one**, because the session limit killed two of the
six evidence agents mid-run. The four that returned were judged, patched and committed before the
survivors were re-dispatched. That is a deliberate softening of "commit each batch's patches with
the batch": the rule exists so evidence is not lost to a dead transcript, and committing a partial
batch serves it better than holding four entries hostage to two. Split by entry, never mid-entry.

**What batch 11 found, beyond confirming the batch-10 summary:** Spring Security 6.0's flip of an
unmatched `authorizeHttpRequests` rule to `DENY` is recorded in *neither* the 6.0 migration guide
nor the 6.0 What's New page - only in gh-11958 and the commit. A quiet release note is not evidence
of a quiet release, so read the issue tracker when a claim turns on a default. Two Spring CVEs were
traced and deliberately omitted (CVE-2023-34035, CVE-2025-41248) because both floors now sit below
every supported branch: a floor no supported version fails is words without a fix. And go's entry
gave two remediations that *panic* - `grpc.UnaryInterceptor` set twice, and chi's `Use()` after a
route - which is the no-op shape from batch 10 in a louder form, and worth briefing as its own
check: does the prescribed edit survive being applied to code that already has the thing?

**What the CWE-287 re-run found**, beyond confirming the summary: `golang-jwt` has no floor anywhere
in the go entry (v5.2.2 / v4.5.2); the csharp entry names only the legacy
`System.IdentityModel.Tokens.Jwt` and never `Microsoft.IdentityModel.JsonWebTokens`, the default
since .NET 8, whose `TokenValidatedContext.SecurityToken` no longer casts to `JwtSecurityToken`;
jjwt rejects `alg: none` by default from 0.12 unless `JwtParserBuilder.unsecured()` opts in, so the
entry's "never use `parse()`/`parseClaimsJwt()`, which accept `alg: none`" was a version-blind
absolute; the php-jwt array-of-algorithms form is *removed* (6.0.0 repurposed the third parameter to
`?stdClass &$headers`, so it is a `TypeError`), not deprecated as the entry said; and
`PASSWORD_HASHERS` "strongest first" would have flagged Django's shipped default, which lists
PBKDF2 first and Argon2 third - the sixth instance of the vendor's own recommended configuration
being written up as a defect.

**Word budget is the live constraint from batch 10 on**, and the identified candidate has now been
spent. All six unsourced timing figures ("0.003 ms against 63 ms" and its five siblings) are gone -
six independent agents each returned NO PRIMARY SOURCE FOUND for the one they were given, and the
quantities were replaced with what the source actually shows, that the miss branch never reaches the
hasher at all. That paid for the version floors: the CWE-287 files went from 613-744 words to
723-827 against CLAUDE.md's ~800 guideline.

**That warning did not generalise, and batch 11 is the correction.** CWE-306's six entries started
at 496-618 words, so each had 180-300 words of headroom and nothing had to come out; they landed at
716-789. The constraint is per-CWE, not a property of the sweep - measure the entries before
planning a trade. It will bind again wherever a family already sits near 800.

**Batch 12 confirmed both halves of that.** CWE-798 and CWE-522 started at 246-472 words, the widest
headroom yet, and all eleven landed between 692 and 798. But `cwe/522/javascript` reached 823 with
the step-5 additions and had to be trimmed back, so the ceiling is real and does bind once a family
is rich in named APIs, floors and per-ecosystem divergences. Measure after step 5, not just after
the vendor pass - reconciliation adds words too.

### Batch 9 - what it changed about the method

Two findings generalise past the two CWEs swept, and both argue for checking a *family*
rather than a CWE at a time:

- **A defect can live in the seam between two entries.** CWE-862 and CWE-863 contradicted
  each other on the status an ownership failure returns - 404 in one, 403 in the other -
  in both the `go` and `javascript` pairs, and CWE-566's root contradicted its own three
  language files and its own Key Principles in the same sentence. No per-file review finds
  these, because each file is internally consistent. Sweep the doctrine across the family
  in one pass.
- **Prose review does not substitute for the evidence pass.** Section 1 recorded CWE-863
  as "Reviewed. All six language entries carry framework traps. No changes." All six were
  defective. The earlier pass read for plausibility; this one traced claims to vendors.

**Three items were swept family-wide** (862, 863, 285, 566, 287) rather than per batch,
since they recur in every authn/authz entry:

1. *The 401/403/404 doctrine.* RFC 9110 puts credentials-present-but-refused under 401 as
   well, so "401 only when authentication is missing" was wrong; the `WWW-Authenticate`
   MUST appeared nowhere in the corpus; and the 862/863 pairs disagreed with each other.
2. *"Indistinguishable in status and body" was overstated.* Laravel's `denyAsNotFound()`
   throws a different exception class from a genuine miss and renders a different default
   body, so the two 404s are separable unless the body is asserted too.
3. *`Taint Sinks` had drifted off its own contract.* Several files listed expression
   fragments (`role != "admin"`), prose ("routes missing shared authorization middleware")
   or, in `863/go`, `authorize...Access()` - a name that by construction does not exist in
   the code being searched, since the finding *is* its absence.

**New recurring defect shapes**, to brief future batches on:

- *An API named that does not exist.* `IAuthorizationHandler<TRequirement, TResource>` has
  no generic form; the type is the abstract class `AuthorizationHandler<,>`. Same shape as
  the CWE-502/javascript `serialize-javascript` defect.
- *A fix that has been removed from the framework's default skeleton.* `$this->authorize()`
  was the primary remediation in both PHP entries, prescribed six times; Laravel 11 dropped
  `AuthorizesRequests` from the base controller, so it is undefined on a default app.
- *An opt-in that is off by default.* `@Secured` is inert without
  `@EnableMethodSecurity(securedEnabled = true)`, while both Java entries accepted its
  presence as evidence the method was protected.
- *A stated benefit that fails in the case it names.* "Prefer `@PreAuthorize` at the service
  layer so the rule applies regardless of which caller invokes it" - method security is
  proxy-based, so a self-invocation on `this` bypasses it entirely.
- *A claim about the framework's own recommended API.* `user.IsInRole()` was listed as a
  taint sink; it appears inside Microsoft's own resource-based handler sample, so flagging
  it generates findings against correct code.
- *An identity claim assumed to hold the user id.* `ClaimTypes.NameIdentifier` is populated
  only while inbound claim mapping is on, and the API that disables it renamed at ASP.NET
  Core 8.
- *A described vulnerability that does not occur.* CWE-863/php claimed a class-level
  `can('update', Order::class)` "skips ownership entirely"; Laravel shifts the class-name
  argument off and the documented use is abilities taking only a user. The entry described
  a fail-open that the framework does not produce.

The per-batch loop, in full:

1. Pick the next CWE family from the order below; one subagent per language entry.
2. Brief each agent for EVIDENCE ONLY - claim quoted verbatim, vendor sentence quoted verbatim with
   URL, when the behaviour was introduced and in which release, what the vendor does *not* say, and
   whether a stated mechanism is vendor-supported or only its outcome. No verdicts: "is this true?"
   answers yes for a claim that is true and still broken, which is the dominant failure mode.
   Give each brief the language's own vendor sources and, where known, the specific trap to check -
   that targeting is what surfaced the `IsPrivate` and `mysql2` defects.
3. Re-verify directly any finding that will reverse a claim or delete a recommendation.
4. Patch, then re-read each patched file end to end.
5. Run the `docs/` reconciliation for that CWE family (see above) and fix both directions.
6. `python scripts/lint.py`, check no language file has grown past ~950 words, commit.

**Remaining, in the intended order:** authn/authz is complete (862, 863, 287, 306, 285, 522, 566, 798);
next is crypto and randomness (326, 330, 331, 338, 347, 295, 780, 316), web hygiene (352, 601, 614, 434, 942,
209, 201), and last the memory/native and resource entries (125, 787, 121, 415, 416, 823, 824, 401,
362, 367, 377), which are the least likely to be handed to this skill by a web-application scanner.

### Config-first remediation ordering - swept and fixed

Run 4's one failure was arm B on `LogForgeOnFailure`: all three judges scored it `fix_quality` 1,
on a criterion with zero disagreement across the pool. `cwe/117/java` stated the trap correctly in
its guidance paragraph and then opened `Remediation Steps` with the dependency and the encoder
config, so the guided arm shipped a code edit that neutralised nothing and deferred closure to an
assumed Logback binding and an unversioned dependency. The unguided arm encoded at the call site
and scored 2.00.

That is the CWE-78 shape a second time: **an entry whose leading remediation is an infrastructure
or configuration change produces a fix that leaves the reported line open.**

Swept all 500 entries for a first remediation step that changes build, config or deployment rather
than the code the finding names. 14 candidates; 6 changed:

- `cwe/117` root, `java`, `csharp`, `javascript`, `python` - call-site encoding now leads, with
  structured logging as the durable follow-up rather than the fix, and each says why it is not a
  drop-in for one finding (depends on the binding present, needs a pinned version, reformats every
  line emitted). `cwe/117/go` already had this order and is the shape the others moved to.
- `cwe/209/javascript` - the reported route leads, since centralized middleware only runs for
  errors that reach it.
- `cwe/209/python` - the exception handler leads; `DEBUG` is the environment, not the handler.
- `cwe/79/python` - the reported `|safe`/`mark_safe` leads; Django autoescape is on by default, so
  "enable autoescaping" is usually a no-op while the marker is the live issue.
- `cwe/201/python` - the serializer/`response_model` leads; `DEBUG = False` covers the debug error
  page, not the response body.

Checked and deliberately left: the `cwe/352` family (adding the CSRF middleware genuinely is the
fix), `cwe/611/javascript` (configuring the parser is the sink fix), `cwe/614/csharp` (the step is
a code change at the sink), `cwe/285/java` (`@PreAuthorize` silently does nothing without
`@EnableMethodSecurity`, so it is a precondition rather than a substitute, and the code change
follows immediately), `cwe/1321` and `cwe/943/python` (matched the heuristic on the word "config"
in a locate step).

Verified: re-running the CWE-117 case against the updated entry produced a call-site `encodeForLog`
helper covering the control range plus U+2028/U+2029 and the backslash, the `Throwable` kept in
trailing position, the unreported second sink fixed too, and an explicit statement that closing the
finding needs no configuration or dependency change. Recorded at `evals/runs-v4/verify/`. One
unblinded run - it confirms the entry no longer steers toward the config change, not that the
change helps in general.

### Coverage gaps surfaced by building the eval corpus

Mapping OWASP Benchmark's categories onto the knowledge base exposed three gaps, all outside the
Top 25 and none previously recorded:

- ~~CWE-643 (XPath Injection) has no entry at all.~~ **Done.** Root plus `java`, `csharp` and
  `python` authored. The organising fact is that XPath 1.0 string literals have no escape sequence,
  so escaping is not available as a fallback and binding is the only general fix - and the three
  languages differ sharply on whether they offer it. `lxml` binds natively
  (`tree.xpath("//user[@name=$name]", name=value)`); Java needs an `XPathVariableResolver` installed
  before compiling; .NET has **no** built-in binding at all, since `XPathExpression.SetContext`
  resolves namespaces rather than variables, so the practical fix there is a static node set compared
  in C#, or LINQ to XML. CWE-91 now routes the query half of its scope to CWE-643.
- **CWE-328** now has `csharp`, `java`, `php` and `python` entries. Password hashing is where the
  language-specific traps concentrate, and each is an API default a model does not reliably carry:
  .NET's `Rfc2898DeriveBytes` derives with **HMAC-SHA1** unless a `HashAlgorithmName` is passed, and
  its legacy default iteration count is 1000 - so the obvious "move off MD5" fix lands on SHA-1 while
  looking correct; every constructor is obsolete from .NET 10. Python's `usedforsecurity=False` (3.9+)
  resolves a cache-key finding without changing the algorithm at all. PHP's `PASSWORD_DEFAULT` is
  *designed* to change between releases, which is why `password_needs_rehash()` is not optional. Java
  has no password hasher in the JDK, and `MessageDigest` is not thread-safe, so a shared static
  instance corrupts digests under concurrency. `javascript` and `go` are still to add.
- **CWE-327 needs no language entries.** Settled by checking MITRE rather than by authoring: 327 is a
  Class marked Allowed-with-Review whose ParentOf list is CWE-328, CWE-780 and CWE-1240, and it now
  states that decision procedure in its guidance - weak hash to CWE-328, a sound-but-fast password
  hash to CWE-916, RSA without OAEP to CWE-780, and laterally to CWE-326 for key size and mode, which
  is a *sibling* under CWE-693 rather than a child. All of those already have language entries
  (326 and 780 have five each, 328 now has four), so authoring a parallel `327/{language}` set would
  duplicate them. 327 keeps direct guidance for what has no better child: an algorithm broken outright
  (DES, 3DES, RC4) and protocol or cipher-suite selection.
- **CWE-501** now has `java`, `csharp`, `python` and `javascript` entries. It is an OWASP Benchmark
  category (`trustbound`) with 83 true positives - more than the CWE-643 gap - and unlike CWE-327 it
  genuinely needed them, because the trusted store differs per framework and so does what a bad write
  exposes. The organising point across all four: **a signature proves origin, not trustworthiness.**
  Flask's default session is a client-side signed cookie the user can read but not modify, so a bad
  write there discloses as well as escalates; Django's is server-side unless `SESSION_ENGINE` says
  otherwise. ASP.NET Core's authentication cookie is signed and encrypted by Data Protection, which
  proves the server issued the claim rather than that anyone checked it. A JWT is the same weakness
  with a signature on it - `jwt.verify()` succeeding says the token is ours, not that the claim was
  validated at issue time. Java's case with no visible write is Spring MVC `@SessionAttributes`, where
  data binding promotes a `@ModelAttribute` into the session with no `setAttribute` in the source.
- **Both families are now complete** at six languages each (`csharp`, `go`, `java`, `javascript`,
  `php`, `python`). Two more verified defaults came out of the last pair: Go's
  `bcrypt.GenerateFromPassword` **rejects** a password over 72 bytes with `ErrPasswordTooLong` rather
  than truncating - a deliberate divergence from the reference implementation - while
  `CompareHashAndPassword` still accepts one and compares the first 72, so login keeps working for a
  legacy password registration would now refuse. And PHP's `session.use_strict_mode` is **off by
  default**, so until it is set PHP adopts any session id the client presents, meaning an attacker can
  fix the session a validated value is then written into.

- **CWE-522 covers no JWT secret strength or token lifetime.** Surfaced by batch 12's step-5
  reconciliation: `docs/CWE-522` carries "Weak JWT Secrets and Long-Lived Tokens" in its root and an
  "Insecure JWT Implementation" section in its java, javascript and python pages, where none of our
  five CWE-522 entries mentions either. A brute-forceable signing secret is squarely an
  insufficiently protected credential. Whether it belongs in 522 or routes to CWE-326/CWE-330 is the
  first question to settle, since 522 already routes password hashing elsewhere.

None is a defect in existing guidance; they are absences. Recorded here rather than fixed, since
adding entries is authoring work and a separate decision.

Two things worth settling before starting:

- **CWE-400 is absent.** It is the only Top 25 entry with no directory. Creating it is authoring
  work rather than review work, so it is a separate decision from the rest of this list.
- **MITRE rank is a proxy, not the real signal.** The Top 25 is derived from CVE/KEV data - what
  gets exploited in the wild - whereas this skill receives whatever a SAST tool flags in
  application code. If scanner output is available showing which CWEs actually arrive, that beats
  MITRE ordering for prioritising this list. Absent it, rank order is consistent with the first
  pass and defensible.

Beyond rank 25 there are roughly 160 further entries whose prose has never been reviewed. The
version-claim sweep covered all of them for that one error class only.
## Done this session (context)

- `Safe Pattern` retired across all 307 language files; guidance is prose-only. Spec, template and
  linter updated to match.
- `SKILL.md`: C++ now routes to `cpp/` (12 directories were unreachable); router CWEs now re-enter
  to load the child entry, with `20/INDEX.md` given the numbered mapping that hop needs.
- CWE-94 and CWE-287 reconciled against the updated docs, including the user-enumeration timing
  oracle across all seven CWE-287 files.
- Three criticals fixed: `22/java` double decode (plus NFC removal from root/csharp/javascript),
  `434/java` `Files.probeContentType()`, `79/perl` Template Toolkit vs HTML::Mason.
- `PROGRESS.md` removed (its pass was complete).
- `89/csharp:25` fixed: `Parameters.Add(...)` now assigns `.Value` on the returned parameter, and
  `size` is scoped to variable-length types.
- The sweep's 248 removed code blocks were audited for detail lost with them, using a detector
  calibrated against the `89/csharp` defect and hand-verified afterwards. Five entries had lost
  something (`434/javascript`, `434/php`, `918/php`, `326/go`, `114/c`); all five are now fixed.
  Everything else survived the rewrite, in several cases more completely than the block stated it.
  The A/B validation of guidance quality with blocks vs without was never run.
- All graded review findings applied across CWE-22, 78, 79, 89, 125/416/787, 352, 434, 862, and the
  20/77/94/287 group. Three claims were corrected against current sources while doing so: the PHP
  `proc_open` fix versions are 8.1.28/8.2.18/8.3.5 with a further bypass fixed in 8.1.29/8.2.20/8.3.8
  (CVE-2024-5585), `gorilla/csrf` has no fixed release for CVE-2025-47909, and ASP.NET Core does not
  execute uploaded `.aspx`/`.cshtml` at all - unknown content types 404.
- Version-claim sweep completed across all 187 CWE directories: 110 version assertions in 61 files
  extracted mechanically, routine standard-library floors taken as read, and the 13 specific enough
  to be wrong verified against upstream sources. Two were wrong, both now fixed - `88/java` called
  the `java.net.URL` constructors "deprecated for removal" when JDK 20 marked them
  `@Deprecated(since="20")` without `forRemoval`, and `611/php` said
  `libxml_disable_entity_loader()` was removed in 8.4 when it is deprecated since 8.0 and still
  present in 8.5 (that bullet also described `LIBXML_NO_XXE` as disabling entity substitution when
  it blocks external entity loading). Eleven checked out: Python 3.14 `\z`, Java 18
  `Runtime.exec(String)`, Go 1.24 `crypto/rand` panic, PHP 8.4 `LIBXML_NO_XXE`, `tarfile` filter
  default from 3.14, `closefrom` in glibc 2.34, XStream 1.4.7/1.4.18, AWS SDK for Java v1 end of
  support, Node CVE-2016-2216, and PHP 5.1.2 `header()`. The `88/java` error was shared with `docs/`,
  which has since been corrected there. **One of the eleven has since failed on re-check:** the Spring
  Security `sessionFixation()` default was recorded as verified, but the entry attributed
  `changeSessionId` on Servlet 3.1+ to Spring Security 4. The 3.2.9.RELEASE reference already carries
  the four-option list with that default; 3.1.7.RELEASE has three options and `migrateSession`. The
  *behaviour* checked out and the *version* did not - which is the failure mode a claim-by-claim sweep
  is least likely to catch, since the sentence reads correct.
- `SKILL.md` hardened on two evidenced defects: Step 5 no longer licenses supplying a library
  version from model recall (the failure mode behind three wrong version claims found this
  session), and Step 4 now treats a non-exploitable trace as a valid outcome in *both* modes -
  previously that path existed only in `references/tone.md`, which autonomous mode never reads,
  so CI runs had no way to conclude a finding was a false positive. `autonomous-output.md` gained
  a `verdict` field separating `not_exploitable` from `undetermined`. Go added to the Step 3
  language table (29 entries, more than C or C++, both already listed).
- `306/` given the same six language entries its siblings `287/` and `862/` carry (csharp, go, java,
  javascript, php, python), each covering where routes escape the framework's auth wiring.
- Two corrections from reading `docs/`: the CVE-2024-1874 fix version for the PHP 8.3 branch is
  reported inconsistently (8.3.5 vs 8.3.6), so `78/php` now anchors on the CVE-2024-5585 floor
  instead; and `434/csharp` names Razor runtime compilation as the content-root code-execution path.
- `CLAUDE.md` now states that `77/{language}` covers non-shell interpreters only, with shell sinks
  routed to `78/`; `scripts/lint.py` strips a `#fragment` before checking a link target exists.
