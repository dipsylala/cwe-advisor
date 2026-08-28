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
(Claude and Codex), which this repo has not, and the version-claim pass found it correct and this
repo behind on several claims - so on a factual disagreement the working assumption is that
`docs/` is right until checked against the vendor.

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
| 18 | CWE-863 Incorrect Authorization | yes | 6 | **Reviewed.** Agrees with CWE-862; boundary stated consistently in both. All six language entries carry framework traps. No changes |
| 19 | CWE-918 SSRF | yes | 6 | **Reviewed.** Stronger than the note implied. One gap: `python` - see below |
| 20 | CWE-119 Buffer bounds | yes | 0 | **Reviewed.** Read/write split to 125/787 is complete; now also names 121 for a stack buffer |
| 21 | CWE-476 NULL Pointer Dereference | yes | 3 | **Done.** Root reviewed; `c`, `cpp` and `java` entries authored |
| 22 | CWE-798 Hard-coded Credentials | yes | 6 | **Reviewed.** Root and five language entries condensed - see below |
| 23 | CWE-190 Integer Overflow | yes | 5 | **Done.** Root and `java` reviewed; `csharp` and `go` entries authored |
| 24 | CWE-400 Uncontrolled Resource Consumption | yes | 0 | **Done.** Root authored; routes to CWE-1333 and CWE-674 where the finding names a mechanism |
| 25 | CWE-306 Missing Authentication | yes | 6 | **Reviewed.** Root is strong - routing-table framing, gateway-only trap, unlinked-route point. No changes |

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

Still to verify, roughly in harm order:

- `cwe/476/c` - the compiler deleting a null check placed after a dereference, and CVE-2009-1897 as
  its canonical instance; `assert` under `NDEBUG`; `realloc` leaving the original block valid
- `cwe/476/cpp` - `operator*` on an empty `std::optional` being undefined while `.value()` throws;
  `dynamic_cast` returning null for pointers and throwing `std::bad_cast` for references;
  `map::operator[]` inserting rather than reporting absence
- `cwe/328/php` - `PASSWORD_DEFAULT` being allowed to change between releases; bcrypt's 72-byte
  truncation
- `cwe/328/java` - `DelegatingPasswordEncoder`'s `{id}` prefix and `upgradeEncoding()`
- `cwe/328/go` - `crypto.Hash` values panicking unless the implementing package is linked in
- `cwe/501/csharp` - the security stamp validation interval; `TempData`'s default cookie provider
- `cwe/501/php` - Laravel's `cookie` session driver and `APP_KEY` rotation
- `cwe/190/go` - `math.MaxInt` requiring Go 1.17+
- `cwe/643/java` - the variable resolver having to be installed before `compile()`


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
  support, Node CVE-2016-2216, PHP 5.1.2 `header()`, and the Spring Security `sessionFixation()`
  default. The `88/java` error was shared with `docs/`, which has since been corrected there.
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
