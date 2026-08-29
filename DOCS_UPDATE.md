# Findings for the `docs/` corpus

Suggested changes to `docs/`, and nothing else. `docs/` is gitignored here and maintained
elsewhere, so this file is the hand-off channel rather than a change set applied directly.

**How these were found.** Step 5 of the triage sweep compares each swept CWE family against
its `docs/` parent. The comparison runs both ways and most of what it surfaces is a defect
*here*; only the residue pointing the other way is recorded. Items are removed once the
`docs/` maintainer lands them, so this file is a live queue rather than a history - the
CWE-88, CWE-113 and CWE-91 findings raised in batches 5-8 have all been actioned and taken
out.

**Before acting on any of it, re-verify.** Floors move, APIs change, and some items are
older than the pass that recorded them; provenance caveats are noted in place.

**One process note, learned the hard way.** Quote the `docs/` file, not this repo's
counterpart. The scope error corrected in finding 1 came from assuming the two corpora said
the same thing; two of the three files named there did not carry the defect at all.

---

## Per-file findings

### 1. `docs/CWE-863/java/index.md:42` - `@PostAuthorize` offered for object-level authorization without the write-ordering caveat

`docs/CWE-863/java/index.md:42` presents it as the missing half of a role-only check:

> Spring Security has the missing half and it is easy to overlook because it looks like
> more of the same annotation. `@PostAuthorize("returnObject.owner == authentication.name")`
> evaluates against the loaded object

That is correct for a read. The Spring Security reference carries a caveat none of the
three files states, and it bites on exactly the update/delete paths these entries also
cover:

> Note that `@PostAuthorize` is not recommended for classes that perform database writes
> since that typically means that a database change was made before the security
> invariants were checked. A common example of doing this is if you have `@Transactional`
> and `@PostAuthorize` on the same method. Instead, read the value first, using
> `@PostAuthorize` on the read, and then perform the database write, should that read is
> authorized.

Source: https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html

The vendor sentence immediately after that one is worth carrying too: "If you must do
something like this, you can ensure that `@EnableTransactionManagement` comes before
`@EnableMethodSecurity`."

What makes it sharper than a general caveat: the vulnerable example directly above line 42
is `updateOrder` - a `@PutMapping` doing `findById` then `save()` - and the line offers
`@PostAuthorize` as "the missing half" for exactly that. Every secure pattern later on the
same page uses `@PreAuthorize("... @orderSecurity.isOwner(#id, authentication.name)")`.

**Scope correction.** An earlier revision of this finding also named `docs/CWE-862/java` and
`docs/CWE-285/java`. Neither carries the defect - 862/java's only `@PostAuthorize` mention is
a comment about `@EnableMethodSecurity`, and the phrase attributed to 285/java appears
nowhere in the corpus. Both were asserted from this repo's own files without reading the
`docs/` originals. `docs/CWE-566/java:770` already states the caveat completely, including
the transaction-rollback condition.

### 2. `docs/CWE-611/csharp/index.md:31,53` - the .NET DTD defaults want a per-API qualifier

Offered rather than reported as a defect: the version claim this replaces was withdrawn as
stated, but the disentangled form is real and is the qualifier that page is missing.

> The safe defaults are dated per API rather than per runtime, and the split is not
> Core-versus-Framework: `XmlReaderSettings.DtdProcessing` has defaulted to `Prohibit`
> since .NET Framework **4.0**, and `XmlReaderSettings.XmlResolver` to `null` since
> .NET Framework **4.5.2**. `XmlDocument` is the real exception - Microsoft documents no
> null default for its `XmlResolver`, and states that when the document is not loaded
> through an `XmlReader` its own resolver is always used.

So there are three separate dates, not one: DTD *processing* (4.0), the *resolver* (4.5.2),
and `XmlDocument`.

**Narrowing on that third API.** "Never got a safe default at all" holds for .NET Framework
only. In `dotnet/runtime`, `XmlDocument._resolver` has no initializer, `SetupReader` assigns
it only `if (this.HasSetResolver)`, and `XmlTextReaderImpl`'s v1 constructor sets
`_xmlResolver = null` - so external entities are not resolved by default on Core/5+. DTD
parsing is still on there (`_dtdProcessing = DtdProcessing.Parse`). The accurate shape is
three dates plus a runtime split on the third API.

**Provenance caveat:** the per-API split was traced during sweep batch 2. The runtime split
above came from the `docs/` maintainer's own reading of `dotnet/runtime`.

### 3. `docs/CWE-287/java/index.md:146` - `DaoAuthenticationProvider` encodes the decoy lazily, not at start-up

Claim, verbatim:

> Spring Security's own `DaoAuthenticationProvider` already does all of this - it encodes a fixed
> `userNotFoundPassword` at start-up and runs `matches()` against it when `loadUserByUsername`
> throws

The `matches()` half is right. "At start-up" is not: in `DaoAuthenticationProvider`,
`prepareTimingAttackProtection()` is called from `retrieveUser()` - i.e. on the first
authentication attempt - and is guarded by `if (this.userNotFoundEncodedPassword == null)`.
`doAfterPropertiesSet()` contains only an assertion on the `UserDetailsService`. Additionally,
`setPasswordEncoder(...)` resets `userNotFoundEncodedPassword` to null, deferring the encode again.

Two conditions the sentence also omits: the `matches()` runs only on `UsernameNotFoundException`
(not on other `retrieveUser` failures), and only `if (authentication.getCredentials() != null)`.

Source: `core/src/main/java/org/springframework/security/authentication/dao/DaoAuthenticationProvider.java`
(private methods, so not in the published Javadoc; the vendor's own traceability anchor is SEC-2056).

This repo carried the same wording; corrected here in the CWE-287 sweep, along with the two
conditions on the decoy `matches()` and the 7.0 constructor removal.

### 4. `docs/CWE-287/php/index.md:134,141,212` - `session_regenerate_id(true)` is prescribed against the manual's own guidance

The page recommends the `true` argument in five places and builds a pitfall on it:

> **Calling `session_regenerate_id()` without the `true` argument**, which leaves the old session
> data accessible under the old ID for the remainder of its lifetime instead of destroying it -
> pass `true` so the previous session is actually invalidated, not just superseded.

php.net takes the opposite position. On the parameter:

> "Whether to delete the old associated session file or not. **You should not delete old session if
> you need to avoid races caused by deletion or detect/avoid session hijack attacks.**"

And in the function's Warning block:

> "You should not destroy old session data immediately, but should use destroy time-stamp and
> control access to old session ID. Otherwise, concurrent access to page may result in inconsistent
> state, or you may have lost session, or it may cause client (browser) side race condition and may
> create many session ID needlessly. **Immediate session data deletion disables session hijack
> attack detection and prevention also.**"

Source: <https://www.php.net/manual/en/function.session-regenerate-id.php>

Not a claim that `true` is wrong - the manual documents a real trade-off and the page's stated
reason for it is accurate. But the manual's recommended shape is regenerate-without-delete plus a
destroy timestamp, and the pitfall as written tells a reader the opposite is simply an error. Worth
at least acknowledging the trade-off. This repo carried the same unconditional instruction and now
carries the trade-off instead.

### 5. `docs/CWE-287/python/index.md:104` - `User()` should be the configured user model

Claim, verbatim:

> `User().set_password(password)` in the `DoesNotExist` branch is what stops the *response time*
> from answering "does this address have an account".

Django's own implementation uses the configured `AUTH_USER_MODEL`, not
`django.contrib.auth.models.User`: `ModelBackend.authenticate` calls `UserModel().set_password(password)`
(and, from 6.1, `check_password_with_timing_attack_mitigation` calls `get_user_model()().set_password(password)`).
On a project with a custom user model - which Django recommends for new projects - `User()` hashes
against the wrong model, and the surrounding code will already be using `get_user_model()`.

The rest of that paragraph is more careful than this repo's counterpart: it scopes the measurement
to Django 6.1, which is the release where `check_password_with_timing_attack_mitigation()` exists at
all. Confirmed since: the function is present in `stable/6.1.x` and absent from `stable/6.0.x`, and
earlier releases equalise the branches inline instead, so an entry naming the function without the
version describes a mechanism most projects do not have. This repo's version cited it without the
version; both that and the `User()` model are now corrected here.

---

## Systematic gap: version floors

Not a per-file defect, but the single highest-value thing to act on. `docs/` carries
almost no version or advisory metadata, and across nine sweep batches that was the
category where this repo most often had to add something rather than correct something.

**Treat this table as a starting list, not a change set.** These are advisory-derived floors
as of the sweep, and floors move - re-check each row against the vendor before adopting it.
Note also that *floor* and *latest release* are different numbers: the floor is the lowest
version carrying every known fix, which is the actionable one, and CLAUDE.md's rule is that
"use the latest version" is not a fix.

Floors traced to vendor releases this pass, on subjects `docs/` covers without them:

| Subject | Floor / status |
|---|---|
| `bleach` (Python sanitizer) | **End of maintenance.** 6.4.0 (June 2026) is final; repo archived; an open `linkify` advisory has no fix and no prospect of one. Successor is `nh3` |
| DOMPurify | **3.4.13** - the highest *fixed* version across its advisories, so the minimum safe one. Latest release is 3.4.14, which carries no advisory of its own |
| jsdom, for server-side DOMPurify | **20.0.0+**; DOMPurify's README says happy-dom "is not considered safe" |
| HtmlSanitizer (.NET) | **9.2.1039**. The advisory-derived floor is 9.0.892 (GHSA-j92c-7v7g-gj3f / CVE-2026-25543), but the record undercounts: the `SanitizeDom` bypass fixed in 9.2.1039 was never filed - the release note reads "Fix attribute bypass in SanitizeDom(string) wrapper elements" |
| FreeMarker auto-escaping | **2.3.24+**, and off by default (`undefined` output format "does no escaping") |
| Jakarta Mail SMTP injection | CVE-2025-7962, fixed in `org.eclipse.angus:smtp` **2.0.4** / `com.sun.mail:jakarta.mail` **2.0.2** and **1.6.8** - the implementation artifact, not the API one |
| PyYAML | **5.4** (last `FullLoader` RCE fix), **6.0** (`Loader` becomes mandatory) |
| Jinja2 sandbox | **3.1.6** |
| Spring `UriComponentsBuilder` | **6.1.6 / 6.0.19 / 5.3.34** - three CVEs, each bypassing the last |
| Spring `redirect:` prefix (CVE-2026-41844) | **7.0.8** on 7.0.x; **6.2.19** on 6.2.x |
| Spring `UrlFilenameViewController` (CVE-2026-47887) | **7.0.9** is the only OSS fix. 7.0.8.1 / 6.2.20 / 6.1.29 / 6.0.31 / 5.3.50 / 5.2.26 are Enterprise Support Only - a different sink from the `redirect:` prefix above, and the two were previously conflated in one row |
| Node `child_process` on Windows | **18.20.4 / 20.15.1 / 22.4.1** (CVE-2024-27980, then CVE-2024-36138 bypassing it) |
| PHP `proc_open` array form on Windows | **8.1.29 / 8.2.20 / 8.3.8** (CVE-2024-1874, then CVE-2024-5585) |
| CGI.pm `escapeHTML` | **4.21** - before it, `'` was escaped only for ISO-8859-1/Windows-1252 charsets |
| Python `email` header rejection | **3.8.20 / 3.9.20 / 3.10.15 / 3.11.10 / 3.12.5 / 3.13** (CVE-2024-6923) |
