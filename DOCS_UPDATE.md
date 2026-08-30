# Findings for the `docs/` corpus

Suggested changes to `docs/`, and nothing else. `docs/` is gitignored here and maintained
elsewhere, so this file is the hand-off channel rather than a change set applied directly.

**How these were found.** Step 5 of the triage sweep compares each swept CWE family against
its `docs/` parent. The comparison runs both ways and most of what it surfaces is a defect
*here*; only the residue pointing the other way is recorded. Items are removed once the
`docs/` maintainer lands them, so this file is a live queue rather than a history - the
CWE-88, CWE-113 and CWE-91 findings raised in batches 5-8 have all been actioned and taken
out.

**Findings 6-8 come from re-running batch 10 against CWE-287.** All three are defects both
corpora carried, found by tracing to source rather than by comparing the two, and all three
are now fixed on this side. They are the reason the reconciliation runs both ways: a shared
defect is invisible to a comparison.

**Findings 10 and 11 come from batch 13** (CWE-285 and CWE-566) and are the same kind: a
sentence true in general, asserted where the exception applies. Both were checked against the
`docs/` file rather than against this repo's counterpart, and both turn on something the vendor
states outside its own prose - a Javadoc element added in a point release, and an `Assert.state`
in the configuration source.

**Two items have been withdrawn on the maintainer's reading**, both in findings 5 and 9 and
both the same error: a claim true of the API in general, asserted at a page that does not do
the thing. Each was checked against the `docs/` original before withdrawal. That is now two
false positives from this side against three confirmed shared defects, which is the ratio to
keep in mind when reading anything here that has not been re-verified.

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
`docs/` originals. `docs/CWE-566/java:770` states the transaction-rollback condition, which
those two do not - but not the whole caveat: batch 13 grepped that file and it carries no
`EnableTransactionManagement` mention at all, so it gives the failure condition and neither of
the vendor's two remedies.

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

### 5. `docs/CWE-287/python/index.md:104` - the `ModelBackend` mechanism sentence wants a version qualifier

**The `User()` half of this finding is withdrawn as a false positive against `docs/`.** It read:

> Django's own implementation uses the configured `AUTH_USER_MODEL`, not
> `django.contrib.auth.models.User` [...] `User()` hashes against the wrong model

The page binds `User = get_user_model()` at line 83, inside the same `authenticate()` as the
`User()` call at line 90, and never imports `django.contrib.auth.models.User` anywhere. `User()`
there *is* the configured model. What the name is bound to decides this, and the finding checked the
name.

Worth recording how it happened, because the file's own process note - quote the `docs/` file, not
this repo's counterpart - was added in the same revision that carried this finding, and did not
prevent it. The note is necessary and not sufficient: quoting the line is not enough when the defect
claim depends on a binding established 7 lines earlier. **Read the enclosing scope, not just the
quoted line.** This repo's counterpart has been amended to check the import rather than the name,
so it stops generating the same false finding in developer code.

What survives, and is not disputed: at 104,

> `django.contrib.auth.backends.ModelBackend` already does this through
> `check_password_with_timing_attack_mitigation()`

is unscoped, while the *measurement* two sentences earlier is correctly scoped to Django 6.1. That
function is 6.1+ only - present in `stable/6.1.x`, absent from `stable/6.0.x` - and earlier releases
equalise the branches inline in `ModelBackend.authenticate` instead. The conclusion (stock backend,
false positive) holds on every release; only the named mechanism does not.

### 6. `docs/CWE-287/go/index.md:215,229` - `store.New` does not discard a planted session cookie

The strongest item in this batch, because it is a worked example with a comment telling the reader
what it does. At 215-216:

> ```go
> // Start a brand-new session rather than reusing any pre-login session cookie
> session, _ := store.New(r, "session")
> ```

and the prose at 229:

> `store.New` (rather than `store.Get`) issues a fresh session rather than reusing whatever session
> cookie the request already carried, which is the defense against session fixation: an attacker who
> set a known session ID on the victim's browser before login gets a discarded session, not an
> authenticated one.

`gorilla/sessions` does not do this. `CookieStore.New` reads the request cookie, decodes it into
`session.Values` and sets `IsNew = false` when the decode succeeds - the same as `Get`. Its own doc
comment gives the only difference:

> "The difference between New() and Get() is that calling New() twice will decode the session data
> twice, while Get() registers and reuses the same decoded session after the first call."

Source: https://raw.githubusercontent.com/gorilla/sessions/main/store.go (`CookieStore.New`,
`FilesystemStore.New`, `CookieStore.Get`)

`FilesystemStore.New` behaves the same way, additionally calling `s.load(session)` off the decoded
ID. So the example promotes the planted session rather than discarding it, and the reader has a
comment telling them the fixation defense is in place.

What the library actually supports: `FilesystemStore.Save` mints a new random ID only when
`session.ID == ""`, and erases the stored record when `Options.MaxAge <= 0` - so rotation is erase
the old record, then save a session whose `ID` is empty. With `CookieStore` there is no server-side
identifier at all, so the equivalent is replacing `session.Values` wholesale rather than adding the
authenticated user to values decoded from the planted cookie. Worth stating that this is application
code that will not arrive upstream: `gorilla/sessions` last released v1.4.0 in August 2024, and
issue #235, which asked for identifier regeneration, was closed unfixed.

This repo carried the same claim and it is now corrected here.

### 7. `docs/CWE-287/php/index.md:175` - Laravel closes the login timing channel itself

Claim, verbatim:

> `Auth::attempt()` does not close the enumeration timing channel, and it is worth knowing that
> before treating it as the whole fix. `SessionGuard::hasValidCredentials()` is
> `! is_null($user) && $this->provider->validateCredentials($user, $credentials)`, so when the user
> provider finds no matching record the hasher is never reached and the request is answered without
> paying for a verification

The quoted line of `hasValidCredentials()` is exact and the short-circuit is real. What the
paragraph misses is that the short-circuit happens *inside* a timebox. `SessionGuard::attempt()` is:

> ```php
> return $this->timebox->call(function ($timebox) use ($credentials, $remember) {
>     ...
>     if ($this->hasValidCredentials($user, $credentials)) { ... $timebox->returnEarly(); return true; }
>     $this->fireFailedEvent($user, $credentials);
>     return false;
> }, $this->timeboxDuration);
> ```

with `int $timeboxDuration = 200000` on the constructor. `Timebox::call` sleeps the remainder unless
`returnEarly()` was called, and `returnEarly()` is on the success path only - so every failing path,
no-such-user included, is padded to 200 ms.

Source: https://raw.githubusercontent.com/laravel/framework/master/src/Illuminate/Auth/SessionGuard.php

History, because the page's advice was right once: the Timebox was added around
`hasValidCredentials()` in **9.32.0** for CVE-2022-40482, and moved out to wrap `attempt()` entirely
- covering the `retrieveByCredentials()` lookup too - in **12.14.0** (2025-05-13, PR #55701) and
**11.45.0** (backported, PR #55705). Below 9.32.0 the paragraph is correct as written.

The actionable consequence is the sentence after it: the page tells the reader to add
`Hash::check($password, DUMMY_HASH)` on the `getLastAttempted() === null` branch. On any supported
Laravel that is a second verification inside an already-padded call - it does not reopen the channel,
but it is work added to close something already closed, and it leaves the reader believing the
framework is weaker than it is. This repo carried the same instruction and it is now corrected here.

### 8. `docs/CWE-287/javascript/index.md:129,146` - the manual `regenerate()` wrapper, and its stated reason

The secure example wraps `req.login()` in `req.session.regenerate()`:

> ```javascript
> // SECURE - session.regenerate() issues a new session ID before storing the login
> req.session.regenerate((err) => {
>   if (err) return next(err);
>   req.login(user, (err) => { ... });
> });
> ```

and explains at 146:

> Calling `regenerate()` before `req.login()` ensures the new session, not the old one, is the one
> Passport actually populates.

Passport has done this itself since **0.6.0** (2022-05-20), which fixed CVE-2022-25896 /
GHSA-v923-w3x8-wh69. `SessionManager.logIn` calls `req.session.regenerate()` and serializes the user
inside that callback:

> ```javascript
> // regenerate the session, which is good practice to help
> // guard against forms of session fixation
> req.session.regenerate(function(err) {
>   ...
>   self._serializeUser(user, req, function(err, obj) {
>     if (options.keepSessionInfo) { merge(req.session, prevSession); }
>     ...
> ```

Source: https://raw.githubusercontent.com/jaredhanson/passport/master/lib/sessionmanager.js

So on 0.6.0+ the example regenerates twice, and the stated reason is no longer why it works -
Passport populates the session it regenerated itself, whether or not the caller regenerated first.
Passport's own login example is a bare `req.login(...)`.

Two things the page could carry instead of the wrapper, both of which bite in real code:

- `{ keepSessionInfo: true }`, added in the same release. Regeneration drops everything already in
  the session, so a flash message, a CSRF token or a `returnTo` path written before login is lost
  unless this is passed. A reader following the current example loses that state with no indication
  why.
- The session store must implement `regenerate`. `cookie-session` does not, which surfaces as
  `req.session.regenerate is not a function` (passport issues #907, #939, #965).

The wrapper is still required on 0.5.x and earlier, so this wants a version qualifier rather than
deletion. This repo carried the same instruction and it is now corrected here.

### 9. A version qualifier for jjwt, offered rather than reported

Not a defect. `docs/CWE-287/java/index.md:63` describes the unsigned `parse()`/`parseClaimsJwt()`
methods accurately. From jjwt **0.12** those paths reject an `alg: none` token by default -
`DefaultJwtParser` carries "Unsecured JWSs (those with an alg header value of 'none') are disallowed
by default as mandated by RFC 7518 3.6. If you wish to allow them to be parsed, call the
JwtParserBuilder.unsecured() method" - so on a current version the finding to look for is that
opt-in, not the method choice. Both methods are deprecated since 0.12, not removed.

**A second item here has been withdrawn.** It reported `docs/CWE-287/csharp/index.md` for not
carrying the .NET 8 handler split, on the grounds that `TokenValidatedContext.SecurityToken` is now
a `JsonWebToken` and code casting it to `JwtSecurityToken` fails at run time. That page casts
nothing: `JwtSecurityToken` appears exactly once, at line 71, as `new JwtSecurityToken(token)`
inside a *vulnerable* example showing a `SignatureValidator` that never verifies. The run-time
failure had nothing to bite. Same error class as finding 5's withdrawn half - a general truth about
the API asserted at a page that does not exercise it. The advisory floor it carried is real and has
moved to the floors table below.

### 10. `docs/CWE-566/java/index.md:129` - a Hibernate `@Filter` does not cover the lookup this page is about

Claim, verbatim:

> For an application-wide version of the same idea, a Hibernate `@Filter` or a tenant
> discriminator applies the predicate to every query rather than to the ones somebody
> remembered.

Hibernate's own `@FilterDef` Javadoc states the exception, and it is the case CWE-566 names:

> By default, a filter does not apply to lookups by primary key, for example, when: fetching a
> `@ManyToOne` association, or `find()` is called.

Source: https://docs.hibernate.org/orm/6.6/javadocs/org/hibernate/annotations/FilterDef.html

`findById()` resolves to `find()`, so an ownership filter left at the default does not apply to
the taint sink the page traces. The element that changes this is `applyToLoadByKey`, and it is
new: checked across the 6.0, 6.2, 6.3, 6.4, 6.5 and 6.6 Javadoc, `applyToLoadByKey` appears only
at **6.6** and `autoEnabled` - which removes the per-session `Session.enableFilter` call - only at
**6.5**. Below 6.6 there is no documented way to make a filter cover a by-id load at all.

"Every query" is right for the query paths and wrong for the one the surrounding section is
remediating. The fix is a qualifier rather than a deletion: name `applyToLoadByKey = true` and its
6.6 floor, and keep `enableFilter`/`autoEnabled` distinct.

### 11. `docs/CWE-285/java/index.md:259` - `.anyRequest()` before a specific matcher throws rather than shadows

Claim, verbatim:

> **Filter chain matcher order:** a broad `.anyRequest().authenticated()` or an earlier
> `.requestMatchers("/api/**").permitAll()` placed before a more specific admin-only matcher
> can shadow it; Spring Security uses the first matching rule, not the most specific one.

The second half is correct - an earlier `permitAll()` on a broad pattern genuinely shadows a
later, more specific rule, and first-match-wins is the vendor's documented semantics. The first
half is a different outcome. `AbstractRequestMatcherRegistry` guards it:

> `public C requestMatchers(RequestMatcher... requestMatchers) {`
> `    Assert.state(!this.anyRequestConfigured, "Can't configure requestMatchers after anyRequest");`

Source: https://github.com/spring-projects/spring-security/blob/main/config/src/main/java/org/springframework/security/config/annotation/web/AbstractRequestMatcherRegistry.java

So a matcher added after `anyRequest()` is not silently shadowed - the context fails to start with
`IllegalStateException: Can't configure requestMatchers after anyRequest`. The same guard covers a
repeated `anyRequest()` ("Can't configure anyRequest after itself") and `dispatcherTypeMatchers`.

Worth separating, because the two halves need opposite advice: the `permitAll()` case is a silent
misconfiguration to audit for, while the `anyRequest()` case cannot reach production. The
reference manual documents the ordering semantics but not the exception, which exists only in
source - so this is a case where reading the vendor's prose alone would leave the page as it is.

---

### 12. `docs/CWE-326/python/index.md:36` - Fernet offered as an AES-256 option, against the same page's own secure pattern

The Overview's Primary Defence line reads:

> **Primary Defence:** Use `cryptography` library with `Fernet` or AES-256-GCM for symmetric
> encryption, `bcrypt` or `argon2` for password hashing, and avoid deprecated algorithms like
> DES or MD5.

Presented that way on a page about *encryption strength*, the "or" reads as a choice between
two equivalent options. The same file already states the correct fact 580 lines further down,
in the Fernet secure pattern:

> Fernet is AES-128-CBC then HMAC-SHA256 over the result (encrypt-then-MAC).
> generate_key() returns 32 bytes: 16 for the cipher, 16 for the MAC.

Both are traceable to the Fernet spec's Key Format section - "Signing-key, 128 bits;
Encryption-key, 128 bits" - and to `cryptography`'s own `fernet.py`, which splits `key[:16]` as
the signing key and `key[16:]` as the AES key and runs it through `modes.CBC`. So the page is
right in its detail and loose in its headline, and only the headline is near the top where a
reader forming a plan will see it.

Worth noting why this matters more here than it would elsewhere: `cryptography`'s Fernet page
never states the cipher, the key size or the mode at all - its only key sentence is ":param
key: A URL-safe base64-encoded 32-byte key." A reader who checks the vendor doc to resolve the
ambiguity does not find the answer there. Suggested fix is to qualify the Overview line rather
than remove Fernet, which is a sound construction: name it as the recipes-layer option at the
128-bit level, and AES-256-GCM where 256 is the requirement.

Sources: https://github.com/fernet/spec/blob/master/Spec.md ,
https://github.com/pyca/cryptography/blob/main/src/cryptography/fernet.py ,
https://cryptography.io/en/latest/fernet/

### 13. `docs/CWE-295/csharp/index.md` - `ServicePointManager` claimed inert against `HttpClient`/`SslStream` from .NET 5, contradicted by .NET 9's remap

The page states:

> From .NET 5 onwards `HttpClient` and `SslStream` ignore it entirely... Confirmed on .NET 10:
> with the bypass installed, `new HttpClient().GetAsync(...)` throws `HttpRequestException`
> for `UntrustedRoot`.

Microsoft's own reference page contradicts the .NET 10 empirical claim:

> Since .NET 9, the `ServerCertificateValidationCallback` property maps to
> `RemoteCertificateValidationCallback` on `SocketsHttpHandler.SslOptions`.

Source: https://learn.microsoft.com/en-us/dotnet/api/system.net.servicepointmanager.servercertificatevalidationcallback?view=net-10.0

So the "ignore it entirely" framing was accurate for .NET 5 through .NET 8, and the docs/ page's
"Confirmed on .NET 10" test result looks like it was run against an SDK below 9, or predates
the .NET 9 change and was never re-run after upgrading the target framework in the test project.
On .NET 9+, a global `ServicePointManager.ServerCertificateValidationCallback` bypass reaches
modern `HttpClient` traffic again - the opposite of what the page currently says.

Sources: https://learn.microsoft.com/en-us/dotnet/api/system.net.servicepointmanager.servercertificatevalidationcallback?view=net-10.0

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
| `Microsoft.IdentityModel.*` / `System.IdentityModel.Tokens.Jwt` | **7.1.2** on 7.x, **6.34.0** on 6.x, **5.7.0** on 5.x (CVE-2024-21319 / GHSA-59j7-ghrg-fj52, a denial of service through JWE token decompression) |
| Python `email` header rejection | **3.8.20 / 3.9.20 / 3.10.15 / 3.11.10 / 3.12.5 / 3.13** (CVE-2024-6923) |
