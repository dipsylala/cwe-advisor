# TODO

Outstanding work from the top-15 CWE review (MITRE Top 25 ranks 1-15) and the `Safe Pattern`
retirement. Findings are graded as they were reported: **critical** = following the guidance
yields insecure or broken code, **major** = a real fix would likely be wrong or incomplete,
**minor** = imprecision a competent LLM survives.

The three criticals and both structural defects are already fixed. Everything below is open.

## 1. Known-broken guidance - fix first

- `89/csharp/INDEX.md:25` - prescribes `SqlCommand.Parameters.Add(name, SqlDbType, size)`, which
  creates a parameter without assigning a value. Code written from this throws "expects parameter
  @x, which was not supplied" at execute time. Needs `.Value` - e.g.
  `cmd.Parameters.Add("@id", SqlDbType.Int).Value = id;`. (`size` is also meaningless for `Int`;
  it belongs with `VarChar`/`NVarChar`.)

  This was introduced by the `Safe Pattern` sweep: `git log -p` shows `.Value = userInput` inside
  the deleted code block, and the prose that replaced it dropped the assignment.

## 2. Regression sweep - scope unknown

The `Safe Pattern` sweep removed 307 code blocks across two passes. One confirmed case (above)
lost a detail the replacement prose did not carry. **The other 281 first-pass deletions have not
been audited for the same class of loss.**

Pattern to look for: prose that names an API without saying what to do with its result - the
assignment, the return value to test, the argument that carries the payload. Mechanical starting
point: `git diff` each deleted block against the surviving bullets and check every identifier in
the block still appears somewhere in the file.

The A/B validation (guidance quality with blocks vs without) was proposed but never run. The case
for the sweep rests on redundancy mapping, not measurement.

## 3. Review findings by CWE

### CWE-22 Path Traversal
- **major** Read-vs-write asymmetry missing from root, `java`, `go`, `javascript`. `toRealPath()`,
  `filepath.EvalSymlinks`, and `fs.realpathSync.native()` all fail on a not-yet-existing
  destination, so applying the guidance to an upload breaks it. Only `php` and `python` handle it.
- **major** `22/java` steps contradict its own principles: offers `Path.normalize()` as
  canonicalisation (line 15 says it is textual) and asks for a string prefix check (line 14
  requires `Path.startsWith(Path)`).
- **major** `22/csharp:15` `FileInfo.ResolveLinkTarget(returnFinalTarget: true)` returns `null`
  when the object is not a link, and reports only on that object - a junction on an ancestor
  still escapes. Say what to test and that the real control is denying untrusted write access to
  the base directory.
- **major** `22/csharp:29` "Strip or reject path traversal sequences" contradicts `22/INDEX.md:26`
  ("Reject, do not strip"). Drop "Strip or".
- **major** `22/go:12` `EvalSymlinks` errors on a write path; nothing says what to do with the
  error, inviting a `realpath() ?: raw` style fallback. Mention `os.OpenRoot`/`Root.Create` (1.24+).
- **minor** `22/csharp:13` stale string-prefix bullet; `:14` omits `Path.AltDirectorySeparatorChar`.
- **minor** `22/go:25` omits making the base absolute (`filepath.Abs`) before comparison.
- **minor** `22/javascript:28` rejects a legitimate file named `..foo`; test `'..' + path.sep`.
- **minor** `22/python:13` `os.O_CREAT | os.O_EXCL` omits `os.O_WRONLY`, so the write fails.
- **minor** `22/INDEX.md` is 571 words against the ~500 guideline (lint warns at 650).

### CWE-78 OS Command Injection
- **major** `78/java:16` says keep `jdk.lang.Process.allowAmbiguousCommands` at `false`; it is
  **unset** by default, which selects legacy behaviour. Must be set explicitly.
- **major** `78/javascript:16` notes CVE-2024-27980 without saying patched Node *rejects* a
  `.bat`/`.cmd` target with `EINVAL` - and that setting `shell: true` to silence it re-opens the
  surface the fix closed.
- **major** `78/php:16` internally contradictory and unusable for a version check. Fixed versions
  (8.1.27, 8.2.16, 8.3.3) dropped. Missing: `exec()`/`system()`/`shell_exec()`/backticks are
  unaffected because they always invoke a shell, and the fix does not reach a batch file that
  interpolates `%1` itself.
- **minor** `78/php:13` conflates `escapeshellcmd()` (does not quote - treat a finding "fixed"
  with it as unfixed) and `escapeshellarg()` (platform-dependent quoting).
- **minor** `78/php` omits `Symfony\Component\Process\Process` (array constructor).
- **minor** `78/java:15` omits that `Runtime.exec(String)` is deprecated since Java 18.
- **minor** `78/csharp:16` "use `-File` with a signed script" - signing is not the control.

### CWE-79 XSS
- **major** `79/javascript:19` sinks omit Angular (`DomSanitizer.bypassSecurityTrust*`,
  `[innerHTML]`), server-side `res.send()`/`res.write()` built with template literals,
  `eval()`/`Function()`, `jQuery.html()`, `Range.createContextualFragment`, and
  `location.hash`/`postMessage` as DOM-XSS sources.
- **major** `79/javascript:24` "enable auto-escaping in EJS, Pug, Handlebars" - none has a switch;
  all escape by default. Name the raw pairs: `<%= %>`/`<%- %>`, `{{ }}`/`{{{ }}}`, `#{}`/`!{}`.
- **major** `79/javascript:27` percent-encoding does not neutralise `javascript:`/`data:text/html`
  in `href`/`src`. Parse with `new URL(value, base)` and allowlist `parsed.protocol`.
- **major** `79/java:11` lists `th:attr` as an escaping opt-out; Thymeleaf escapes it. Real
  opt-outs are `th:utext`, `[(...)]` inlining, `th:inline="javascript"`, `javascript:` in `th:href`.
- **major** `79/csharp:18` sinks omit `MarkupString` (the Blazor sink).
- **major** `79/php` lists Blade `{!! !!}` and Twig `|raw` as sinks with no sanitiser named for
  the legitimate rich-HTML case - HTML Purifier (`ezyang/htmlpurifier`, `mews/purifier`) or
  Symfony HtmlSanitizer (6.1+). Same gap in `79/go` (`bluemonday`).
- **minor** `79/csharp:11` the stated reason is wrong - `HtmlEncode` does encode `<`. The real
  reason HTML encoding fails in a JS context is untouched backslashes/line terminators. Name
  `HttpUtility.JavaScriptStringEncode()`.
- **minor** `79/java:24` JSP has no auto-escape setting; Thymeleaf already escapes; FreeMarker's
  `output_format` is the only real switch.
- **minor** `79/php:22` remediation step drops `ENT_SUBSTITUTE` that lines 9-10 argue for;
  `json_encode()` needs `JSON_HEX_APOS | JSON_HEX_QUOT` as well as `JSON_HEX_TAG | JSON_HEX_AMP`.
- **minor** `79/python:25` step still writes `bleach.clean(...)` after lines 5/13 say prefer `nh3`;
  bleach is PyPI-classified `Development Status :: 7 - Inactive`.
- **minor** `79/python` omits `json.dumps()` not escaping `</script>` (use `json_script`/`|tojson`)
  and `{% autoescape off %}` as a sink.
- **minor** `79/go:13` no exported attribute/CSS escaper exists in `html/template`.
- **minor** CSP header written with a hyphen not a colon in `79/javascript:26` and `79/php:27`.

### CWE-89 SQL Injection
- **major** `89/javascript:19` "Sequelize `.raw()`" does not exist. Sinks are
  `sequelize.query(sql, { replacements })`, `Sequelize.literal()`, `knex.raw()`,
  `dataSource.query()`, `createQueryBuilder().where(...)`.
- **major** `89/javascript:26` gives no binding form; each library differs (`:name` +
  `replacements`, array to `knex.raw`, `.where('x = :n', { n })`).
- **major** `89/python:24` `%s` is given as a placeholder with no warning it is not the `%`
  operator. `cursor.execute(sql % user_id)` is the most common Python SQLi.
- **major** `89/php` omits `PDO::ATTR_EMULATE_PREPARES => false` and `charset=utf8mb4` in the DSN.
  With emulation on, PDO builds the SQL client-side and the charset caveat applies to it too.
- **minor** `89/php:15` names `mysql_real_escape_string` (removed in PHP 7.0).
- **minor** `89/java:18` omits that a `PreparedStatement` built from a pre-concatenated string is
  still injectable, plus `EntityManager.createQuery()` (JPQL) and Spring `JdbcTemplate` sinks.
- **minor** `89/python:15` labels allowlisting as "escaping"; name `psycopg2.sql.Identifier`.

### CWE-125 / CWE-416 / CWE-787 (memory safety)
- **major** `125/c` lists `read()` as an out-of-bounds *read* sink - it writes into `buf` (CWE-787).
  Missing the real over-read sinks: `strlen`/`strcmp`/`strchr`/`printf("%s")` on a buffer with no
  NUL inside its allocation, and `write()`/`send()` transmitting more than was received.
- **major** `125/c` instructs clamping an `sscanf()` field width. C has no dynamic field width
  (`*` is assignment suppression) - the instruction cannot be implemented. The real rule: ensure
  the source is NUL-terminated within its allocation, and use a literal width (`%99s`).
- **major** `125/c:12` loses the signed-index trap: `(size_t)offset + length <= buffer_size` with
  `offset == -1` wraps and passes. Test the sign while the value is still signed.
- **major** `416/INDEX.md:9` leads with "null the pointer after free" then lines 15-17 correctly
  say nulling is not the fix. Inverted against docs, where ownership is the primary defence.
- **major** `416/c:12` suggests passing "a handle **or index**"; a bare index resolves to a
  different object after slot reuse. Needs a generation counter, incremented on release *and* on
  re-acquire, wide enough not to wrap.
- **major** `416/cpp` names escaping views as the dominant modern shape but never gives the rule:
  a non-owning view may live in a parameter or short-lived local, never in a member, container, or
  outliving return. Also missing the view-of-a-temporary shape.
- **minor** `416/c:9` release signature has no entry guard (`if (sp == NULL || *sp == NULL) return;`)
  though the test bullet requires a second call to be a no-op.
- **minor** `416/c:14` as written endorses `p = realloc(p, n)`, which leaks on NULL return.
- **minor** `416/cpp:14` `shared_ptr` capture inside a member function needs
  `std::enable_shared_from_this` / `shared_from_this()`; note `std::move_only_function` (C++23).
- **minor** `787/c:10` truncation test omits `snprintf`'s negative return:
  `if (written < 0 || (size_t)written >= sizeof(dest))`.
- **minor** `787/c:11` `strncpy` + explicit terminator cannot report truncation.
- **minor** `787/c` uses `sizeof(dest)` throughout without noting it yields pointer size on a
  `char *` parameter - a silent truncation and a common LLM error.
- **minor** `787/c:20` sinks omit `scanf`/`sscanf` with `%s` and no width, and `strncat`.
- **minor** `787/cpp:27` `_ITERATOR_DEBUG_LEVEL` defaults to 2 only in debug builds.
- **minor** `125/cpp:26` `std::span::at` does not exist before C++26.
- **minor** `_FORTIFY_SOURCE=2` -> `=3` in `125/c` and `787/c` (shared staleness with docs).
- **minor** `125/INDEX.md` has no CWE-119/126/127 mapping line and no cross-reference to 787,
  though a single untrusted length drives both ends of a `memcpy`.

### CWE-352 CSRF
- **major** `352/INDEX.md` never says state-changing GET is unprotected - CSRF middleware guards
  only non-safe methods, so `GET /account/delete?confirm=true` stays open with protection enabled.
  Only `go` and `java` mention it.
- **major** `352/csharp:26,28` `AutoValidateAntiforgeryTokenAttribute` and
  `[ValidateAntiForgeryToken]` are MVC filters and do not apply to minimal APIs. Name
  `app.UseAntiforgery()` and the controller-to-minimal-API migration gap.
- **major** `352/csharp:17` `AntiforgeryOptions.HeaderName` is `null` by default; the header
  approach rejects every correct client until configured.
- **major** `352/go:25` gorilla/csrf accepts only the field name `gorilla.csrf.Token`; name
  `csrf.TemplateField(r)` and the `X-CSRF-Token` header.
- **major** `352/javascript:24` `doubleCsrf({...})` omits `getSessionIdentifier`, the mechanism
  that binds the token to the session. Version-sensitive - see section 4.
- **major** `352/python` omits FastAPI, where "enable framework-native CSRF protection globally"
  is wrong advice - it has none. With `starlette-wtf`, `CSRFProtectMiddleware` validates nothing;
  `@csrf_protect` is the enforcement point.
- **minor** `352/INDEX.md:15` vs `:24` inconsistent token size ("128 bits" vs "32 bytes").
- **minor** `352/java:24` does not name the header (`X-CSRF-TOKEN`, or `X-XSRF-TOKEN` with
  `CookieCsrfTokenRepository.withHttpOnlyFalse()`); `ignoringRequestMatchers` scoped too broadly
  is missing from the sink list.
- **minor** `352/python:14` conflates `flask_wtf.FlaskForm` (validates on its own) with plain
  `wtforms.Form` (carries no token).

### CWE-434 Unrestricted Upload
- **major** Stored *extension* provenance is unstated in root, `csharp`, `go`, `java`,
  `javascript`, `python`. A UUID plus a client-chosen suffix still lets the attacker pick the half
  that decides how the file is served. Derive the extension from the detected type via a
  `mime -> ext` allowlist map. Only `php:16` currently says this.
- **major** `434/INDEX.md:10` presents magic-byte detection as authoritative. It identifies the
  prefix only; polyglots pass every signature check. Re-encoding is what removes the payload.
- **major** `434/php:11` `.htaccess` `php_flag engine off` is a mod_php directive and a silent
  no-op under PHP-FPM. Give the FPM form (`<FilesMatch>` + `Require all denied` + `SetHandler none`)
  and say to confirm the SAPI.
- **major** `434/csharp:15` carries the IIS-classic threat model onto ASP.NET Core. Verify against
  current .NET before editing (section 4). The live sink there is `.html`/`.svg` under `wwwroot`
  served from the app origin, plus writes into the content root.
- **major** `434/python:12` Pillow requires reopening the file after `verify()`;
  `open` -> `verify` -> `load`/`save` raises.
- **major** `434/python:16` is backwards - validators *do* run under `full_clean()`/`is_valid()`.
  The real trap is `Model.objects.create()`/`.save()` bypassing `full_clean()` entirely.
- **minor** `434/csharp` `Path.GetRandomFileName()` returns an 8.3 name containing a dot; docs use
  `Guid.NewGuid().ToString("N")`. Also missing the `ReadAtLeastAsync` short-read caveat.
- **minor** `434/php:10` no `extension_loaded('fileinfo')` check - `finfo_open()` raises rather
  than degrading, and an absent check looks identical to one that passed.

### CWE-862 Missing Authorization
- **major** The existence oracle is missing from root and prescribed against in `javascript:25`,
  `go:11,26` and `INDEX.md:17` (load-then-compare + blanket 403). Scope the query by owner so
  "not yours" and "does not exist" are indistinguishable in status and body. The 403 test
  assertions (root:29, csharp:30, go:28, java:30, js:28, python:30) would fail against a correctly
  scoped lookup.
- **major** `862/php:16` swaps the frameworks - `Response::denyAsNotFound()` is Laravel; Symfony
  uses `#[IsGranted(..., statusCode: 404)]` (6.2+) or `createNotFoundException()`. Contradicted by
  line 30 of the same file.
- **major** `862/INDEX.md:27` missing "every operation, not just the reported one" (read, update,
  delete, export). `python:12` has the list/detail variant; the root, which unlisted languages
  inherit, has neither.
- **minor** `862/python:15` prefer `self.get_object()` over `check_object_permissions` (the latter
  answers 403 and re-creates the oracle); missing the staff-branch caveat where `get_queryset()`
  widens but `has_object_permission()` compares owner IDs alone.
- **minor** `862/python` no Flask; `862/javascript` no NestJS (including stacked guards being
  ANDed); `862/java` no Jakarta EE.

### CWE-20 / CWE-77 / CWE-94 / CWE-287 (mostly reconciled)
- **major** `20/INDEX.md:22` missing the regex anchoring trap - `$` matches before a trailing
  newline in Python `re`, .NET `Regex` and PCRE, so `^[a-zA-Z0-9.-]+$` accepts `evil.com\n`.
  Use `re.fullmatch()` / `Matcher.matches()` / `\A...\z`. `77/INDEX.md:14` has it; CWE-20 does not.
- **minor** `20/INDEX.md` has no explicit allowlist-over-denylist principle.
- **major** `77/INDEX.md:5,17` routing omits CWE-77's non-shell children: CWE-1427 (prompt
  injection, and `1427/` exists here) and CWE-917 (expression language). A prompt-injection
  finding tagged CWE-77 currently routes nowhere.
- **minor** `77/java:12,25` `InternetAddress.validate()` returns `void` and throws
  `AddressException`; `new InternetAddress(String)` parses leniently unless passed `true`.
- **minor** `94/java` docs' point that `sandbox.allow()` grants permission but not reach (needs
  `JexlBuilder.namespaces(...)` or a context variable; denial is silently `null`) was left out.
- **minor** `287/INDEX.md:17` routes lockout to CWE-307 while `287/csharp` keeps lockout guidance.
  Deliberate, but the two files describe different homes for it.
- **minor** The ASP.NET Core `FallbackPolicy` / `RequireAuthenticatedUser()` technique (flip
  endpoints to protected-unless-`AllowAnonymous`) exists nowhere in the knowledge base - not in
  `287/csharp`, and `306/` has no language directories.

## 4. Confirm before editing (version-sensitive)

These were reported from recall or from docs' measured notes, and should be checked against
current sources first:

- `csrf-csrf` current major: is `getSessionIdentifier` required, and was `generateToken` renamed
  to `generateCsrfToken`? If the entry is deliberately pinned to v3.0.x, only the first applies.
- gorilla/csrf cross-origin advisory - confirm the exact patched version (reported as < 1.7.3).
- Go 1.25 `net/http.CrossOriginProtection` (Fetch-metadata CSRF defence) as an option alongside
  gorilla/csrf.
- ASP.NET Core static-file behaviour for `.aspx`/`.ashx`/`.cshtml` under `UseStaticFiles()`
  (reported as 404 on current .NET) before rewriting `434/csharp:15`.
- Node fixed versions for CVE-2024-27980 (18.20.2 / 20.12.2 / 21.7.3) and PHP's (8.1.27 / 8.2.16
  / 8.3.3).

## 5. Repo and process

- **`docs/` is not in version control.** `.gitignore:31` ignores it; `git ls-files docs` is empty.
  492 files of researched source material exist only on one machine, with no history and no review
  trail, and every reconciliation claim made against it is unreproducible.
- **`docs/` contains at least one error that propagated into the knowledge base** - the Spring
  Security `migrateSession()` default (since corrected in both). Reviewing the knowledge base
  *against docs alone* would have ratified it. Keep an independent-knowledge axis in any future
  review.
- **`docs/` has shared blind spots**, not just inherited omissions - e.g.
  `CSharpScript.EvaluateAsync()` was missing from docs as well (since added), and
  `_FORTIFY_SOURCE=2` is stale in both trees.
- **One genuinely broken link in docs**: `docs/CWE-94/javascript/index.md` -> `code`.
- **`scripts/lint.py` skips `docs/`** (`SKIP_DIRS`). `check_links()` still does not strip a
  `#fragment` before the existence check, so docs cannot be linted without ~31 false positives.
  Fix that if docs link rot should be checked.
- **Record the deliberate CWE-77/78 divergence in `CLAUDE.md`.** `77/{lang}` covers non-shell
  command interpreters while `docs/CWE-77/{lang}` covers the shell case; `77/INDEX.md` routes
  shell sinks to CWE-78. This rationale lived only in `PROGRESS.md`, which has been deleted, so
  the next person to compare the two trees will read it as an unreconciled divergence. Same for
  `382/java` and `926/android` having no docs counterpart, and the deliberate omission of docs'
  `Overview` / `Risk` / `Common Pitfalls` / OWASP sections.

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
