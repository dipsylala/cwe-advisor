# CWE-80: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) - Perl

## LLM Guidance

CWE-80 is the subset of CWE-79 that covers injection of script-related HTML tags - `<script>`, `<img onerror=...>`, `<iframe>`, and similar - into web output. In Perl this happens when CGI.pm, Template Toolkit, or Mojolicious render user-controlled data into HTML without encoding, letting attacker-supplied markup reconstruct one of these tags. The fix is the same output-encoding discipline as CWE-79: encode HTML metacharacters so tag delimiters cannot be formed, rather than blocklisting tag names. Which tool does that, and whether it is on by default, differs sharply between the three.

**Primary Defence:** `HTML::Entities::encode_entities()` for HTML contexts, or a template layer whose escaping is on by default.

## Key Principles

- `HTML::Entities::encode_entities($string)` with no second argument escapes control characters, `<`, `>`, `&`, `"`, `'`, and everything above ASCII 127. **The second argument replaces that set rather than adding to it**, so `encode_entities($x, '<>&"')` silently stops escaping the single quote - which is the character that matters inside a single-quoted attribute
- `CGI::escapeHTML()` delegates to `HTML::Entities`, and CGI.pm's own documentation says "really you should just use that instead". It also has a version seam: before **CGI.pm 4.21** the single quote was escaped only when the charset was ISO-8859-1 or Windows-1252, so on an older CGI.pm with a UTF-8 charset `'` came through unescaped. From 4.21 the set is `&<>"'`, controlled by `$CGI::ENCODE_ENTITIES`
- CGI.pm was removed from the Perl core in **5.22** and must now be installed from CPAN. Its HTML-generation functions are soft-deprecated, and its documentation states the trap directly: "The automatic escaping does not apply to other shortcuts, such as h1(). You should call escapeHTML() yourself on untrusted data"
- **Template Toolkit has no auto-escape configuration option.** `default_escape_flags` is an HTML::Mason option, not a TT one, and `AUTO_FILTER` belongs to `Template::Alloy` and to the `Template::AutoFilter` subclass - which has not been released since 2014. TT's only supported mechanism is per-variable: `[% var | html %]` or a `[% FILTER html %]` block. Treat every unfiltered `[% var %]` in a TT template as a sink, because nothing else will catch it
- TT's own manual understates its `html` filter as converting four characters; the implementation also escapes `'`. Rely on the behaviour, not the manual, and do not infer that the single quote is uncovered
- **Mojolicious escaping is inverted between its two layers.** In Mojolicious `.ep` templates `<%= %>` escapes and `<%== %>` is raw. In bare `Mojo::Template` the `auto_escape` attribute defaults to off, which reverses them - `<%= %>` is then the raw tag. Check which layer the code is in before judging a tag safe
- `Mojo::ByteStream` values (including anything from `b()`) are always excluded from Mojolicious's automatic escaping, so wrapping a value in one is the same as marking it raw
- Encode the quote characters as well as `<`, `>` and `&`. The CWE-80 payload `<img src=x onerror=alert(1)>` only needs a quote to break out when it is injected into an existing attribute
- Use Content Security Policy without `'unsafe-inline'` as defence-in-depth; it is the absence of that keyword, not the presence of `'self'`, that blocks inline scripts and event handlers

## Taint Sinks

`print`/`say` with interpolated CGI parameters, `[% var %]` (unfiltered TT), `<%== %>` and `%==` (Mojolicious), `Mojo::ByteStream::b()`, `CGI::h1()`/`p()` and the other CGI.pm HTML builders, `$CGI::ENCODE_ENTITIES` narrowed

## Remediation Steps

- Replace direct output of user data with `encode_entities()`, passing no second argument unless you have checked what the replacement set omits
- In Template Toolkit, add `| html` to every interpolation of untrusted data - there is no global setting to reach for, and the CPAN modules that add one are unmaintained
- In Mojolicious, confirm the tag form: `<%= %>` in a `.ep` template is escaped, `<%== %>` is not, and a `Mojo::ByteStream` bypasses both
- Review all CGI parameter usage and apply appropriate encoding functions; prefer a template engine over CGI.pm's HTML builders, as its own documentation recommends
- Sweep the whole script rather than the reported line. With no implicit escaping anywhere in the language, one unencoded interpolation usually means a file full of them - check every `print`, `qq{}` and heredoc carrying a parameter
- Implement CSP headers without `'unsafe-inline'` to block inline scripts and event handlers
- Test with `<script>alert(1)</script>` and `<img src=x onerror=alert(1)>`, and confirm legitimate text containing `<`, `>` and `&` still displays correctly
