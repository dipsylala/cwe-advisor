# CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Perl

## LLM Guidance

Cross-Site Scripting (CWE-79) occurs when untrusted data is included in web pages without proper encoding, allowing attackers to inject malicious scripts that execute in victim browsers. This leads to session hijacking, credential theft, or malware distribution. Perl applications must use context-appropriate encoding functions like `escapeHTML()` from CGI.pm or `encode_entities()` from HTML::Entities before outputting user data to HTML contexts. CGI.pm was removed from Perl core in 5.22 and is CPAN-only now - code still calling it is old enough to warrant a wider look, not just a version bump.

## Key Principles

- Always HTML-encode user input before rendering in HTML contexts using `encode_entities()` or `escapeHTML()`
- CGI.pm's `escapeHTML()` only escapes a single quote unconditionally from version 4.11 on; before 4.11 it escapes `'` only when the object's charset is ISO-8859-1/Windows-1252 and leaves it raw under other charsets, including UTF-8 - a single-quoted attribute (`class='user'`) is still breakable (`' onmouseover='alert(1)`) on an older CGI.pm even after calling `escapeHTML()`
- `param()` returns every value for a repeated query parameter in list context, so passing it straight into a function call is the bug, not just a double-read risk: `encode_entities($cgi->param('note'))` against `?note=<payload>&note=q` calls `encode_entities('<payload>', 'q')`, where the second value becomes the unsafe-character set and the payload is emitted unescaped. Force scalar context - assign to a scalar first, or write `scalar $cgi->param('note')` - before handing the value to any encoder. Verified against HTML::Entities: the two-value form leaves `<script>` raw, both scalar forms escape it
- Template Toolkit does not auto-escape: apply `[% var | html %]` per variable or wrap a region in `[% FILTER html %]`, or install `Template::AutoFilter` and set `AUTO_FILTER => 'html'` to make escaping the default; keep `EVAL_PERL => 0`, which is a code-execution control rather than an output-encoding one
- HTML::Mason escapes nothing unless asked: `default_escape_flags` is empty by default, so `<% $var %>` is raw output - set `default_escape_flags => 'h'`, use `| h` where a component overrides a different global, and treat `| n` as an escaping opt-out that needs justifying
- In Mojolicious templates, `<%= %>` escapes and `<%== %>` does not; treat `<%== %>`, `%==`, and `Mojo::ByteStream`/`b()` as the raw-output sinks
- Validate and sanitize input on server-side; apply allowlists for expected formats
- Set Content-Security-Policy headers to restrict script execution sources; a nonce has to come from an OS CSPRNG (`Crypt::URandom`, not `rand()`, which is predictable from prior output) and change on every response, or it is not a nonce
- Never insert untrusted data directly into JavaScript, CSS, or URL contexts without proper encoding
- `HTML::Entities::encode_entities($value)` with no second argument escapes a broad default set; pass the characters explicitly (`'<>&"\''`) when the output must be predictable, and remember it is for HTML text and attribute context only. Because the second argument is that character set, anything that reaches it by accident - a list-context `param()`, an array that flattens - narrows the escaping instead of raising an error
- Use `URI::Escape`'s `uri_escape()` for a value going into a URL and `JSON::XS` (or `JSON::PP`) to emit a value into a `<script>` block - an HTML encoder is wrong in both places
- In Mojolicious, `$c->render(text => ...)` does not escape while the template `<%= %>` does; `param()` returns raw request data, so the escaping decision belongs at the point of output

## Taint Sinks

`print`/`say` with raw interpolation, unfiltered Template Toolkit `[% var %]`, unconfigured Mason `<% %>`, CGI.pm builders (`h1()`, `p()`) fed unescaped input

## Remediation Steps

- Identify all locations where user input is rendered in HTML output
- Replace direct variable interpolation with HTML encoding functions
- Use `HTML::Entities::encode_entities($user_input)` for HTML body/attribute contexts, where `$user_input` is already a scalar - never `encode_entities($cgi->param(...))` directly, which passes a repeated parameter's second value as the unsafe-character list and silently disables the encoding
- Apply Template Toolkit's HTML filter (`[% var | html %]`) to every interpolated variable - it is not applied automatically
- Implement Content-Security-Policy headers to block inline scripts
- Test with XSS payloads like `<script>alert(1)</script>` to verify fixes
