# CWE-80: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) - Perl

## LLM Guidance

CWE-80 is the subset of CWE-79 that covers injection of script-related HTML tags - `<script>`, `<img onerror=...>`, `<iframe>`, and similar - into web output. In Perl this happens when CGI.pm, Template Toolkit, or Mojolicious render user-controlled data into HTML without encoding, letting attacker-supplied markup reconstruct one of these tags. The fix is the same output-encoding discipline as CWE-79: encode HTML metacharacters (`<`, `>`, `&`, quotes) so tag delimiters cannot be formed, rather than trying to blocklist specific tag names.

**Primary Defence:** Use CGI.pm's `escapeHTML()` or HTML::Entities' `encode_entities()` for HTML contexts so raw `<script>`/`<img>`/`<iframe>` markup cannot survive into the response.

## Key Principles

- Encode all user input before outputting to HTML using `CGI::escapeHTML()` or `HTML::Entities::encode_entities()` so `<`, `>`, and `&` cannot form script-related tags
- Do not rely on blocklisting tag names like `<script>` or `<iframe>` - encoding metacharacters prevents any tag from being reconstructed
- Use Content Security Policy headers (`script-src 'self'`) as defence-in-depth against any script-related markup that does get through
- Apply context-specific encoding (HTML, URL, JavaScript) based on output location
- Never insert untrusted data directly into JavaScript blocks or event handler attributes (e.g. `onerror`, `onload`)
- Template Toolkit escapes nothing by default: set `default_escape_flags => 'h'` (or Mojolicious's `AUTO_FILTER` equivalent) so escaping is the default rather than a per-variable habit

## Taint Sinks

`print`/`say` interpolating unescaped CGI parameters, unfiltered Template Toolkit `[% var %]`, Mojolicious `<%= %>` fed unescaped input, CGI.pm builders (`h1()`, `p()`) fed unescaped input

## Remediation Steps

- Replace all direct output of user data with `escapeHTML()`/`encode_entities()` wrapper calls so `<script>`, `<img>`, and `<iframe>` cannot be reconstructed
- Implement CSP headers with `script-src 'self'` directive to block inline scripts
- Review all CGI parameter usage and apply appropriate encoding functions
- Use templating systems with auto-escaping (Template Toolkit with HTML filter, Mojolicious's auto-escaping `<%= %>`)
- Test with script-tag payloads like `<script>alert(1)</script>` and `<img src=x onerror=alert(1)>` to verify protection
- Audit code for direct `print`/`say` statements containing CGI parameters
