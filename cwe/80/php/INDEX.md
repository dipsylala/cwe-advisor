# CWE-80: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) - PHP

## LLM Guidance

CWE-80 is the subset of CWE-79 covering injection of script-related HTML tags. In PHP the fix is output encoding with `htmlspecialchars()`, or a template layer that applies it for you. Both Blade and Twig escape by default, so a finding is usually a raw-output construct rather than a missing setting - and the flags to pass `htmlspecialchars()` changed in PHP 8.1, which makes the version worth checking before adding any.

## Key Principles

- Apply output encoding at the point of rendering, not at input, and use context-appropriate encoding (HTML, JavaScript, URL, CSS)
- **Since PHP 8.1 the `htmlspecialchars()` default is `ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML401`; before that it was `ENT_COMPAT`, which left the single quote unescaped.** On 8.1+ a bare `htmlspecialchars($data)` is already correct for the common case; on older versions the flags have to be passed
- If you do pass flags, pass `ENT_SUBSTITUTE` with them. It is in the modern default for a reason: without it, input containing an invalid byte sequence for the given encoding makes `htmlspecialchars()` return an **empty string** rather than substituting U+FFFD. `ENT_QUOTES | ENT_SUBSTITUTE` is the set to use; adding `ENT_HTML5` changes only whether the single quote becomes `&apos;` or `&#039;` and is not a security property
- Use framework auto-escaping - Laravel Blade `{{ }}` and Twig `{{ }}`. Neither has anything to "enable": Blade's is unconditional, and Twig's is on by default. What differs is Twig's *strategy*: standalone `Twig\Environment` defaults to `html`, while Symfony sets `name`, which picks the strategy from the file extension - and under that strategy a `.txt.twig` template has escaping **disabled** outright
- Blade escapes with `ENT_QUOTES | ENT_SUBSTITUTE` and **double-encodes by default**; `Blade::withoutDoubleEncoding()` is the documented opt-out. Note `{{ }}` is not unconditional: `e()` returns any `Htmlable` object's `toHtml()` without escaping it
- **For a JavaScript context, `JSON_HEX_TAG | JSON_HEX_AMP` is not enough.** Those cover `<`, `>` and `&`, leaving both quote characters intact - and a `json_encode` result is full of literal `"`. Add `JSON_HEX_APOS | JSON_HEX_QUOT` where the value lands in an HTML attribute or inline script. In Laravel, `Illuminate\Support\Js::from` is the vendor's own answer, documented as ensuring the JSON "has been properly escaped for inclusion within HTML quotes"
- Escaping for an HTML body or a *quoted* attribute is a different job from an unquoted one. Twig draws the line explicitly - `html` covers "the HTML body context, or for HTML attributes values inside quotes", while `html_attr` is the strategy for an attribute value without quotes. Quote your attributes and the distinction stops mattering
- Set Content-Security-Policy without `'unsafe-inline'`, which is what blocks inline scripts and event handlers

## Taint Sinks

unescaped `echo`/`print`/`<?= ?>`, Blade `{!! !!}`, Twig `|raw`, a `.txt.twig` template under Symfony's `name` strategy, `Htmlable::toHtml()` returning untrusted markup

## Remediation Steps

- Identify all user-controlled data rendered in responses
- Replace raw output (`<?= ?>`, `{!! !!}`, `|raw`) with the escaped form
- Use `htmlspecialchars($data, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')` for HTML, or rely on the 8.1+ default
- For JavaScript, use `json_encode($data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT)`, or `Js::from()` in Laravel
- Check the Twig escaping strategy rather than assuming it is on, since the extension decides it under Symfony
- Quote every HTML attribute that interpolates a value
- Validate the fix with `<script>alert(1)</script>` **and** `<img src=x onerror=alert(1)>`, and confirm legitimate text containing `<`, `>` and `&` still displays correctly
