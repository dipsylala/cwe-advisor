# CWE-80: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) - JavaScript

## LLM Guidance

CWE-80 is the subset of CWE-79 covering injection of script-related HTML tags. In JavaScript it happens when user input reaches an HTML-parsing DOM sink such as `innerHTML`. Note what the sink actually does with a `<script>` tag: MDN states that `innerHTML` "does prevent `<script>` elements from executing when they are injected" - the vector that works is markup with an event handler, `<img src='x' onerror='alert(1)'>`. Fixing the literal `<script>` case therefore proves nothing. Use `textContent` where the value is text, and a sanitizer where it is markup.

## Key Principles

- Use `textContent` for user-controlled data. MDN's own note on `innerHTML` names it: "`Node.textContent` should be used when you know that the user provided content should be plain text. This prevents it being parsed as HTML." `innerText` is not an equivalent - it is layout-aware, so reading it forces a reflow, and setting it converts line breaks into `<br>` elements
- Use framework escaping (React JSX, Vue templates, Angular bindings) and know each one's escape hatch: React's `dangerouslySetInnerHTML`, Vue's `v-html` - whose docs say "**never** on user-provided content" - and Angular's `bypassSecurityTrustHtml`. Angular is the one that sanitizes an `[innerHTML]` binding for you
- **DOMPurify needs a version floor, and the history is why.** It has carried mXSS bypasses, prototype-pollution bypasses and a run of `IN_PLACE` escapes, several of them incomplete fixes for the one before - the `ALLOWED_ATTR` pollution fixed in 3.4.11 is titled as bypassing the 3.4.7 hook guard. The operative floor is **3.4.13**
- Two DOMPurify usage traps its README documents. It permits HTML, SVG **and** MathML by default - pass `USE_PROFILES: { html: true }` where only HTML is wanted. And `sanitize()` is not re-entrant: calling it from inside a hook can silently widen a strict `ALLOWED_TAGS` back to the default, with no error
- Sanitizing on the server needs its own floor: DOMPurify's README requires **jsdom 20.0.0+** ("There are known attack vectors in, e.g. jsdom v19.0.0 that are fixed in jsdom v20.0.0") and says happy-dom "is not considered safe at this point"
- Insert only the sanitizer's return value. The README's stated foot-gun is modifying sanitized markup afterwards, or handing it to another library that rewrites it - either "might easily void the effects of sanitization"
- Trusted Types is the platform-level control: the CSP directive `require-trusted-types-for 'script'` makes every HTML sink reject a plain string, so an unconverted value throws instead of injecting. Baseline since early 2026 (Chrome 83, Firefox 148, Safari 26). DOMPurify integrates through `RETURN_TRUSTED_TYPE`
- `script-src 'self'` blocks inline `<script>` *and* inline event handlers, which is what closes the `onerror` vector - but only because `'unsafe-inline'` is absent, and `'self'` still permits any same-origin script. A nonce or hash policy with `'strict-dynamic'` is the stronger form
- The native `Element.setHTML()` sanitizer is not yet a substitute: no Safari support, and both shipping engines currently leave `<base>` in the allowlist

## Taint Sinks

`innerHTML`, `outerHTML`, `ShadowRoot.innerHTML`, `document.write()`, `document.writeln()`, `insertAdjacentHTML()`, `setHTMLUnsafe()`, `DOMParser.parseFromString()`, `Document.parseHTMLUnsafe()`, `Range.createContextualFragment()`, `HTMLIFrameElement.srcdoc`

## Remediation Steps

- Identify all locations where user input is rendered to the DOM, using the sink list above rather than `innerHTML` alone
- Where a project already has an escaping helper, grep its *callers* rather than its definition: the recurring defect is a correct element-content encoder reused by a later caller in an attribute, which CWE-80's element-content framing does not cover
- Replace the sink with `textContent` where the value is plain text, or framework escaping for dynamic content
- Where markup is genuinely required, sanitize with `DOMPurify.sanitize()` at 3.4.13 or later, insert only its return value, and narrow the profile to HTML
- Check the manifest for the server-side case too, since jsdom below 20.0.0 reintroduces XSS regardless of DOMPurify's version
- Note that `document.write()` is deprecated and flagged by MDN as a candidate for removal - replace it rather than escaping into it
- Set restrictive CSP headers, and adopt `require-trusted-types-for 'script'` where the browser targets allow it
- Test with `<img src=x onerror=alert(1)>` rather than `<script>alert(1)</script>`, since `innerHTML` does not execute the latter and a test using it passes against unfixed code
