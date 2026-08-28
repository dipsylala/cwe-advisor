# CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - JavaScript

## LLM Guidance

Cross-Site Scripting (XSS) occurs when untrusted data is rendered in web pages without proper encoding, allowing attackers to inject malicious scripts.

**Primary Defence:** Use framework auto-escaping (React JSX, Vue templates), `textContent` for DOM manipulation, or DOMPurify for rich HTML sanitization.

## Key Principles

- Use framework built-in escaping mechanisms (React JSX, Vue templates, template engines with escaping enabled)
- Never use `innerHTML`, `dangerouslySetInnerHTML`, or `v-html` with untrusted data
- Sanitize rich HTML with DOMPurify before rendering
- Apply Content Security Policy (CSP) headers as defence-in-depth
- Encode data appropriately for context (HTML, JavaScript, URL)

## Taint Sinks

`innerHTML`, `outerHTML`, `document.write()`, `insertAdjacentHTML()`, `dangerouslySetInnerHTML`, `v-html`, Angular `[innerHTML]` and `DomSanitizer.bypassSecurityTrustHtml()`/`bypassSecurityTrustScript()`/`bypassSecurityTrustResourceUrl()`, `jQuery.html()`/`.append()`, `Range.createContextualFragment()`, `eval()`/`new Function()`, `res.send()`/`res.write()` built from a template literal. DOM-XSS sources feeding these: `location.hash`, `location.search`, `document.referrer`, and the `data` of a `postMessage` event

## Remediation Steps

- Replace `innerHTML` with `textContent` or framework-safe rendering
- All three of EJS, Pug and Handlebars escape by default, so the usual bug is the raw-output tag - but
  two of them do have a global override worth grepping for: Handlebars' `compile` accepts
  `noEscape: true`, and EJS accepts a replacement `escape` function. Either one silently disables
  escaping while every `{{ }}` and `<%= %>` in the codebase still looks safe. The bug is always the raw-output tag: replace EJS `<%- %>` with `<%= %>`, Handlebars `{{{ }}}` with `{{ }}`, and Pug `!{}`/`!=` with `#{}`/`=`
- Sanitize user-generated HTML with `DOMPurify.sanitize()` and assign only its return value to
  `innerHTML`, with nothing modifying the markup afterwards - DOMPurify's own guidance is that
  post-sanitisation edits can void the sanitisation. Set the floor at 3.4.0: CVE-2026-41238 affects
  3.0.1 through 3.3.3 under the plain `DOMPurify.sanitize(input)` call with no special configuration,
  and supersedes the 3.2.4 floor often quoted for the earlier `SAFE_FOR_TEMPLATES` bypass
- DOMPurify's stated scope is HTML re-insertion sinks. Its own threat model excludes moving the
  result into SVG, MathML, XML, an attribute or a rawtext element, and it does not sanitise CSS inside
  `style`, so sanitised output is not a value you can then place in any context
- Set a CSP, but not an allowlist one: MDN's position is that allowlist policies "don't provide
  effective protection against XSS", and `script-src 'self'` is one. Use a strict CSP built on a
  per-response nonce or a hash, with `object-src 'none'` and `base-uri 'none'` alongside it. Where the
  application can adopt it, `require-trusted-types-for 'script'` is the control MDN points to for the
  `innerHTML` class of sink specifically
- For a value that lands in `href` or `src`, percent-encoding is not the control - it leaves the `javascript:` and `data:text/html` schemes intact and merely encodes their payload. Parse with `new URL(value, base)`, reject anything whose `parsed.protocol` is outside an allowlist such as `https:`/`http:`/`mailto:`, and render the parsed result
