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
- Do not look for an auto-escaping switch in EJS, Pug or Handlebars - none of them has one, because all three escape by default. The bug is always the raw-output tag: replace EJS `<%- %>` with `<%= %>`, Handlebars `{{{ }}}` with `{{ }}`, and Pug `!{}`/`!=` with `#{}`/`=`
- Sanitize user-generated HTML with `DOMPurify.sanitize()` and assign only its return value to `innerHTML`
- Set CSP headers - `Content-Security-Policy: default-src 'self'; script-src 'self'`
- For a value that lands in `href` or `src`, percent-encoding is not the control - it leaves the `javascript:` and `data:text/html` schemes intact and merely encodes their payload. Parse with `new URL(value, base)`, reject anything whose `parsed.protocol` is outside an allowlist such as `https:`/`http:`/`mailto:`, and render the parsed result
