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

`innerHTML`, `outerHTML`, `document.write()`, `dangerouslySetInnerHTML`, `v-html`, `insertAdjacentHTML()`

## Remediation Steps

- Replace `innerHTML` with `textContent` or framework-safe rendering
- Enable auto-escaping in template engines (EJS, Pug, Handlebars)
- Sanitize user-generated HTML with `DOMPurify.sanitize()` and assign only its return value to `innerHTML`
- Set CSP headers - `Content-Security-Policy - default-src 'self'; script-src 'self'`
- Validate and encode URL parameters before rendering
