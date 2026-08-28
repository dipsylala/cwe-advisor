# CWE-83: Improper Neutralization of Script in Attributes in a Web Page

## LLM Guidance

CWE-83 is the attribute-injection form of XSS: untrusted data is placed inside an HTML attribute value - most dangerously an event-handler attribute (`onclick`, `onerror`, `onload`, `onmouseover`) or a URI-valued attribute (`href`, `src`, `action`, `formaction`) - without neutralizing characters that let the attacker break out of the attribute or supply a `javascript:` URI. Even when the surrounding markup is otherwise safe, a missing or incomplete attribute-value encoding, or an unquoted attribute, can let an attacker inject a new attribute or turn the existing one into executable script. The fix is attribute-context-aware output encoding plus consistently quoting every attribute value - encoding meant for the HTML body is not sufficient here, because an attribute value is parsed twice: the browser first reads it out of the markup, then hands the result to a parser chosen by the attribute (a URL parser for `href`/`src`, the JavaScript parser for `on*`, the CSS parser for `style`). Getting the first parse right says nothing about the second.

## Key Principles

- Always quote attribute values (double or single quotes) - never emit unquoted attributes, since an unquoted value can be broken out of with a single space
- Apply attribute-context encoding (encode `"`, `'`, and other characters that terminate the quote or attribute) - HTML-body encoding alone does not protect an attribute value
- Never populate an event-handler attribute (`onclick`, `onerror`, `onload`, etc.) with untrusted data at all - bind behavior with `addEventListener()` or a framework's event binding instead of inline `on*` attribute strings
- For URI-valued attributes (`href`, `src`, `action`, `formaction`), validate the scheme against an allowlist (`http:`, `https:`, `mailto:`) and reject `javascript:` and `data:` unless explicitly required
- Use a security-focused encoding library scoped to the attribute context rather than a generic HTML-body encoder
- Do not assume the framework validates the scheme for you: Angular sanitizes the URL context (and refuses a `RESOURCE_URL` binding such as `<script src>` outright without an explicit bypass), React blocks `javascript:` in `href`/`src` but allows `data:text/html,...`, and Vue neither validates nor blocks a scheme - its escaping goes through `setAttribute`, which closes the breakout and does nothing about the URI
- Implement Content Security Policy (CSP) as defence-in-depth, including a policy that blocks inline event handlers

## Remediation Steps

- Identify the attribute context - Determine which HTML attribute renders untrusted data and whether it is a generic attribute, an event-handler attribute, or a URI-valued attribute
- Confirm quoting - Ensure the attribute value is quoted; add quotes if it is not
- Apply attribute-value encoding - Encode `"`/`'` and other quote-breaking characters using an encoder scoped to attribute-value context, not HTML-body context
- Eliminate event-handler injection - Move any untrusted-data-driven behavior out of inline `on*` attributes into JavaScript event listeners registered separately from the markup
- Validate URI schemes - For `href`/`src`/`action`/`formaction`, allowlist permitted schemes and reject `javascript:`/`data:`
- Implement CSP - Add a Content-Security-Policy that disallows inline event handlers and `javascript:` URIs as a secondary control
- Test - Attempt attribute-breakout and `javascript:`-URI payloads to confirm the encoding and scheme validation block them
