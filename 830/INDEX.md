# CWE-830: Inclusion of Web Functionality from an Untrusted Source

## LLM Guidance

Including third-party web functionality, such as a script, stylesheet, widget, or embed, from an external origin gives that code the same origin privileges as the including page: full access to its DOM, cookies, and data, with no isolation. This is risky even when the source is trustworthy at inclusion time, because a later compromise of that origin, CDN, or build pipeline silently compromises every page that includes it. The fix is to pin included content to a verified version, restrict which origins may supply executable content, and isolate embedded functionality that does not need page access.

## Key Principles

- Verify that fetched third-party content matches what was reviewed before allowing the browser to execute it, rather than trusting the origin indefinitely
- Restrict which origins may supply scripts or stylesheets to the page through an explicit allowlist, rather than allowing inclusion from any domain
- Isolate embedded functionality that does not need to read or modify the host page's data so a compromise of that source cannot reach the page's cookies or DOM
- Avoid embedding third-party functionality on pages that handle credentials, payment data, or other high-value actions
- Treat an unpinned or version-floating external include as equivalent to trusting that origin's current and all future content indefinitely
- Combine origin restriction, integrity verification, and isolation as defence-in-depth rather than relying on any single control
- Know what Subresource Integrity does not cover: it applies to the one request carrying the attribute, and a chat, ad, or analytics tag is usually a small loader that fetches the real payload at runtime with no integrity attribute on those second-stage requests - so pinning the snippet pins the part that was never going to change
- A hash pinned to a versionless URL turns the vendor's next rolling release into a blank widget rather than a security event, which is why many vendors ask you not to set one; pin a specific versioned file, prefer self-hosting a reviewed copy, and otherwise rely on isolation and origin restriction
- Build the CSP from `default-src 'none'` and open only what the page needs, since every unset *fetch* directive falls back to it - but `form-action` and `base-uri` do **not** fall back, so under `default-src 'none'` a form can still post anywhere and an injected `<base>` can still retarget every relative URL
- Isolate the widget from data it does not need: a cross-origin iframe with a narrow `postMessage` contract keeps it out of the page's DOM and cookies

## Remediation Steps

- Locate - Identify every script, stylesheet, or embed tag that loads content from an external origin
- Trace data flow - Determine whether the referenced origin, path, or version is fixed, attacker-influenced, or able to change without the including page being updated
- Identify the unsafe pattern - Look for external includes with no integrity verification, no origin restriction, or same-origin script inclusion of functionality that does not need page access
- Replace with the safe pattern - Pin the include to a specific, reviewed version verified through subresource integrity, and restrict allowed script and style origins through a content security policy
- Add secondary controls - Move widgets that do not need host page access into an isolated, sandboxed embed, and self-host critical third-party code where feasible to remove the external dependency entirely
- Test - Alter the referenced content or its integrity hash and confirm the browser blocks execution; attempt to load from an origin not on the allowlist and confirm it is blocked; confirm a sandboxed embed cannot access the host page's cookies or DOM
