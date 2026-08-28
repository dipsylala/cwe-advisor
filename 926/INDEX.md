# CWE-926: Improper Export of Android Application Components

## LLM Guidance

Android Component Export occurs when application components (activities, services, broadcast receivers, or content providers) are unintentionally exposed to other applications. This vulnerability arises when components lack explicit `android:exported` declarations, allowing unauthorized apps to interact with sensitive functionality. All exposed components must be intentionally configured and protected.

## Key Principles

- Never allow components to be accessible by other applications unless explicitly intended and protected
- All activities, services, receivers, and providers must declare `android:exported` explicitly in AndroidManifest.xml
- Any component exposed beyond the application boundary must enforce authorization through signature-level permissions or runtime caller validation
- Default to `android:exported="false"` for internal-only components
- Declare `android:exported` explicitly rather than relying on the pre-Android-12 default, so adding an intent filter later cannot silently export the component
- Use `protectionLevel="signature"` for a component that must be exported, which restricts callers to apps signed with the same certificate - a boundary the OS enforces before your code runs; `normal` and `dangerous` levels can be granted to unrelated apps
- A package name is not a trust boundary: any app can declare any package name, so check the caller's signing certificate fingerprint against an allowlist and fail closed on any exception during the lookup
- Verifying the caller does not make the payload trustworthy - validate the intent's extras and URIs as untrusted input even from an allowed app

## Remediation Steps

- Review flaw details to identify which component lacks proper export declaration
- Audit all activities, services, broadcast receivers, and content providers in `AndroidManifest.xml`
- Identify components with intent filters that require explicit `android:exported` on Android 12+
- Determine which components should be internal-only versus accessible to other applications
- Set `android:exported="false"` for internal components and `android:exported="true"` only when necessary
- Add signature-level permissions or implement runtime caller validation for all exported components
