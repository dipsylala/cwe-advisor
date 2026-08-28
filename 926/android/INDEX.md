# CWE-926: Improper Export of Android Application Components - Android

## LLM Guidance

Android activities, services, broadcast receivers, and content providers become reachable by any other installed app when `android:exported="true"` is set, or when a component has an intent filter and `android:exported` is left unset on API levels below 31 (API 31+ requires the attribute explicitly and fails the build otherwise). Improper export means a sensitive component is reachable with no permission check and no caller validation. The primary remediation is setting `android:exported="false"` on every component that has no legitimate cross-app caller, and adding a signature-level permission plus runtime caller validation on any component that must remain exported.

## Key Principles

- Declare `android:exported` explicitly on every `<activity>`, `<service>`, `<receiver>`, and `<provider>` in `AndroidManifest.xml`; do not rely on the platform default
- Default to `android:exported="false"` unless the component is intentionally reachable by other apps
- Protect any exported component with `android:permission` (or `android:readPermission`/`android:writePermission` on a `<provider>`) using `android:protectionLevel="signature"`
- Avoid `normal` or `dangerous` protection levels for components that handle sensitive data or privileged actions - both can be granted to unrelated apps
- Treat the package name from `getCallingPackage()` as spoofable; validate the caller's signing certificate fingerprint when identity matters
- Validate every value read from an incoming `Intent` (extras, data URI, action) as untrusted, even after the caller is verified
- Declare `android:exported` explicitly rather than relying on the pre-Android-12 default, so adding an intent filter later cannot silently export the component
- Restrict an exported component with a `signature`-level permission, and verify the caller's signing certificate in code rather than its package name, which any app can declare

## Taint Sinks

`android:exported="true"` without `android:permission`, missing `android:exported` on components with intent filters, unchecked `getCallingPackage()`

## Remediation Steps

- Locate - Audit `AndroidManifest.xml` for every `<activity>`, `<service>`, `<receiver>`, and `<provider>`, noting any with `android:exported="true"`, a missing `android:exported` attribute, or an intent filter with no explicit export value
- Trace data flow - For each exported component, identify what data the component reads from `getIntent()`, `onStartCommand()`, `onReceive()`, or provider query/insert/update/delete calls
- Replace the unsafe pattern - Set `android:exported="false"` on components with no legitimate external caller; keep `android:exported="true"` only where cross-app access is an intended feature
- Bind, encode, validate, or authorize - For components that remain exported, add a custom permission with `android:protectionLevel="signature"` and apply it via `android:permission`, `android:readPermission`, or `android:writePermission`
- Break taint after allowlist validation - In component code, validate `getCallingPackage()` (or `Binder.getCallingUid()` for bound services) against an allowlist of trusted signing certificate SHA-256 fingerprints, and fail closed on any lookup error before acting on intent data
- Harden configuration - Check `app/build/intermediates/merged_manifests/` after manifest merging, since a library's manifest can override an app-level `android:exported="false"`
- Test - Run `./gradlew lint` and confirm no `ExportedReceiver`/`ExportedService`/`ExportedContentProvider` warnings; use `adb shell dumpsys package <app>` and `adb shell am start -n <app>/<component>` from an unsigned test app to confirm internal components reject external launches and exported components enforce their permission
