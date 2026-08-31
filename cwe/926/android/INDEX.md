# CWE-926: Improper Export of Android Application Components - Android

## LLM Guidance

Android activities, services, broadcast receivers, and content providers become reachable by any other installed app when `android:exported="true"` is set, or when a component has an intent filter and `android:exported` is left unset on API levels below 31 (API 31+ requires the attribute explicitly and fails the build otherwise). Improper export means a sensitive component is reachable with no permission check and no caller validation. The primary remediation is setting `android:exported="false"` on every component that has no legitimate cross-app caller, and adding a signature-level permission plus runtime caller validation on any component that must remain exported.

## Key Principles

- Declare `android:exported` explicitly on every `<activity>`, `<service>`, `<receiver>`, and `<provider>` in `AndroidManifest.xml`; do not rely on the platform default
- Default to `android:exported="false"` unless the component is intentionally reachable by other apps
- Protect any exported component with `android:permission` (or `android:readPermission`/`android:writePermission` on a `<provider>`) using `android:protectionLevel="signature"`
- Avoid `normal` or `dangerous` protection levels for components that handle sensitive data or privileged actions - both can be granted to unrelated apps
- An `Activity`'s `getCallingPackage()` reports the true caller for a normal `startActivityForResult()` launch, but an intermediary activity can relay a different caller's identity onto it via `Intent.FLAG_ACTIVITY_FORWARD_RESULT` (a confused-deputy chain, not a value the calling app sets directly) - validate the caller's signing certificate fingerprint when identity, not just presence of a package name, matters. `ContentProvider.getCallingPackage()` is separately verified by the system against the actual calling UID and throws `SecurityException` on mismatch, so it does not carry the same caveat
- Validate every value read from an incoming `Intent` (extras, data URI, action) as untrusted, even after the caller is verified
- Declare `android:exported` explicitly rather than relying on the pre-Android-12 default, so adding an intent filter later cannot silently export the component
- Restrict an exported component with a `signature`-level permission (or, from API 31, `android:protectionLevel="knownSigner"` with a `knownCerts` digest, so the permission need not be co-signed at build time), and verify the caller's signing certificate in code for identity decisions rather than trusting a package name alone

## Taint Sinks

`android:exported="true"` without `android:permission`, missing `android:exported` on components with intent filters, an authorization decision based on `Activity.getCallingPackage()` alone

## Remediation Steps

- Locate - Audit `AndroidManifest.xml` for every `<activity>`, `<service>`, `<receiver>`, and `<provider>`, noting any with `android:exported="true"`, a missing `android:exported` attribute, or an intent filter with no explicit export value
- Trace data flow - For each exported component, identify what data the component reads from `getIntent()`, `onStartCommand()`, `onReceive()`, or provider query/insert/update/delete calls
- Replace the unsafe pattern - Set `android:exported="false"` on components with no legitimate external caller; keep `android:exported="true"` only where cross-app access is an intended feature
- Bind, encode, validate, or authorize - For components that remain exported, add a custom permission with `android:protectionLevel="signature"` and apply it via `android:permission`, `android:readPermission`, or `android:writePermission`
- Break taint after allowlist validation - In component code, validate `getCallingPackage()` (or `Binder.getCallingUid()` for bound services) against an allowlist of trusted signing certificate SHA-256 fingerprints, and fail closed on any lookup error before acting on intent data
- Harden configuration - Declaring `android:exported` explicitly on every component (as above) is also what prevents a library from silently exporting it: manifest merging only lets a library's value fill in when the app manifest omits the attribute; an explicit app-level value that conflicts with a library's produces a build-time merge error unless resolved with a `tools:node` marker. Check `app/build/intermediates/merged_manifests/` to confirm the final merged value for any component whose declaration is unclear or library-only
- Test - Run `./gradlew lint` and confirm no `ExportedReceiver`/`ExportedService`/`ExportedContentProvider` warnings; use `adb shell dumpsys package <app>` and `adb shell am start -n <app>/<component>` from an unsigned test app to confirm internal components reject external launches and exported components enforce their permission
