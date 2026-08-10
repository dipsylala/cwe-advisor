# CWE-618: Exposed Unsafe ActiveX Method

## LLM Guidance

ActiveX controls marked "safe for scripting" expose their methods to any web page a browser navigates to, with no caller-trust check, so a hostile site can invoke privileged operations - file access, command execution, registry changes - through the control. This applies only to Internet Explorer, which is no longer supported by any current browser, so the durable remediation is removal: replace the control's functionality with sandboxed web-platform APIs rather than trying to secure the control in place.

## Key Principles

- There is no secure configuration for exposing privileged operations to unauthenticated, cross-origin script callers; removal is the primary defence
- "Safe for scripting" is a compatibility marker, not a security guarantee about what the exposed methods can do
- Prefer sandboxed browser-native replacements (user-initiated file selection APIs, Web Crypto, WebUSB/WebBluetooth, IndexedDB) for capabilities ActiveX used to provide
- If removal must be staged, withdraw dangerous methods entirely as the interim step rather than attempting to validate their input safely
- Any method that must remain temporarily reachable needs allowlist-based input validation and logging of the calling page's origin
- Treat any remaining ActiveX usage as end-of-life technical debt with no legitimate remaining audience, not a stable configuration

## Remediation Steps

- Locate - find ActiveX object declarations (classid/CLSID references) and enumerate the methods each control exposes to script
- Trace data flow - identify which exposed methods perform file, process, or registry operations, and confirm whether the control's safety interface marks it safe for untrusted callers
- Identify the unsafe pattern - a privileged method reachable from arbitrary script with no origin or trust check
- Replace with the safe pattern - migrate the functionality to the corresponding sandboxed web-platform API and remove the ActiveX control and its markup
- If immediate removal is not possible, withdraw the most dangerous methods (command execution, arbitrary file write) entirely rather than attempting to guard them
- Add secondary controls - allowlist-validate any remaining exposed method's input and log the calling page's origin for every invocation
- Test - confirm dangerous methods reject invocation and log the attempt, confirm the web-platform replacement works in all supported browsers, and confirm no ActiveX object or CLSID references remain
