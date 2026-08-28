# CWE Identifier Lookup

Fallback for SKILL.md Step 1 when the developer describes a vulnerability by name or industry term instead of giving a CWE number. Match the description case-insensitively against the CWE ID, Name, or Aliases columns below.

- If exactly one row matches, use that CWE ID and state which CWE you matched to, so the developer can correct you if it's wrong.
- If more than one row matches (e.g. "CORS misconfiguration" matches both CWE-346 and CWE-942), list the candidates and ask the developer which one applies.
- If nothing matches, ask the developer to confirm the CWE number.

| CWE ID | Name | Aliases |
|---|---|---|
| 15 | External Control of System or Configuration Setting | - |
| 16 | Configuration | - |
| 20 | Improper Input Validation | input validation |
| 22 | Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | directory traversal, dot-dot-slash |
| 41 | Improper Resolution of Path Equivalence | path equivalence bypass |
| 73 | External Control of File Name or Path | path manipulation |
| 74 | Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') | generic injection |
| 77 | Improper Neutralization of Special Elements used in a Command ('Command Injection') | - |
| 78 | Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') | shell injection, RCE via shell |
| 79 | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') | XSS |
| 80 | Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) | - |
| 83 | Improper Neutralization of Script in Attributes in a Web Page | attribute-based XSS |
| 88 | Improper Neutralization of Argument Delimiters in a Command ('Argument Injection') | - |
| 89 | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') | SQLi |
| 90 | Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection') | - |
| 91 | XML Injection (aka Blind XPath Injection) | XPath injection |
| 93 | Improper Neutralization of CRLF Sequences ('CRLF Injection') | email header injection, SMTP header injection |
| 94 | Improper Control of Generation of Code ('Code Injection') | RCE, arbitrary code execution |
| 95 | Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection') | - |
| 98 | Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion') | RFI |
| 99 | Improper Control of Resource Identifiers ('Resource Injection') | - |
| 103 | Struts: Incomplete validate() Method Definition | - |
| 104 | Struts: Form Bean Does Not Extend Validation Class | - |
| 111 | Direct Use of Unsafe JNI | unsafe JNI |
| 112 | Missing XML Validation | - |
| 113 | Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting') | HTTP response splitting |
| 114 | Process Control | - |
| 115 | Misinterpretation of Input | - |
| 117 | Improper Output Neutralization for Logs | log injection, log forging |
| 118 | Incorrect Access of Indexable Resource ('Range Error') | - |
| 119 | Improper Restriction of Operations within the Bounds of a Memory Buffer | buffer overflow |
| 121 | Stack-based Buffer Overflow | stack overflow |
| 125 | Out-of-bounds Read | buffer over-read, OOB read |
| 129 | Improper Validation of Array Index | - |
| 134 | Use of Externally-Controlled Format String | format string vulnerability |
| 135 | Incorrect Calculation of Multi-Byte String Length | - |
| 159 | Improper Handling of Invalid Use of Special Elements | - |
| 170 | Improper Null Termination | - |
| 183 | Permissive List of Allowed Inputs | - |
| 185 | Incorrect Regular Expression | - |
| 190 | Integer Overflow or Wraparound | integer overflow |
| 191 | Integer Underflow (Wrap or Wraparound) | integer underflow |
| 192 | Integer Coercion Error | - |
| 193 | Off-by-one Error | - |
| 195 | Signed to Unsigned Conversion Error | - |
| 196 | Unsigned to Signed Conversion Error | - |
| 197 | Numeric Truncation Error | - |
| 200 | Exposure of Sensitive Information to an Unauthorized Actor | information disclosure, info leak |
| 201 | Insertion of Sensitive Information Into Sent Data | - |
| 208 | Observable Timing Discrepancy | timing attack, timing side channel, timing oracle |
| 209 | Generation of Error Message Containing Sensitive Information | verbose error message, stack trace disclosure |
| 215 | Insertion of Sensitive Information Into Debugging Code | - |
| 223 | Omission of Security-relevant Information | - |
| 234 | Failure to Handle Missing Parameter | - |
| 242 | Use of Inherently Dangerous Function | banned function |
| 243 | Creation of Chroot Jail Without Changing Working Directory | chroot escape |
| 245 | J2EE Bad Practices: Direct Management of Connections | - |
| 248 | Uncaught Exception | - |
| 250 | Execution with Unnecessary Privileges | - |
| 252 | Unchecked Return Value | - |
| 256 | Plaintext Storage of a Password | plaintext password |
| 259 | Use of Hard-coded Password | hardcoded password |
| 261 | Weak Encoding for Password | - |
| 269 | Improper Privilege Management | - |
| 272 | Least Privilege Violation | - |
| 273 | Improper Check for Dropped Privileges | - |
| 274 | Improper Handling of Insufficient Privileges | - |
| 276 | Incorrect Default Permissions | insecure default permissions |
| 282 | Improper Ownership Management | - |
| 284 | Improper Access Control | broken access control |
| 285 | Improper Authorization | authorization bypass |
| 287 | Improper Authentication | broken authentication, authentication bypass |
| 295 | Improper Certificate Validation | TLS certificate validation bypass, SSL cert validation |
| 296 | Improper Following of a Certificate's Chain of Trust | - |
| 297 | Improper Validation of Certificate with Host Mismatch | hostname verification bypass |
| 298 | Improper Validation of Certificate Expiration | - |
| 299 | Improper Check for Certificate Revocation | - |
| 306 | Missing Authentication for Critical Function | unauthenticated endpoint |
| 311 | Missing Encryption of Sensitive Data | data not encrypted at rest |
| 312 | Cleartext Storage of Sensitive Information | plaintext storage |
| 313 | Cleartext Storage in a File or on Disk | - |
| 316 | Cleartext Storage of Sensitive Information in Memory | - |
| 319 | Cleartext Transmission of Sensitive Information | unencrypted transmission, data sent over HTTP |
| 321 | Use of Hard-coded Cryptographic Key | hardcoded encryption key |
| 326 | Inadequate Encryption Strength | weak key length |
| 327 | Use of a Broken or Risky Cryptographic Algorithm | weak cryptography, broken crypto |
| 328 | Use of Weak Hash | weak hashing algorithm |
| 329 | Generation of Predictable IV with CBC Mode | predictable IV |
| 330 | Use of Insufficiently Random Values | weak randomness, insecure randomness |
| 331 | Insufficient Entropy | low entropy |
| 338 | Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) | insecure PRNG, weak RNG |
| 345 | Insufficient Verification of Data Authenticity | - |
| 346 | Origin Validation Error | CORS misconfiguration |
| 347 | Improper Verification of Cryptographic Signature | signature verification bypass, JWT alg none |
| 352 | Cross-Site Request Forgery (CSRF) | CSRF |
| 354 | Improper Validation of Integrity Check Value | - |
| 359 | Exposure of Private Personal Information to an Unauthorized Actor | PII exposure |
| 362 | Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') | race condition |
| 364 | Signal Handler Race Condition | - |
| 366 | Race Condition within a Thread | - |
| 367 | Time-of-check Time-of-use (TOCTOU) Race Condition | TOCTOU |
| 377 | Insecure Temporary File | predictable temp file |
| 382 | J2EE Bad Practices: Use of System.exit() | - |
| 384 | Session Fixation | - |
| 385 | Covert Timing Channel | - |
| 398 | Indicator of Poor Code Quality | - |
| 400 | Uncontrolled Resource Consumption | resource exhaustion, DoS, denial of service |
| 401 | Missing Release of Memory after Effective Lifetime (Memory Leak) | memory leak |
| 402 | Transmission of Private Resources into a New Sphere ('Resource Leak') | resource leak |
| 404 | Improper Resource Shutdown or Release | unclosed resource |
| 415 | Double Free | - |
| 416 | Use After Free | UAF |
| 421 | Race Condition During Access to Alternate Channel | - |
| 426 | Untrusted Search Path | PATH manipulation |
| 427 | Uncontrolled Search Path Element | DLL hijacking, binary planting |
| 434 | Unrestricted Upload of File with Dangerous Type | unrestricted file upload, malicious file upload |
| 441 | Unintended Proxy or Intermediary ('Confused Deputy') | confused deputy |
| 454 | External Initialization of Trusted Variables or Data Stores | - |
| 470 | Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection') | unsafe reflection |
| 472 | External Control of Assumed-Immutable Web Parameter | hidden field tampering |
| 476 | NULL Pointer Dereference | null deref, NPE |
| 477 | Use of Obsolete Function | deprecated function use |
| 479 | Signal Handler Use of a Non-Reentrant Function | - |
| 489 | Active Debug Code | debug code in production |
| 494 | Download of Code Without Integrity Check | missing SRI, unsigned code download |
| 497 | Exposure of Sensitive System Information to an Unauthorized Control Sphere | - |
| 498 | Cloneable Class Containing Sensitive Information | - |
| 501 | Trust Boundary Violation | - |
| 502 | Deserialization of Untrusted Data | insecure deserialization, unsafe deserialization |
| 506 | Embedded Malicious Code | backdoor |
| 511 | Logic/Time Bomb | logic bomb |
| 514 | Covert Channel | - |
| 522 | Insufficiently Protected Credentials | - |
| 526 | Exposure of Sensitive Information Through Environmental Variables | secrets in env vars |
| 530 | Exposure of Backup File to an Unauthorized Control Sphere | exposed backup file |
| 532 | Insertion of Sensitive Information into Log File | secrets in logs, sensitive data logging |
| 538 | Insertion of Sensitive Information into Externally-Accessible File or Directory | - |
| 547 | Use of Hard-coded, Security-relevant Constants | - |
| 548 | Exposure of Information Through Directory Listing | directory browsing enabled |
| 557 | Concurrency Issues | - |
| 560 | Use of umask() with chmod-style Argument | - |
| 564 | SQL Injection: Hibernate | HQL injection |
| 566 | Authorization Bypass Through User-Controlled SQL Primary Key | IDOR via primary key |
| 597 | Use of Wrong Operator in String Comparison | - |
| 601 | URL Redirection to Untrusted Site ('Open Redirect') | open redirect |
| 611 | Improper Restriction of XML External Entity Reference | XXE |
| 614 | Sensitive Cookie in HTTPS Session Without 'Secure' Attribute | missing Secure cookie flag |
| 615 | Inclusion of Sensitive Information in Source Code Comments | secrets in code comments |
| 618 | Exposed Unsafe ActiveX Method | - |
| 628 | Function Call with Incorrectly Specified Arguments | - |
| 639 | Authorization Bypass Through User-Controlled Key | IDOR, insecure direct object reference |
| 642 | External Control of Critical State Data | - |
| 656 | Reliance on Security Through Obscurity | security through obscurity |
| 665 | Improper Initialization | - |
| 668 | Exposure of Resource to Wrong Sphere | - |
| 675 | Multiple Operations on Resource in Single-Operation Context | - |
| 676 | Use of Potentially Dangerous Function | dangerous function |
| 691 | Insufficient Control Flow Management | - |
| 693 | Protection Mechanism Failure | disabled security control, bypassed security control |
| 708 | Incorrect Ownership Assignment | - |
| 732 | Incorrect Permission Assignment for Critical Resource | insecure file permissions |
| 749 | Exposed Dangerous Method or Function | - |
| 757 | Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade') | downgrade attack, protocol downgrade |
| 759 | Use of a One-Way Hash without a Salt | unsalted hash |
| 760 | Use of a One-Way Hash with a Predictable Salt | predictable salt |
| 778 | Insufficient Logging | missing audit log |
| 780 | Use of RSA Algorithm without OAEP | RSA PKCS1v1.5 padding |
| 787 | Out-of-bounds Write | OOB write |
| 798 | Use of Hard-coded Credentials | hardcoded credentials, hardcoded secrets |
| 823 | Use of Out-of-range Pointer Offset | - |
| 824 | Access of Uninitialized Pointer | dangling pointer |
| 829 | Inclusion of Functionality from Untrusted Control Sphere | untrusted third-party code |
| 830 | Inclusion of Web Functionality from an Untrusted Source | untrusted script inclusion |
| 862 | Missing Authorization | missing access control check |
| 863 | Incorrect Authorization | authorization logic flaw |
| 915 | Improperly Controlled Modification of Dynamically-Determined Object Attributes | mass assignment |
| 916 | Use of Password Hash With Insufficient Computational Effort | weak password hashing |
| 918 | Server-Side Request Forgery (SSRF) | SSRF |
| 926 | Improper Export of Android Application Components | exported Android component |
| 942 | Permissive Cross-domain Security Policy with Untrusted Domains | CORS misconfiguration, wildcard CORS |
| 943 | Improper Neutralization of Special Elements in Data Query Logic | NoSQL injection |
| 1105 | Insufficient Encapsulation of Machine-Dependent Functionality | - |
| 1174 | ASP.NET Misconfiguration: Improper Model Validation | - |
| 1236 | Improper Neutralization of Formula Elements in a CSV File | CSV injection, formula injection |
| 1321 | Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution') | prototype pollution, __proto__ pollution |
| 1333 | Inefficient Regular Expression Complexity | ReDoS, catastrophic backtracking |
| 1426 | Improper Validation of Generative AI Output | unsafe LLM output handling |
| 1427 | Improper Neutralization of Input Used for LLM Prompting | prompt injection, jailbreak |
