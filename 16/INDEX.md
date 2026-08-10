# CWE-16: Configuration

## LLM Guidance

Configuration weaknesses arise when software is deployed with insecure defaults, missing hardening, or an exposed administrative surface instead of an explicit, secure-by-default posture. This is a broad MITRE category; when a finding names a specific mechanism (an access-control gap, a weak TLS setting, debug mode left on, permissive file permissions), prefer the more specific CWE for that mechanism and use this guidance only when no narrower CWE fits. The core fix is to replace defaults with an explicit, minimal, environment-appropriate setting and verify it against a hardening baseline rather than assuming defaults are safe.

## Key Principles

- Treat secure-by-default as the goal: disable unused features, interfaces, and debug/verbose modes before deployment
- Never rely on installation or framework defaults in production; every setting should be an explicit, reviewed choice
- Separate configuration from code and from secrets; keep settings in version-controlled config and secrets in a dedicated secrets manager
- Restrict administrative and diagnostic interfaces to trusted networks and authenticated users only
- Keep environment-specific configurations (dev, staging, production) distinct so weaker settings never reach production
- Apply defence-in-depth: pair hardened configuration with monitoring and periodic reassessment against a recognized baseline

## Remediation Steps

- Locate - identify the specific setting, file, or interface responsible for the finding (headers, debug flags, credentials, permissions, protocol/cipher choice, exposed endpoint)
- Trace data flow - determine how the configuration is loaded (config file, environment variable, framework default, infrastructure-as-code template) and which environments it affects
- Identify the unsafe pattern - name the exact deviation from a hardened baseline (default credential, verbose error output, permissive CORS, weak TLS version, world-readable file, open admin panel)
- Replace with the safe pattern - set the explicit secure value, disable the unnecessary feature, or restrict the interface to authenticated/internal access only
- Add secondary controls - apply least privilege to accounts and processes, centralize secrets management, and log/alert on configuration or access-control changes
- Test - verify the fixed configuration against a recognized hardening baseline and confirm the original finding no longer reproduces
