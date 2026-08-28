# CWE-276: Incorrect Default Permissions

## LLM Guidance

This vulnerability occurs when a file, directory, database, cloud storage bucket, service, or installed component is created with overly permissive defaults - world-readable/writable modes, a default-allow network or firewall rule, or a default administrative account - before any application-level access control has a chance to run. The core fix is to make every creation path set an explicit restrictive permission, credential, or policy at creation time rather than inheriting whatever the OS, platform, framework, or installer ships with. Treat installer scripts, deployment templates, infrastructure-as-code, and platform/cloud defaults as part of the attack surface, not just application code.

## Key Principles

- Default to deny: newly created resources should start with the minimum access needed, not the platform's out-of-the-box default
- Set permissions explicitly at creation time (file mode, umask, ACL, bucket policy, security group rule) instead of relying on inherited or unset defaults
- Replace default or blank credentials on first boot or deploy; do not ship a fixed default admin account or password
- Review installer scripts, container images, IaC templates (Terraform, CloudFormation, Helm charts), and platform/cloud defaults as explicitly as application code, since this is the class of finding most often surfaced by hardening checklists and IaC scanners
- Distinguish from CWE-732: CWE-276 is about the baseline state a resource is created or provisioned with (a default umask, a template, a platform default); CWE-732 is about a specific permission assignment set incorrectly in application logic (a bad chmod call, an ACL bug). Fix CWE-276 by changing the default; fix CWE-732 by fixing the specific assignment
- Apply defence-in-depth: keep an authorization check at the point of use so a future default regression is not the only barrier
- Fix the template, not the instance: tightening an existing bucket or file by hand leaves the module, installer, or image build that created it producing the same permissive default for the next deployment
- Do not assume a managed platform's default is safe - several major providers have shipped permissive defaults (public-read storage, open management ports) that require an explicit opt-out
- Where the finding is an unchanged default administrative account or password rather than a permission, it is CWE-1392/CWE-1393 with CWE-798 carrying the credential remediation; this entry is about permissions and policies

## Remediation Steps

- Locate - identify every place a resource is created or provisioned: file/directory creation, database or bucket provisioning, service installation, container image build, IaC template, or first-boot sequence
- Determine the current default - check what permission mode, credential, or network rule applies when no explicit value is set (OS umask, platform default ACL, cloud default policy, installer default account)
- Confirm the default is overly permissive - compare against least privilege for the resource's sensitivity (world-writable files, public-read buckets, 0.0.0.0/0 ingress rules, and well-known default passwords are common findings)
- Set an explicit restrictive default - specify file mode/umask in code or deployment scripts, set bucket/storage policies to private with explicit allow rules, set security group/firewall rules to default-deny, and force credential rotation on first run
- Fix templates and installers, not just running instances - update the IaC template, installer, or image build so newly created resources inherit the corrected default
- Add secondary controls - keep application-level authorization checks and logging so future default drift is not the sole barrier
- Test - provision a fresh instance from the corrected template/installer and verify its permissions, credentials, and network rules match least privilege before any manual hardening step
