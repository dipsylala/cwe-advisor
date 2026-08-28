# CWE-530: Exposure of Backup File to an Unauthorized Control Sphere

## LLM Guidance

This weakness occurs when backup, temporary, editor-swap, or archived copies of application files, such as files ending in .bak, .old, ~, .swp, or .zip, are left reachable by the web server or object storage. These files often bypass normal application routing and access control because they are served directly as static content, and can reveal source code, credentials, connection strings, or prior versions of sensitive logic. The core fix is to exclude these files from the deployed artifact entirely, rather than relying on access rules to block them after the fact.

## Key Principles

- Primary defence: remove backup, temporary, and editor-artifact files as part of the build or release process, before anything is deployed
- Never place backup files, exported databases, or archives inside the web root or a publicly readable storage prefix
- Use packaging or build rules that include only files required to run the application, excluding version control directories, backup files, and local secrets or config
- Configure web server deny rules for common backup extensions as defence-in-depth, not as the primary control, since a missed extension or new naming convention bypasses a rule-only approach
- Give backups a separate storage location with its own access control, retention, and encryption policy
- Defence-in-depth: periodically scan production and staging endpoints for exposed backup files, not only the repository

## Remediation Steps

- Locate - Identify where backup or temporary files are produced (editors, deployment scripts, database export jobs) and where the deployed artifact or storage bucket is publicly reachable (sink)
- Trace data flow - Confirm whether these files are copied into the release artifact, container image, or public storage during build or deployment
- Identify the unsafe pattern - Backup or temporary files included in the deployed artifact, or stored inside a publicly served directory or prefix
- Replace with the safe pattern - Add a build step that deletes these files before packaging, and move backups to access-controlled storage outside the web root
- Add secondary controls - Web server or reverse proxy deny rules for backup extensions, and packaging manifests that allowlist included files
- Test - After deployment, probe common backup filenames and extensions against the public endpoint and confirm they return not found or denied
