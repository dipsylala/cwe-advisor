# CWE-548: Exposure of Information Through Directory Listing

## LLM Guidance

Directory listing occurs when a web server or static-file component returns a browsable index of a directory's contents instead of a specific resource, typically because no index file is present and auto-index/directory browsing is enabled. This reveals file names, structure, and often backup or configuration files never meant to be public. The fix is to disable directory browsing at the serving layer itself, not to mask it by dropping placeholder index files into each directory.

## Key Principles

- Disable directory browsing explicitly at every layer that serves static content: web server, reverse proxy, and application static-file middleware
- Placeholder index files are not a fix - they hide the symptom in existing directories but leave the setting enabled, so any new directory is exposed again
- Treat application-level static-file serving the same as a web server configuration: no listing-capable option should be enabled in production
- Do not rely on obscurity; unlinked but browsable directories are trivially found by automated scanning
- Remove sensitive files (backups, VCS metadata, configuration) from served directories regardless of listing status
- Check non-standard enumeration paths as well as the normal browser view, since some protocols can list a directory independently of auto-index
- Check each layer's actual default rather than adding a setting everywhere: nginx `autoindex` is off by default, IIS directory browsing is disabled by default, and Tomcat's `DefaultServlet` `listings` init-param defaults to `false` - so the finding is usually something having switched one on
- Express has no listing option at all: `express.static` serves named files and 404s a directory path, so a listing means the separate `serve-index` middleware is mounted and removing it is the fix
- Disabling the listing does not protect a predictable name - `.env`, `config.php.bak`, `db.sql` are reachable without one (CWE-538)

## Remediation Steps

- Locate - identify every component serving static files: reverse proxy, web server, application framework static middleware, CDN origin
- Trace exposure - check whether directory browsing/auto-index is enabled for each served path, including directories added after initial configuration
- Identify the unsafe pattern - an auto-index setting left at its default-enabled state, or application code that lists and renders directory contents
- Replace with the safe pattern - explicitly disable directory browsing at the serving layer; if a listing feature is genuinely required, gate it behind authorization scoped to what the requesting user may see
- Remove sensitive files from served directories independent of the listing fix
- Add secondary controls - deny rules for backup and configuration file extensions at the server layer
- Test - request known and newly created directories that lack an index file and confirm a denied/not-found response rather than a file listing
