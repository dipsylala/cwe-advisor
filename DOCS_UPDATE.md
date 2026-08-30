# Findings for the `docs/` corpus

Suggested changes to `docs/`, and nothing else. `docs/` is gitignored here and maintained
elsewhere, so this file is the hand-off channel rather than a change set applied directly.

1. `docs/CWE-401/csharp/index.md` claims CA2000 and CA1816 "are both in the default .NET
   analyzer set." Microsoft's own code-analysis rule reference states otherwise: CA2000
   ("Dispose objects before losing scope") is listed as not enabled by default, and CA1816
   ("Call GC.SuppressFinalize correctly") is enabled only as a suggestion-level default, not a
   warning. Both need enabling deliberately (and raising to error severity) rather than already
   running - "raising warnings to errors for those two rules" presumes a starting state neither
   rule is actually in.
