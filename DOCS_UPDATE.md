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

2. `docs/CWE-196/c/index.md` states the mixed signed/unsigned comparison rule as "the usual
   arithmetic conversions convert the unsigned operand to the signed type only where that type
   can represent every value it might hold, and in every other case the signed operand is the
   one that converts." This is backwards for the common case. C11 6.3.1.8's actual rule is
   gated on conversion rank, not representability: when the unsigned operand's rank is greater
   than or equal to the signed operand's rank - the ordinary case, e.g. `int` vs `size_t` - the
   signed operand converts to unsigned regardless of whether it could represent every unsigned
   value. Representability only decides the direction in the less common case where the signed
   operand's rank is strictly greater. `cwe/196/c/INDEX.md` in this repo carried the identical
   error until this sweep pass corrected it to state the rank-gated rule.
