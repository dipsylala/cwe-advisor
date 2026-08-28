# CWE-502: Deserialization of Untrusted Data - C#

## LLM Guidance

Insecure deserialization in .NET occurs when untrusted data is deserialized using unsafe formatters like BinaryFormatter, NetDataContractSerializer, or ObjectStateFormatter, enabling remote code execution through arbitrary type instantiation. The core fix is to avoid deserializing untrusted data entirely, or use safe serializers like System.Text.Json with strict type controls.

## Key Principles

- Replace `BinaryFormatter`, `NetDataContractSerializer`, and `ObjectStateFormatter` with `System.Text.Json` or `DataContractSerializer` - these have no safe configuration, and Microsoft states `BinaryFormatter` cannot be made secure rather than merely being risky
- Establish which target framework the code builds for before proposing the fix: `BinaryFormatter` is obsolete from .NET 5, and from .NET 9 the in-box implementation throws on use with the compatibility switches that previously re-enabled it removed. On .NET 9+ the finding is a runtime failure rather than a live vulnerability, and re-enabling is not an option to offer
- Never use `Newtonsoft.Json` with `TypeNameHandling` set to `All`, `Objects`, or `Auto` on untrusted input; use `TypeNameHandling.None` (the default)
- Allowlist types explicitly: if polymorphic deserialization is unavoidable with Newtonsoft.Json, pair `TypeNameHandling` with a `SerializationBinder` that restricts to known types
- Apply input validation after deserialization when using safe serializers like `System.Text.Json`
- `LosFormatter` and unprotected `__VIEWSTATE` are the ASP.NET-specific sinks: keep `ViewStateMac`/`ViewStateEncryptionMode` enabled and the machine key secret, since a deserializable ViewState is remote code execution
- `XmlSerializer` is safe only when the type is fixed at compile time - a type name resolved from input via `Type.GetType()` puts the attacker back in control of what is constructed
- Where a binder is unavoidable, implement `SerializationBinder.BindToType` as an allowlist and `BindToName` to keep assembly-qualified names out of the payload

## Taint Sinks

`BinaryFormatter.Deserialize()`, `NetDataContractSerializer.Deserialize()`, `ObjectStateFormatter.Deserialize()`, `SoapFormatter.Deserialize()`, `JsonConvert.DeserializeObject()` with `TypeNameHandling`

## Remediation Steps

- Identify all deserialization points: `BinaryFormatter`, `NetDataContractSerializer`, `SoapFormatter`, `ObjectStateFormatter`, and `JsonConvert.DeserializeObject` with `TypeNameHandling` set to anything other than `None`
- Replace unsafe formatters with `System.Text.Json` for JSON or `DataContractSerializer` for XML with known types configured
- For Newtonsoft.Json with `TypeNameHandling` enabled: either remove `TypeNameHandling` entirely, or implement a `SerializationBinder` that allowlists permitted types
- Add HMAC-based integrity validation to verify data has not been tampered with before deserialization
- Run static analysis tools to detect remaining unsafe deserialization usage
