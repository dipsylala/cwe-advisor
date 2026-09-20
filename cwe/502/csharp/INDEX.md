# CWE-502: Deserialization of Untrusted Data - C#

## LLM Guidance

Insecure deserialization in .NET occurs when untrusted data is deserialized using unsafe formatters like BinaryFormatter, NetDataContractSerializer, or ObjectStateFormatter, enabling remote code execution through arbitrary type instantiation. The core fix is to avoid deserializing untrusted data entirely, or use safe serializers like System.Text.Json with strict type controls.

## Key Principles

- Replace `BinaryFormatter`, `NetDataContractSerializer`, and `ObjectStateFormatter` with `System.Text.Json` or `DataContractSerializer` - these have no safe configuration, and Microsoft states `BinaryFormatter` cannot be made secure rather than merely being risky. Ask who writes the payloads first: that swap only works where the same change owns the producer, and Microsoft's own migration guide covers the other case with `System.Formats.Nrbf` - `NrbfDecoder.Decode` reads an NRBF payload without loading or instantiating any encoded type, so stored rows and externally produced bytes can be read with `StartsWithPayloadHeader` and rewritten under the new serializer rather than rejected
- Establish which target framework the code builds for before proposing the fix: `BinaryFormatter` is obsolete from .NET 5, and from .NET 9 the in-box implementation always throws `PlatformNotSupportedException`. The compatibility switch was not removed - it is no longer sufficient on its own, and a project can still restore the behaviour with the unsupported `System.Runtime.Serialization.Formatters` package alongside `EnableUnsafeBinaryFormatterSerialization`. So on .NET 9+ the finding is a runtime failure rather than a live vulnerability unless that package is present, in which case it is live again and the package is the thing to remove. The reverse holds on .NET Framework 4.8, which is still supported and where the same code is fully exploitable - so the runtime decides whether this is urgent or already dead
- Never use `Newtonsoft.Json` with `TypeNameHandling` set to `All`, `Objects`, or `Auto` on untrusted input; use `TypeNameHandling.None` (the default)
- Allowlist types explicitly: if polymorphic deserialization is unavoidable with Newtonsoft.Json, pair `TypeNameHandling` with an `ISerializationBinder` assigned to `JsonSerializerSettings.SerializationBinder` that restricts to known types - the `Binder` property taking a `System.Runtime.Serialization.SerializationBinder` is the obsolete one
- Apply input validation after deserialization when using safe serializers like `System.Text.Json`
- `LosFormatter` and unprotected `__VIEWSTATE` are the ASP.NET-specific sinks: keep `ViewStateMac`/`ViewStateEncryptionMode` enabled and the machine key secret, since a deserializable ViewState is remote code execution
- `XmlSerializer` is safe only when the type is fixed at compile time - a type name resolved from input via `Type.GetType()` puts the attacker back in control of what is constructed
- Where a binder is unavoidable, implement `ISerializationBinder.BindToType` as an allowlist and `BindToName` to keep assembly-qualified names out of the payload

## Taint Sinks

`BinaryFormatter.Deserialize()`, `NetDataContractSerializer.Deserialize()`, `ObjectStateFormatter.Deserialize()`, `SoapFormatter.Deserialize()`, `JsonConvert.DeserializeObject()` with `TypeNameHandling`

## Remediation Steps

- Identify all deserialization points: `BinaryFormatter`, `NetDataContractSerializer`, `SoapFormatter`, `ObjectStateFormatter`, and `JsonConvert.DeserializeObject` with `TypeNameHandling` set to anything other than `None`
- Replace unsafe formatters with `System.Text.Json` for JSON or `DataContractSerializer` for XML with known types configured
- For Newtonsoft.Json with `TypeNameHandling` enabled: either remove `TypeNameHandling` entirely, or implement an `ISerializationBinder` that allowlists permitted types
- Add HMAC-based integrity validation to verify data has not been tampered with before deserialization
- Run static analysis tools to detect remaining unsafe deserialization usage
