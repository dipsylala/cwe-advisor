# CWE-502: Insecure Deserialization - C\# / .NET

## LLM Guidance

Insecure deserialization in .NET occurs when untrusted data is deserialized using unsafe formatters like BinaryFormatter, NetDataContractSerializer, or ObjectStateFormatter, enabling remote code execution through arbitrary type instantiation. The core fix is to avoid deserializing untrusted data entirely, or use safe serializers like System.Text.Json with strict type controls.

## Key Principles

- Replace `BinaryFormatter`, `NetDataContractSerializer`, and `ObjectStateFormatter` with `System.Text.Json` or `DataContractSerializer` — these have no safe configuration
- Never use `Newtonsoft.Json` with `TypeNameHandling` set to `All`, `Objects`, or `Auto` on untrusted input; use `TypeNameHandling.None` (the default)
- Allowlist types explicitly: if polymorphic deserialization is unavoidable with Newtonsoft.Json, pair `TypeNameHandling` with a `SerializationBinder` that restricts to known types
- Apply input validation after deserialization when using safe serializers like `System.Text.Json`

## Remediation Steps

- Identify all deserialization points: `BinaryFormatter`, `NetDataContractSerializer`, `SoapFormatter`, `ObjectStateFormatter`, and `JsonConvert.DeserializeObject` with `TypeNameHandling` set to anything other than `None`
- Replace unsafe formatters with `System.Text.Json` for JSON or `DataContractSerializer` for XML with known types configured
- For Newtonsoft.Json with `TypeNameHandling` enabled: either remove `TypeNameHandling` entirely, or implement a `SerializationBinder` that allowlists permitted types
- Add HMAC-based integrity validation to verify data has not been tampered with before deserialization
- Run static analysis tools to detect remaining unsafe deserialization usage

## Safe Pattern

```csharp
// SAFE: System.Text.Json — no type resolution by default (.NET Core 3.0+)
var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
UserData user = JsonSerializer.Deserialize<UserData>(jsonInput, options);

// SAFE: Newtonsoft.Json — TypeNameHandling.None (the default; state it explicitly)
var settings = new JsonSerializerSettings
{
    TypeNameHandling = TypeNameHandling.None
};
UserData user = JsonConvert.DeserializeObject<UserData>(jsonInput, settings);
```
