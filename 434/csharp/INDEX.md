# CWE-434: Unrestricted Upload of File with Dangerous Type - C#

## LLM Guidance

ASP.NET Core receives uploads as `IFormFile` on an action method. The common mistake is validating on `IFormFile.ContentType` or the extension from `IFormFile.FileName`, both of which are supplied by the client in the multipart request and not verified by the framework. Validate the file's signature (magic bytes) from its actual stream, generate the storage filename with `Path.GetRandomFileName()`, and write outside `wwwroot`.

## Key Principles

- Do not gate validation on `IFormFile.ContentType` or the extension of `IFormFile.FileName` - both are client-supplied request metadata
- Read the file signature from `IFormFile.OpenReadStream()` and compare the leading bytes against known magic numbers for the allowed types (or use a library such as a maintained magic-byte/file-signature package)
- Configure `FormOptions.MultipartBodyLengthLimit` (and `[RequestSizeLimit]`/`[RequestFormLimits]` on the action) to bound upload size before the body is fully buffered
- Generate the stored filename with `Path.GetRandomFileName()`; never use `IFormFile.FileName` as the storage path
- Store files outside `wwwroot` (or any directory served by `UseStaticFiles`); serve them back through an authorized action that streams from private storage
- Re-encode images (e.g., via `System.Drawing` alternatives like `SixLabors.ImageSharp`, decode then re-save) before persisting, to strip embedded active content

## Remediation Steps

- Locate - Find the action method with an `IFormFile` (or `IFormFileCollection`) parameter that accepts the upload
- Trace data flow - Follow `ContentType` and `FileName` from the model binder through to storage and any action that serves the file back
- Replace the unsafe pattern - Remove any check that trusts `ContentType` or the `FileName` extension as the sole gate
- Bind, encode, validate, or authorize - Read the stream via `OpenReadStream()`, check the file signature against an allowlist, and reject on mismatch
- Break taint after allowlist validation - Use the signature-matched type and a `Path.GetRandomFileName()` value for storage, not the client-supplied `FileName`
- Harden configuration - Set `FormOptions.MultipartBodyLengthLimit`, and confirm the storage path is outside `wwwroot`
- Test - Verify rejection of files with a mismatched extension/signature pair, oversized files, and traversal sequences in `FileName`

## Safe Pattern

```csharp
// SAFE: file-signature validation, generated filename, storage outside wwwroot
using System.IO;
using System.Linq;

private static readonly Dictionary<string, byte[]> Signatures = new()
{
    [".png"] = new byte[] { 0x89, 0x50, 0x4E, 0x47 },
    [".jpg"] = new byte[] { 0xFF, 0xD8, 0xFF },
};

private static readonly string UploadDir = "/var/app-data/uploads"; // outside wwwroot

public async Task<string> StoreUploadAsync(IFormFile file)
{
    using var stream = file.OpenReadStream();
    var header = new byte[4];
    int read = await stream.ReadAsync(header, 0, header.Length);

    // SAFE: detect real type from the file's signature, not ContentType/FileName
    var match = Signatures.FirstOrDefault(sig =>
        read >= sig.Value.Length && header.Take(sig.Value.Length).SequenceEqual(sig.Value));

    if (match.Key is null)
    {
        throw new InvalidOperationException("Unsupported file type");
    }

    var storedName = Path.GetRandomFileName() + match.Key;
    var targetPath = Path.Combine(UploadDir, storedName);

    stream.Seek(0, SeekOrigin.Begin);
    await using var output = new FileStream(targetPath, FileMode.CreateNew);
    await stream.CopyToAsync(output);

    return storedName;
}
```
