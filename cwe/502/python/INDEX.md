# CWE-502: Deserialization of Untrusted Data - Python

## LLM Guidance

Python's `pickle` module executes arbitrary code during deserialization, enabling remote code execution when unpickling untrusted data. Attackers craft malicious pickle payloads that invoke `__reduce__` or `__setstate__` methods to run system commands. Primary fix: Replace pickle with JSON (`json.loads()`), MessagePack, or Protocol Buffers for all untrusted data.

## Key Principles

- Never use `pickle.loads()`, `pickle.load()`, `marshal.loads()`, `shelve`, or `pd.read_pickle()` with untrusted data
- Replace pickle with JSON for object serialization (requires manual object reconstruction)
- Use `yaml.safe_load()` instead of `yaml.load()` or `yaml.unsafe_load()`
- For pandas DataFrames, use CSV, Parquet, or Feather formats instead of pickle
- A restricted `Unpickler` overriding `find_class` narrows what can be constructed, but Python's own
  documentation stops short of calling it safe and redirects to alternatives - so treat it as a last
  resort for a trusted-but-tampered channel, not a licence to accept untrusted pickles, and pair it
  with an `hmac` signature, which addresses tampering but not trust in the producer
- The `Loader=` argument decides safety, not the function name: `yaml.load(data, Loader=yaml.Loader)` and `yaml.full_load()` construct objects, while `yaml.safe_load()` does not. `FullLoader` was intended to be safe and was not: PyYAML's own note records that trivial exploits remained as of 5.3.1, so set the floor at 5.4 if any code relies on it and prefer `safe_load` regardless
- Check the installed PyYAML version before treating a bare `yaml.load(data)` as live: 5.1 deprecated the Loader-less call and warns, and 6.0 made `Loader` a required argument, so on 6.0+ that call raises `TypeError` and never reaches a parser

## Taint Sinks

`pickle.loads()`, `pickle.load()`, `marshal.loads()`, `shelve.open()`, `yaml.load()`, `yaml.unsafe_load()`, `pd.read_pickle()`

## Remediation Steps

- Identify all deserialization calls (`pickle.loads()`, `pd.read_pickle()`, `yaml.load()`, etc.)
- Replace with safe alternatives - `json.loads()` for objects, `pd.read_parquet()` for DataFrames
- Update file extensions and storage mechanisms (`.pkl` → `.json` or `.parquet`)
- Manually reconstruct objects from deserialized dictionaries with validation
- For Django sessions, confirm rather than set `SESSION_SERIALIZER` - JSON has been the default since
  1.6, and `PickleSerializer` was deprecated in 4.1 and removed in 5.0, so on a current version this
  is a no-op and a finding here means the project pinned the pickle serializer deliberately
- Test that legitimate data flows work correctly with new serialization format
