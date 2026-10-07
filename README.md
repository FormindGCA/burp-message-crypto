# BO Message Crypto for Burp Suite

A Java/Montoya extension for inspecting form/XML business-object messages with
selected encrypted values. It adds a **Message Crypto** configuration tab and
custom request/response editor tabs. Cryptography uses Java's standard JCE providers.

The default profile is **AES / ECB / zero padding / UTF-8 / hex / `ENC:`**.
The shared key is **blank** until you configure it. No application-specific key
is embedded in the extension.

## Build and install

From the project directory:

```sh
nix develop --command mvn package
```

Or use Maven and JDK 17+ directly:

```sh
mvn package
```

In Burp Suite Community or Professional:

1. Open **Extensions -> Installed -> Add**.
2. Select extension type **Java**.
3. Select **`target/burp-message-crypto-0.1.0.jar`**.
4. Open the **Message Crypto** suite tab and configure the profile.

Compiled against Montoya API **2025.2** and Java 17. Use a Burp version supporting
that API. The shaded JAR contains Jackson under a private namespace; the Montoya
API itself is provided by Burp and is not bundled.

## Proxy setup

HTTP messages can be intercepted once the client routes its requests through
Burp's proxy listener. For HTTPS, the client must also trust the Burp CA certificate
in the certificate store used by that client/runtime.

For a Windows .NET Framework client using `HttpWebRequest`, Windows proxy settings
or an application-level `system.net/defaultProxy` setting are usual options.
A configuration example is:

```xml
<configuration>
  <system.net>
    <defaultProxy enabled="true">
      <proxy proxyaddress="http://127.0.0.1:8080"
             usesystemdefault="false" bypassonlocal="false" />
    </defaultProxy>
  </system.net>
</configuration>
```

Merge the section into the client's existing configuration rather than replacing
that file. The proxy address must be reachable **from the client process**;
loopback is appropriate only when Burp runs on that same host. For a remotely
hosted desktop/session, configure the listener address and client proxy accordingly.

Export Burp's CA certificate and install it in the Windows trusted-root store
used by the client account, then restart the client if needed. Certificate pinning,
mutual TLS, application-specific proxies, and deployment policy can require
additional setup. This extension operates on messages Burp already sees; it does
not change the client's proxy or certificate configuration.

TLS interception reveals the HTTP form/XML body. Application-level encrypted
fields still require the matching crypto profile and key.

## Configure cryptography

| Setting | Choices / meaning |
|---|---|
| Algorithm | AES or DESede (TripleDES) |
| Mode | ECB, CBC, or GCM |
| Padding | ZERO, PKCS7, or NONE |
| Ciphertext format | HEX or BASE64, with configurable prefix |
| Shared key encoding | UTF8 literal, HEX bytes, or BASE64 bytes |
| IV/nonce encoding | HEX, BASE64, or UTF8 |
| Plaintext charset | Java charset name, normally UTF-8 |
| GCM AAD | Optional UTF-8 additional authenticated data |
| Path regex | Determines which request/response editor tabs are offered |

Key sizes are byte lengths after decoding: AES accepts 16/24/32 bytes; DESede
requires 24 bytes. CBC requires a 16-byte AES IV or an 8-byte DESede IV. ECB
does not use an IV. Java's `PKCS5Padding` implements the selected PKCS7-compatible
block padding. ZERO adds padding only to an incomplete block and strips trailing
NUL characters after text decryption; original trailing NULs are indistinguishable
from padding.

The key is used directly, without a password KDF. HEX means a hexadecimal
representation of key bytes, not an ASCII hex string used as the key. The default
legacy profile's format is:

```text
ENC: + hex(AES-ECB(plaintext encoded as UTF-8, zero-padded))
```

Click **Apply configuration** before opening messages. Existing editor tabs keep
the profile captured when their message was opened so a later configuration
change cannot silently switch the key used for a pending edit. Reopen/reselect a
message to use a new profile. The extension does not save keys to Burp preferences
or files. **Clear shared key and scratchpad** clears the active profile/input;
already-open message snapshots retain their captured profile until discarded.

### IV framing and GCM

CBC uses the configured IV; no IV is automatically prepended, extracted, or
generated. Set it to the value required by the message being inspected.

GCM accepts a 12-byte nonce, NONE padding, and a 128-bit authentication tag appended
to the ciphertext (Java JCE's format). It supports decryption in editors and
manual encryption in the scratchpad. **Automatic GCM re-encryption is refused**
because the current generic editor cannot update a protocol-specific nonce field.
For manual GCM encryption, configure a fresh nonce and place both the resulting
ciphertext/tag and the nonce into the protocol's appropriate wire fields.

ECB/zero-padded formats have no authentication tag; a successfully decoded string
alone cannot establish that a key or payload is correct.

## Edit requests and responses

By default, tabs are enabled for paths ending in `/MessageHandler` or
`/RealtimeHandler`, optionally with `.aspx`. Adjust the path regex for other handlers.

Open **Message Crypto** in a request or response editor. The view is an editable
JSON document:

```json
{
  "fields": [
    {"id": "form.0", "label": "action", "value": "createetk", "encrypted": false, "locked": false},
    {"id": "form.1", "label": "password", "value": "demo-password", "encrypted": true, "locked": false}
  ]
}
```

The real document also includes instructions and warnings. Edit **`value`** to
change plaintext. Keep **`encrypted: true`** to re-encrypt the changed value.
Setting it to false intentionally emits plaintext; setting it to true on a plain
field applies encryption. Keep the original IDs and fields array.

- Form parameter IDs preserve ordering and distinguish duplicate parameter names.
- A `msg` parameter shows its URL-decoded XML as a parent field. Individual
  `ENC:` literals also appear as decrypted child fields, such as
  `form.2.cipher.0`.
- To change an encrypted XML value, edit its child field. To edit ordinary XML
  structure/text, edit the parent field. Do not edit a parent and its children in
  the same operation; the extension rejects that ambiguous combination.
- Whole encrypted form values/body values are also supported.
- Responses expose a parent `body` field and any embedded encrypted spans.
- Fields that cannot be decrypted are **locked** and retain their original wire
  value; warnings explain the failed operation. Configure the correct profile
  and reopen the message to unlock them.

Unchanged messages return the exact original HTTP object. Within changed forms,
unchanged parameters preserve their original escaping and bytes. Changed nested
spans are replaced in their original positions without parsing/reformatting the
whole XML document. Body updates are passed through Montoya's `withBody` API.

Invalid JSON, unknown IDs, overlapping edits, locked-field edits, and crypto
errors return the original message and display a red **EDITS NOT APPLIED** banner.
Read-only Burp editor contexts remain read-only. The extension registers editor
providers, not an automatic proxy rewriting handler: traffic is changed only by
explicit edits in an editable context, such as Repeater or an intercepted message.

The manual scratchpad accepts plaintext for encryption or prefixed ciphertext for
decryption, using the applied profile.

## Synthetic local demo

The packaged JAR includes an independent loopback demo server. It uses a public
synthetic test key, not a key from any application.

```sh
# Keep this running in a terminal:
nix develop --command java -cp target/burp-message-crypto-0.1.0.jar \
  local.messagecrypto.DemoServer

# Print a complete sample HTTP request in another terminal:
nix develop --command java -cp target/burp-message-crypto-0.1.0.jar \
  local.messagecrypto.DemoServer --sample
```

The server listens on `127.0.0.1:18080`. Paste the sample into Burp Repeater and
set the target to that HTTP endpoint. Configure:

```text
AES / ECB / ZERO / HEX / UTF-8 / prefix ENC:
Key encoding: HEX
Synthetic key: 000102030405060708090a0b0c0d0e0f
```

The password field should display `demo-password`. Change its `value`, send the
request, then inspect the response tab: the encrypted `Echo` field should decrypt
to the edited password. The server does not log received plaintext.

## Validation and limits

```sh
nix develop --command mvn test
nix develop --command python3 scripts/check_jar.py
nix develop --command python3 scripts/demo_smoke.py
```

Tests cover known-answer AES and GCM vectors, padding/charset behavior,
AES-CBC/TripleDES round-trips, GCM tag rejection, loss-preserving form/XML edits,
duplicate parameters, locked fields, invalid edits, immutable profile snapshots,
and request adapters against mocked Montoya interfaces. The demo smoke test
exercises the packaged synthetic server over actual loopback HTTP.

The extension has been compiled against the real Montoya API and tested with
mocked editor interfaces; loading it into an actual Burp session and testing with
a real application is still a live verification step.

Current limits:

- HTTP bodies only: headers and URL query parameters use Burp's ordinary editors.
- Automatic crypto discovery uses contiguous prefixed HEX/Base64 literals, not
  arbitrary encrypted blobs, encrypted field-name schemas, XML-escaped prefixes,
  or unprefixed ciphertext.
- It is a literal-span editor, not a schema-aware XML editor. For unusual contexts
  such as CDATA/comments or protocol-specific escaping, use the parent/raw editor
  and inspect the resulting wire representation.
- Compressed bodies are not offered in the custom tabs. Request an uncompressed
  response or handle decompression separately in Burp.
- Text must decode correctly in the declared HTTP charset (default UTF-8).
- Editor bodies are limited to 2 MiB and 2,048 fields.
- No automatic IV framing, key derivation, signing, server-side validation, or
  native encryption-library invocation is implemented.

Dependencies and plugin versions are pinned in `pom.xml`; Nix development tools
are pinned in `flake.lock`. Maven needs access to Maven Central on the first build.
