# Encrypted Remote Config pipeline

`tools/encrypt-config.js` converts a private JSON authoring source into the
single public `config/config.json` AES-256-GCM envelope. Supply the 32-byte
key only through `CONFIG_ENCRYPTION_KEY_B64`; the tool never prints the key or
plaintext.

```powershell
$env:CONFIG_ENCRYPTION_KEY_B64 = '<base64 for the injected 32-byte key>'
node tools/encrypt-config.js private-config/config.plaintext.json config/config.json
node tools/verify-encrypted-config.js config/config.json
Remove-Item Env:CONFIG_ENCRYPTION_KEY_B64
```

The nonce is freshly generated as 12 bytes for every run and the GCM tag is
16 bytes. The public envelope contains only `format`, `keyId`, `nonce`,
`ciphertext`, and `tag`. The private source is intentionally gitignored and
must not be deployed. Production key provisioning remains an external
release/build-secret concern; no key is stored in this repository.
