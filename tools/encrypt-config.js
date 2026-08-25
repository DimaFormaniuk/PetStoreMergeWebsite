#!/usr/bin/env node

// Encrypt a private Remote Config source into the single public envelope.
// The key is supplied only through CONFIG_ENCRYPTION_KEY_B64 and is never logged.

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const inputPath = process.argv[2];
const outputPath = process.argv[3] || path.resolve(__dirname, '..', 'config', 'config.json');
const keyText = process.env.CONFIG_ENCRYPTION_KEY_B64;

function fail(message) {
  process.stderr.write(`encrypt-config: ${message}\n`);
  process.exitCode = 1;
}

if (!inputPath) {
  fail('usage: node tools/encrypt-config.js <private-plaintext-json> [output-path]');
} else if (!keyText) {
  fail('CONFIG_ENCRYPTION_KEY_B64 is required');
} else {
  try {
    const key = Buffer.from(keyText, 'base64');
    if (key.length !== 32) throw new Error('CONFIG_ENCRYPTION_KEY_B64 must decode to 32 bytes');

    const plaintextText = fs.readFileSync(inputPath, 'utf8');
    const plaintext = JSON.parse(plaintextText);
    const canonicalPlaintext = JSON.stringify(plaintext);
    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
    // Must match Unity RemoteConfigEncryption.BuildAssociatedData exactly.
    cipher.setAAD(Buffer.from('psm-config-v1|1', 'utf8'));
    const ciphertext = Buffer.concat([
      cipher.update(Buffer.from(canonicalPlaintext, 'utf8')),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();
    if (tag.length !== 16) throw new Error('AES-GCM authentication tag must be 16 bytes');

    const envelope = {
      format: 'psm-config-v1',
      keyId: 1,
      nonce: nonce.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      tag: tag.toString('base64'),
    };
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(outputPath, `${JSON.stringify(envelope, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
    process.stdout.write(`encrypted config written: ${path.relative(process.cwd(), outputPath)}\n`);
  } catch (error) {
    fail(error instanceof SyntaxError ? 'plaintext source is not valid JSON' : error.message);
  }
}
