#!/usr/bin/env node

// Validate and decrypt an envelope for local/CI checks without printing its contents.

const fs = require('node:fs');
const crypto = require('node:crypto');

const envelopePath = process.argv[2];
const keyText = process.env.CONFIG_ENCRYPTION_KEY_B64;

function fail(message) {
  process.stderr.write(`verify-encrypted-config: ${message}\n`);
  process.exitCode = 1;
}

if (!envelopePath || !keyText) {
  fail('usage: CONFIG_ENCRYPTION_KEY_B64=<base64> node tools/verify-encrypted-config.js <config.json>');
} else {
  try {
    const key = Buffer.from(keyText, 'base64');
    if (key.length !== 32) throw new Error('key must decode to 32 bytes');
    const envelope = JSON.parse(fs.readFileSync(envelopePath, 'utf8'));
    const expected = ['format', 'keyId', 'nonce', 'ciphertext', 'tag'];
    if (JSON.stringify(Object.keys(envelope).sort()) !== JSON.stringify(expected.sort())) {
      throw new Error('envelope fields do not match psm-config-v1');
    }
    if (envelope.format !== 'psm-config-v1' || envelope.keyId !== 1) {
      throw new Error('unsupported format or keyId');
    }
    const nonce = Buffer.from(envelope.nonce, 'base64');
    const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
    const tag = Buffer.from(envelope.tag, 'base64');
    if (nonce.length !== 12 || tag.length !== 16 || ciphertext.length === 0) {
      throw new Error('invalid nonce, ciphertext, or tag length');
    }
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
    // Must match Unity RemoteConfigEncryption.BuildAssociatedData exactly.
    decipher.setAAD(Buffer.from('psm-config-v1|' + envelope.keyId, 'utf8'));
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
    JSON.parse(plaintext);
    process.stdout.write('encrypted config verification: PASS\n');
  } catch (error) {
    fail(error instanceof SyntaxError ? 'envelope or decrypted plaintext is not valid JSON' : error.message);
  }
}
