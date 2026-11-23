// SPDX-License-Identifier: MIT
const assert = require('node:assert/strict')
const { pbkdf2Sync } = require('node:crypto')
const { test } = require('node:test')
const { PBKDF2 } = require('crypto-js')

test('CVE-2023-46233 — default PBKDF2 matches the advisory’s defensive parameters', () => {
  const passphrase = 'public test passphrase'
  const salt = 'public test salt'
  const expected = pbkdf2Sync(passphrase, salt, 250_000, 16, 'sha256').toString('hex')
  assert.ok(PBKDF2(passphrase, salt).toString() === expected,
    'Default PBKDF2 output must match the SHA-256 reference at 250,000 iterations')
})
