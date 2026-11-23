// SPDX-License-Identifier: MIT
const assert = require('node:assert/strict')
const { pbkdf2Sync } = require('node:crypto')
const { test } = require('node:test')
const { PBKDF2 } = require('crypto-js')

const fixtures = new Map([
  ['ascii', ['public test passphrase', 'public test salt']],
  ['unicode', ['café public', 'sel public Ω']]
])
const fixture = process.argv[2] ?? 'ascii'
assert.ok(fixtures.has(fixture), 'Unknown public test fixture')
const [passphrase, salt] = fixtures.get(fixture)

test(`CVE-2023-46233 — default PBKDF2 matches the reference for fixture ${fixture}`, () => {
  const expected = pbkdf2Sync(passphrase, salt, 250_000, 16, 'sha256').toString('hex')
  assert.ok(PBKDF2(passphrase, salt).toString() === expected,
    'Default PBKDF2 output must match the SHA-256 reference at 250,000 iterations')
})
