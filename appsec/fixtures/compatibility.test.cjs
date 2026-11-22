// SPDX-License-Identifier: MIT
const assert = require('node:assert/strict')
const { test } = require('node:test')
const parse = require('minimist')

test('parses regular boolean flags and positional arguments', () => {
  assert.deepEqual(parse(['--verbose', 'report'], { boolean: ['verbose'] }), {
    _: ['report'],
    verbose: true
  })
})
