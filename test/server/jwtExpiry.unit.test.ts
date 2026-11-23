// SPDX-License-Identifier: MIT
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { randomBytes } from 'node:crypto'
import { test } from 'node:test'

const middleware = require('express-jwt')
const jwt = createRequire(require.resolve('express-jwt'))('jsonwebtoken')

test('express-jwt accepts a current signed token and rejects an expired one', async () => {
  const secret = randomBytes(32).toString('hex')
  const verify = middleware({ secret })
  for (const minutes of [5, -5]) {
    const token = jwt.sign({ sub: 'clock-test' }, secret, { expiresInMinutes: minutes })
    const req = { method: 'GET', headers: { authorization: `Bearer ${token}` }, user: undefined as { sub: string } | undefined }
    const result = new Promise<void>((resolve, reject) => {
      verify(req, {}, (err?: Error) => err == null ? resolve() : reject(err))
    })
    if (minutes > 0) {
      await result
      assert.equal(req.user?.sub, 'clock-test')
    } else {
      await assert.rejects(result, /expired/i)
      assert.equal(req.user, undefined)
    }
  }
})
