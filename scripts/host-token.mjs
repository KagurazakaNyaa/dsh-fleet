import assert from 'node:assert/strict'
import http from 'node:http'
import { mkdtemp, rm } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

const home = await mkdtemp(path.join(os.tmpdir(), 'dsh-fleet-test-'))
process.env.DSH_HOME = home
process.env.DSH_FLEET_PORT = '3072'

const TOKEN = 'token-from-headless-dsh'
const { apply } = await import('../index.js')

const routes = new Map()
const disposers = []
const ctx = {
  effect(fn) {
    const disposer = fn()
    if (typeof disposer === 'function') disposers.push(disposer)
    return disposer
  },
  get(name) {
    if (name === 'connection') {
      return { authenticatedUrl: (base) => `${base}?token=${TOKEN}` }
    }
    if (name === 'workspaceRegistry') {
      return { list: () => [{ id: 'ws-local', title: 'Local', path: '/srv/local' }] }
    }
    return undefined
  },
  webServer: {
    port: 5999,
    register(route) {
      routes.set(route.path, route)
      return () => routes.delete(route.path)
    },
  },
}

apply(ctx)

const server = http.createServer((req, res) => {
  const pathname = new URL(req.url || '/', 'http://localhost').pathname
  const route = routes.get(pathname)
  if (!route) {
    res.statusCode = 404
    res.end()
    return
  }
  route.handler(req, res)
})
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
const localBase = `http://127.0.0.1:${server.address().port}/api/dsh-fleet`

async function call(pathname, body) {
  const response = await fetch(`${localBase}${pathname}`, body === undefined
    ? { headers: { accept: 'application/json' } }
    : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
  const text = await response.text()
  const data = text === '' ? null : JSON.parse(text)
  if (!response.ok) throw new Error(`${pathname} -> ${response.status} ${text}`)
  return data
}

try {
  let identity = null
  for (let attempt = 0; attempt < 40; attempt += 1) {
    identity = await call('/identity')
    if (identity.listener.port !== 0) break
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  assert.equal(identity.tokenAvailable, true)
  assert.equal(identity.listener.port, 3072)
  console.log('ok host read its own dsh web token')

  const paired = await call('/pair', { address: '127.0.0.1:3072', token: TOKEN })
  assert.equal(paired.peer.deviceId, identity.deviceId)
  console.log('ok token pairing accepted by the real host code')

  const peers = await call('/peers')
  assert.equal(peers.peers.length, 1)
  console.log('ok peer recorded')

  const rejected = await fetch(`${localBase}/pair`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ address: '127.0.0.1:3072', token: 'wrong-token' }),
  })
  assert.equal(rejected.status, 400)
  console.log('ok wrong token rejected by the host')

  const workspaces = await call('/workspaces')
  assert.deepEqual(workspaces.workspaces.map((item) => item.id), ['ws-local'])
  console.log('ok local workspace catalog served')

  await call('/peers/delete', { deviceId: identity.deviceId })
  console.log('ok cleanup')
} finally {
  await new Promise((resolve) => server.close(resolve))
  for (const dispose of disposers) {
    try {
      await dispose()
    } catch {
      // ignore
    }
  }
  await rm(home, { recursive: true, force: true })
}

console.log('host token pairing: all checks passed')
