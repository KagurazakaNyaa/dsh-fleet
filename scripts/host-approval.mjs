import assert from 'node:assert/strict'
import http from 'node:http'
import { mkdtemp, rm } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

const home = await mkdtemp(path.join(os.tmpdir(), 'dsh-fleet-approval-'))
process.env.DSH_HOME = home
process.env.DSH_FLEET_PORT = '3075'

const { apply } = await import('../index.js')

const routes = new Map()
const handlers = new Map()
const disposers = []
const prompts = []
const fakeSession = { seq: 0, snapshotEvents: () => [] }

const ctx = {
  effect(fn) {
    const disposer = fn()
    if (typeof disposer === 'function') disposers.push(disposer)
    return disposer
  },
  get(name) {
    if (name === 'connection') return { authenticatedUrl: (base) => `${base}?token=approval-token` }
    if (name === 'workspaceRegistry') return { list: () => [{ id: 'ws-1', title: 'One', path: '/srv/one' }] }
    if (name === 'sessionController') {
      return {
        async create() {
          return { sessionId: 's-1' }
        },
        async prompt(request) {
          prompts.push(request)
          return { accepted: true }
        },
        async list() {
          return { items: [] }
        },
      }
    }
    if (name === 'sessions') return { get: (id) => (id === 's-1' ? fakeSession : undefined) }
    if (name === 'agents') return { get: () => undefined }
    return undefined
  },
  on(event, handler) {
    handlers.set(event, handler)
    return () => handlers.delete(event)
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
const base = `http://127.0.0.1:${server.address().port}/api/dsh-fleet`

async function call(pathname, body) {
  const response = await fetch(`${base}${pathname}`, body === undefined
    ? { headers: { accept: 'application/json' } }
    : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
  const text = await response.text()
  if (!response.ok) throw new Error(`${pathname} -> ${response.status} ${text}`)
  return text === '' ? null : JSON.parse(text)
}

try {
  let identity = null
  for (let attempt = 0; attempt < 40; attempt += 1) {
    identity = await call('/identity')
    if (identity.listener.port !== 0) break
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  await call('/pair', { address: '127.0.0.1:3075', code: identity.pairingCode })
  await call('/peers/session-access', { deviceId: identity.deviceId, allow: true })
  console.log('ok self-paired')

  const task = await call('/peers/task', { deviceId: identity.deviceId, workspaceId: 'ws-1', text: 'run it' })
  assert.equal(task.sessionId, 's-1')
  assert.equal(prompts.length, 1)
  console.log('ok task created')

  const approvalHandler = handlers.get('approval/request')
  assert.equal(typeof approvalHandler, 'function')

  const decision = approvalHandler({ agent: { id: 's-1' }, toolName: 'bash', reason: 'rm -rf build' }, async () => 'unavailable')
  assert.ok(decision instanceof Promise)

  const pending = await call('/peers/task/poll', { taskId: task.taskId })
  assert.equal(pending.approvals.length, 1)
  assert.equal(pending.approvals[0].toolName, 'bash')
  assert.equal(pending.approvals[0].sessionId, 's-1')
  console.log('ok approval surfaced to the hub')

  await call('/peers/task/approve', { taskId: task.taskId, approvalId: pending.approvals[0].id, outcome: 'allowed-once' })
  assert.equal(await decision, 'allowed-once')
  console.log('ok remote approval decided the request')

  const after = await call('/peers/task/poll', { taskId: task.taskId })
  assert.equal(after.approvals.length, 0)

  const fallthrough = await approvalHandler({ agent: { id: 'local-session' }, toolName: 'bash' }, async () => 'rejected')
  assert.equal(fallthrough, 'rejected')
  console.log('ok non-fleet sessions still go to the local answerer')

  await call('/peers/delete', { deviceId: identity.deviceId })
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

console.log('host approval: all checks passed')
process.exit(0)
