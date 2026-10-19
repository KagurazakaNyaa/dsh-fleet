import assert from 'node:assert/strict'
import http from 'node:http'
import { mkdtemp, rm } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

const home = await mkdtemp(path.join(os.tmpdir(), 'dsh-fleet-task-'))
process.env.DSH_HOME = home
process.env.DSH_FLEET_PORT = '3074'

const TOKEN = 'task-test-token'
const { apply } = await import('../index.js')

const routes = new Map()
const disposers = []
const prompts = []
const events = [
  { seq: 0, type: 'user/message', data: { content: [{ type: 'text', text: 'hi' }] } },
  { seq: 1, type: 'assistant/message', data: { message: { content: [{ type: 'text', text: 'hello there' }] } } },
  { seq: 2, type: 'turn/end', data: { reason: { kind: 'completed' } } },
]
const fakeSession = {
  seq: 2,
  snapshotEvents(from, to) {
    return events.filter((event) => event.seq >= from && event.seq < to)
  },
}

const ctx = {
  effect(fn) {
    const disposer = fn()
    if (typeof disposer === 'function') disposers.push(disposer)
    return disposer
  },
  get(name) {
    if (name === 'connection') return { authenticatedUrl: (base) => `${base}?token=${TOKEN}` }
    if (name === 'workspaceRegistry') return { list: () => [{ id: 'ws-1', title: 'One', path: '/srv/one' }] }
    if (name === 'sessionController') {
      return {
        async create({ workspaceId }) {
          assert.equal(workspaceId, 'ws-1')
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
  on() {
    return () => {}
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
  assert.equal(identity.listener.port, 3074)

  await call('/pair', { address: '127.0.0.1:3074', code: identity.pairingCode })
  await call('/peers/ui-access', { deviceId: identity.deviceId, allow: true })
  await call('/peers/session-access', { deviceId: identity.deviceId, allow: true })
  console.log('ok self-paired with both grants')

  const opened = await call('/peers/ui', { deviceId: identity.deviceId })
  assert.match(opened.url, /^http:\/\/127\.0\.0\.1:\d+\/$/)
  assert.match(opened.loginUrl, /token=task-test-token/)
  console.log('ok ui proxy url carries the owner token')

  const task = await call('/peers/task', { deviceId: identity.deviceId, workspaceId: 'ws-1', text: 'do the thing' })
  assert.equal(task.sessionId, 's-1')
  assert.equal(prompts.length, 1)
  assert.deepEqual(prompts[0].content, [{ type: 'text', text: 'do the thing' }])
  console.log('ok hub task created and prompted the owner')

  const poll = await call('/peers/task/poll', { taskId: task.taskId })
  assert.deepEqual(poll.messages.map((frame) => frame.role), ['user', 'assistant', 'status'])
  assert.equal(poll.messages[1].text, 'hello there')
  assert.equal(poll.running, false)
  const pollAgain = await call('/peers/task/poll', { taskId: task.taskId })
  assert.equal(pollAgain.messages.length, 0)
  console.log('ok task tail with cursor')

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

console.log('host task: all checks passed')
process.exit(0)
