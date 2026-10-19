import assert from 'node:assert/strict'
import http from 'node:http'
import { mkdtemp, rm } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

const home = await mkdtemp(path.join(os.tmpdir(), 'dsh-fleet-question-'))
process.env.DSH_HOME = home
process.env.DSH_FLEET_PORT = '3076'

const { apply } = await import('../index.js')

const routes = new Map()
const handlers = new Map()
const disposers = []
const fakeSession = { seq: 0, snapshotEvents: () => [] }

const ctx = {
  effect(fn) {
    const disposer = fn()
    if (typeof disposer === 'function') disposers.push(disposer)
    return disposer
  },
  get(name) {
    if (name === 'connection') return { authenticatedUrl: (base) => `${base}?token=question-token` }
    if (name === 'workspaceRegistry') return { list: () => [{ id: 'ws-1', title: 'One', path: '/srv/one' }] }
    if (name === 'sessionController') {
      return {
        async create() {
          return { sessionId: 's-1' }
        },
        async prompt() {
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
  await call('/pair', { address: '127.0.0.1:3076', code: identity.pairingCode })
  await call('/peers/session-access', { deviceId: identity.deviceId, allow: true })
  console.log('ok self-paired')

  const task = await call('/peers/task', { deviceId: identity.deviceId, workspaceId: 'ws-1', text: 'ask me' })
  assert.equal(task.sessionId, 's-1')

  const questionHandler = handlers.get('user-questions/request')
  assert.equal(typeof questionHandler, 'function')

  const pendingAnswer = questionHandler({
    agent: { id: 's-1' },
    questions: [{
      id: 'q1',
      question: 'Which environment?',
      header: 'Target',
      options: [{ label: 'staging' }, { label: 'production' }],
    }],
  }, async () => ({ answers: [] }))
  assert.ok(pendingAnswer instanceof Promise)

  const pending = await call('/peers/task/poll', { taskId: task.taskId })
  assert.equal(pending.questions.length, 1)
  assert.equal(pending.questions[0].questions[0].question, 'Which environment?')
  assert.deepEqual(
    pending.questions[0].questions[0].options.map((option) => option.label),
    ['staging', 'production'],
  )
  console.log('ok question surfaced to the hub')

  await call('/peers/task/answer', {
    taskId: task.taskId,
    questionId: pending.questions[0].id,
    answers: [{ id: 'q1', selected: ['staging'] }],
  })
  assert.deepEqual(await pendingAnswer, { answers: [{ id: 'q1', selected: ['staging'] }] })
  console.log('ok remote answer resolved the question')

  const after = await call('/peers/task/poll', { taskId: task.taskId })
  assert.equal(after.questions.length, 0)

  const fallthrough = await questionHandler({ agent: { id: 'local-session' }, questions: [] }, async () => ({ answers: [{ id: 'x', selected: [] }] }))
  assert.deepEqual(fallthrough, { answers: [{ id: 'x', selected: [] }] })
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

console.log('host questions: all checks passed')
process.exit(0)
