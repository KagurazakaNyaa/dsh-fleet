import { createHash, generateKeyPairSync, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto'
import { chmod, mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import {
  peerApprovalRespond,
  peerApprovals,
  peerPair,
  peerQuestionRespond,
  peerQuestions,
  peerSessionCreate,
  peerSessionPrompt,
  peerSessionTail,
  peerSessions,
  peerUiToken,
  peerWorkspaces,
  startPeerServer,
} from './peer.js'
import { connectTunnel, startUiProxy } from './tunnel.js'

export const name = 'dsh-fleet'
export const inject = ['webServer']

const BASE = '/api/dsh-fleet'
const MAX_BODY_BYTES = 64 * 1024
const PROBE_TIMEOUT_MS = 2500
const MAX_INSTANCES = 64

function dshHome() {
  return process.env.DSH_HOME || path.join(os.homedir(), '.dsh')
}

function stateFile() {
  return path.join(dshHome(), 'dsh-fleet', 'instances.json')
}

function identityFile() {
  return path.join(dshHome(), 'dsh-fleet', 'identity.json')
}

function peersFile() {
  return path.join(dshHome(), 'dsh-fleet', 'peers.json')
}

const runtime = {
  peerPort: 0,
  peerHost: '127.0.0.1',
  peerError: '',
}

function peerListenPort() {
  const configured = Number(process.env.DSH_FLEET_PORT)
  return Number.isInteger(configured) && configured > 0 && configured < 65_536 ? configured : 3071
}

function peerListenHost() {
  const configured = String(process.env.DSH_FLEET_HOST || '').trim()
  if (configured === '') return '127.0.0.1'
  return configured
}

function runtimeFile() {
  return path.join(dshHome(), 'dsh-fleet', 'runtime.json')
}

/**
 * Desktop picks a random web port every launch and prints nothing to a
 * terminal, so the live origin is published for the CLI and for the UI.
 */
async function writeRuntime(ctx) {
  try {
    const port = ctx.webServer && ctx.webServer.port
    if (!port) return
    const file = runtimeFile()
    await mkdir(path.dirname(file), { recursive: true })
    await writeFile(file, `${JSON.stringify({
      version: 1,
      webUrl: `http://127.0.0.1:${port}`,
      peerHost: runtime.peerHost,
      peerPort: runtime.peerPort,
      pid: process.pid,
      updatedAt: Date.now(),
    }, null, 2)}\n`, 'utf8')
  } catch {
    // Discovery is best effort; the UI still works without it.
  }
}

function groupHex(hex, size = 4) {
  return String(hex).toUpperCase().match(new RegExp(`.{1,${size}}`, 'g')).join('-')
}

let identityCache = null
let identityPromise = null

async function readIdentityFile() {
  try {
    const parsed = JSON.parse(await readFile(identityFile(), 'utf8'))
    if (parsed && parsed.deviceId && parsed.publicKey && parsed.privateKey && parsed.pairingCode) {
      return parsed
    }
  } catch {
    // No usable identity on disk yet.
  }
  return null
}

async function mintIdentity() {
  const existing = await readIdentityFile()
  if (existing !== null) {
    identityCache = existing
    return existing
  }
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' }).toString()
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
  const der = publicKey.export({ type: 'spki', format: 'der' })
  return await persistIdentity({
    version: 1,
    deviceId: groupHex(createHash('sha256').update(der).digest().subarray(0, 16).toString('hex')),
    pairingCode: groupHex(randomBytes(12).toString('hex')),
    publicKey: publicPem,
    privateKey: privatePem,
    createdAt: Date.now(),
  })
}

/**
 * One identity per process, including the first concurrent callers: the
 * in-flight promise is shared so two simultaneous readers cannot mint two
 * different key pairs.
 */
async function loadIdentity() {
  if (identityCache !== null) return identityCache
  if (identityPromise === null) {
    identityPromise = mintIdentity().finally(() => {
      identityPromise = null
    })
  }
  return await identityPromise
}

function emptyState() {
  return { version: 1, instances: [] }
}

function sendJson(res, status, value) {
  res.statusCode = status
  res.setHeader('content-type', 'application/json; charset=utf-8')
  res.setHeader('cache-control', 'no-store')
  res.end(JSON.stringify(value))
}

function sameOrigin(req) {
  const origin = req.headers.origin
  if (origin === undefined || origin === '') return true
  try {
    return new URL(origin).host === req.headers.host
  } catch {
    return false
  }
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0
    const chunks = []
    req.on('data', (chunk) => {
      size += chunk.length
      if (size > MAX_BODY_BYTES) {
        reject(new Error('body-too-large'))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8').trim()
      if (text === '') return resolve({})
      try {
        const value = JSON.parse(text)
        if (value === null || typeof value !== 'object' || Array.isArray(value)) {
          reject(new Error('body-must-be-an-object'))
          return
        }
        resolve(value)
      } catch {
        reject(new Error('invalid-json-body'))
      }
    })
    req.on('error', reject)
  })
}

async function loadState() {
  try {
    const text = await readFile(stateFile(), 'utf8')
    const parsed = JSON.parse(text)
    if (!parsed || !Array.isArray(parsed.instances)) return emptyState()
    return {
      version: 1,
      instances: parsed.instances.filter((item) => item && typeof item === 'object'),
    }
  } catch {
    return emptyState()
  }
}

async function saveState(state) {
  const file = stateFile()
  await mkdir(path.dirname(file), { recursive: true })
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`
  await writeFile(tmp, `${JSON.stringify(state, null, 2)}\n`, 'utf8')
  await rename(tmp, file)
}

function cleanText(value, max) {
  const text = typeof value === 'string' ? value.trim() : ''
  if (text.length > max) throw new Error('field-too-long')
  return text
}

function normalizeInstance(input, previous) {
  const label = cleanText(input.name, 80)
  if (label === '') throw new Error('name-required')

  const rawUrl = cleanText(input.url, 2048).replace(/\/+$/, '')
  if (rawUrl === '') throw new Error('url-required')
  let parsed
  try {
    parsed = new URL(rawUrl)
  } catch {
    throw new Error('url-invalid')
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('url-protocol')
  }

  const token = cleanText(input.token, 4096)
  const note = cleanText(input.note, 500)

  const rawTags = Array.isArray(input.tags) ? input.tags : []
  const tags = [...new Set(rawTags
    .map((tag) => cleanText(tag, 24))
    .filter((tag) => tag !== ''))].slice(0, 8)

  const now = Date.now()
  return {
    id: previous ? previous.id : randomUUID(),
    name: label,
    url: rawUrl,
    token,
    tags,
    note,
    createdAt: previous ? previous.createdAt : now,
    updatedAt: now,
  }
}

function withToken(instance) {
  if (!instance.token) return instance.url
  const join = instance.url.includes('?') ? '&' : '?'
  return `${instance.url}${join}token=${encodeURIComponent(instance.token)}`
}

async function probeInstance(instance) {
  const started = Date.now()
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS)
  try {
    const response = await fetch(`${instance.url}/`, {
      redirect: 'manual',
      signal: controller.signal,
      headers: { accept: 'text/html,application/xhtml+xml' },
    })
    const text = await response.text()
    const isDsh = text.includes('__DSH_BOOT__')
      || text.includes('DeepSeek Harness')
      || (response.status === 401 && text.includes('dsh web authentication'))
    return {
      id: instance.id,
      ok: isDsh,
      dsh: isDsh,
      status: response.status,
      latencyMs: Date.now() - started,
    }
  } catch (error) {
    return {
      id: instance.id,
      ok: false,
      dsh: false,
      error: error && error.name === 'AbortError' ? 'timeout' : String((error && error.message) || error),
      latencyMs: Date.now() - started,
    }
  } finally {
    clearTimeout(timer)
  }
}

async function persistIdentity(identity) {
  const file = identityFile()
  await mkdir(path.dirname(file), { recursive: true })
  const tmp = `${file}.${process.pid}.tmp`
  await writeFile(tmp, `${JSON.stringify(identity, null, 2)}\n`, 'utf8')
  await rename(tmp, file)
  try {
    await chmod(file, 0o600)
  } catch {
    // POSIX-only; Windows inherits the profile directory ACL.
  }
  identityCache = identity
  return identity
}

async function loadPeers() {
  try {
    const parsed = JSON.parse(await readFile(peersFile(), 'utf8'))
    if (!parsed || !Array.isArray(parsed.peers)) return { version: 1, peers: [] }
    return { version: 1, peers: parsed.peers.filter((item) => item && typeof item.deviceId === 'string') }
  } catch {
    return { version: 1, peers: [] }
  }
}

async function savePeers(peers) {
  const file = peersFile()
  await mkdir(path.dirname(file), { recursive: true })
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`
  await writeFile(tmp, `${JSON.stringify({ version: 1, peers }, null, 2)}\n`, 'utf8')
  await rename(tmp, file)
}

const peerStore = {
  async upsertPeer(record) {
    const state = await loadPeers()
    const index = state.peers.findIndex((item) => item.deviceId === record.deviceId)
    const previous = index === -1 ? null : state.peers[index]
    const next = {
      ...(previous ?? {}),
      ...record,
      grants: Array.isArray(record.grants) ? record.grants : (previous && Array.isArray(previous.grants) ? previous.grants : []),
      uiAccess: typeof record.uiAccess === 'boolean' ? record.uiAccess : Boolean(previous && previous.uiAccess),
      sessionAccess: typeof record.sessionAccess === 'boolean' ? record.sessionAccess : Boolean(previous && previous.sessionAccess),
      pairedAt: (previous && previous.pairedAt) || record.pairedAt || Date.now(),
    }
    if (index === -1) state.peers.push(next)
    else state.peers[index] = next
    await savePeers(state.peers)
    return next
  },
  async getPeer(deviceId) {
    const state = await loadPeers()
    return state.peers.find((item) => item.deviceId === deviceId)
  },
  async touchPeer(deviceId) {
    const state = await loadPeers()
    const peer = state.peers.find((item) => item.deviceId === deviceId)
    if (!peer) return
    peer.lastSeenAt = Date.now()
    await savePeers(state.peers)
  },
}

function listLocalWorkspaces(ctx) {
  const registry = ctx.get('workspaceRegistry')
  if (!registry || typeof registry.list !== 'function') return []
  try {
    return registry.list().map((workspace) => ({
      id: workspace.id,
      title: workspace.title,
      path: workspace.path,
      status: 'ok',
    }))
  } catch {
    return []
  }
}

function toPeerIdentity(identity) {
  return {
    deviceId: identity.deviceId,
    publicPem: identity.publicKey,
    privatePem: identity.privateKey,
    pairingCode: identity.pairingCode,
  }
}

/**
 * Session metadata only: ids, titles, cwd and running state. Message content
 * never leaves the owner through this call.
 */async function listRemoteSessions(ctx) {
  const controller = ctx.get('sessionController')
  if (!controller || typeof controller.list !== 'function') return []
  try {
    const value = await controller.list({}, new AbortController().signal)
    const items = (value && value.items) || []
    return items.slice(0, 50).map((item) => ({
      sessionId: String(item.sessionId),
      updatedAt: Number(item.updatedAt) || 0,
      running: Boolean(item.running),
      cwd: typeof item.cwd === 'string' ? item.cwd : '',
      parentSessionId: item.parentSessionId ? String(item.parentSessionId) : '',
      title: (item.projections && item.projections.values && item.projections.values.title) || '',
    }))
  } catch {
    return []
  }
}

/**
 * The token `dsh web` prints at startup, read from the live connection service
 * instead of any on-disk copy. Used as an alternative bootstrap credential.
 */
function ownWebToken(ctx) {
  try {
    const connection = ctx.get('connection')
    if (!connection || typeof connection.authenticatedUrl !== 'function') return ''
    const port = ctx.webServer && ctx.webServer.port
    const url = new URL(connection.authenticatedUrl(`http://127.0.0.1:${port}/`))
    return url.searchParams.get('token') || ''
  } catch {
    return ''
  }
}

function verifyWebToken(ctx, candidate) {
  const expected = ownWebToken(ctx)
  if (!expected || candidate.length !== expected.length) return false
  try {
    return timingSafeEqual(Buffer.from(candidate), Buffer.from(expected))
  } catch {
    return false
  }
}

function publicIdentity(identity) {
  return {
    deviceId: identity.deviceId,
    pairingCode: identity.pairingCode,
    publicKey: identity.publicKey,
    createdAt: identity.createdAt,
  }
}

async function handleIdentity(ctx, req, res) {
  const identity = await loadIdentity()
  sendJson(res, 200, {
    ...publicIdentity(identity),
    name: os.hostname(),
    webUrl: ctx.webServer && ctx.webServer.port ? `http://127.0.0.1:${ctx.webServer.port}` : '',
    tokenAvailable: ownWebToken(ctx) !== '',
    listener: { host: runtime.peerHost, port: runtime.peerPort, error: runtime.peerError },
  })
}

async function handleRotatePairingCode(req, res) {
  const identity = await loadIdentity()
  const next = { ...identity, pairingCode: groupHex(randomBytes(12).toString('hex')) }
  await persistIdentity(next)
  sendJson(res, 200, publicIdentity(next))
}

function messageText(message) {
  const blocks = message && message.content
  if (!Array.isArray(blocks)) return ''
  const parts = []
  for (const block of blocks) {
    if (block && block.type === 'text' && typeof block.text === 'string') parts.push(block.text)
    else if (block && block.type === 'reasoning' && typeof block.text === 'string') parts.push(`[reasoning] ${block.text}`)
  }
  return parts.join('\n').trim()
}

function sessionFrame(event) {
  if (!event || typeof event !== 'object') return null
  const base = { seq: Number(event.seq) || 0, type: String(event.type || '') }
  if (event.type === 'user/message') return { ...base, role: 'user', text: messageText(event.data) }
  if (event.type === 'assistant/message') return { ...base, role: 'assistant', text: messageText(event.data && event.data.message) }
  if (event.type === 'tool/call') return { ...base, role: 'tool', text: String((event.data && event.data.name) || 'tool') }
  if (event.type === 'tool/result') return { ...base, role: 'tool-result', text: '' }
  if (event.type === 'turn/end') {
    const kind = event.data && event.data.reason && event.data.reason.kind
    return { ...base, role: 'status', text: String(kind || 'end') }
  }
  return null
}

async function tailSessionForPeer(ctx, sessionId, since) {
  const sessions = ctx.get('sessions')
  const session = sessions && typeof sessions.get === 'function' ? sessions.get(sessionId) : undefined
  if (!session) return { frames: [], cursor: since, running: false }
  const last = Number(session.seq) || 0
  const from = Number.isFinite(since) && since > 0 ? since : 0
  const events = session.snapshotEvents(from, last + 1) || []
  const frames = []
  for (const event of events) {
    const frame = sessionFrame(event)
    if (frame !== null) frames.push(frame)
  }
  const agents = ctx.get('agents')
  const agent = agents && typeof agents.get === 'function' ? agents.get(sessionId) : undefined
  return { frames, cursor: last + 1, running: Boolean(agent) }
}

const fleetSessions = new Map()
const pendingApprovals = new Map()
const pendingQuestions = new Map()

async function createSessionForPeer(ctx, workspaceId, deviceId) {
  const controller = ctx.get('sessionController')
  if (!controller || typeof controller.create !== 'function') throw new Error('session-create-unavailable')
  const value = await controller.create({ workspaceId })
  const sessionId = String(value.sessionId)
  fleetSessions.set(sessionId, String(deviceId || ''))
  return sessionId
}

async function handleApprovalRequest(request, next) {
  const sessionId = request && request.agent && request.agent.id
  if (!sessionId || !fleetSessions.has(sessionId)) return await next()
  const deviceId = fleetSessions.get(sessionId)
  const id = randomUUID()
  const outcome = await new Promise((resolve) => {
    const timer = setTimeout(() => {
      pendingApprovals.delete(id)
      resolve(null)
    }, 60_000)
    pendingApprovals.set(id, {
      id,
      sessionId,
      deviceId,
      toolName: String(request.toolName || ''),
      reason: String(request.reason || ''),
      createdAt: Date.now(),
      answer(value) {
        clearTimeout(timer)
        pendingApprovals.delete(id)
        resolve(value)
      },
    })
  })
  if (outcome === null) return await next()
  return outcome
}

function listApprovalsForPeer(deviceId) {
  return [...pendingApprovals.values()]
    .filter((item) => item.deviceId === deviceId)
    .map((item) => ({
      id: item.id,
      sessionId: item.sessionId,
      toolName: item.toolName,
      reason: item.reason,
      createdAt: item.createdAt,
    }))
}

function respondApprovalForPeer(deviceId, id, outcome) {
  const pending = pendingApprovals.get(id)
  if (!pending || pending.deviceId !== deviceId) return false
  if (outcome !== 'allowed-once' && outcome !== 'rejected' && outcome !== 'cancelled') return false
  pending.answer(outcome)
  return true
}

async function handleQuestionsRequest(request, next) {
  const sessionId = request && request.agent && request.agent.id
  if (!sessionId || !fleetSessions.has(sessionId)) return await next()
  const deviceId = fleetSessions.get(sessionId)
  const questions = (Array.isArray(request.questions) ? request.questions : [])
    .map((question) => ({
      id: String(question.id || ''),
      question: String(question.question || ''),
      header: String(question.header || ''),
      detail: String(question.detail || ''),
      multiSelect: question.multiSelect === true,
      options: (Array.isArray(question.options) ? question.options : []).map((option) => ({
        label: String(option.label || ''),
        description: String(option.description || ''),
      })),
    }))
    .filter((question) => question.id !== '')
  if (questions.length === 0) return await next()
  const id = randomUUID()
  const answer = await new Promise((resolve) => {
    const timer = setTimeout(() => {
      pendingQuestions.delete(id)
      resolve(null)
    }, 120_000)
    pendingQuestions.set(id, {
      id,
      sessionId,
      deviceId,
      questions,
      createdAt: Date.now(),
      answer(value) {
        clearTimeout(timer)
        pendingQuestions.delete(id)
        resolve(value)
      },
    })
  })
  if (answer === null) return await next()
  return answer
}

function listQuestionsForPeer(deviceId) {
  return [...pendingQuestions.values()]
    .filter((item) => item.deviceId === deviceId)
    .map((item) => ({
      id: item.id,
      sessionId: item.sessionId,
      questions: item.questions,
      createdAt: item.createdAt,
    }))
}

function respondQuestionForPeer(deviceId, id, answers) {
  const pending = pendingQuestions.get(id)
  if (!pending || pending.deviceId !== deviceId) return false
  const byId = new Map()
  for (const answer of answers) {
    if (!answer || typeof answer.id !== 'string') return false
    const question = pending.questions.find((item) => item.id === answer.id)
    if (!question) return false
    const selected = Array.isArray(answer.selected)
      ? answer.selected.filter((value) => typeof value === 'string')
      : []
    const labels = new Set(question.options.map((option) => option.label))
    for (const value of selected) {
      if (!labels.has(value)) return false
    }
    const custom = typeof answer.custom === 'string' && answer.custom !== '' ? answer.custom : undefined
    if (selected.length === 0 && custom === undefined) return false
    byId.set(answer.id, { id: answer.id, selected, ...(custom === undefined ? {} : { custom }) })
  }
  if (byId.size !== pending.questions.length) return false
  pending.answer({ answers: [...byId.values()] })
  return true
}

async function promptSessionForPeer(ctx, sessionId, text) {
  const controller = ctx.get('sessionController')
  if (!controller || typeof controller.prompt !== 'function') throw new Error('session-prompt-unavailable')
  await controller.prompt({
    requestId: `fleet-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`,
    sessionId,
    mode: 'queue',
    content: [{ type: 'text', text }],
  })
}

function uiTokenFor(ctx) {
  const connection = ctx.get('connection')
  const port = ctx.webServer && ctx.webServer.port
  if (!connection || typeof connection.authenticatedUrl !== 'function' || !port) return ''
  try {
    return connection.authenticatedUrl(`http://127.0.0.1:${port}/`)
  } catch {
    return ''
  }
}

async function handleState(req, res) {
  const state = await loadState()
  sendJson(res, 200, { ...state, home: dshHome() })
}

async function handleSave(req, res) {
  const body = await readBody(req)
  const state = await loadState()
  const id = typeof body.id === 'string' ? body.id : ''
  const index = id === '' ? -1 : state.instances.findIndex((item) => item.id === id)
  if (id !== '' && index === -1) {
    sendJson(res, 404, { message: 'instance-not-found' })
    return
  }
  if (index === -1 && state.instances.length >= MAX_INSTANCES) {
    sendJson(res, 409, { message: 'too-many-instances' })
    return
  }
  const previous = index === -1 ? null : state.instances[index]
  const instance = normalizeInstance(body, previous)
  if (index === -1) state.instances.push(instance)
  else state.instances[index] = instance
  await saveState(state)
  sendJson(res, 200, { instance, instances: state.instances })
}

async function handleDelete(req, res) {
  const body = await readBody(req)
  const id = typeof body.id === 'string' ? body.id : ''
  const state = await loadState()
  const next = state.instances.filter((item) => item.id !== id)
  if (next.length === state.instances.length) {
    sendJson(res, 404, { message: 'instance-not-found' })
    return
  }
  await saveState({ version: 1, instances: next })
  sendJson(res, 200, { instances: next })
}

async function handleProbe(req, res) {
  const body = await readBody(req)
  const state = await loadState()
  const targets = []
  if (typeof body.id === 'string' && body.id !== '') {
    const found = state.instances.find((item) => item.id === body.id)
    if (found) targets.push(found)
  } else if (typeof body.url === 'string' && /^https?:\/\//i.test(body.url)) {
    targets.push({ id: 'adhoc', url: body.url.replace(/\/+$/, '') })
  } else {
    targets.push(...state.instances)
  }
  const results = await Promise.all(targets.map((item) => probeInstance(item)))
  sendJson(res, 200, { results, probedAt: Date.now() })
}

async function handleLaunch(req, res) {
  const body = await readBody(req)
  const id = typeof body.id === 'string' ? body.id : ''
  const state = await loadState()
  const instance = state.instances.find((item) => item.id === id)
  if (!instance) {
    sendJson(res, 404, { message: 'instance-not-found' })
    return
  }
  sendJson(res, 200, { url: withToken(instance) })
}

async function handlePeers(req, res) {
  const state = await loadPeers()
  sendJson(res, 200, {
    peers: state.peers,
    listener: { host: runtime.peerHost, port: runtime.peerPort, error: runtime.peerError },
  })
}

async function handlePair(req, res) {
  const body = await readBody(req)
  const address = cleanText(body.address, 255)
  const code = cleanText(body.code, 128)
  const token = cleanText(body.token, 1024)
  if (address === '' || (code === '' && token === '')) {
    sendJson(res, 400, { message: 'address-and-credential-required' })
    return
  }
  const identity = toPeerIdentity(await loadIdentity())
  const { hello } = await peerPair({ address, code: code || undefined, token: token || undefined, identity, name: os.hostname() })
  const peer = await peerStore.upsertPeer({
    deviceId: hello.deviceId,
    publicKey: hello.publicKey,
    name: hello.name || hello.deviceId,
    address,
    lastSeenAt: Date.now(),
  })
  sendJson(res, 200, { peer })
}

async function handlePeerWorkspaces(req, res) {
  const body = await readBody(req)
  const deviceId = String(body.deviceId || '')
  const peer = await peerStore.getPeer(deviceId)
  if (!peer) {
    sendJson(res, 404, { message: 'peer-not-found' })
    return
  }
  if (!peer.address) {
    sendJson(res, 409, { message: 'peer-has-no-address' })
    return
  }
  const identity = toPeerIdentity(await loadIdentity())
  const workspaces = await peerWorkspaces({ address: peer.address, identity })
  await peerStore.touchPeer(deviceId)
  sendJson(res, 200, { workspaces })
}

async function handleGrant(req, res) {
  const body = await readBody(req)
  const deviceId = String(body.deviceId || '')
  const peer = await peerStore.getPeer(deviceId)
  if (!peer) {
    sendJson(res, 404, { message: 'peer-not-found' })
    return
  }
  const workspaceId = cleanText(body.workspaceId, 200)
  if (workspaceId === '') {
    sendJson(res, 400, { message: 'workspace-required' })
    return
  }
  const grants = new Set(Array.isArray(peer.grants) ? peer.grants : [])
  if (body.allow === true) grants.add(workspaceId)
  else grants.delete(workspaceId)
  const next = await peerStore.upsertPeer({ ...peer, grants: [...grants] })
  sendJson(res, 200, { peer: next })
}

const uiProxies = new Map()

function splitAddress(address) {
  const value = String(address ?? '').trim()
  const index = value.lastIndexOf(':')
  if (index <= 0) return null
  const host = value.slice(0, index)
  const port = Number(value.slice(index + 1))
  if (host === '' || !Number.isInteger(port) || port <= 0 || port > 65_535) return null
  return { host, port }
}

async function handleUiAccess(req, res) {
  const body = await readBody(req)
  const peer = await peerStore.getPeer(String(body.deviceId || ''))
  if (!peer) {
    sendJson(res, 404, { message: 'peer-not-found' })
    return
  }
  const next = await peerStore.upsertPeer({ ...peer, uiAccess: body.allow === true })
  sendJson(res, 200, { peer: next })
}

async function handlePeerUi(req, res) {
  const body = await readBody(req)
  const peer = await peerStore.getPeer(String(body.deviceId || ''))
  if (!peer) {
    sendJson(res, 404, { message: 'peer-not-found' })
    return
  }
  const target = splitAddress(peer.address)
  if (target === null) {
    sendJson(res, 409, { message: 'peer-has-no-address' })
    return
  }
  const identity = toPeerIdentity(await loadIdentity())
  let proxy = uiProxies.get(peer.deviceId)
  if (!proxy) {
    try {
      const probe = await connectTunnel({ host: target.host, port: target.port, identity, timeoutMs: 3000 })
      probe.close()
    } catch (error) {
      const message = String((error && error.message) || error)
      if (message.includes('403')) {
        sendJson(res, 403, { message: 'ui-access-not-granted' })
        return
      }
      sendJson(res, 502, { message: `tunnel-unavailable: ${message}` })
      return
    }
    proxy = await startUiProxy({ host: target.host, port: target.port, identity })
    uiProxies.set(peer.deviceId, proxy)
  }
  let loginUrl = `http://127.0.0.1:${proxy.port}/`
  try {
    const ownerUrl = await peerUiToken({ address: peer.address, identity, timeoutMs: 4000 })
    const token = ownerUrl === '' ? '' : new URL(ownerUrl).searchParams.get('token')
    if (token) loginUrl = `${loginUrl}?token=${encodeURIComponent(token)}`
  } catch {
    // The plain URL still works when this browser already holds the owner cookie.
  }
  sendJson(res, 200, { url: `http://127.0.0.1:${proxy.port}/`, loginUrl, port: proxy.port })
}

const tasks = new Map()

async function handlePeerTask(req, res) {
  const body = await readBody(req)
  const peer = await peerStore.getPeer(String(body.deviceId || ''))
  if (!peer) {
    sendJson(res, 404, { message: 'peer-not-found' })
    return
  }
  const workspaceId = cleanText(body.workspaceId, 200)
  const text = cleanText(body.text, 20_000)
  if (workspaceId === '' || text === '') {
    sendJson(res, 400, { message: 'workspace-and-text-required' })
    return
  }
  const identity = toPeerIdentity(await loadIdentity())
  const sessionId = await peerSessionCreate({ address: peer.address, identity, workspaceId })
  if (sessionId === '') {
    sendJson(res, 502, { message: 'session-create-empty' })
    return
  }
  await peerSessionPrompt({ address: peer.address, identity, sessionId, text })
  const taskId = randomUUID()
  tasks.set(taskId, { deviceId: peer.deviceId, sessionId, cursor: 0, createdAt: Date.now() })
  sendJson(res, 200, { taskId, sessionId })
}

async function handleTaskPoll(req, res) {
  const body = await readBody(req)
  const task = tasks.get(String(body.taskId || ''))
  if (!task) {
    sendJson(res, 404, { message: 'task-not-found' })
    return
  }
  const peer = await peerStore.getPeer(task.deviceId)
  if (!peer) {
    sendJson(res, 404, { message: 'peer-not-found' })
    return
  }
  const identity = toPeerIdentity(await loadIdentity())
  const tail = await peerSessionTail({ address: peer.address, identity, sessionId: task.sessionId, since: task.cursor })
  const cursor = Number(tail && tail.cursor)
  if (Number.isFinite(cursor) && cursor >= task.cursor) task.cursor = cursor
  let approvals = []
  try {
    const all = await peerApprovals({ address: peer.address, identity })
    approvals = all.filter((item) => item.sessionId === task.sessionId)
  } catch {
    approvals = []
  }
  let questions = []
  try {
    const all = await peerQuestions({ address: peer.address, identity })
    questions = all.filter((item) => item.sessionId === task.sessionId)
  } catch {
    questions = []
  }
  sendJson(res, 200, {
    sessionId: task.sessionId,
    messages: (tail && tail.frames) || [],
    running: Boolean(tail && tail.running),
    approvals,
    questions,
    cursor: task.cursor,
  })
}

async function handleTaskApprove(req, res) {  const body = await readBody(req)
  const task = tasks.get(String(body.taskId || ''))
  if (!task) {
    sendJson(res, 404, { message: 'task-not-found' })
    return
  }
  const peer = await peerStore.getPeer(task.deviceId)
  if (!peer) {
    sendJson(res, 404, { message: 'peer-not-found' })
    return
  }
  const id = cleanText(body.approvalId, 100)
  const outcome = String(body.outcome || '')
  if (id === '' || !['allowed-once', 'rejected', 'cancelled'].includes(outcome)) {
    sendJson(res, 400, { message: 'approval-id-and-outcome-required' })
    return
  }
  const identity = toPeerIdentity(await loadIdentity())
  await peerApprovalRespond({ address: peer.address, identity, id, outcome })
  sendJson(res, 200, { accepted: true })
}

async function handleTaskAnswer(req, res) {
  const body = await readBody(req)
  const task = tasks.get(String(body.taskId || ''))
  if (!task) {
    sendJson(res, 404, { message: 'task-not-found' })
    return
  }
  const peer = await peerStore.getPeer(task.deviceId)
  if (!peer) {
    sendJson(res, 404, { message: 'peer-not-found' })
    return
  }
  const id = cleanText(body.questionId, 100)
  const answers = Array.isArray(body.answers) ? body.answers : null
  if (id === '' || answers === null) {
    sendJson(res, 400, { message: 'question-id-and-answers-required' })
    return
  }
  const identity = toPeerIdentity(await loadIdentity())
  await peerQuestionRespond({ address: peer.address, identity, id, answers })
  sendJson(res, 200, { accepted: true })
}

async function handlePeerSessions(req, res) {
  const body = await readBody(req)
  const peer = await peerStore.getPeer(String(body.deviceId || ''))
  if (!peer) {
    sendJson(res, 404, { message: 'peer-not-found' })
    return
  }
  const target = splitAddress(peer.address)
  if (target === null) {
    sendJson(res, 409, { message: 'peer-has-no-address' })
    return
  }
  const identity = toPeerIdentity(await loadIdentity())
  const sessions = await peerSessions({ address: peer.address, identity })
  await peerStore.touchPeer(peer.deviceId)
  sendJson(res, 200, { sessions })
}

async function handleSessionAccess(req, res) {
  const body = await readBody(req)
  const peer = await peerStore.getPeer(String(body.deviceId || ''))
  if (!peer) {
    sendJson(res, 404, { message: 'peer-not-found' })
    return
  }
  const next = await peerStore.upsertPeer({ ...peer, sessionAccess: body.allow === true })
  sendJson(res, 200, { peer: next })
}

async function handlePeerDelete(req, res) {  const body = await readBody(req)
  const deviceId = String(body.deviceId || '')
  const state = await loadPeers()
  const next = state.peers.filter((item) => item.deviceId !== deviceId)
  if (next.length === state.peers.length) {
    sendJson(res, 404, { message: 'peer-not-found' })
    return
  }
  await savePeers(next)
  const proxy = uiProxies.get(deviceId)
  if (proxy) {
    uiProxies.delete(deviceId)
    try {
      proxy.server.close()
    } catch {
      // already closed
    }
  }
  sendJson(res, 200, { peers: next })
}

async function handleLocalWorkspaces(ctx, req, res) {
  sendJson(res, 200, { workspaces: listLocalWorkspaces(ctx) })
}

function guard(handler) {
  return (req, res) => {
    void (async () => {
      if (!sameOrigin(req)) {
        sendJson(res, 403, { message: 'cross-origin' })
        return
      }
      try {
        await handler(req, res)
      } catch (error) {
        const message = String((error && error.message) || error)
        sendJson(res, 400, { message })
      }
    })()
  }
}

export function apply(ctx) {
  const routes = [
    ['/state', 'GET', handleState],
    ['/identity', 'GET', (req, res) => handleIdentity(ctx, req, res)],
    ['/identity/rotate', 'POST', handleRotatePairingCode],
    ['/save', 'POST', handleSave],
    ['/delete', 'POST', handleDelete],
    ['/probe', 'POST', handleProbe],
    ['/launch', 'POST', handleLaunch],
    ['/peers', 'GET', handlePeers],
    ['/pair', 'POST', handlePair],
    ['/peers/workspaces', 'POST', handlePeerWorkspaces],
    ['/peers/grant', 'POST', handleGrant],
    ['/peers/ui-access', 'POST', handleUiAccess],
    ['/peers/ui', 'POST', handlePeerUi],
    ['/peers/session-access', 'POST', handleSessionAccess],
    ['/peers/sessions', 'POST', handlePeerSessions],
    ['/peers/task', 'POST', handlePeerTask],
    ['/peers/task/poll', 'POST', handleTaskPoll],
    ['/peers/task/approve', 'POST', handleTaskApprove],
    ['/peers/task/answer', 'POST', handleTaskAnswer],
    ['/peers/delete', 'POST', handlePeerDelete],
    ['/workspaces', 'GET', (req, res) => handleLocalWorkspaces(ctx, req, res)],
  ]

  for (const [suffix, method, handler] of routes) {
    const route = `${BASE}${suffix}`
    const wrapped = guard(handler)
    ctx.effect(() => ctx.webServer.register({
      kind: 'exact',
      path: route,
      handler: (req, res) => {
        if (req.method !== method) {
          res.statusCode = 405
          res.setHeader('allow', method)
          res.end()
          return
        }
        wrapped(req, res)
      },
    }), `dsh-fleet: ${method} ${route}`)
  }

  ctx.on('approval/request', (request, next) => handleApprovalRequest(request, next), { prepend: true, global: true })
  ctx.on('user-questions/request', (request, next) => handleQuestionsRequest(request, next), { prepend: true, global: true })

  ctx.effect(() => {
    let peerServer = null
    let disposed = false
    void loadIdentity().then(async (identity) => {
      if (disposed) return
      peerServer = startPeerServer({
        identity: toPeerIdentity(identity),
        store: peerStore,
        listWorkspaces: () => listLocalWorkspaces(ctx),
        listSessions: () => listRemoteSessions(ctx),
        uiToken: () => uiTokenFor(ctx),
        createSession: (workspaceId, deviceId) => createSessionForPeer(ctx, workspaceId, deviceId),
        promptSession: (sessionId, text) => promptSessionForPeer(ctx, sessionId, text),
        tailSession: (sessionId, since) => tailSessionForPeer(ctx, sessionId, since),
        listApprovals: (deviceId) => listApprovalsForPeer(deviceId),
        respondApproval: (deviceId, id, outcome) => respondApprovalForPeer(deviceId, id, outcome),
        listQuestions: (deviceId) => listQuestionsForPeer(deviceId),
        respondQuestion: (deviceId, id, answers) => respondQuestionForPeer(deviceId, id, answers),
        verifyToken: (candidate) => verifyWebToken(ctx, candidate),
        tunnelTargetPort: Number(ctx.webServer && ctx.webServer.port) || 0,
        name: os.hostname(),
        host: runtime.peerHost,
        port: peerListenPort(),
      })
      try {
        const info = await peerServer.start()
        runtime.peerPort = info.port
        runtime.peerError = ''
        await writeRuntime(ctx)
      } catch (error) {
        runtime.peerError = String((error && error.message) || error)
        console.warn(`[dsh-fleet] peer listener unavailable: ${runtime.peerError}`)
      }
    }).catch((error) => {
      runtime.peerError = String((error && error.message) || error)
      console.warn(`[dsh-fleet] identity unavailable: ${runtime.peerError}`)
    })
    return () => {
      disposed = true
      if (peerServer !== null) void peerServer.close()
      for (const proxy of uiProxies.values()) {
        try {
          proxy.server.close()
        } catch {
          // already closed
        }
      }
      uiProxies.clear()
      void unlink(runtimeFile()).catch(() => {})
    }
  }, 'dsh-fleet: peer listener')

  runtime.peerHost = peerListenHost()
  void writeRuntime(ctx)
}
