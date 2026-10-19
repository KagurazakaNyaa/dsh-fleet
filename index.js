import { createHash, generateKeyPairSync, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto'
import { chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { peerPair, peerWorkspaces, startPeerServer } from './peer.js'

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

function groupHex(hex, size = 4) {
  return String(hex).toUpperCase().match(new RegExp(`.{1,${size}}`, 'g')).join('-')
}

let identityCache = null

async function loadIdentity() {
  if (identityCache !== null) return identityCache
  try {
    const parsed = JSON.parse(await readFile(identityFile(), 'utf8'))
    if (parsed && parsed.deviceId && parsed.publicKey && parsed.privateKey && parsed.pairingCode) {
      identityCache = parsed
      return parsed
    }
  } catch {
    // Fall through and mint a new device identity.
  }
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' }).toString()
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
  const der = publicKey.export({ type: 'spki', format: 'der' })
  const identity = {
    version: 1,
    deviceId: groupHex(createHash('sha256').update(der).digest().subarray(0, 16).toString('hex')),
    pairingCode: groupHex(randomBytes(12).toString('hex')),
    publicKey: publicPem,
    privateKey: privatePem,
    createdAt: Date.now(),
  }
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

async function handlePeerDelete(req, res) {
  const body = await readBody(req)
  const deviceId = String(body.deviceId || '')
  const state = await loadPeers()
  const next = state.peers.filter((item) => item.deviceId !== deviceId)
  if (next.length === state.peers.length) {
    sendJson(res, 404, { message: 'peer-not-found' })
    return
  }
  await savePeers(next)
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

  ctx.effect(() => {
    let peerServer = null
    let disposed = false
    void loadIdentity().then(async (identity) => {
      if (disposed) return
      peerServer = startPeerServer({
        identity: toPeerIdentity(identity),
        store: peerStore,
        listWorkspaces: () => listLocalWorkspaces(ctx),
        verifyToken: (candidate) => verifyWebToken(ctx, candidate),
        name: os.hostname(),
        host: runtime.peerHost,
        port: peerListenPort(),
      })
      try {
        const info = await peerServer.start()
        runtime.peerPort = info.port
        runtime.peerError = ''
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
    }
  }, 'dsh-fleet: peer listener')
}
