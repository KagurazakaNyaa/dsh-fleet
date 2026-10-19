import { createHash, createPublicKey, sign, verify } from 'node:crypto'
import http from 'node:http'
import { attachTunnel } from './tunnel.js'

export const PROTOCOL = 1
export const MAX_BODY_BYTES = 256 * 1024
export const CLOCK_SKEW_MS = 60_000
export const NONCE_TTL_MS = 120_000

export class PeerError extends Error {
  constructor(status, code) {
    super(code)
    this.status = status
    this.code = code
  }
}

export function sha256Hex(input) {
  return createHash('sha256').update(input).digest('hex')
}

export function deviceIdFromDer(der) {
  const hex = createHash('sha256').update(der).digest().subarray(0, 16).toString('hex').toUpperCase()
  return hex.match(/.{1,4}/g).join('-')
}

export function publicKeyDerBase64(pem) {
  return createPublicKey(pem).export({ type: 'spki', format: 'der' }).toString('base64')
}

export function publicKeyFromDerBase64(value) {
  return createPublicKey({ key: Buffer.from(String(value), 'base64'), format: 'der', type: 'spki' })
}

export function canonicalRequest(method, path, timestamp, nonce, bodyHash) {
  return [String(method).toUpperCase(), path, String(timestamp), nonce, bodyHash].join('\n')
}

export function signRequest(identity, method, path, body, options = {}) {
  const timestamp = String(options.timestamp ?? Date.now())
  const nonce = options.nonce ?? `${Date.now().toString(36)}${Math.random().toString(36).slice(2)}`
  const raw = body === undefined || body === null
    ? Buffer.alloc(0)
    : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body))
  const payload = canonicalRequest(method, path, timestamp, nonce, sha256Hex(raw))
  const signature = sign(null, Buffer.from(payload), identity.privatePem).toString('base64')
  const headers = {
    'x-fleet-device': identity.deviceId,
    'x-fleet-timestamp': timestamp,
    'x-fleet-nonce': nonce,
    'x-fleet-signature': signature,
  }
  if (options.code) headers['x-fleet-code'] = options.code
  if (options.token) headers['x-fleet-token'] = options.token
  if (options.publicKey) headers['x-fleet-public-key'] = options.publicKey
  return { headers, body: raw }
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0
    const chunks = []
    req.on('data', (chunk) => {
      size += chunk.length
      if (size > MAX_BODY_BYTES) {
        reject(new PeerError(413, 'body-too-large'))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => resolve(Buffer.concat(chunks)))
    req.on('error', reject)
  })
}

function sendJson(res, status, value) {
  res.statusCode = status
  res.setHeader('content-type', 'application/json; charset=utf-8')
  res.setHeader('cache-control', 'no-store')
  res.end(JSON.stringify(value))
}

function headerValue(req, name) {
  const value = req.headers[name]
  return typeof value === 'string' ? value : ''
}

function verifySignature(req, rawBody, publicKey, seenNonces) {
  const deviceId = headerValue(req, 'x-fleet-device')
  const timestamp = Number(headerValue(req, 'x-fleet-timestamp'))
  const nonce = headerValue(req, 'x-fleet-nonce')
  const signature = headerValue(req, 'x-fleet-signature')
  if (!deviceId || !nonce || !signature || !Number.isFinite(timestamp)) {
    throw new PeerError(401, 'missing-signature')
  }
  if (Math.abs(Date.now() - timestamp) > CLOCK_SKEW_MS) {
    throw new PeerError(401, 'stale-timestamp')
  }
  const key = `${deviceId}:${nonce}`
  const now = Date.now()
  for (const [entry, expiry] of seenNonces) {
    if (expiry < now) seenNonces.delete(entry)
  }
  if (seenNonces.has(key)) throw new PeerError(401, 'replayed-nonce')
  const path = new URL(req.url || '/', 'http://localhost').pathname
  const payload = canonicalRequest(req.method, path, timestamp, nonce, sha256Hex(rawBody))
  const ok = verify(null, Buffer.from(payload), publicKey, Buffer.from(signature, 'base64'))
  if (!ok) throw new PeerError(403, 'bad-signature')
  seenNonces.set(key, now + NONCE_TTL_MS)
  return deviceId
}

/**
 * Start this instance's peer listener. The listener carries control-plane
 * messages only: identity, pairing, workspace metadata.
 */
export function startPeerServer(options) {
  const identity = options.identity
  const store = options.store
  const listWorkspaces = options.listWorkspaces ?? (() => [])
  const host = options.host ?? '127.0.0.1'
  const port = options.port ?? 3071
  const name = options.name ?? 'dsh'
  const seenNonces = new Map()

  const server = http.createServer((req, res) => {
    void (async () => {
      try {
        const path = new URL(req.url || '/', 'http://localhost').pathname
        if (req.method === 'GET' && path === '/hello') {
          sendJson(res, 200, {
            protocol: PROTOCOL,
            deviceId: identity.deviceId,
            name,
            publicKey: publicKeyDerBase64(identity.publicPem),
          })
          return
        }

        if (req.method === 'POST' && path === '/pair') {
          const raw = await readRawBody(req)
          const code = headerValue(req, 'x-fleet-code')
          const token = headerValue(req, 'x-fleet-token')
          let bootstrapOk = false
          if (code !== '') {
            bootstrapOk = code === identity.pairingCode
            if (!bootstrapOk) throw new PeerError(403, 'bad-pairing-code')
          } else if (token !== '' && typeof options.verifyToken === 'function') {
            bootstrapOk = await options.verifyToken(token)
            if (!bootstrapOk) throw new PeerError(403, 'bad-token')
          } else {
            throw new PeerError(403, 'missing-bootstrap-credential')
          }
          void bootstrapOk
          const callerKey = publicKeyFromDerBase64(headerValue(req, 'x-fleet-public-key'))
          const callerId = deviceIdFromDer(callerKey.export({ type: 'spki', format: 'der' }))
          const signedBy = verifySignature(req, raw, callerKey, seenNonces)
          if (signedBy !== callerId) throw new PeerError(403, 'device-id-mismatch')
          let body = {}
          if (raw.length > 0) {
            try {
              body = JSON.parse(raw.toString('utf8'))
            } catch {
              throw new PeerError(400, 'invalid-json')
            }
          }
          const record = {
            deviceId: callerId,
            publicKey: callerKey.export({ type: 'spki', format: 'der' }).toString('base64'),
            name: typeof body.name === 'string' ? body.name.slice(0, 80) : '',
            grants: [],
            pairedAt: Date.now(),
            lastSeenAt: Date.now(),
          }
          await store.upsertPeer(record)
          if (typeof options.onPaired === 'function') await options.onPaired(record)
          sendJson(res, 200, {
            protocol: PROTOCOL,
            deviceId: identity.deviceId,
            name,
            publicKey: publicKeyDerBase64(identity.publicPem),
          })
          return
        }

        if (req.method === 'GET' && path === '/ui-token') {
          const callerId = headerValue(req, 'x-fleet-device')
          const peer = await store.getPeer(callerId)
          if (!peer || peer.uiAccess !== true) throw new PeerError(403, 'ui-access-required')
          const signedBy = verifySignature(req, Buffer.alloc(0), publicKeyFromDerBase64(peer.publicKey), seenNonces)
          if (signedBy !== peer.deviceId) throw new PeerError(403, 'device-id-mismatch')
          if (typeof options.uiToken !== 'function') throw new PeerError(503, 'ui-token-unavailable')
          sendJson(res, 200, { protocol: PROTOCOL, url: await options.uiToken() })
          return
        }

        if (req.method === 'POST' && path === '/session/create') {
          const raw = await readRawBody(req)
          const callerId = headerValue(req, 'x-fleet-device')
          const peer = await store.getPeer(callerId)
          if (!peer || peer.sessionAccess !== true) throw new PeerError(403, 'session-access-required')
          const signedBy = verifySignature(req, raw, publicKeyFromDerBase64(peer.publicKey), seenNonces)
          if (signedBy !== peer.deviceId) throw new PeerError(403, 'device-id-mismatch')
          const body = raw.length === 0 ? {} : JSON.parse(raw.toString('utf8'))
          const workspaceId = typeof body.workspaceId === 'string' ? body.workspaceId : ''
          if (workspaceId === '') throw new PeerError(400, 'workspace-required')
          const sessionId = await options.createSession(workspaceId, callerId)
          if (typeof store.touchPeer === 'function') await store.touchPeer(callerId)
          sendJson(res, 200, { protocol: PROTOCOL, sessionId })
          return
        }

        if (req.method === 'POST' && path === '/session/prompt') {
          const raw = await readRawBody(req)
          const callerId = headerValue(req, 'x-fleet-device')
          const peer = await store.getPeer(callerId)
          if (!peer || peer.sessionAccess !== true) throw new PeerError(403, 'session-access-required')
          const signedBy = verifySignature(req, raw, publicKeyFromDerBase64(peer.publicKey), seenNonces)
          if (signedBy !== peer.deviceId) throw new PeerError(403, 'device-id-mismatch')
          const body = raw.length === 0 ? {} : JSON.parse(raw.toString('utf8'))
          const sessionId = typeof body.sessionId === 'string' ? body.sessionId : ''
          const text = typeof body.text === 'string' ? body.text : ''
          if (sessionId === '' || text === '') throw new PeerError(400, 'session-and-text-required')
          await options.promptSession(sessionId, text)
          if (typeof store.touchPeer === 'function') await store.touchPeer(callerId)
          sendJson(res, 200, { protocol: PROTOCOL, accepted: true })
          return
        }

        if (req.method === 'GET' && path === '/session/tail') {
          const callerId = headerValue(req, 'x-fleet-device')
          const peer = await store.getPeer(callerId)
          if (!peer || peer.sessionAccess !== true) throw new PeerError(403, 'session-access-required')
          const signedBy = verifySignature(req, Buffer.alloc(0), publicKeyFromDerBase64(peer.publicKey), seenNonces)
          if (signedBy !== peer.deviceId) throw new PeerError(403, 'device-id-mismatch')
          const requestUrl = new URL(req.url || '/', 'http://localhost')
          const sessionId = requestUrl.searchParams.get('sessionId') || ''
          const since = Number(requestUrl.searchParams.get('since') || '0')
          if (sessionId === '') throw new PeerError(400, 'session-required')
          const tail = await options.tailSession(sessionId, Number.isFinite(since) ? since : 0)
          sendJson(res, 200, { protocol: PROTOCOL, ...tail })
          return
        }

        if (req.method === 'GET' && path === '/session/questions') {
          const callerId = headerValue(req, 'x-fleet-device')
          const peer = await store.getPeer(callerId)
          if (!peer || peer.sessionAccess !== true) throw new PeerError(403, 'session-access-required')
          const signedBy = verifySignature(req, Buffer.alloc(0), publicKeyFromDerBase64(peer.publicKey), seenNonces)
          if (signedBy !== peer.deviceId) throw new PeerError(403, 'device-id-mismatch')
          const questions = typeof options.listQuestions === 'function' ? options.listQuestions(peer.deviceId) : []
          sendJson(res, 200, { protocol: PROTOCOL, questions })
          return
        }

        if (req.method === 'POST' && path === '/session/questions/respond') {
          const raw = await readRawBody(req)
          const callerId = headerValue(req, 'x-fleet-device')
          const peer = await store.getPeer(callerId)
          if (!peer || peer.sessionAccess !== true) throw new PeerError(403, 'session-access-required')
          const signedBy = verifySignature(req, raw, publicKeyFromDerBase64(peer.publicKey), seenNonces)
          if (signedBy !== peer.deviceId) throw new PeerError(403, 'device-id-mismatch')
          const body = raw.length === 0 ? {} : JSON.parse(raw.toString('utf8'))
          const id = typeof body.id === 'string' ? body.id : ''
          const answers = Array.isArray(body.answers) ? body.answers : null
          if (id === '' || answers === null) throw new PeerError(400, 'id-and-answers-required')
          const accepted = typeof options.respondQuestion === 'function'
            ? options.respondQuestion(peer.deviceId, id, answers)
            : false
          if (!accepted) throw new PeerError(404, 'question-not-found')
          sendJson(res, 200, { protocol: PROTOCOL, accepted: true })
          return
        }

        if (req.method === 'GET' && path === '/session/approvals') {
          const callerId = headerValue(req, 'x-fleet-device')
          const peer = await store.getPeer(callerId)
          if (!peer || peer.sessionAccess !== true) throw new PeerError(403, 'session-access-required')
          const signedBy = verifySignature(req, Buffer.alloc(0), publicKeyFromDerBase64(peer.publicKey), seenNonces)
          if (signedBy !== peer.deviceId) throw new PeerError(403, 'device-id-mismatch')
          const approvals = typeof options.listApprovals === 'function' ? options.listApprovals(peer.deviceId) : []
          sendJson(res, 200, { protocol: PROTOCOL, approvals })
          return
        }

        if (req.method === 'POST' && path === '/session/approvals/respond') {
          const raw = await readRawBody(req)
          const callerId = headerValue(req, 'x-fleet-device')
          const peer = await store.getPeer(callerId)
          if (!peer || peer.sessionAccess !== true) throw new PeerError(403, 'session-access-required')
          const signedBy = verifySignature(req, raw, publicKeyFromDerBase64(peer.publicKey), seenNonces)
          if (signedBy !== peer.deviceId) throw new PeerError(403, 'device-id-mismatch')
          const body = raw.length === 0 ? {} : JSON.parse(raw.toString('utf8'))
          const id = typeof body.id === 'string' ? body.id : ''
          const outcome = typeof body.outcome === 'string' ? body.outcome : ''
          if (id === '' || outcome === '') throw new PeerError(400, 'id-and-outcome-required')
          const accepted = typeof options.respondApproval === 'function'
            ? options.respondApproval(peer.deviceId, id, outcome)
            : false
          if (!accepted) throw new PeerError(404, 'approval-not-found')
          sendJson(res, 200, { protocol: PROTOCOL, accepted: true })
          return
        }

        if (req.method === 'GET' && path === '/sessions') {          const callerId = headerValue(req, 'x-fleet-device')
          const peer = await store.getPeer(callerId)
          if (!peer || peer.sessionAccess !== true) throw new PeerError(403, 'session-access-required')
          const signedBy = verifySignature(req, Buffer.alloc(0), publicKeyFromDerBase64(peer.publicKey), seenNonces)
          if (signedBy !== peer.deviceId) throw new PeerError(403, 'device-id-mismatch')
          const sessions = typeof options.listSessions === 'function' ? await options.listSessions() : []
          if (typeof store.touchPeer === 'function') await store.touchPeer(callerId)
          sendJson(res, 200, { protocol: PROTOCOL, sessions })
          return
        }

        if (req.method === 'GET' && path === '/workspaces') {
          const callerId = headerValue(req, 'x-fleet-device')
          const peer = await store.getPeer(callerId)
          if (!peer) throw new PeerError(403, 'unknown-peer')
          const signedBy = verifySignature(req, Buffer.alloc(0), publicKeyFromDerBase64(peer.publicKey), seenNonces)
          if (signedBy !== peer.deviceId) throw new PeerError(403, 'device-id-mismatch')
          const grants = Array.isArray(peer.grants) ? peer.grants : []
          const workspaces = listWorkspaces()
            .filter((workspace) => grants.includes(workspace.id))
            .map((workspace) => ({
              id: workspace.id,
              title: workspace.title,
              path: workspace.path,
              status: workspace.status ?? 'ok',
            }))
          if (typeof store.touchPeer === 'function') await store.touchPeer(callerId)
          sendJson(res, 200, { protocol: PROTOCOL, workspaces })
          return
        }

        sendJson(res, 404, { error: 'not-found' })
      } catch (error) {
        const status = error instanceof PeerError ? error.status : 500
        sendJson(res, status, { error: error instanceof PeerError ? error.code : 'internal-error' })
      }
    })()
  })

  if (typeof options.tunnelTargetPort === 'number' && options.tunnelTargetPort > 0) {
    attachTunnel(server, {
      targetPort: options.tunnelTargetPort,
      authorize: async (request) => {
        const deviceId = headerValue(request, 'x-fleet-device')
        const peer = await store.getPeer(deviceId)
        if (!peer || peer.uiAccess !== true) return null
        const verified = verifySignature(request, Buffer.alloc(0), publicKeyFromDerBase64(peer.publicKey), seenNonces)
        return verified === peer.deviceId ? peer : null
      },
    })
  }

  return {
    server,
    start() {      return new Promise((resolve, reject) => {
        server.once('error', reject)
        server.listen(port, host, () => {
          const address = server.address()
          resolve({ port: typeof address === 'object' && address ? address.port : port, host })
        })
      })
    },
    close() {
      return new Promise((resolve) => server.close(() => resolve()))
    },
  }
}

export function normalizePeerAddress(address) {
  const value = String(address ?? '').trim().replace(/\/+$/, '')
  if (value === '') throw new Error('address-required')
  return /^https?:\/\//i.test(value) ? value : `http://${value}`
}

export async function peerHello(address, options = {}) {
  const base = normalizePeerAddress(address)
  const response = await fetch(`${base}/hello`, {
    headers: { accept: 'application/json' },
    signal: AbortSignal.timeout(options.timeoutMs ?? 2500),
  })
  if (!response.ok) throw new Error(`hello ${response.status}`)
  const data = await response.json()
  if (data.protocol !== PROTOCOL) throw new Error('protocol-mismatch')
  return data
}

export async function peerPair(options) {
  const base = normalizePeerAddress(options.address)
  const timeoutMs = options.timeoutMs ?? 8000
  const hello = await peerHello(base, { timeoutMs })
  const body = { name: options.name ?? '' }
  const signed = signRequest(options.identity, 'POST', '/pair', body, {
    code: options.code,
    token: options.token,
    publicKey: publicKeyDerBase64(options.identity.publicPem),
  })
  const response = await fetch(`${base}/pair`, {
    method: 'POST',
    headers: { ...signed.headers, 'content-type': 'application/json', accept: 'application/json' },
    body: signed.body,
    signal: AbortSignal.timeout(timeoutMs),
  })
  const text = await response.text()
  let ack = null
  try {
    ack = text ? JSON.parse(text) : null
  } catch {
    ack = null
  }
  if (!response.ok) throw new Error(`pair ${response.status}${ack && ack.error ? ` ${ack.error}` : ''}`)
  return { hello, ack }
}

export async function peerWorkspaces(options) {  const base = normalizePeerAddress(options.address)
  const signed = signRequest(options.identity, 'GET', '/workspaces')
  const response = await fetch(`${base}/workspaces`, {
    headers: { ...signed.headers, accept: 'application/json' },
    signal: AbortSignal.timeout(options.timeoutMs ?? 5000),
  })
  const text = await response.text()
  let data = null
  try {
    data = text ? JSON.parse(text) : null
  } catch {
    data = null
  }
  if (!response.ok) throw new Error(`workspaces ${response.status}${data && data.error ? ` ${data.error}` : ''}`)
  return (data && data.workspaces) || []
}

export async function peerSessions(options) {
  const base = normalizePeerAddress(options.address)
  const signed = signRequest(options.identity, 'GET', '/sessions')
  const response = await fetch(`${base}/sessions`, {
    headers: { ...signed.headers, accept: 'application/json' },
    signal: AbortSignal.timeout(options.timeoutMs ?? 5000),
  })
  const text = await response.text()
  let data = null
  try {
    data = text ? JSON.parse(text) : null
  } catch {
    data = null
  }
  if (!response.ok) throw new Error(`sessions ${response.status}${data && data.error ? ` ${data.error}` : ''}`)
  return (data && data.sessions) || []
}

async function signedCall(options) {
  const base = normalizePeerAddress(options.address)
  const pathname = String(options.path).split('?')[0]
  const signed = signRequest(options.identity, options.method, pathname, options.body)
  const headers = { ...signed.headers, accept: 'application/json' }
  if (options.body !== undefined) headers['content-type'] = 'application/json'
  const response = await fetch(`${base}${options.path}`, {
    method: options.method,
    headers,
    body: options.body === undefined ? undefined : signed.body,
    signal: AbortSignal.timeout(options.timeoutMs ?? 8000),
  })
  const text = await response.text()
  let data = null
  try {
    data = text ? JSON.parse(text) : null
  } catch {
    data = null
  }
  if (!response.ok) {
    throw new Error(`${options.path} ${response.status}${data && data.error ? ` ${data.error}` : ''}`)
  }
  return data
}

export async function peerUiToken(options) {
  const data = await signedCall({ ...options, method: 'GET', path: '/ui-token', timeoutMs: options.timeoutMs ?? 4000 })
  return (data && data.url) || ''
}

export async function peerSessionCreate(options) {
  const data = await signedCall({
    ...options,
    method: 'POST',
    path: '/session/create',
    body: { workspaceId: options.workspaceId },
  })
  return (data && data.sessionId) || ''
}

export async function peerSessionPrompt(options) {
  return await signedCall({
    ...options,
    method: 'POST',
    path: '/session/prompt',
    body: { sessionId: options.sessionId, text: options.text },
  })
}

export async function peerSessionTail(options) {
  const query = new URLSearchParams({ sessionId: options.sessionId, since: String(options.since ?? 0) })
  return await signedCall({
    ...options,
    method: 'GET',
    path: `/session/tail?${query.toString()}`,
    timeoutMs: options.timeoutMs ?? 4000,
  })
}

export async function peerApprovals(options) {
  const data = await signedCall({ ...options, method: 'GET', path: '/session/approvals', timeoutMs: options.timeoutMs ?? 4000 })
  return (data && data.approvals) || []
}

export async function peerApprovalRespond(options) {
  return await signedCall({
    ...options,
    method: 'POST',
    path: '/session/approvals/respond',
    body: { id: options.id, outcome: options.outcome },
  })
}

export async function peerQuestions(options) {
  const data = await signedCall({ ...options, method: 'GET', path: '/session/questions', timeoutMs: options.timeoutMs ?? 4000 })
  return (data && data.questions) || []
}

export async function peerQuestionRespond(options) {
  return await signedCall({
    ...options,
    method: 'POST',
    path: '/session/questions/respond',
    body: { id: options.id, answers: options.answers },
  })
}

