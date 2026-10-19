import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { deviceIdFromDer, startPeerServer } from '../peer.js'

const DSH = 'http://127.0.0.1:57472/api/dsh-fleet'
const TOKEN = 'sessions-integration-token'
const PEER_PORT = 3997

const { publicKey, privateKey } = generateKeyPairSync('ed25519')
const identity = {
  deviceId: deviceIdFromDer(publicKey.export({ type: 'spki', format: 'der' })),
  publicPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  pairingCode: 'SESS-SESS-SESS-SESS-SESS-SESS',
}

const peers = new Map()
const store = {
  async upsertPeer(record) {
    peers.set(record.deviceId, record)
  },
  async getPeer(deviceId) {
    return peers.get(deviceId)
  },
  async touchPeer() {},
}

const sessions = [
  { sessionId: 's-alpha', title: 'Alpha', cwd: '/srv/alpha', running: true, updatedAt: 1700000000000 },
  { sessionId: 's-beta', title: 'Beta', cwd: '/srv/beta', running: false, updatedAt: 1700000001000 },
]

const server = startPeerServer({
  identity,
  store,
  listWorkspaces: () => [],
  listSessions: () => sessions,
  name: 'owner',
  port: PEER_PORT,
  verifyToken: async (candidate) => candidate === TOKEN,
  onPaired: async (record) => {
    record.sessionAccess = true
  },
})
await server.start()

async function call(path, body) {
  const response = await fetch(`${DSH}${path}`, body === undefined
    ? { headers: { accept: 'application/json' } }
    : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
  const text = await response.text()
  if (!response.ok) throw new Error(`${path} -> ${response.status} ${text}`)
  return text === '' ? null : JSON.parse(text)
}

try {
  await call('/pair', { address: `127.0.0.1:${PEER_PORT}`, token: TOKEN })
  console.log('ok paired with the fake owner')

  const listed = await call('/peers/sessions', { deviceId: identity.deviceId })
  assert.equal(listed.sessions.length, 2)
  assert.equal(listed.sessions[0].title, 'Alpha')
  assert.equal(listed.sessions[0].running, true)
  console.log('ok remote session metadata fetched through the plugin')
} finally {
  await call('/peers/delete', { deviceId: identity.deviceId }).catch(() => {})
  void server.close()
}

console.log('sessions integration: all checks passed')
process.exit(0)
