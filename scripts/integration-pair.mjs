import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { deviceIdFromDer, startPeerServer } from '../peer.js'

const DSH = 'http://127.0.0.1:57472/api/dsh-fleet'
const CODE = 'TEST-CODE-0000-1111-2222-3333'
const PORT = 3999

const { publicKey, privateKey } = generateKeyPairSync('ed25519')
const identity = {
  deviceId: deviceIdFromDer(publicKey.export({ type: 'spki', format: 'der' })),
  publicPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  pairingCode: CODE,
}

const peers = new Map()
const store = {
  async upsertPeer(record) {
    peers.set(record.deviceId, record)
  },
  async getPeer(deviceId) {
    return peers.get(deviceId)
  },
  async touchPeer(deviceId) {
    const peer = peers.get(deviceId)
    if (peer) peer.lastSeenAt = Date.now()
  },
}

const workspaces = [
  { id: 'ws-a', title: 'Alpha', path: '/srv/alpha', status: 'ok' },
  { id: 'ws-b', title: 'Beta', path: '/srv/beta', status: 'ok' },
]

const server = startPeerServer({
  identity,
  store,
  listWorkspaces: () => workspaces,
  name: 'fake-peer',
  port: PORT,
  onPaired: async (record) => {
    record.grants = ['ws-a']
  },
})

async function call(path, body) {
  const response = await fetch(`${DSH}${path}`, body === undefined
    ? { headers: { accept: 'application/json' } }
    : { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify(body) })
  const text = await response.text()
  if (!response.ok) throw new Error(`${path} -> ${response.status} ${text}`)
  return text === '' ? null : JSON.parse(text)
}

await server.start()
try {
  const paired = await call('/pair', { address: `127.0.0.1:${PORT}`, code: CODE })
  assert.equal(paired.peer.deviceId, identity.deviceId)
  assert.equal(peers.size, 1)
  console.log('ok paired with fake peer', paired.peer.deviceId)

  const list = await call('/peers')
  assert.ok(list.peers.some((peer) => peer.deviceId === identity.deviceId))
  console.log('ok peer visible in registry')

  const result = await call('/peers/workspaces', { deviceId: identity.deviceId })
  assert.deepEqual(result.workspaces.map((workspace) => workspace.id), ['ws-a'])
  console.log('ok remote workspace metadata fetched:', result.workspaces.map((workspace) => workspace.title).join(', '))

  const wrongCode = await fetch(`${DSH}/pair`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ address: `127.0.0.1:${PORT}`, code: 'NOPE' }),
  })
  assert.equal(wrongCode.status, 400)
  console.log('ok wrong pairing code surfaces as an error')
} finally {
  await call('/peers/delete', { deviceId: identity.deviceId }).catch(() => {})
  await server.close()
}

console.log('integration pair: all checks passed')
