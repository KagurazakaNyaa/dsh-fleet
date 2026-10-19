import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { deviceIdFromDer, peerSessions, publicKeyDerBase64, startPeerServer } from '../peer.js'

function makeIdentity(code) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  return {
    deviceId: deviceIdFromDer(publicKey.export({ type: 'spki', format: 'der' })),
    publicPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    pairingCode: code,
  }
}

const alice = makeIdentity('AAAA-AAAA-AAAA-AAAA-AAAA-AAAA')
const bob = makeIdentity('BBBB-BBBB-BBBB-BBBB-BBBB-BBBB')

const peers = new Map([[
  alice.deviceId,
  { deviceId: alice.deviceId, publicKey: publicKeyDerBase64(alice.publicPem), name: 'alice', sessionAccess: true, grants: [] },
]])
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
  { sessionId: 's-1', title: 'Alpha', cwd: '/srv/a', running: true, updatedAt: 1700000000000 },
  { sessionId: 's-2', title: '', cwd: '', running: false, updatedAt: 1700000001000 },
]

const server = startPeerServer({
  identity: bob,
  store,
  listWorkspaces: () => [],
  listSessions: () => sessions,
  name: 'bob',
  port: 0,
})
const { port } = await server.start()
const address = `127.0.0.1:${port}`

try {
  const listed = await peerSessions({ address, identity: alice })
  assert.deepEqual(listed, sessions)
  console.log('ok session metadata listed for a granted peer')

  peers.get(alice.deviceId).sessionAccess = false
  await assert.rejects(peerSessions({ address, identity: alice }), /session-access-required/)
  console.log('ok session list refused without the grant')
} finally {
  await server.close()
}

console.log('sessions smoke: all checks passed')
process.exit(0)
