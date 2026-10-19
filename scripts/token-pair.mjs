import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { deviceIdFromDer, peerPair, startPeerServer } from '../peer.js'

const TOKEN = 'token-printed-by-dsh-web'

function makeIdentity(pairingCode) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  return {
    deviceId: deviceIdFromDer(publicKey.export({ type: 'spki', format: 'der' })),
    publicPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    pairingCode,
  }
}

function memoryStore() {
  const peers = new Map()
  return {
    peers,
    async upsertPeer(record) {
      peers.set(record.deviceId, record)
    },
    async getPeer(deviceId) {
      return peers.get(deviceId)
    },
    async touchPeer() {},
  }
}

const alice = makeIdentity('AAAA-AAAA-AAAA-AAAA-AAAA-AAAA')
const bob = makeIdentity('BBBB-BBBB-BBBB-BBBB-BBBB-BBBB')
const storeBob = memoryStore()

const serverBob = startPeerServer({
  identity: bob,
  store: storeBob,
  listWorkspaces: () => [],
  name: 'bob',
  port: 0,
  verifyToken: async (candidate) => candidate === TOKEN,
})

const { port } = await serverBob.start()
const address = `127.0.0.1:${port}`

try {
  const paired = await peerPair({ address, token: TOKEN, identity: alice, name: 'alice' })
  assert.equal(paired.ack.deviceId, bob.deviceId)
  assert.equal(storeBob.peers.size, 1)
  console.log('ok paired with the dsh web token')

  await assert.rejects(
    peerPair({ address, token: 'not-the-token', identity: alice, name: 'alice' }),
    /bad-token/,
  )
  console.log('ok wrong token rejected')

  await assert.rejects(
    peerPair({ address, identity: alice, name: 'alice' }),
    /missing-bootstrap-credential/,
  )
  console.log('ok pairing without any credential rejected')

  const viaCode = await peerPair({ address, code: bob.pairingCode, identity: alice, name: 'alice' })
  assert.equal(viaCode.ack.deviceId, bob.deviceId)
  console.log('ok pairing code still works alongside the token')
} finally {
  await serverBob.close()
}

console.log('token pair: all checks passed')
