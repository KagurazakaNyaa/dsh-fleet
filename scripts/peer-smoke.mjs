import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import {
  deviceIdFromDer,
  peerHello,
  peerPair,
  peerWorkspaces,
  signRequest,
  startPeerServer,
} from '../peer.js'

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
    async touchPeer(deviceId) {
      const peer = peers.get(deviceId)
      if (peer) peer.lastSeenAt = Date.now()
    },
  }
}

const alice = makeIdentity('AAAA-BBBB-CCCC-DDDD-EEEE-FFFF')
const bob = makeIdentity('1111-2222-3333-4444-5555-6666')
const storeAlice = memoryStore()
const storeBob = memoryStore()
const bobWorkspaces = [
  { id: 'ws-public', title: 'Public', path: '/srv/public', status: 'ok' },
  { id: 'ws-private', title: 'Private', path: '/srv/private', status: 'ok' },
]

const serverAlice = startPeerServer({ identity: alice, store: storeAlice, listWorkspaces: () => [], name: 'alice', port: 0 })
const serverBob = startPeerServer({ identity: bob, store: storeBob, listWorkspaces: () => bobWorkspaces, name: 'bob', port: 0 })

const { port: portAlice } = await serverAlice.start()
const { port: portBob } = await serverBob.start()
const bobAddress = `127.0.0.1:${portBob}`

try {
  const hello = await peerHello(bobAddress)
  assert.equal(hello.deviceId, bob.deviceId)
  assert.equal(hello.name, 'bob')
  console.log('ok hello', hello.deviceId)

  await assert.rejects(
    peerPair({ address: bobAddress, code: 'WRONG', identity: alice, name: 'alice' }),
    /bad-pairing-code/,
  )
  console.log('ok rejects bad pairing code')

  const paired = await peerPair({ address: bobAddress, code: bob.pairingCode, identity: alice, name: 'alice' })
  assert.equal(paired.ack.deviceId, bob.deviceId)
  assert.equal(storeBob.peers.size, 1)
  assert.equal([...storeBob.peers.values()][0].deviceId, alice.deviceId)
  console.log('ok pair', alice.deviceId, '->', bob.deviceId)

  const before = await peerWorkspaces({ address: bobAddress, identity: alice })
  assert.deepEqual(before, [])
  console.log('ok no grants -> empty workspace list')

  storeBob.peers.get(alice.deviceId).grants = ['ws-public']
  const after = await peerWorkspaces({ address: bobAddress, identity: alice })
  assert.deepEqual(after.map((workspace) => workspace.id), ['ws-public'])
  console.log('ok granted workspace visible')

  const signed = signRequest(alice, 'GET', '/workspaces')
  const url = `http://${bobAddress}/workspaces`
  const first = await fetch(url, { headers: signed.headers })
  assert.equal(first.status, 200)
  const replay = await fetch(url, { headers: signed.headers })
  assert.equal(replay.status, 401)
  console.log('ok replay rejected')

  const tamperSigned = signRequest(alice, 'GET', '/workspaces')
  const forged = Buffer.alloc(64).toString('base64')
  const tampered = await fetch(url, { headers: { ...tamperSigned.headers, 'x-fleet-signature': forged } })
  assert.equal(tampered.status, 403)
  console.log('ok bad signature rejected')

  const unknown = signRequest(alice, 'GET', '/workspaces')
  const stranger = makeIdentity('9999')
  const unknownRes = await fetch(url, { headers: { ...unknown.headers, 'x-fleet-device': stranger.deviceId } })
  assert.equal(unknownRes.status, 403)
  console.log('ok unknown peer rejected')
} finally {
  await serverAlice.close()
  await serverBob.close()
  void portAlice
}

console.log('peer smoke: all checks passed')
