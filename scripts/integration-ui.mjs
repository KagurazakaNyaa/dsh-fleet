import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import http from 'node:http'
import { deviceIdFromDer, startPeerServer } from '../peer.js'

const DSH = 'http://127.0.0.1:57472/api/dsh-fleet'
const TOKEN = 'ui-integration-token'
const PEER_PORT = 3998

const { publicKey, privateKey } = generateKeyPairSync('ed25519')
const identity = {
  deviceId: deviceIdFromDer(publicKey.export({ type: 'spki', format: 'der' })),
  publicPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  pairingCode: 'UIUI-UIUI-UIUI-UIUI-UIUI-UIUI',
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

const owner = http.createServer((req, res) => {
  res.setHeader('content-type', 'text/html; charset=utf-8')
  res.end('<html><body>OWNER-UI</body></html>')
})
await new Promise((resolve) => owner.listen(0, '127.0.0.1', resolve))

const peerServer = startPeerServer({
  identity,
  store,
  listWorkspaces: () => [],
  name: 'owner',
  port: PEER_PORT,
  tunnelTargetPort: owner.address().port,
  verifyToken: async (candidate) => candidate === TOKEN,
  onPaired: async (record) => {
    record.uiAccess = true
  },
})
await peerServer.start()

async function call(path, body) {
  const response = await fetch(`${DSH}${path}`, body === undefined
    ? { headers: { accept: 'application/json' } }
    : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
  const text = await response.text()
  const data = text === '' ? null : JSON.parse(text)
  if (!response.ok) {
    const error = new Error(`${path} -> ${response.status} ${text}`)
    error.status = response.status
    throw error
  }
  return data
}

try {
  const paired = await call('/pair', { address: `127.0.0.1:${PEER_PORT}`, token: TOKEN })
  assert.equal(paired.peer.deviceId, identity.deviceId)
  console.log('ok paired with the fake owner')

  const opened = await call('/peers/ui', { deviceId: identity.deviceId })
  assert.match(opened.url, /^http:\/\/127\.0\.0\.1:\d+\/$/)
  console.log('ok proxy url', opened.url)

  const page = await fetch(opened.url)
  const text = await page.text()
  assert.match(text, /OWNER-UI/)
  console.log('ok owner UI served through the loopback proxy')
} finally {
  await call('/peers/delete', { deviceId: identity.deviceId }).catch(() => {})
  void peerServer.close()
  owner.closeAllConnections?.()
  void owner.close()
}

console.log('ui integration: all checks passed')
process.exit(0)
