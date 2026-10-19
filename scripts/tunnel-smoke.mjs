import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import http from 'node:http'
import { deviceIdFromDer, publicKeyDerBase64, startPeerServer } from '../peer.js'
import { CLOSE, DATA, connectTunnel, startUiProxy, OPEN } from '../tunnel.js'

function makeIdentity(pairingCode) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  return {
    deviceId: deviceIdFromDer(publicKey.export({ type: 'spki', format: 'der' })),
    publicPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    pairingCode,
  }
}

function memoryStore(records) {
  const peers = new Map(records.map((record) => [record.deviceId, record]))
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

async function main() {
  const owner = http.createServer((req, res) => {
    res.setHeader('content-type', 'text/html; charset=utf-8')
    res.end('<html><body>OWNER-UI</body></html>')
  })
  await new Promise((resolve) => owner.listen(0, '127.0.0.1', resolve))
  const ownerPort = owner.address().port

  const alice = makeIdentity('AAAA-AAAA-AAAA-AAAA-AAAA-AAAA')
  const mallory = makeIdentity('CCCC-CCCC-CCCC-CCCC-CCCC-CCCC')
  const bob = makeIdentity('BBBB-BBBB-BBBB-BBBB-BBBB-BBBB')

  const storeBob = memoryStore([{
    deviceId: alice.deviceId,
    publicKey: publicKeyDerBase64(alice.publicPem),
    name: 'alice',
    uiAccess: true,
    grants: [],
  }])

  const serverBob = startPeerServer({
    identity: bob,
    store: storeBob,
    listWorkspaces: () => [],
    name: 'bob',
    port: 0,
    tunnelTargetPort: ownerPort,
  })
  const { port: portBob } = await serverBob.start()

  try {
    const tunnel = await connectTunnel({ host: '127.0.0.1', port: portBob, identity: alice })
    let received = Buffer.alloc(0)
    const finished = new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('tunnel-timeout')), 5000)
      tunnel.onFrame((frame) => {
        if (frame.type === DATA) received = Buffer.concat([received, frame.payload])
        if (frame.type === CLOSE) {
          clearTimeout(timer)
          resolve()
        }
      })
    })
    tunnel.send(OPEN)
    tunnel.send(DATA, Buffer.from('GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n'))
    await finished
    assert.match(received.toString('utf8'), /OWNER-UI/)
    tunnel.close()
    console.log('ok tunnel relays the owner web response')

    await assert.rejects(
      connectTunnel({ host: '127.0.0.1', port: portBob, identity: mallory }),
      /tunnel-rejected-403/,
    )
    console.log('ok unpaired peer rejected by the tunnel')

    const proxy = await startUiProxy({ host: '127.0.0.1', port: portBob, identity: alice })
    const response = await fetch(`http://127.0.0.1:${proxy.port}/`)
    const text = await response.text()
    assert.match(text, /OWNER-UI/)
    console.log('ok loopback proxy serves the owner UI')
  } finally {
    void serverBob.close()
    owner.closeAllConnections?.()
    void owner.close()
  }
}

try {
  await main()
  console.log('tunnel smoke: all checks passed')
  process.exit(0)
} catch (error) {
  console.error(error)
  process.exit(1)
}
