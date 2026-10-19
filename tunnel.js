import net from 'node:net'
import { signRequest } from './peer.js'

export const OPEN = 1
export const DATA = 2
export const CLOSE = 3

const HEADER_BYTES = 9
const MAX_FRAME_BYTES = 1024 * 1024
const UPGRADE_HEAD = 'dsh-fleet-tunnel'

export function encodeFrame(id, type, payload) {
  const body = payload && payload.length ? payload : Buffer.alloc(0)
  const head = Buffer.alloc(HEADER_BYTES)
  head.writeUInt32BE(id >>> 0, 0)
  head[4] = type
  head.writeUInt32BE(body.length, 5)
  return body.length === 0 ? head : Buffer.concat([head, body])
}

export function decodeFrames(buffer) {
  const frames = []
  let offset = 0
  while (buffer.length - offset >= HEADER_BYTES) {
    const id = buffer.readUInt32BE(offset)
    const type = buffer[offset + 4]
    const length = buffer.readUInt32BE(offset + 5)
    if (length > MAX_FRAME_BYTES) break
    const start = offset + HEADER_BYTES
    if (buffer.length - start < length) break
    frames.push({ id, type, payload: buffer.subarray(start, start + length) })
    offset = start + length
  }
  return { frames, rest: buffer.subarray(offset) }
}

function tunnelRejection(socket, status, reason) {
  socket.write(`HTTP/1.1 ${status} ${reason}\r\nconnection: close\r\ncontent-length: 0\r\n\r\n`)
  socket.destroy()
}

/**
 * Accept `Upgrade: dsh-fleet-tunnel` connections on an existing peer listener
 * and relay each stream to a loopback TCP port (the owner's own dsh web).
 */
export function attachTunnel(server, options) {
  const targetPort = options.targetPort
  const authorize = options.authorize

  server.on('upgrade', (req, socket) => {
    void (async () => {
      if (String(req.headers.upgrade || '').toLowerCase() !== UPGRADE_HEAD) {
        tunnelRejection(socket, 426, 'Upgrade Required')
        return
      }
      try {
        const peer = await authorize(req)
        if (!peer) {
          tunnelRejection(socket, 403, 'Forbidden')
          return
        }
        socket.write([
          'HTTP/1.1 101 Switching Protocols',
          `upgrade: ${UPGRADE_HEAD}`,
          'connection: Upgrade',
          '',
          '',
        ].join('\r\n'))
        socket.setNoDelay(true)
      } catch {
        tunnelRejection(socket, 403, 'Forbidden')
        return
      }

      const streams = new Map()

      const send = (id, type, payload) => {
        if (socket.destroyed) return
        socket.write(encodeFrame(id, type, payload))
      }

      const openStream = (id) => {
        if (streams.has(id)) return
        const upstream = net.connect(targetPort, '127.0.0.1')
        streams.set(id, upstream)
        upstream.on('data', (chunk) => send(id, DATA, chunk))
        upstream.on('end', () => {
          send(id, CLOSE)
          streams.delete(id)
        })
        upstream.on('close', () => streams.delete(id))
        upstream.on('error', () => {
          send(id, CLOSE)
          streams.delete(id)
          upstream.destroy()
        })
        upstream.setNoDelay(true)
      }

      let buffer = Buffer.alloc(0)
      socket.on('data', (chunk) => {
        buffer = buffer.length === 0 ? chunk : Buffer.concat([buffer, chunk])
        const decoded = decodeFrames(buffer)
        buffer = decoded.rest
        for (const frame of decoded.frames) {
          if (frame.type === OPEN) openStream(frame.id)
          else if (frame.type === DATA) {
            const upstream = streams.get(frame.id)
            if (upstream && !upstream.destroyed) upstream.write(frame.payload)
          } else if (frame.type === CLOSE) {
            const upstream = streams.get(frame.id)
            streams.delete(frame.id)
            if (upstream) upstream.end()
          }
        }
      })

      const cleanup = () => {
        for (const upstream of streams.values()) upstream.destroy()
        streams.clear()
      }
      socket.on('close', cleanup)
      socket.on('error', cleanup)
    })()
  })
}

/**
 * Open one tunnel connection to a paired peer. Each local proxied connection
 * uses its own tunnel for now; stream ids are already carried so multiplexing
 * can be added without a protocol change.
 */
export function connectTunnel(options) {
  const host = options.host
  const port = options.port
  const identity = options.identity
  const timeoutMs = options.timeoutMs ?? 5000

  return new Promise((resolve, reject) => {
    const socket = net.connect(port, host)
    socket.setNoDelay(true)
    let settled = false

    const fail = (error) => {
      if (settled) return
      settled = true
      socket.destroy()
      reject(error)
    }

    const timer = setTimeout(() => fail(new Error('tunnel-timeout')), timeoutMs)
    socket.once('error', (error) => {
      clearTimeout(timer)
      fail(error)
    })

    socket.once('connect', () => {
      const signed = signRequest(identity, 'GET', '/tunnel')
      const lines = [
        'GET /tunnel HTTP/1.1',
        `Host: ${host}:${port}`,
        `Upgrade: ${UPGRADE_HEAD}`,
        'Connection: Upgrade',
      ]
      for (const [name, value] of Object.entries(signed.headers)) lines.push(`${name}: ${value}`)
      socket.write(`${lines.join('\r\n')}\r\n\r\n`)
    })

    let head = Buffer.alloc(0)
    const onHead = (chunk) => {
      head = Buffer.concat([head, chunk])
      const boundary = head.indexOf('\r\n\r\n')
      if (boundary === -1) {
        if (head.length > 16 * 1024) fail(new Error('tunnel-handshake-too-large'))
        return
      }
      const text = head.subarray(0, boundary).toString('latin1')
      const status = Number(text.split(' ')[1])
      const rest = head.subarray(boundary + 4)
      if (status !== 101) {
        fail(new Error(`tunnel-rejected-${status}`))
        return
      }
      clearTimeout(timer)
      socket.removeListener('data', onHead)
      settled = true

      let buffer = Buffer.alloc(0)
      const listeners = []

      const dispatch = (chunk) => {
        buffer = buffer.length === 0 ? chunk : Buffer.concat([buffer, chunk])
        const decoded = decodeFrames(buffer)
        buffer = decoded.rest
        for (const frame of decoded.frames) {
          for (const listener of listeners) listener(frame)
        }
      }

      socket.on('data', dispatch)

      resolve({
        socket,
        onFrame(listener) {
          listeners.push(listener)
        },
        send(type, payload) {
          if (!socket.destroyed) socket.write(encodeFrame(1, type, payload))
        },
        close() {
          socket.destroy()
        },
      })
      if (rest.length > 0) dispatch(rest)
    }

    socket.on('data', onHead)
  })
}

/** Bind a loopback port that relays every connection to the peer's dsh web. */
export function startUiProxy(options) {
  const server = net.createServer((client) => {
    client.setNoDelay(true)
    void (async () => {
      try {
        const tunnel = await connectTunnel({
          host: options.host,
          port: options.port,
          identity: options.identity,
          timeoutMs: options.timeoutMs,
        })
        tunnel.onFrame((frame) => {
          if (frame.type === DATA) client.write(frame.payload)
          else if (frame.type === CLOSE) client.end()
        })
        tunnel.send(OPEN)
        client.on('data', (chunk) => tunnel.send(DATA, chunk))
        client.on('end', () => tunnel.send(CLOSE))
        client.on('close', () => tunnel.close())
        client.on('error', () => tunnel.close())
      } catch {
        client.destroy()
      }
    })()
  })

  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      resolve({ server, port: typeof address === 'object' && address ? address.port : 0 })
    })
  })
}
