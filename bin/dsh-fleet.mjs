#!/usr/bin/env node
/**
 * Headless control for a running dsh-fleet plugin.
 *
 * Talks to the local DSH web API, so it works with no browser and no UI:
 *
 *   node bin/dsh-fleet.mjs identity
 *   node bin/dsh-fleet.mjs pair 192.168.3.245:3071 --token <token printed by dsh web>
 *   node bin/dsh-fleet.mjs pair 127.0.0.1:3071 --code ABCD-...
 *   node bin/dsh-fleet.mjs peers
 *   node bin/dsh-fleet.mjs workspaces <deviceId>
 *   node bin/dsh-fleet.mjs grant <deviceId> <workspaceId> [--revoke]
 *   node bin/dsh-fleet.mjs workspaces-local
 *
 * `--local` points at the local DSH web origin (default http://127.0.0.1:3080,
 * or $DSH_WEB_URL).
 */

import { readFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

const HELP = `dsh-fleet CLI

  identity                     show this device's id, pairing code and peer listener
  pair <address> [--token T] [--code C]
                               pair with a peer; --token is the token dsh web printed
  peers                        list paired peers
  workspaces <deviceId>        fetch that peer's granted workspace metadata
  workspaces-local             list this instance's workspaces
  sessions <deviceId>          list that peer's session metadata
  task <deviceId> <wsId> <text...>
                               create a session on the peer and submit text
  task-poll <taskId>           read new events of a submitted task
  task-approve <taskId> <approvalId> [allow|deny]
                               answer a pending approval on the owner
  session-access <deviceId> [--revoke]
                               allow or revoke a peer's access to this session list
  grant <deviceId> <wsId> [--revoke]
                               allow or revoke a peer's access to a local workspace
  unpeer <deviceId>            forget a peer

Options:
  --local <url>                local DSH web origin; defaults to $DSH_WEB_URL, then
                               $DSH_HOME/dsh-fleet/runtime.json (written by the plugin,
                               so DeepSeek Desktop's random port is found automatically),
                               then http://127.0.0.1:3080
  --json                       raw JSON output
`

function parseArguments(argv) {
  const positional = []
  const flags = {}
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index]
    if (value === '--json') {
      flags.json = true
      continue
    }
    if (value.startsWith('--')) {
      const name = value.slice(2)
      const next = argv[index + 1]
      if (next === undefined || next.startsWith('--')) {
        flags[name] = true
        continue
      }
      flags[name] = next
      index += 1
      continue
    }
    positional.push(value)
  }
  return { positional, flags }
}

function normalizeBase(value) {
  return String(value).replace(/\/+$/, '')
}

async function resolveLocal(flags) {
  if (typeof flags.local === 'string' && flags.local !== '') return normalizeBase(flags.local)
  if (process.env.DSH_WEB_URL) return normalizeBase(process.env.DSH_WEB_URL)
  const home = process.env.DSH_HOME || path.join(os.homedir(), '.dsh')
  try {
    const runtime = JSON.parse(await readFile(path.join(home, 'dsh-fleet', 'runtime.json'), 'utf8'))
    if (runtime && typeof runtime.webUrl === 'string' && runtime.webUrl !== '') {
      return normalizeBase(runtime.webUrl)
    }
  } catch {
    // No published runtime; fall back to the documented default.
  }
  return 'http://127.0.0.1:3080'
}

async function call(flags, path, body) {
  const base = await resolveLocal(flags)
  const url = `${base}/api/dsh-fleet${path}`
  const response = await fetch(url, body === undefined
    ? { headers: { accept: 'application/json' } }
    : {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify(body),
      })
  const text = await response.text()
  let data = null
  try {
    data = text === '' ? null : JSON.parse(text)
  } catch {
    data = null
  }
  if (!response.ok) {
    const reason = (data && (data.message || data.error)) || text || `HTTP ${response.status}`
    throw new Error(`${path}: ${reason}`)
  }
  return data
}

function print(value, flags) {
  if (flags.json) {
    console.log(JSON.stringify(value, null, 2))
    return
  }
  console.log(JSON.stringify(value, null, 2))
}

async function main() {
  const { positional, flags } = parseArguments(process.argv.slice(2))
  const [command, first, second] = positional

  if (!command || command === 'help' || flags.help) {
    console.log(HELP.trim())
    return
  }

  if (command === 'identity') {
    print(await call(flags, '/identity'), flags)
    return
  }

  if (command === 'pair') {
    if (!first) throw new Error('pair requires <address>')
    const credential = {}
    if (typeof flags.code === 'string') credential.code = flags.code
    if (typeof flags.token === 'string') credential.token = flags.token
    if (!credential.code && !credential.token) throw new Error('pair requires --token or --code')
    const result = await call(flags, '/pair', { address: first, ...credential })
    print(result, flags)
    return
  }

  if (command === 'peers') {
    print(await call(flags, '/peers'), flags)
    return
  }

  if (command === 'workspaces') {
    if (!first) throw new Error('workspaces requires <deviceId>')
    print(await call(flags, '/peers/workspaces', { deviceId: first }), flags)
    return
  }

  if (command === 'workspaces-local') {
    print(await call(flags, '/workspaces'), flags)
    return
  }

  if (command === 'sessions') {
    if (!first) throw new Error('sessions requires <deviceId>')
    print(await call(flags, '/peers/sessions', { deviceId: first }), flags)
    return
  }

  if (command === 'task') {
    if (!first || !second || positional.length < 4) throw new Error('task requires <deviceId> <workspaceId> <text>')
    const text = positional.slice(3).join(' ')
    print(await call(flags, '/peers/task', { deviceId: first, workspaceId: second, text }), flags)
    return
  }

  if (command === 'task-poll') {
    if (!first) throw new Error('task-poll requires <taskId>')
    print(await call(flags, '/peers/task/poll', { taskId: first }), flags)
    return
  }

  if (command === 'task-approve') {
    if (!first || !second) throw new Error('task-approve requires <taskId> <approvalId> [allow|deny]')
    const outcome = positional[3] === 'deny' ? 'rejected' : 'allowed-once'
    print(await call(flags, '/peers/task/approve', { taskId: first, approvalId: second, outcome }), flags)
    return
  }

  if (command === 'session-access') {
    if (!first) throw new Error('session-access requires <deviceId>')
    print(await call(flags, '/peers/session-access', { deviceId: first, allow: flags.revoke !== true }), flags)
    return
  }

  if (command === 'grant') {
    if (!first || !second) throw new Error('grant requires <deviceId> <workspaceId>')
    print(await call(flags, '/peers/grant', { deviceId: first, workspaceId: second, allow: flags.revoke !== true }), flags)
    return
  }

  if (command === 'unpeer') {
    if (!first) throw new Error('unpeer requires <deviceId>')
    print(await call(flags, '/peers/delete', { deviceId: first }), flags)
    return
  }

  throw new Error(`unknown command: ${command}`)
}

main().catch((error) => {
  console.error(`dsh-fleet: ${error.message}`)
  process.exitCode = 1
})
