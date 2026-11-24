// F8 harness client: opens one collaboration session on edm-<doc> and reports, as JSON lines on stdout,
// when it is synced and when (and with which close code) the server ends it.
// Usage: node client.mjs <ws-url> <doc-id> <jwt>
import { HocuspocusProvider } from '@hocuspocus/provider'
import WebSocket from 'ws'
import * as Y from 'yjs'
const [url, doc, token] = process.argv.slice(2)
const out = (o) => process.stdout.write(JSON.stringify({ t: Date.now() / 1000, ...o }) + '\n')
const provider = new HocuspocusProvider({
  url, name: `edm-${doc}`, token, document: new Y.Doc(), WebSocketPolyfill: WebSocket,
  maxAttempts: 1,
  onAuthenticated: () => out({ ev: 'authenticated' }),
  onAuthenticationFailed: ({ reason }) => { out({ ev: 'auth_failed', reason }); process.exit(0) },
  onSynced: () => out({ ev: 'synced' }),
  onClose: ({ event }) => { out({ ev: 'closed', code: event?.code, reason: event?.reason }); process.exit(0) },
})
setTimeout(() => { out({ ev: 'timeout' }); process.exit(0) }, 120000)
