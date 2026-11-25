/**
 * ZTA-ABAC Platform – Hocuspocus WebSocket Collaboration Server
 *
 * Two namespaces:
 *   - Resource UUIDs (e.g. "abc-123")  → PEP /pep/access/{id}/check
 *   - EDM document IDs prefixed "edm-" → /internal/documents/{id}/check
 *
 * Auth flow (per connection):
 *   1. Client sends JWT as the WebSocket token
 *   2. onAuthenticate verifies access
 *   3. Write permission is stored in context
 *
 * Persistence:
 *   Resource:  GET/PUT /api/v1/internal/resources/{id}/document
 *   EDM doc:   GET/PUT /api/v1/internal/documents/{id}/ydoc
 */

import { Server } from '@hocuspocus/server'
import fetch from 'node-fetch'
import { createHmac } from 'crypto'

const BACKEND_URL     = process.env.BACKEND_URL    || 'http://backend:8000'
const INTERNAL_SECRET = process.env.HOCUSPOCUS_SECRET || 'hocuspocus_internal_secret_change_in_prod'
const PORT            = parseInt(process.env.PORT || '1234', 10)

// ── Internal auth headers (HMAC + timestamp, 30-second replay window) ────────

function makeInternalHeaders(extra = {}) {
  const ts  = Math.floor(Date.now() / 1000).toString()
  const sig = createHmac('sha256', INTERNAL_SECRET).update(ts).digest('hex')
  return {
    'X-Internal-Secret':    sig,
    'X-Internal-Timestamp': ts,
    ...extra,
  }
}

// ── Helpers ───────────────────────────────────────────────────

async function pepCheck(resourceId, jwt, action) {
  try {
    const res = await fetch(
      `${BACKEND_URL}/api/v1/pep/access/${resourceId}/check?action=${action}`,
      { headers: { Authorization: `Bearer ${jwt}` }, signal: AbortSignal.timeout(5000) }
    )
    if (!res.ok) return false
    const data = await res.json()
    return data.allowed === true
  } catch {
    return false
  }
}

async function edmCheck(docId, jwt, action) {
  try {
    const res = await fetch(
      `${BACKEND_URL}/api/v1/internal/documents/${docId}/check?token=${encodeURIComponent(jwt)}&action=${action}`,
      { headers: makeInternalHeaders(), signal: AbortSignal.timeout(5000) }
    )
    if (!res.ok) return false
    const data = await res.json()
    return data.allowed === true
  } catch {
    return false
  }
}

async function loadResource(resourceId) {
  try {
    const res = await fetch(
      `${BACKEND_URL}/api/v1/internal/resources/${resourceId}/document`,
      { headers: makeInternalHeaders(), signal: AbortSignal.timeout(5000) }
    )
    if (!res.ok) return null
    const data = await res.json()
    if (!data.content) return null
    return Buffer.from(data.content, 'base64')
  } catch (err) {
    console.error('[hocuspocus] loadResource error:', err.message)
    return null
  }
}

async function storeResource(resourceId, state) {
  try {
    const content = Buffer.from(state).toString('base64')
    await fetch(
      `${BACKEND_URL}/api/v1/internal/resources/${resourceId}/document`,
      {
        method: 'PUT',
        headers: makeInternalHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ content }),
        signal: AbortSignal.timeout(5000),
      }
    )
  } catch (err) {
    console.error('[hocuspocus] storeResource error:', err.message)
  }
}

async function loadEdmDoc(docId) {
  try {
    const res = await fetch(
      `${BACKEND_URL}/api/v1/internal/documents/${docId}/ydoc`,
      { headers: makeInternalHeaders(), signal: AbortSignal.timeout(5000) }
    )
    if (!res.ok) return null
    const data = await res.json()
    if (!data.content) return null
    return Buffer.from(data.content, 'base64')
  } catch (err) {
    console.error('[hocuspocus] loadEdmDoc error:', err.message)
    return null
  }
}

async function storeEdmDoc(docId, state) {
  try {
    const content = Buffer.from(state).toString('base64')
    await fetch(
      `${BACKEND_URL}/api/v1/internal/documents/${docId}/ydoc`,
      {
        method: 'PUT',
        headers: makeInternalHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ content }),
        signal: AbortSignal.timeout(5000),
      }
    )
  } catch (err) {
    console.error('[hocuspocus] storeEdmDoc error:', err.message)
  }
}

// ── Server ────────────────────────────────────────────────────

const server = Server.configure({
  port: PORT,
  quiet: false,

  async onAuthenticate({ token, documentName }) {
    if (!token) throw new Error('No authentication token provided')

    const isEdm   = documentName.startsWith('edm-')
    const id      = isEdm ? documentName.slice(4) : documentName

    const canRead  = isEdm ? await edmCheck(id, token, 'read')  : await pepCheck(id, token, 'read')
    if (!canRead) throw new Error(`Access denied to ${documentName}`)

    const canWrite = isEdm ? await edmCheck(id, token, 'write') : await pepCheck(id, token, 'write')

    console.log(`[hocuspocus] auth OK doc=${documentName} isEdm=${isEdm} canWrite=${canWrite}`)
    // [eval-fork F8] keep the credential so the session can be re-authorized while open
    return { permission: canWrite ? 'write' : 'read', isEdm, id, token, checkedAt: Date.now() }
  },

  async onLoadDocument({ documentName, document, context }) {
    const { isEdm, id } = context ?? {}
    const state = isEdm ? await loadEdmDoc(id) : await loadResource(documentName)
    if (state && state.length > 0) {
      const { applyUpdate } = await import('yjs')
      applyUpdate(document, state)
    }
    return document
  },

  async onStoreDocument({ documentName, document, context }) {
    const { isEdm, id } = context ?? {}
    const { encodeStateAsUpdate } = await import('yjs')
    const state = encodeStateAsUpdate(document)
    if (isEdm) {
      await storeEdmDoc(id, state)
    } else {
      await storeResource(documentName, state)
    }
    console.log(`[hocuspocus] stored ${documentName} bytes=${state.length}`)
  },

  async onConnect({ documentName, connectionsCount }) {
    console.log(`[hocuspocus] connect ${documentName} total=${connectionsCount ?? '?'}`)
  },

  async onDisconnect({ documentName, connectionsCount }) {
    console.log(`[hocuspocus] disconnect ${documentName} remaining=${connectionsCount ?? '?'}`)
  },

  async onAwarenessUpdate({ documentName, added, updated, removed, awareness }) {
    if ((added?.length || 0) + (updated?.length || 0) + (removed?.length || 0) > 0) {
      const total = awareness?.getStates?.()?.size ?? 0
      console.log(`[hocuspocus] awareness ${documentName} +${added?.length || 0} ~${updated?.length || 0} -${removed?.length || 0} total=${total}`)
    }
  },
})

// [eval-fork F8] Continuous authorization: every REAUTH_MS each open connection is
// re-checked with the same decision procedure as at connect. A connection that lost read
// access is closed; one that lost write access becomes read-only. Bound on a revoked
// session's lifetime: REAUTH_MS + one decision round trip (+ the backend's own staleness).
const REAUTH_MS = parseInt(process.env.HOCUSPOCUS_REAUTH_MS || '5000', 10)

async function reauthorize(conn) {
  const c = conn.context ?? {}
  if (!c.token) return
  const check = c.isEdm ? edmCheck : pepCheck
  const target = c.isEdm ? c.id : conn.document?.name
  const canRead = await check(target, c.token, 'read')
  if (!canRead) {
    console.log(`[hocuspocus] reauth DENY read doc=${conn.document?.name} -> closing`)
    conn.close({ code: 4403, reason: 'Access revoked' })
    return
  }
  if (!conn.readOnly) {
    const canWrite = await check(target, c.token, 'write')
    if (!canWrite) {
      console.log(`[hocuspocus] reauth DENY write doc=${conn.document?.name} -> read-only`)
      conn.readOnly = true
    }
  }
  c.checkedAt = Date.now()
}

setInterval(async () => {
  const docs = server.hocuspocus?.documents ?? new Map()
  const conns = []
  for (const doc of docs.values()) {
    for (const conn of doc.getConnections()) conns.push(conn)
  }
  await Promise.allSettled(conns.map(reauthorize))
}, REAUTH_MS)

server.listen().then(() => {
  console.log(`[hocuspocus] Collaboration server running on port ${PORT}`)
  console.log(`[hocuspocus] Backend: ${BACKEND_URL}`)
})
