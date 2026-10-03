<script setup>
// ------------------------------------------------------------------
// API Playground (TEST PURPOSE ONLY)
// A thin dev tool to exercise any /api endpoint and inspect the raw
// response. Requests are sent with the current session's JWT, so RBAC
// still applies exactly as in production. Not part of the product UX.
// ------------------------------------------------------------------
import { ref, computed } from 'vue'
import { session } from '../store.js'
import { toasts } from '../toast.js'

// ---- Preset catalog (mirrors the real Ninja routes) ---------------
const presets = [
  { m: 'GET',    p: '/api/health/live', d: 'Liveness probe' },
  { m: 'GET',    p: '/api/health/ready', d: 'Readiness probe' },
  { m: 'POST',   p: '/api/auth/login', d: 'Get a JWT',
    body: { username: 'admin', password: 'admin' } },
  { m: 'GET',    p: '/api/config', d: 'Public chains+assets registry' },
  { m: 'GET',    p: '/api/stats', d: 'Custody overview aggregates' },
  { m: 'GET',    p: '/api/chains/status', d: 'Per-chain node status' },

  { m: 'POST',   p: '/api/wallet/create', d: 'Provision EOAs (idempotent bulk)',
    body: { subject_user_id: 'user1', networks: ['ETH'], asset_keys: ['ETH'] } },
  { m: 'POST',   p: '/api/wallet/address', d: 'Get/create one deposit EOA',
    body: { subject_user_id: 'user1', network: 'ETH', address_index: 0, asset_key: 'ETH' } },
  { m: 'POST',   p: '/api/wallet/balance/check', d: 'Indexer check → gas+auto-sweep',
    body: { subject_user_id: 'user1', network: 'ETH', asset_key: 'ETH' } },
  { m: 'GET',    p: '/api/sweeps/{sweep_id}', d: 'Sweep job status' },

  { m: 'POST',   p: '/api/withdrawals/request', d: 'Create PENDING_APPROVAL',
    body: { subject_user_id: 'user1', network: 'ETH', to_address: '0x1111111111111111111111111111111111111111', amount: 0.01, asset_key: 'ETH' } },
  { m: 'GET',    p: '/api/withdrawals', d: 'My withdrawals (?subject=)',
    body: null, query: '?subject=user1' },
  { m: 'GET',    p: '/api/withdrawals/{wd_id}', d: 'Withdrawal detail' },
  { m: 'POST',   p: '/api/withdrawals/{wd_id}/approve', d: 'ADMIN: approve+broadcast',
    body: { admin_notes: 'ok via playground' } },
  { m: 'POST',   p: '/api/withdrawals/{wd_id}/deny', d: 'ADMIN: deny',
    body: { admin_notes: 'no via playground' } },
  { m: 'GET',    p: '/api/admin/withdrawals', d: 'ADMIN: all withdrawals' },

  { m: 'POST',   p: '/api/admin/address/resolve', d: 'Classify an address',
    body: { address: '0x0000000000000000000000000000000000000001' } },
  { m: 'GET',    p: '/api/gas-station', d: 'Gas/hot balances per chain' },

  { m: 'GET',    p: '/api/ops/summary', d: 'Ops platform summary' },
  { m: 'GET',    p: '/api/ops/chains', d: 'Ops chain registry' },
  { m: 'GET',    p: '/api/ops/assets', d: 'Ops asset registry' },
  { m: 'GET',    p: '/api/ops/nodes/health', d: 'Node health snapshot' },
  { m: 'GET',    p: '/api/ops/balances', d: 'Exchange-owned balances' },
  { m: 'GET',    p: '/api/ops/transactions', d: 'Transaction ledger' },
  { m: 'GET',    p: '/api/ops/alerts', d: 'Alerts feed' },
  { m: 'GET',    p: '/api/ops/activity', d: 'Operator activity' },
]

const METHODS = ['GET', 'POST', 'PATCH', 'DELETE']
const mColors = { GET: 'chip-brand', POST: 'chip-accent', PATCH: 'chip-warn', DELETE: 'chip-danger' }

// ---- Request builder state ----------------------------------------
const method = ref('GET')
const path = ref('/api/stats')
const bodyText = ref('')
const sending = ref(false)

// path params extracted from {placeholder} tokens
const pathParams = computed(() => {
  const names = [...path.value.matchAll(/\{(\w+)\}/g)].map((x) => x[1])
  return names.map((n) => ({ name: n, value: refPlaceholder(n) }))
})
const paramValues = ref({})
function refPlaceholder(n) { return paramValues.value[n] ?? '' }

const resolvedPath = computed(() => {
  let p = path.value
  for (const k of Object.keys(paramValues.value)) {
    p = p.replaceAll(`{${k}}`, encodeURIComponent(paramValues.value[k] || `{${k}}`))
  }
  return p
})

function loadPreset(item) {
  method.value = item.m
  path.value = item.p
  paramValues.value = {}
  bodyText.value = item.body ? JSON.stringify(item.body, null, 2) : ''
}

// ---- Response viewer + history -------------------------------------
const resp = ref(null) // { status, statusText, ms, size, body }
const history = ref([])

const statusColor = (s) =>
  s >= 500 ? 'text-danger-400' : s >= 400 ? 'text-warn-400' : s >= 200 ? 'text-accent-400' : 'text-slate-400'
const statusChip = (s) =>
  s >= 500 ? 'chip-danger' : s >= 400 ? 'chip-warn' : s >= 200 ? 'chip-accent' : 'chip'

const prettyBody = computed(() => {
  if (!resp.value) return ''
  try { return JSON.stringify(resp.value.body, null, 2) } catch { return String(resp.value.body) }
})

async function send() {
  sending.value = true
  resp.value = null
  const t0 = performance.now()
  try {
    const headers = { Accept: 'application/json' }
    if (session.token) headers.Authorization = `Bearer ${session.token}`
    let body = null
    if (!['GET', 'HEAD'].includes(method.value) && bodyText.value.trim()) {
      headers['Content-Type'] = 'application/json'
      body = bodyText.value // send raw; server validation errors are part of the test
    }
    const r = await fetch(resolvedPath.value, { method: method.value, headers, body })
    const ms = Math.round(performance.now() - t0)
    const text = await r.text()
    let parsed
    try { parsed = JSON.parse(text) } catch { parsed = text }
    resp.value = { status: r.status, statusText: r.statusText, ms, size: text.length, body: parsed }
    history.value.unshift({ id: Date.now(), m: method.value, p: resolvedPath.value, s: r.status, ms })
    history.value = history.value.slice(0, 12)
  } catch (e) {
    resp.value = { status: 0, statusText: 'network error', ms: Math.round(performance.now() - t0), size: 0, body: String(e) }
  } finally {
    sending.value = false
  }
}

async function copyResponse() {
  if (!resp.value) return
  try { await navigator.clipboard.writeText(prettyBody.value); toasts.push({ id: Date.now(), message: 'Response copied', type: 'success' }) }
  catch { toasts.push({ id: Date.now(), message: 'Clipboard unavailable', type: 'error' }) }
}
</script>

<template>
  <div class="grid lg:grid-cols-[280px_1fr] gap-5 items-start">
    <!-- Preset catalog -->
    <div class="bento bento-pad lg:sticky lg:top-24 max-h-[70vh] overflow-y-auto">
      <div class="flex items-center justify-between mb-3">
        <div class="label">Endpoint catalog</div>
        <span class="chip">{{ presets.length }}</span>
      </div>
      <button v-for="(it, i) in presets" :key="i" @click="loadPreset(it)"
        class="w-full text-left px-3 py-2 rounded-xl mb-1.5 border transition
               hover:border-brand-500/40 hover:bg-white/[0.03]"
        :class="path === it.p && method === it.m ? 'border-brand-500/50 bg-brand-500/10' : 'border-white/5'">
        <div class="flex items-center gap-2">
          <span class="chip !px-1.5 !py-0 mono !text-[10px]" :class="mColors[it.m]">{{ it.m }}</span>
          <span class="mono text-[11px] text-slate-300 truncate">{{ it.p }}</span>
        </div>
        <div class="text-[10px] text-slate-500 mt-1 pl-1">{{ it.d }}</div>
      </button>
    </div>

    <!-- Builder + response -->
    <div class="space-y-5 min-w-0">
      <div class="bento bento-pad">
        <div class="flex items-center justify-between mb-3">
          <div class="label">Request</div>
          <span class="chip chip-warn">🧪 test tool — RBAC still enforced</span>
        </div>

        <div class="flex gap-2 mb-3">
          <select v-model="method" class="input !w-28 mono">
            <option v-for="m in METHODS" :key="m" :value="m">{{ m }}</option>
          </select>
          <input v-model="path" class="input flex-1 mono" spellcheck="false" placeholder="/api/..." />
          <button class="liquid !px-5" :disabled="sending" @click="send">
            {{ sending ? '…' : 'Send' }}
          </button>
        </div>

        <!-- Path params -->
        <div v-if="path.includes('{')" class="flex flex-wrap gap-2 mb-3">
          <div v-for="pp in pathParams" :key="pp.name" class="flex items-center gap-1.5">
            <span class="label !mb-0">{{ pp.name }}</span>
            <input v-model="paramValues[pp.name]" class="input !w-32 mono !py-1.5" :placeholder="pp.name" />
          </div>
        </div>

        <!-- Body (non-GET) -->
        <div v-if="method !== 'GET'">
          <div class="label mb-1">JSON body</div>
          <textarea v-model="bodyText" rows="6" spellcheck="false"
            class="input mono !text-[12px] leading-relaxed w-full"
            placeholder='{"key": "value"}'></textarea>
        </div>
      </div>

      <!-- Response -->
      <div class="bento bento-pad">
        <div class="flex items-center justify-between mb-3">
          <div class="label">Response</div>
          <div v-if="resp" class="flex items-center gap-2">
            <span class="chip" :class="statusChip(resp.status)">
              {{ resp.status || 'ERR' }} {{ resp.statusText }}
            </span>
            <span class="chip">{{ resp.ms }} ms</span>
            <span class="chip">{{ resp.size }} B</span>
            <button class="liquid-ghost !px-3 !py-1.5 !text-xs" @click="copyResponse">Copy</button>
          </div>
        </div>
        <pre v-if="prettyBody" class="mono text-[12px] leading-relaxed text-slate-300
             bg-ink-950/70 border border-white/5 rounded-xl p-4 overflow-auto max-h-[46vh] whitespace-pre">{{ prettyBody }}</pre>
        <p v-else class="text-sm text-slate-500">Send a request to see the raw JSON response here.</p>
      </div>

      <!-- History -->
      <div v-if="history.length" class="bento bento-pad">
        <div class="label mb-3">Recent calls (this session)</div>
        <div v-for="h in history" :key="h.id"
          class="flex items-center gap-2 py-1.5 border-b border-white/5 last:border-0">
          <span class="chip !px-1.5 mono !text-[10px]" :class="mColors[h.m]">{{ h.m }}</span>
          <span class="mono text-[11px] text-slate-300 truncate flex-1">{{ h.p }}</span>
          <span class="mono text-[11px]" :class="statusColor(h.s)">{{ h.s }}</span>
          <span class="mono text-[10px] text-slate-500">{{ h.ms }}ms</span>
        </div>
      </div>
    </div>
  </div>
</template>
