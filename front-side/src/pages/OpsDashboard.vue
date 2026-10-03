<script setup>
import { ref, onMounted, onUnmounted, computed } from 'vue'
import { Ops } from '../api.js'
import { toast } from '../toast.js'
import SystemHealth from '../components/SystemHealth.vue'

// All dashboard data is sourced from the database via the Ops REST API.
const summary = ref(null)
const loading = ref(false)
const err = ref('')
const lastUpdated = ref('')
const autoRefresh = ref(true)

const txs = ref([])
const alerts = ref([])
const activity = ref([])

// ---- RPC / Node registry (editable; drives live indexer balance checks) ----
const nodes = ref([])
const editingNode = ref(null)   // node id currently being edited
const editForm = ref({ url: '', name: '', priority: 10, is_primary: false, enabled: true })
const newNode = ref({ chain_id: 'ETH', name: '', url: '', kind: 'rpc', priority: 10, is_primary: false })
const probing = ref('')        // node id being probed
const chainOptions = ['ETH', 'BSC', 'TRX', 'SOL', 'TON']

async function loadNodes() {
  try {
    const { data } = await Ops.nodes()
    nodes.value = data.items || data
  } catch (e) {
    // non-fatal: dashboard still works without node list
  }
}

function startEdit(n) {
  editingNode.value = n.id
  editForm.value = { url: n.url, name: n.name, priority: n.priority,
                     is_primary: n.is_primary, enabled: n.enabled }
}

async function saveEdit(n) {
  try {
    await Ops.updateNode(n.id, editForm.value)
    toast(`Node ${n.name} updated`, 'success')
    editingNode.value = null
    await loadNodes()
  } catch (e) {
    toast(e?.response?.data?.detail || 'Update failed', 'error')
  }
}

async function probe(n) {
  probing.value = n.id
  try {
    await Ops.probeNode(n.id)
    await loadNodes()
    const fresh = nodes.value.find(x => x.id === n.id)
    toast(fresh?.healthy ? `${n.name}: healthy (${fresh.latency_ms}ms)` : `${n.name}: unhealthy`,
          fresh?.healthy ? 'success' : 'error')
  } catch (e) {
    toast(e?.response?.data?.detail || 'Probe failed', 'error')
  } finally {
    probing.value = ''
  }
}

async function addNode() {
  if (!newNode.value.name || !newNode.value.url) {
    toast('Node name and URL are required', 'error')
    return
  }
  try {
    await Ops.addNode(newNode.value)
    toast(`Node ${newNode.value.name} registered`, 'success')
    newNode.value = { chain_id: 'ETH', name: '', url: '', kind: 'rpc', priority: 10, is_primary: false }
    await loadNodes()
  } catch (e) {
    toast(e?.response?.data?.detail || 'Add node failed', 'error')
  }
}

let poll = null

async function load() {
  loading.value = true
  err.value = ''
  try {
    const [{ data: s }, { data: t }, { data: a }, { data: act }] = await Promise.all([
      Ops.summary(),
      Ops.transactions(),
      Ops.alerts({ resolved: false }),
      Ops.activity(),
    ])
    summary.value = s
    txs.value = t.items || t
    alerts.value = a.items || a
    activity.value = act.items || act
    lastUpdated.value = new Date().toLocaleTimeString()
  } catch (e) {
    err.value = e?.response?.data?.detail || 'Failed to load ops dashboard'
  } finally {
    loading.value = false
  }
}

async function ack(alertId) {
  try {
    await Ops.ackAlert(alertId, 'acked via ops dashboard')
    toast(`Alert #${alertId} acknowledged`, 'success')
    await load()
  } catch (e) {
    toast(e?.response?.data?.detail || 'Ack failed', 'error')
  }
}

function statusChip(s) {
  return {
    pending: 'chip',
    broadcasted: 'chip-brand',
    confirmed: 'chip-accent',
    failed: 'chip-danger',
  }[s] || 'chip'
}

// KPI tiles (all from DB aggregates) — bento grid items.
const kpis = computed(() => {
  const s = summary.value
  if (!s) return []
  return [
    { key: 'chains', label: 'Active chains', value: s.chains_total, sub: `${s.assets_total} assets onboarded`, tone: 'brand', icon: '⛓' },
    { key: 'nodes', label: 'Nodes online', value: s.nodes_total, sub: `${s.nodes_unhealthy} unhealthy`, tone: s.nodes_unhealthy ? 'danger' : 'accent', icon: '🖧' },
    { key: 'balances', label: 'Watched balances', value: s.balances_total, sub: `${s.balances_confirmed_sum} confirmed`, tone: 'accent', icon: '◆' },
    { key: 'txns', label: 'Transactions', value: s.transactions_total, sub: `${s.alerts_open} open alerts`, tone: 'brand', icon: '⇄' },
  ]
})

function toneIcon(tone) {
  return {
    brand: 'from-brand-500/30 to-brand-400/10 text-brand-300',
    accent: 'from-accent-500/30 to-accent-400/10 text-accent-300',
    danger: 'from-danger-500/30 to-danger-400/10 text-danger-400',
  }[tone] || 'from-white/10 to-white/5 text-slate-200'
}

function startPolling() {
  clearInterval(poll)
  if (autoRefresh.value) poll = setInterval(load, 8000)
}
function toggleRefresh() {
  autoRefresh.value = !autoRefresh.value
  startPolling()
}

onMounted(() => { load(); loadNodes(); startPolling() })
onUnmounted(() => clearInterval(poll))
</script>

<template>
  <div class="relative space-y-6">
    <!-- ambience orbs -->
    <div class="orb h-72 w-72 bg-brand-500/20 -top-24 -left-24 animate-floaty"></div>
    <div class="orb h-80 w-80 bg-accent-500/15 top-10 right-0 animate-floaty" style="animation-delay:1.5s"></div>

    <!-- ===== Bento header ===== -->
    <div class="bento bento-pad flex flex-wrap items-center justify-between gap-4 relative overflow-hidden">
      <div class="absolute -right-16 -top-16 h-48 w-48 rounded-full bg-brand-500/10 blur-2xl"></div>
      <div class="relative">
        <div class="flex items-center gap-2">
          <span class="section-bar"></span>
          <div class="label">Operations & custody console</div>
        </div>
        <h1 class="font-display text-2xl sm:text-3xl text-grad mt-1">Exchange Ops Overview</h1>
      </div>
      <div class="relative flex items-center gap-3">
        <span class="chip chip-brand">OPERATOR / AUDITOR</span>
        <span v-if="lastUpdated" class="mono text-[11px] text-slate-500">updated {{ lastUpdated }}</span>
        <button class="liquid-ghost !px-3 !py-1.5 text-xs" @click="load" :disabled="loading">
          {{ loading ? 'Syncing...' : 'Refresh' }}
        </button>
        <button class="liquid-ghost !px-3 !py-1.5 text-xs" @click="toggleRefresh">
          {{ autoRefresh ? 'Auto: ON' : 'Auto: OFF' }}
        </button>
      </div>
    </div>

    <p v-if="err" class="text-sm text-danger-400">{{ err }}</p>

    <!-- ===== KPI bento grid ===== -->
    <div class="bento-grid">
      <div v-for="k in kpis" :key="k.key" class="kpi">
        <div class="flex items-start justify-between gap-3">
          <div class="min-w-0">
            <div class="label truncate">{{ k.label }}</div>
            <div class="stat-num mt-1">{{ k.value }}</div>
            <div class="mt-1 text-xs text-slate-400 truncate">{{ k.sub }}</div>
          </div>
          <div :class="['kpi-icon', toneIcon(k.tone)]">{{ k.icon }}</div>
        </div>
      </div>
    </div>

    <div v-if="!kpis.length && loading" class="text-slate-500 text-sm">Loading ops summary...</div>

    <!-- ===== System health bento ===== -->
    <SystemHealth />

    <!-- ===== RPC / Node registry (editable) ===== -->
    <div class="bento bento-pad">
      <div class="flex flex-wrap items-center justify-between gap-3 mb-4">
        <div class="flex items-center gap-2">
          <span class="section-bar"></span>
          <div class="label">RPC / Node registry — live indexer endpoints</div>
        </div>
        <span class="text-[11px] text-slate-500">Balance checks use these nodes (DB-first, env fallback). Edits apply immediately.</span>
      </div>

      <div v-if="!nodes.length" class="text-center text-slate-500 py-8">
        No nodes registered yet — the indexer falls back to env RPC URLs. Add one below.
      </div>
      <div v-else class="overflow-x-auto -mx-2">
        <table class="w-full text-sm">
          <thead>
            <tr class="text-left text-slate-500 text-[11px] uppercase tracking-wider">
              <th class="pb-3 pr-4">Chain</th>
              <th class="pb-3 pr-4">Name</th>
              <th class="pb-3 pr-4">URL</th>
              <th class="pb-3 pr-4">Prio</th>
              <th class="pb-3 pr-4">Primary</th>
              <th class="pb-3 pr-4">Health</th>
              <th class="pb-3 pr-4">Latency</th>
              <th class="pb-3">Actions</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-white/5">
            <tr v-for="n in nodes" :key="n.id" class="text-slate-300 hover:bg-white/5">
              <td class="py-2.5 pr-4"><span class="chip chip-brand">{{ n.chain_id }}</span></td>
              <td class="py-2.5 pr-4">
                <input v-if="editingNode === n.id" v-model="editForm.name"
                       class="input !py-1 !text-xs w-28" />
                <span v-else>{{ n.name }}</span>
              </td>
              <td class="py-2.5 pr-4 mono text-[11px] max-w-[260px]">
                <input v-if="editingNode === n.id" v-model="editForm.url"
                       class="input !py-1 !text-xs w-full" />
                <span v-else class="truncate block" :title="n.url">{{ n.url }}</span>
              </td>
              <td class="py-2.5 pr-4">
                <input v-if="editingNode === n.id" v-model.number="editForm.priority" type="number"
                       class="input !py-1 !text-xs w-16" />
                <span v-else>{{ n.priority }}</span>
              </td>
              <td class="py-2.5 pr-4">
                <input v-if="editingNode === n.id" v-model="editForm.is_primary" type="checkbox" />
                <span v-else :class="n.is_primary ? 'text-accent-300' : 'text-slate-600'">
                  {{ n.is_primary ? '★' : '—' }}</span>
              </td>
              <td class="py-2.5 pr-4">
                <span class="chip" :class="n.healthy === false ? 'chip-danger' : (n.healthy ? 'chip-accent' : 'chip')">
                  {{ n.healthy === false ? 'down' : (n.healthy ? 'up' : 'unknown') }}
                </span>
              </td>
              <td class="py-2.5 pr-4 mono text-[11px]">{{ n.latency_ms != null ? n.latency_ms + 'ms' : '—' }}</td>
              <td class="py-2.5">
                <div class="flex items-center gap-2">
                  <button v-if="editingNode !== n.id" class="liquid-ghost !px-2.5 !py-1 text-[11px]"
                          @click="startEdit(n)">Edit</button>
                  <template v-else>
                    <button class="liquid-ghost !px-2.5 !py-1 text-[11px]" @click="saveEdit(n)">Save</button>
                    <button class="liquid-ghost !px-2.5 !py-1 text-[11px]" @click="editingNode = null">Cancel</button>
                  </template>
                  <button class="liquid-ghost !px-2.5 !py-1 text-[11px]" :disabled="probing === n.id"
                          @click="probe(n)">{{ probing === n.id ? 'Probing…' : 'Probe' }}</button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Add node -->
      <div class="mt-5 rounded-2xl bg-white/5 border border-white/8 p-4">
        <div class="label mb-3">Register a new RPC node</div>
        <div class="grid grid-cols-2 md:grid-cols-6 gap-3">
          <select v-model="newNode.chain_id" class="input !py-2 text-xs">
            <option v-for="c in chainOptions" :key="c" :value="c">{{ c }}</option>
          </select>
          <input v-model="newNode.name" placeholder="Name (e.g. sepolia-ankr)" class="input !py-2 text-xs" />
          <input v-model="newNode.url" placeholder="https://rpc.example/…" class="input !py-2 text-xs md:col-span-2" />
          <input v-model.number="newNode.priority" type="number" placeholder="Priority" class="input !py-2 text-xs" />
          <button class="liquid !py-2 text-xs" @click="addNode">Add node</button>
        </div>
      </div>
    </div>

    <!-- ===== Lower bento region ===== -->
    <div class="grid grid-cols-1 xl:grid-cols-3 gap-4 auto-rows-min">
      <!-- Transactions (large) -->
      <div class="bento xl:col-span-2 bento-pad">
        <div class="flex items-center gap-2 mb-4">
          <span class="section-bar"></span>
          <div class="label">Recent on-chain transactions</div>
        </div>
        <div v-if="!txs.length" class="text-center text-slate-500 py-12">No transactions yet.</div>
        <div v-else class="overflow-x-auto -mx-2">
          <table class="w-full text-sm">
            <thead>
              <tr class="text-left text-slate-500 text-[11px] uppercase tracking-wider">
                <th class="pb-3 pr-4">Type</th>
                <th class="pb-3 pr-4">Chain</th>
                <th class="pb-3 pr-4">From</th>
                <th class="pb-3 pr-4">To</th>
                <th class="pb-3 pr-4">Amount</th>
                <th class="pb-3 pr-4">Status</th>
                <th class="pb-3">Tx</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-white/5">
              <tr v-for="t in txs.slice(0, 12)" :key="t.id" class="text-slate-300 hover:bg-white/5">
                <td class="py-2.5 pr-4">{{ t.tx_type }}</td>
                <td class="py-2.5 pr-4">{{ t.chain_id }}</td>
                <td class="py-2.5 pr-4 mono text-[11px] max-w-[150px] truncate" :title="t.from_address">{{ t.from_address || '—' }}</td>
                <td class="py-2.5 pr-4 mono text-[11px] max-w-[150px] truncate" :title="t.to_address">{{ t.to_address || '—' }}</td>
                <td class="py-2.5 pr-4">{{ t.amount }}</td>
                <td class="py-2.5 pr-4"><span class="chip" :class="statusChip(t.status)">{{ t.status }}</span></td>
                <td class="py-2.5 mono text-[11px] text-brand-300 max-w-[140px] truncate">{{ t.tx_hash || '—' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Alerts + activity sidebar -->
      <div class="space-y-4">
        <div class="bento bento-pad">
          <div class="flex items-center gap-2 mb-4">
            <span class="section-bar"></span>
            <div class="label">Open alerts</div>
          </div>
          <div v-if="!alerts.length" class="text-center text-slate-500 py-8">No open alerts.</div>
          <div v-else class="space-y-2">
            <div v-for="a in alerts" :key="a.id"
                 class="flex items-center justify-between gap-3 rounded-2xl bg-white/5 border border-white/8 px-4 py-3">
              <div class="min-w-0">
                <div class="text-sm text-slate-200 truncate">{{ a.title }}
                  <span class="chip ml-2" :class="a.severity === 'critical' ? 'chip-danger' : 'chip-brand'">{{ a.severity }}</span>
                </div>
                <div class="text-[11px] text-slate-500 mono">{{ a.chain_id }} · {{ a.detail }}</div>
              </div>
              <button class="liquid-ghost !px-3 !py-1.5 text-xs shrink-0" @click="ack(a.id)">Ack</button>
            </div>
          </div>
        </div>

        <div class="bento bento-pad">
          <div class="flex items-center gap-2 mb-4">
            <span class="section-bar"></span>
            <div class="label">Operator activity (audit)</div>
          </div>
          <div v-if="!activity.length" class="text-center text-slate-500 py-8">No activity recorded.</div>
          <div v-else class="space-y-1.5 text-sm">
            <div v-for="r in activity.slice(0, 12)" :key="r.id"
                 class="flex items-center gap-3 text-slate-400">
              <span class="mono text-[11px] w-10 shrink-0">#{{ r.id }}</span>
              <span class="chip chip-brand shrink-0">{{ r.action }}</span>
              <span class="mono text-[12px] truncate">{{ r.actor_id }}</span>
              <span class="text-slate-500 truncate flex-1">{{ r.target }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>