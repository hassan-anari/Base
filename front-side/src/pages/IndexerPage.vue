<script setup>
import { ref, onMounted } from 'vue'
import { Ops } from '../api.js'
import { toast } from '../toast.js'

// ---- RPC / Node registry (editable; drives live indexer balance checks) ----
const nodes = ref([])
const loading = ref(false)
const editingNode = ref(null)
const editForm = ref({ url: '', name: '', priority: 10, is_primary: false, enabled: true })
const newNode = ref({ chain_id: 'ETH', name: '', url: '', kind: 'rpc', priority: 10, is_primary: false })
const probing = ref('')
const chainOptions = ['ETH', 'BSC', 'TRX', 'SOL', 'TON']

async function loadNodes() {
  loading.value = true
  try {
    const { data } = await Ops.nodes()
    nodes.value = data.items || data
  } catch (e) {
    toast(e?.response?.data?.detail || 'Failed to load nodes', 'error')
  } finally {
    loading.value = false
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

function healthChip(n) {
  if (n.healthy === false) return 'chip-danger'
  if (n.healthy === true) return 'chip-accent'
  return 'chip'
}

onMounted(loadNodes)
</script>

<template>
  <div class="relative space-y-6">
    <!-- ambience -->
    <div class="orb h-72 w-72 bg-brand-500/20 -top-24 -left-24 animate-floaty"></div>

    <!-- Header -->
    <div class="bento bento-pad flex flex-wrap items-center justify-between gap-4 relative overflow-hidden">
      <div class="absolute -right-16 -top-16 h-48 w-48 rounded-full bg-accent-500/10 blur-2xl"></div>
      <div class="relative">
        <div class="flex items-center gap-2">
          <span class="section-bar"></span>
          <div class="label">Indexer & RPC node management</div>
        </div>
        <h1 class="font-display text-2xl sm:text-3xl text-grad mt-1">Indexer Nodes</h1>
        <p class="text-xs text-slate-500 mt-1">
          Balance checks query these RPC nodes live (DB-first, env fallback). Edits apply immediately.
        </p>
      </div>
      <button class="liquid-ghost !px-3 !py-1.5 text-xs" @click="loadNodes" :disabled="loading">
        {{ loading ? 'Loading...' : 'Refresh' }}
      </button>
    </div>

    <!-- Node table -->
    <div class="bento bento-pad">
      <div v-if="!nodes.length && !loading" class="text-center text-slate-500 py-10">
        No nodes registered yet — the indexer falls back to env RPC URLs. Add one below.
      </div>
      <div v-else class="overflow-x-auto -mx-2">
        <table class="w-full text-sm">
          <thead>
            <tr class="text-left text-slate-500 text-[11px] uppercase tracking-wider">
              <th class="pb-3 pr-4">Chain</th>
              <th class="pb-3 pr-4">Name</th>
              <th class="pb-3 pr-4">URL</th>
              <th class="pb-3 pr-4">Kind</th>
              <th class="pb-3 pr-4">Prio</th>
              <th class="pb-3 pr-4">Primary</th>
              <th class="pb-3 pr-4">Health</th>
              <th class="pb-3 pr-4">Latency</th>
              <th class="pb-3 pr-4">Block</th>
              <th class="pb-3">Actions</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-white/5">
            <tr v-for="n in nodes" :key="n.id" class="text-slate-300 hover:bg-white/5">
              <td class="py-2.5 pr-4"><span class="chip chip-brand">{{ n.chain_id }}</span></td>
              <td class="py-2.5 pr-4">
                <input v-if="editingNode === n.id" v-model="editForm.name" class="input !py-1 !text-xs w-28" />
                <span v-else>{{ n.name }}</span>
              </td>
              <td class="py-2.5 pr-4 mono text-[11px] max-w-[240px]">
                <input v-if="editingNode === n.id" v-model="editForm.url" class="input !py-1 !text-xs w-full" />
                <span v-else class="truncate block" :title="n.url">{{ n.url }}</span>
              </td>
              <td class="py-2.5 pr-4 text-[11px] text-slate-500">{{ n.kind }}</td>
              <td class="py-2.5 pr-4">
                <input v-if="editingNode === n.id" v-model.number="editForm.priority" type="number" class="input !py-1 !text-xs w-16" />
                <span v-else>{{ n.priority }}</span>
              </td>
              <td class="py-2.5 pr-4">
                <input v-if="editingNode === n.id" v-model="editForm.is_primary" type="checkbox" />
                <span v-else :class="n.is_primary ? 'text-accent-300' : 'text-slate-600'">
                  {{ n.is_primary ? '★' : '—' }}</span>
              </td>
              <td class="py-2.5 pr-4">
                <span class="chip" :class="healthChip(n)">
                  {{ n.healthy === false ? 'down' : (n.healthy ? 'up' : 'unknown') }}
                </span>
              </td>
              <td class="py-2.5 pr-4 mono text-[11px]">{{ n.latency_ms != null ? n.latency_ms + 'ms' : '—' }}</td>
              <td class="py-2.5 pr-4 mono text-[11px]">{{ n.block_height || '—' }}</td>
              <td class="py-2.5">
                <div class="flex items-center gap-2">
                  <button v-if="editingNode !== n.id" class="liquid-ghost !px-2.5 !py-1 text-[11px]" @click="startEdit(n)">Edit</button>
                  <template v-else>
                    <button class="liquid-ghost !px-2.5 !py-1 text-[11px]" @click="saveEdit(n)">Save</button>
                    <button class="liquid-ghost !px-2.5 !py-1 text-[11px]" @click="editingNode = null">Cancel</button>
                  </template>
                  <button class="liquid-ghost !px-2.5 !py-1 text-[11px]" :disabled="probing === n.id" @click="probe(n)">
                    {{ probing === n.id ? 'Probing...' : 'Probe' }}
                  </button>
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
          <input v-model="newNode.url" placeholder="https://rpc.example/..." class="input !py-2 text-xs md:col-span-2" />
          <input v-model.number="newNode.priority" type="number" placeholder="Priority" class="input !py-2 text-xs" />
          <button class="liquid !py-2 text-xs" @click="addNode">Add node</button>
        </div>
      </div>
    </div>
  </div>
</template>