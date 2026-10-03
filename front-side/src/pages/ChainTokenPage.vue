<script setup>
import { ref, reactive, onMounted } from 'vue'
import { registry, assetsForChain } from '../store.js'
import { ChainTokens, Ops } from '../api.js'
import { toasts } from '../toast.js'

const chains = ref([])
const loading = ref(false)
const err = ref('')

// New chain form
const showChain = ref(false)
const chainForm = reactive({
  chain_id: '', kind: 'evm', display_name: '', evm_chain_id: 0,
  native_asset_key: '', is_testnet: true, min_confirmations: 12,
  sweep_threshold: 0.01, memo_required: false,
})
const chainSaving = ref(false)

// New token form (per chain)
const tokenForm = reactive({
  chain_id: '', asset_key: '', symbol: '', decimals: 18,
  is_native: false, contract_address: '', deposit_threshold: 0.01,
})
const tokenSaving = ref(false)

async function reload() {
  loading.value = true
  err.value = ''
  try {
    const { data } = await Ops.chains()
    chains.value = data
  } catch (e) {
    err.value = e?.response?.data?.detail || 'Failed to load chains'
  } finally {
    loading.value = false
  }
}

function openChain() {
  Object.assign(chainForm, {
    chain_id: '', kind: 'evm', display_name: '', evm_chain_id: 0,
    native_asset_key: '', is_testnet: true, min_confirmations: 12,
    sweep_threshold: 0.01, memo_required: false,
  })
  showChain.value = true
}

async function saveChain() {
  chainSaving.value = true
  try {
    await ChainTokens.create({ ...chainForm })
    toasts.push({ id: Date.now(), message: `Chain ${chainForm.chain_id} created`, type: 'success' })
    showChain.value = false
    await reload()
  } catch (e) {
    toasts.push({ id: Date.now(), message: e?.response?.data?.detail || 'Create failed', type: 'error' })
  } finally {
    chainSaving.value = false
  }
}

async function saveToken() {
  tokenSaving.value = true
  try {
    await ChainTokens.addAsset({ ...tokenForm })
    toasts.push({ id: Date.now(), message: `Token ${tokenForm.symbol} added`, type: 'success' })
    Object.assign(tokenForm, { asset_key: '', symbol: '', decimals: 18, is_native: false, contract_address: '', deposit_threshold: 0.01 })
    await reload()
  } catch (e) {
    toasts.push({ id: Date.now(), message: e?.response?.data?.detail || 'Add token failed', type: 'error' })
  } finally {
    tokenSaving.value = false
  }
}

// RPC node endpoints (edit / rotate RPC URLs)
const nodes = ref([])
const loadingNodes = ref(false)
const nodesErr = ref('')
const editingNode = ref(null)
const nodeEditForm = reactive({ name: '', url: '', kind: '' })
const nodeSaving = ref(false)

async function loadNodes() {
  loadingNodes.value = true
  nodesErr.value = ''
  try {
    const { data } = await Ops.nodesHealth()
    nodes.value = data
  } catch (e) {
    nodesErr.value = e?.response?.data?.detail || 'Failed to load node endpoints'
  } finally {
    loadingNodes.value = false
  }
}

function editNode(node) {
  editingNode.value = node
  Object.assign(nodeEditForm, { name: node.name, url: node.url, kind: node.kind })
}

async function saveNode() {
  if (!editingNode.value) return
  nodeSaving.value = true
  try {
    const payload = {
      name: nodeEditForm.name,
      url: nodeEditForm.url,
      kind: nodeEditForm.kind,
    }
    await Ops.updateNode(editingNode.value.id, payload)
    toasts.push({ id: Date.now(), message: `Node ${editingNode.value.name} updated`, type: 'success' })
    editingNode.value = null
    await loadNodes()
  } catch (e) {
    toasts.push({ id: Date.now(), message: e?.response?.data?.detail || 'Update failed', type: 'error' })
  } finally {
    nodeSaving.value = false
  }
}

function nodesForChain(chainId) {
  return nodes.value.filter((n) => n.chain_id === chainId)
}

onMounted(() => { reload(); loadNodes() })
</script>

<template>
  <div class="space-y-5">
    <!-- Chains list -->
    <div class="bento bento-pad">
      <div class="flex items-center justify-between mb-4">
        <h2 class="font-display text-white text-base">Supported Chains</h2>
        <button class="liquid !px-4 !py-2" @click="openChain">+ Add Chain</button>
      </div>
      <div v-if="loading" class="text-slate-500 text-sm">Loading…</div>
      <div v-else-if="err" class="text-danger-400 text-sm">{{ err }}</div>
      <div v-else class="grid sm:grid-cols-2 xl:grid-cols-3 gap-3">
        <div v-for="c in chains" :key="c.chain_id"
             class="rounded-2xl border border-white/5 bg-ink-900/50 p-4">
          <div class="flex items-center justify-between">
            <div class="font-display text-white">{{ c.display_name }}</div>
            <span class="chip" :class="c.enabled ? 'chip-brand' : 'chip-danger'">
              {{ c.enabled ? 'enabled' : 'disabled' }}
            </span>
          </div>
          <div class="text-[11px] text-slate-500 mono mt-1">{{ c.chain_id }} · {{ c.kind }}</div>
          <dl class="mt-3 grid grid-cols-2 gap-y-1 text-sm">
            <dt class="text-slate-500">Confirms</dt><dd class="text-slate-300 text-right">{{ c.min_confirmations }}</dd>
            <dt class="text-slate-500">Sweep ≥</dt><dd class="text-slate-300 text-right">{{ c.sweep_threshold }}</dd>
            <dt class="text-slate-500">Memo</dt><dd class="text-slate-300 text-right">{{ c.memo_required ? 'yes' : 'no' }}</dd>
            <dt class="text-slate-500">Testnet</dt><dd class="text-slate-300 text-right">{{ c.is_testnet ? 'yes' : 'no' }}</dd>
          </dl>
        </div>
      </div>
    </div>

    <!-- Tokens per chain -->
    <div class="bento bento-pad">
      <h2 class="font-display text-white text-base mb-4">Token Assets</h2>
      <div class="grid sm:grid-cols-2 xl:grid-cols-3 gap-3">
        <div v-for="c in chains" :key="c.chain_id + '-tok'" class="rounded-2xl border border-white/5 bg-ink-900/50 p-4">
          <div class="font-display text-white mb-2">{{ c.display_name }} tokens</div>
          <ul class="space-y-1 text-sm">
            <li v-for="a in assetsForChain(c.chain_id)" :key="a.asset_key"
                class="flex items-center justify-between">
              <span class="text-slate-300">{{ a.symbol }}</span>
              <span class="mono text-[11px] text-slate-500 truncate max-w-[55%]">{{ a.asset_key }}</span>
            </li>
          </ul>
        </div>
      </div>
      <div class="mt-4 grid sm:grid-cols-6 gap-2 items-end">
        <div class="sm:col-span-1"><div class="label mb-1">Chain</div>
          <select v-model="tokenForm.chain_id" class="input w-full">
            <option v-for="c in chains" :key="c.chain_id" :value="c.chain_id">{{ c.chain_id }}</option>
          </select></div>
        <div class="sm:col-span-1"><div class="label mb-1">Asset key</div>
          <input v-model="tokenForm.asset_key" class="input w-full" placeholder="ETH_USDT" /></div>
        <div class="sm:col-span-1"><div class="label mb-1">Symbol</div>
          <input v-model="tokenForm.symbol" class="input w-full" placeholder="USDT" /></div>
        <div class="sm:col-span-1"><div class="label mb-1">Decimals</div>
          <input v-model.number="tokenForm.decimals" type="number" class="input w-full" /></div>
        <div class="sm:col-span-1"><div class="label mb-1">Contract</div>
          <input v-model="tokenForm.contract_address" class="input w-full" placeholder="0x…" /></div>
        <div class="sm:col-span-1"><button class="liquid w-full" :disabled="tokenSaving" @click="saveToken">Add token</button></div>
      </div>
    </div>

    <!-- RPC node endpoints (edit / rotate RPC URLs) -->
    <div class="bento bento-pad">
      <div class="flex items-center justify-between mb-4">
        <h2 class="font-display text-white text-base">RPC Node Endpoints</h2>
        <button class="liquid-ghost" :disabled="loadingNodes" @click="loadNodes">Refresh</button>
      </div>
      <div v-if="loadingNodes" class="text-slate-500 text-sm">Loading nodes...</div>
      <div v-else-if="nodesErr" class="text-danger-400 text-sm">{{ nodesErr }}</div>
      <div v-else class="grid sm:grid-cols-2 xl:grid-cols-3 gap-3">
        <div v-for="c in chains" :key="c.chain_id + '-nodes'" class="rounded-2xl border border-white/5 bg-ink-900/50 p-4">
          <div class="font-display text-white mb-2">{{ c.display_name }} RPC</div>
          <ul v-if="nodesForChain(c.chain_id).length" class="space-y-2">
            <li v-for="n in nodesForChain(c.chain_id)" :key="n.id"
                class="rounded-xl border border-white/5 bg-ink-950/40 p-2">
              <div class="flex items-center justify-between">
                <span class="text-sm text-slate-200">{{ n.name }}</span>
                <button class="text-[11px] text-brand-300 hover:text-brand-200" @click="editNode(n)">Edit</button>
              </div>
              <a :href="n.url" target="_blank" rel="noopener"
                 class="mono text-[11px] text-slate-500 break-all hover:text-slate-300">{{ n.url }}</a>
              <div class="mt-1 flex items-center gap-2">
                <span class="chip" :class="n.healthy ? 'chip-brand' : 'chip-danger'">{{ n.healthy ? 'up' : 'down' }}</span>
                <span class="text-[11px] text-slate-500">{{ n.kind }} · {{ n.sync_status || 'n/a' }}</span>
              </div>
            </li>
          </ul>
          <div v-else class="text-[11px] text-slate-600">No RPC nodes configured</div>
        </div>
      </div>

      <!-- Edit node drawer -->
      <div v-if="editingNode" class="mt-4 bento bento-pad space-y-3 border border-brand-500/30">
        <div class="flex items-center justify-between">
          <h3 class="font-display text-white text-sm">Edit RPC: {{ editingNode.name }}</h3>
          <button class="liquid-ghost" @click="editingNode = null">Close</button>
        </div>
        <div class="grid sm:grid-cols-3 gap-3">
          <div><div class="label mb-1">Name</div><input v-model="nodeEditForm.name" class="input w-full" /></div>
          <div class="sm:col-span-2"><div class="label mb-1">RPC URL</div>
            <input v-model="nodeEditForm.url" class="input w-full" placeholder="https://..." /></div>
        </div>
        <div class="sm:w-1/3"><div class="label mb-1">Kind</div>
          <select v-model="nodeEditForm.kind" class="input w-full">
            <option value="rpc">rpc</option><option value="indexer">indexer</option>
          </select></div>
        <div class="flex justify-end">
          <button class="liquid !px-5" :disabled="nodeSaving" @click="saveNode">Save RPC</button>
        </div>
      </div>
    </div>

    <!-- Add chain drawer -->
    <div v-if="showChain" class="bento bento-pad space-y-3">
      <div class="flex items-center justify-between">
        <h2 class="font-display text-white text-base">New Chain</h2>
        <button class="liquid-ghost" @click="showChain = false">Close</button>
      </div>
      <div class="grid sm:grid-cols-2 gap-3">
        <div><div class="label mb-1">Chain ID</div><input v-model="chainForm.chain_id" class="input w-full" placeholder="MATIC" /></div>
        <div><div class="label mb-1">Kind</div>
          <select v-model="chainForm.kind" class="input w-full">
            <option value="evm">EVM</option><option value="tron">Tron</option>
            <option value="solana">Solana</option><option value="ton">TON</option>
            <option value="other">Other</option>
          </select></div>
        <div><div class="label mb-1">Display name</div><input v-model="chainForm.display_name" class="input w-full" /></div>
        <div><div class="label mb-1">EVM chain id</div><input v-model.number="chainForm.evm_chain_id" type="number" class="input w-full" /></div>
        <div><div class="label mb-1">Native asset key</div><input v-model="chainForm.native_asset_key" class="input w-full" placeholder="ETH_NATIVE" /></div>
        <div><div class="label mb-1">Min confirmations</div><input v-model.number="chainForm.min_confirmations" type="number" class="input w-full" /></div>
        <div><div class="label mb-1">Sweep threshold</div><input v-model.number="chainForm.sweep_threshold" type="number" step="0.0001" class="input w-full" /></div>
        <div class="flex items-center gap-4 pt-6">
          <label class="flex items-center gap-2 text-sm text-slate-300"><input type="checkbox" v-model="chainForm.is_testnet" /> Testnet</label>
          <label class="flex items-center gap-2 text-sm text-slate-300"><input type="checkbox" v-model="chainForm.memo_required" /> Memo required</label>
        </div>
      </div>
      <div class="flex justify-end">
        <button class="liquid !px-5" :disabled="chainSaving" @click="saveChain">Create chain</button>
      </div>
    </div>
  </div>
</template>