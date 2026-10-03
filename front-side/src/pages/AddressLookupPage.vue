<template>
  <div class="space-y-6">
    <div class="card">
      <h2 class="text-lg font-semibold text-ink mb-1">Address Ownership Lookup</h2>
      <p class="text-sm text-slate-400 mb-4">
        Check whether an address belongs to <span class="text-accent font-medium">this
        platform</span>. This is a ledger lookup only — never performs an on-chain
        call. Use it to label internal transfers and prevent mis-routes before
        acting on a counterparty address.
      </p>

      <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div class="md:col-span-2">
          <label class="block text-xs text-slate-400 mb-1">Address</label>
          <input
            v-model="address"
            placeholder="0x... / T... / EQ... / ..."
            class="input font-mono"
          />
        </div>
        <div>
          <label class="block text-xs text-slate-400 mb-1">Network (optional)</label>
          <select v-model="chainId" class="input">
            <option :value="null">Any</option>
            <option v-for="n in networks" :key="n.value" :value="n.value">
              {{ n.label }}
            </option>
          </select>
        </div>
      </div>

      <div class="mt-4 flex items-center gap-3">
        <button class="btn" :disabled="loading || !address" @click="resolve">
          {{ loading ? 'Checking...' : 'Resolve' }}
        </button>
        <button class="btn-ghost" @click="clear">Clear</button>
      </div>
    </div>

    <div v-if="result" class="card" :class="result.is_platform ? 'border-accent/40' : ''">
      <div class="flex items-center justify-between mb-3">
        <h3 class="font-semibold text-ink">Result</h3>
        <span
          class="px-2 py-1 text-xs rounded-full"
          :class="result.is_platform
            ? 'bg-accent/15 text-accent'
            : 'bg-slate-700/40 text-slate-300'"
        >
          {{ result.is_platform ? 'PLATFORM ADDRESS' : 'EXTERNAL ADDRESS' }}
        </span>
      </div>

      <dl class="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3 text-sm">
        <div>
          <dt class="text-slate-400">Address</dt>
          <dd class="font-mono break-all text-ink">{{ result.address }}</dd>
        </div>
        <div>
          <dt class="text-slate-400">Network</dt>
          <dd class="text-ink">{{ result.chain_id || 'Any' }}</dd>
        </div>
        <div>
          <dt class="text-slate-400">Category</dt>
          <dd>
            <span
              class="px-2 py-0.5 rounded text-xs"
              :class="categoryClass(result.category)"
            >{{ result.category }}</span>
          </dd>
        </div>
        <div v-if="result.user_id">
          <dt class="text-slate-400">Subject User</dt>
          <dd class="text-ink">{{ result.user_id }}</dd>
        </div>
        <div v-if="result.asset_key">
          <dt class="text-slate-400">Asset</dt>
          <dd class="text-ink">{{ result.asset_key }}</dd>
        </div>
        <div v-if="result.status">
          <dt class="text-slate-400">Wallet Status</dt>
          <dd class="text-ink">{{ result.status }}</dd>
        </div>
      </dl>

      <p v-if="result.category === 'USER_DEPOSIT'" class="mt-4 text-xs text-slate-400">
        This is a user <span class="text-accent">deposit EOA</span>. Incoming funds
        here are auto-attributed to the subject user above.
      </p>
      <p v-else-if="result.category === 'HOT_WALLET'" class="mt-4 text-xs text-slate-400">
        This is one of our custody <span class="text-accent">hot/gas-station EOAs</span>
        — funds moving here are internal sweeps/topups.
      </p>
      <p v-else class="mt-4 text-xs text-slate-400">
        Not found in our ledger. Treat as an <span class="text-slate-200">external</span>
        address (e.g. a customer withdrawal destination).
      </p>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { AddressLookup, NETWORKS } from '../api.js'
import { toast } from '../toast.js'

const networks = NETWORKS
const address = ref('')
const chainId = ref(null)
const loading = ref(false)
const result = ref(null)

function categoryClass(cat) {
  if (cat === 'USER_DEPOSIT') return 'bg-brand/15 text-brand'
  if (cat === 'HOT_WALLET') return 'bg-accent/15 text-accent'
  return 'bg-slate-700/40 text-slate-300'
}

function clear() {
  address.value = ''
  chainId.value = null
  result.value = null
}

async function resolve() {
  if (!address.value) return
  loading.value = true
  try {
    result.value = await AddressLookup.resolve(address.value.trim(), chainId.value)
  } catch (e) {
    toast.error(e?.response?.data?.detail || 'Lookup failed')
    result.value = null
  } finally {
    loading.value = false
  }
}
</script>