<template>
  <div>
    <div class="flex items-center justify-between mb-4">
      <h2 class="text-lg font-semibold text-slate-100">Custody Gas Stations</h2>
      <span class="text-xs text-slate-400">{{ entries.length }} chains</span>
    </div>

    <!-- Top-up result banner -->
    <div v-if="topupResult"
         class="mb-4 p-3 rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-emerald-200 text-sm">
      Top-up broadcast! tx_hash: <code class="text-emerald-300">{{ topupResult.tx_hash }}</code>
      &middot; {{ topupResult.amount }} &rarr; <span class="font-mono">{{ topupResult.to }}</span>
      <button class="ml-3 text-emerald-300 hover:underline" @click="topupResult = null">dismiss</button>
    </div>

    <!-- Error banner -->
    <div v-if="topupError"
         class="mb-4 p-3 rounded-lg border border-red-500/30 bg-red-500/10 text-red-200 text-sm">
      {{ topupError }}
      <button class="ml-3 text-red-300 hover:underline" @click="topupError = null">dismiss</button>
    </div>

    <!-- Top-up modal -->
    <div v-if="showTopup" class="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
        .self.window @click.self="showTopup = false">
      <div class="bg-slate-800 border border-slate-700 rounded-xl shadow-2xl w-full max-w-md p-6">
        <div class="flex items-center justify-between mb-4">
          <h3 class="text-base font-semibold text-slate-100">Gas Station Top-Up</h3>
          <button class="text-slate-400 hover:text-slate-200" @click="showTopup = false">✕</button>
        </div>
        <p class="text-xs text-slate-400 mb-4">
          Manually top up a custody hot wallet or user deposit EOA with native gas.
          Amount is bounded server-side; destination must be a known platform address.
        </p>
        <form @submit.prevent="submitTopup" class="space-y-3">
          <div>
            <label class="block text-xs text-slate-400 mb-1">Chain</label>
            <select v-model="topupForm.chain_id"
                    class="w-full bg-slate-900 border border-slate-700 rounded px-3 py-2 text-sm text-slate-100">
              <option v-for="e in entries" :key="e.chain_id" :value="e.chain_id">
                {{ e.display_name }} ({{ e.chain_id }})
              </option>
            </select>
          </div>
          <div>
            <label class="block text-xs text-slate-400 mb-1">Destination (hot wallet or deposit EOA)</label>
            <input v-model="topupForm.to_address" required
                   placeholder="0x... / T... / EQ..."
                   class="w-full bg-slate-900 border border-slate-700 rounded px-3 py-2 text-sm text-slate-100 font-mono" />
            <button type="button"
                    class="mt-1 text-xs text-emerald-400 hover:underline"
                    @click="fillHotWallet">
              use this chain's hot wallet
            </button>
          </div>
          <div>
            <label class="block text-xs text-slate-400 mb-1">Amount (native)</label>
            <input v-model.number="topupForm.amount" type="number" step="any" min="0" required
                   placeholder="0.01"
                   class="w-full bg-slate-900 border border-slate-700 rounded px-3 py-2 text-sm text-slate-100" />
          </div>
          <div v-if="isMemoRequired">
            <label class="block text-xs text-slate-400 mb-1">Memo (TON attribution)</label>
            <input v-model="topupForm.memo" placeholder="u123.0"
                   class="w-full bg-slate-900 border border-slate-700 rounded px-3 py-2 text-sm text-slate-100 font-mono" />
          </div>
          <div class="flex justify-end gap-2 pt-2">
            <button type="button" @click="showTopup = false"
                    class="px-4 py-2 text-sm text-slate-300 hover:text-white">Cancel</button>
            <button type="submit" :disabled="topupLoading"
                    class="px-4 py-2 text-sm bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 rounded text-slate-900 font-medium">
              {{ topupLoading ? 'Broadcasting...' : 'Send Top-Up' }}
            </button>
          </div>
        </form>
      </div>
    </div>

    <div class="grid gap-3">
      <div v-for="e in entries" :key="e.chain_id"
           class="border border-slate-700/60 bg-slate-800/40 rounded-lg p-4">
        <div class="flex items-center justify-between">
          <div>
            <span class="text-sm font-medium text-slate-100">{{ e.display_name }}</span>
            <span class="ml-2 text-xs text-slate-400">{{ e.kind }}</span>
          </div>
          <span class="text-xs text-slate-400">{{ e.chain_id }}</span>
        </div>
        <div class="mt-3 grid grid-cols-2 gap-3 text-xs">
          <div>
            <div class="text-slate-400">Gas Station EOA</div>
            <div class="text-slate-200 font-mono truncate">{{ e.gas_station_address }}</div>
          </div>
          <div>
            <div class="text-slate-400">Hot Wallet EOA</div>
            <div class="text-slate-200 font-mono truncate">{{ e.hot_wallet_address }}</div>
          </div>
          <div>
            <div class="text-slate-400">Native Balance</div>
            <div class="text-slate-200">
              {{ e.balance_status === 'AVAILABLE' ? e.native_balance : 'Unavailable' }}
            </div>
          </div>
          <div>
            <div class="text-slate-400">Per-Topup Grant</div>
            <div class="text-slate-200">{{ e.gas_topup_amount }}</div>
          </div>
          <div>
            <div class="text-slate-400">Sweeps Funded</div>
            <div class="text-slate-200">{{ e.sweep_count }}</div>
          </div>
          <div>
            <div class="text-slate-400">Last Top-Up</div>
            <div class="text-slate-200">{{ e.last_topup_at || '—' }}</div>
          </div>
        </div>
        <div class="mt-3">
          <button class="text-xs text-emerald-400 hover:underline"
                  @click="openTopup(e)">
            manual top-up
          </button>
        </div>
      </div>
    </div>

    <div v-if="entries.length === 0 && !loading" class="text-center text-slate-500 text-sm py-8">
      No gas-station data.
    </div>
    <div v-if="loading" class="text-center text-slate-500 text-sm py-8">Loading...</div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { GasStation } from '../api.js'
import { toast } from '../toast.js'
import { createWithdrawalIntentTracker } from '../withdrawalIntent.js'

const entries = ref([])
const loading = ref(false)
const showTopup = ref(false)
const topupLoading = ref(false)
const topupResult = ref(null)
const topupError = ref(null)
const topupIntent = createWithdrawalIntentTracker()
const topupForm = ref({
  chain_id: '',
  to_address: '',
  amount: null,
  memo: null,
})

const memoRequiredChains = ['TON']
const isMemoRequired = computed(() => memoRequiredChains.includes(topupForm.value.chain_id))

async function refresh() {
  loading.value = true
  try {
    const { data } = await GasStation.list()
    entries.value = data.entries || []
  } catch (e) {
    console.error(e)
    toast.error('Failed to load gas stations')
  } finally {
    loading.value = false
  }
}

function openTopup(entry) {
  topupIntent.reset()
  topupResult.value = null
  topupError.value = null
  topupForm.value = {
    chain_id: entry.chain_id,
    to_address: entry.hot_wallet_address || entry.gas_station_address || '',
    amount: entry.gas_topup_amount || null,
    memo: null,
  }
  showTopup.value = true
}

function fillHotWallet() {
  const e = entries.value.find(x => x.chain_id === topupForm.value.chain_id)
  if (e) topupForm.value.to_address = e.hot_wallet_address || e.gas_station_address || ''
}

async function submitTopup() {
  topupLoading.value = true
  topupError.value = null
  topupResult.value = null
  try {
    const payload = {
      chain_id: topupForm.value.chain_id,
      to_address: topupForm.value.to_address,
      amount: Number(topupForm.value.amount),
      memo: topupForm.value.memo || null,
    }
    const fingerprint = Object.values(payload).join('|')
    payload.idempotency_key = topupIntent.keyFor(fingerprint)
    const { data } = await GasStation.topup(payload)
    topupResult.value = data
    toast.success('Top-up broadcast')
    topupIntent.reset()
    showTopup.value = false
    // Refresh balances to reflect the new state.
    refresh()
  } catch (e) {
    const msg = e?.response?.data?.detail || e.message || 'Top-up failed'
    topupError.value = msg
    toast.error(msg)
  } finally {
    topupLoading.value = false
  }
}

onMounted(refresh)
</script>
