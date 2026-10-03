<script setup>
import { ref, reactive, onMounted } from 'vue'
import { Blocklist } from '../api.js'
import { toasts } from '../toast.js'

const entries = ref([])
const loading = ref(false)
const err = ref('')

const showForm = ref(false)
const form = reactive({
  scope: 'WITHDRAW_ADDRESS', value: '', chain_id: '', asset_key: '',
  reason: 'compliance', note: '',
})
const saving = ref(false)

const SCOPE_LABELS = {
  DEPOSIT_ADDRESS: 'Deposit address',
  WITHDRAW_ADDRESS: 'Withdrawal address',
  CHAIN_ASSET: 'Chain + Asset',
}
const REASON_LABELS = {
  compliance: 'Compliance', sanctions: 'Sanctions',
  scam: 'Scam/Phishing', manual: 'Manual', dust: 'Dust/Spam',
}

async function reload() {
  loading.value = true
  err.value = ''
  try {
    const { data } = await Blocklist.list()
    entries.value = data
  } catch (e) {
    err.value = e?.response?.data?.detail || 'Failed to load blocklist'
  } finally {
    loading.value = false
  }
}

function openForm() {
  Object.assign(form, { scope: 'WITHDRAW_ADDRESS', value: '', chain_id: '', asset_key: '', reason: 'compliance', note: '' })
  showForm.value = true
}

async function save() {
  saving.value = true
  try {
    await Blocklist.add({ ...form })
    toasts.push({ id: Date.now(), message: 'Blocklist entry added', type: 'success' })
    showForm.value = false
    await reload()
  } catch (e) {
    toasts.push({ id: Date.now(), message: e?.response?.data?.detail || 'Add failed', type: 'error' })
  } finally {
    saving.value = false
  }
}

async function toggle(entry) {
  try {
    await Blocklist.update(entry.id, { enabled: !entry.enabled })
    toasts.push({ id: Date.now(), message: 'Blocklist updated', type: 'success' })
    await reload()
  } catch (e) {
    toasts.push({ id: Date.now(), message: e?.response?.data?.detail || 'Update failed', type: 'error' })
  }
}

onMounted(reload)
</script>

<template>
  <div class="space-y-5">
    <div class="bento bento-pad">
      <div class="flex items-center justify-between mb-4">
        <h2 class="font-display text-white text-base">Compliance Blocklist</h2>
        <button class="liquid !px-4 !py-2" @click="openForm">+ Add Entry</button>
      </div>
      <p class="text-[12px] text-slate-500 mb-3 leading-relaxed">
        Hotlisted deposit/withdrawal addresses and disabled (chain, asset) pairs are
        screened at deposit-provisioning and withdrawal time. This is the pluggable
        AML/KYC enforcement boundary (a real deployment additionally fans out to an
        external screening provider).
      </p>
      <div v-if="loading" class="text-slate-500 text-sm">Loading...</div>
      <div v-else-if="err" class="text-danger-400 text-sm">{{ err }}</div>
      <div v-else-if="!entries.length" class="text-slate-500 text-sm">No entries yet.</div>
      <div v-else class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead class="text-slate-500 text-left">
            <tr class="border-b border-white/5">
              <th class="py-2 pr-3">Scope</th><th class="py-2 pr-3">Value</th>
              <th class="py-2 pr-3">Chain</th><th class="py-2 pr-3">Asset</th>
              <th class="py-2 pr-3">Reason</th><th class="py-2 pr-3">State</th>
              <th class="py-2"></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="e in entries" :key="e.id" class="border-b border-white/5">
              <td class="py-2 pr-3 text-slate-300">{{ SCOPE_LABELS[e.scope] || e.scope }}</td>
              <td class="py-2 pr-3 mono text-[11px] text-slate-400 max-w-[220px] truncate">{{ e.value }}</td>
              <td class="py-2 pr-3 text-slate-300">{{ e.chain_id || '—' }}</td>
              <td class="py-2 pr-3 text-slate-300">{{ e.asset_key || '—' }}</td>
              <td class="py-2 pr-3 text-slate-300">{{ REASON_LABELS[e.reason] || e.reason }}</td>
              <td class="py-2 pr-3">
                <span class="chip" :class="e.enabled ? 'chip-danger' : 'chip-brand'">
                  {{ e.enabled ? 'ACTIVE' : 'off' }}
                </span>
              </td>
              <td class="py-2">
                <button class="liquid-ghost !px-3 !py-1.5" @click="toggle(e)">
                  {{ e.enabled ? 'Disable' : 'Enable' }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Add form -->
    <div v-if="showForm" class="bento bento-pad space-y-3">
      <div class="flex items-center justify-between">
        <h3 class="font-display text-white">New Blocklist Entry</h3>
        <button class="liquid-ghost" @click="showForm = false">Close</button>
      </div>
      <div class="grid sm:grid-cols-2 gap-3">
        <div><div class="label mb-1">Scope</div>
          <select v-model="form.scope" class="input w-full">
            <option v-for="(lbl, key) in SCOPE_LABELS" :key="key" :value="key">{{ lbl }}</option>
          </select></div>
        <div><div class="label mb-1">Reason</div>
          <select v-model="form.reason" class="input w-full">
            <option v-for="(lbl, key) in REASON_LABELS" :key="key" :value="key">{{ lbl }}</option>
          </select></div>

        <template v-if="form.scope === 'CHAIN_ASSET'">
          <div><div class="label mb-1">Chain</div><input v-model="form.chain_id" class="input w-full" placeholder="ETH" /></div>
          <div><div class="label mb-1">Asset key</div><input v-model="form.asset_key" class="input w-full" placeholder="ETH_USDT" /></div>
        </template>

        <template v-else>
          <div><div class="label mb-1">Value (address)</div>
            <input v-model="form.value" class="input w-full" placeholder="0x... / EQ... / T..." /></div>
          <div><div class="label mb-1">Chain (optional)</div>
            <input v-model="form.chain_id" class="input w-full" placeholder="ETH" /></div>
          <div><div class="label mb-1">Asset (optional)</div>
            <input v-model="form.asset_key" class="input w-full" placeholder="ETH_USDT" /></div>
        </template>

        <div class="sm:col-span-2"><div class="label mb-1">Note</div>
          <input v-model="form.note" class="input w-full" /></div>
      </div>
      <div class="flex justify-end">
        <button class="liquid !px-5" :disabled="saving" @click="save">Add entry</button>
      </div>
    </div>
  </div>
</template>