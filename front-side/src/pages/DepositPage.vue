<script setup>
import { ref, computed, watch } from 'vue'
import { Wallet, NETWORKS, Config } from '../api.js'
import { toasts } from '../toast.js'

// Operator console: act ON BEHALF OF a subject (customer) user.
const subject = ref(localStorage.getItem('ops.subject') || '')
const addresses = ref([])
const balances = ref({})
const loading = ref(false)
const checking = ref(false)
const provisioning = ref(false)
const selectedNetwork = ref('ETH')
const assetKey = ref(null)
const config = ref(null)

const networks = NETWORKS
const selectedMeta = computed(() => networks.find((n) => n.value === selectedNetwork.value))

// Fetch chain/asset registry so the selector includes native + USDT-per-chain.
Config.load().then((r) => { config.value = r.data }).catch(() => {})

watch(subject, (v) => { if (v) localStorage.setItem('ops.subject', v) })

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text)
    toasts.push({ id: Date.now(), message: 'Copied', type: 'success' })
  } catch {
    toasts.push({ id: Date.now(), message: 'Copy failed', type: 'error' })
  }
}

async function provision() {
  if (!subject.value.trim()) {
    toasts.push({ id: Date.now(), message: 'Enter a subject (customer) user id', type: 'error' })
    return
  }
  provisioning.value = true
  try {
    const { data } = await Wallet.create(subject.value.trim())
    addresses.value = data.addresses
    toasts.push({ id: Date.now(), message: 'Deposit EOAs provisioned', type: 'success' })
  } catch (e) {
    toasts.push({ id: Date.now(), message: e?.response?.data?.detail || 'Provision failed', type: 'error' })
  } finally {
    provisioning.value = false
  }
}

async function deriveOne() {
  if (!subject.value.trim()) {
    toasts.push({ id: Date.now(), message: 'Enter a subject (customer) user id', type: 'error' })
    return
  }
  loading.value = true
  try {
    const { data } = await Wallet.getAddress(subject.value.trim(), selectedNetwork.value, 0, assetKey.value)
    const exists = addresses.value.findIndex((a) => a.network === data.network && a.asset_key === data.asset_key)
    if (exists >= 0) addresses.value[exists] = data
    else addresses.value.push(data)
    toasts.push({ id: Date.now(), message: 'Address derived (EOA)', type: 'success' })
  } catch (e) {
    toasts.push({ id: Date.now(), message: e?.response?.data?.detail || 'Derive failed', type: 'error' })
  } finally {
    loading.value = false
  }
}

async function checkBalance(a) {
  if (!subject.value.trim()) return
  checking.value = true
  try {
    const { data } = await Wallet.checkBalance(subject.value.trim(), a.network, a.asset_key)
    balances.value = { ...balances.value, [`${a.network}:${a.asset_key}`]: data }
    if (data.sweep_triggered) {
      toasts.push({ id: Date.now(), message: `Sweep started (job ${data.sweep_job_id})`, type: 'success' })
    } else {
      toasts.push({ id: Date.now(), message: data.reason || 'Below threshold', type: 'info' })
    }
  } catch (e) {
    toasts.push({ id: Date.now(), message: e?.response?.data?.detail || 'Balance check failed', type: 'error' })
  } finally {
    checking.value = false
  }
}

function balFor(a) {
  const k = `${a.network}:${a.asset_key}`
  return balances.value[k]
}
</script>

<template>
  <div class="space-y-5">
    <!-- Subject (customer) selector -->
    <div class="bento bento-pad">
      <div class="label mb-1">Subject customer (user id you are servicing)</div>
      <input v-model="subject" class="input w-full" placeholder="e.g. cust-1001" />
      <p class="mt-2 text-[11px] text-slate-500">
        The logged-in operator provisions deposit EOAs and triggers sweeps <b>on behalf of</b> this customer.
      </p>
    </div>

    <!-- Provision all + derive one -->
    <div class="grid sm:grid-cols-2 gap-4">
      <div class="bento bento-pad">
        <div class="font-display font-semibold text-white mb-3">Bulk provision</div>
        <button class="liquid w-full" :disabled="provisioning" @click="provision">
          {{ provisioning ? 'Provisioning…' : 'Provision all networks (EOA)' }}
        </button>
        <p class="mt-2 text-[11px] text-slate-500">Idempotent — existing addresses are reused.</p>
      </div>
      <div class="bento bento-pad">
        <div class="font-display font-semibold text-white mb-3">Derive one address</div>
        <div class="flex gap-2">
          <select v-model="selectedNetwork" class="input flex-1">
            <option v-for="n in networks" :key="n.value" :value="n.value">{{ n.label }}</option>
          </select>
          <button class="liquid-ghost" :disabled="loading" @click="deriveOne">
            {{ loading ? '…' : 'Derive' }}
          </button>
        </div>
        <p v-if="selectedMeta?.memo" class="mt-2 text-[11px] text-accent-400">
          {{ selectedMeta.label }} uses a memo for deposit attribution.
        </p>
      </div>
    </div>

    <!-- Address list -->
    <div v-if="addresses.length" class="bento bento-pad">
      <div class="flex items-center justify-between mb-3">
        <div class="font-display font-semibold text-white">Deposit EOAs</div>
        <span class="chip chip-brand">EOA only</span>
      </div>
      <div class="space-y-3">
        <div v-for="a in addresses" :key="a.network + a.asset_key"
             class="rounded-2xl border border-white/5 bg-ink-950/40 p-4">
          <div class="flex items-center justify-between mb-2">
            <div class="flex items-center gap-2">
              <span class="chip chip-brand">{{ a.network }}</span>
              <span class="text-slate-400 text-xs mono">{{ a.asset_key }}</span>
            </div>
            <button class="liquid-ghost !px-3 !py-1.5 text-xs" :disabled="checking" @click="checkBalance(a)">
              Check Balance
            </button>
          </div>
          <div class="flex items-center gap-2">
            <code class="mono text-sm text-slate-200 break-all flex-1">{{ a.deposit_address }}</code>
            <button class="liquid-ghost !px-2 !py-1 text-xs" @click="copy(a.deposit_address)">Copy</button>
          </div>
          <div class="mt-1 text-[10px] text-slate-500 mono">path: {{ a.derivation_path }}</div>
          <div v-if="a.memo" class="mt-1 text-[11px] text-accent-400">memo: <span class="mono">{{ a.memo }}</span></div>

          <div v-if="balFor(a)" class="mt-3 rounded-xl bg-ink-900/50 p-3 text-xs space-y-1">
            <div class="flex justify-between"><span class="text-slate-400">Confirmed</span><span class="mono text-slate-200">{{ balFor(a).confirmed_balance }}</span></div>
            <div class="flex justify-between"><span class="text-slate-400">Threshold</span><span class="mono text-slate-200">{{ balFor(a).deposit_threshold }}</span></div>
            <div class="flex justify-between">
              <span class="text-slate-400">Sweep</span>
              <span :class="balFor(a).sweep_triggered ? 'text-accent-400' : 'text-slate-500'">
                {{ balFor(a).sweep_triggered ? 'triggered #' + balFor(a).sweep_job_id : (balFor(a).reason || 'no') }}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
    <div v-else class="bento bento-pad text-center text-slate-500 text-sm py-8">
      Enter a subject customer id and provision deposit EOAs to begin.
    </div>
  </div>
</template>