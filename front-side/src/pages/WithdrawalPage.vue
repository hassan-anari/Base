<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { Withdrawals, NETWORKS } from '../api.js'
import { session } from '../store.js'
import { toasts } from '../toast.js'
import { createWithdrawalIntentTracker } from '../withdrawalIntent.js'

// Operator console: the operator creates withdrawals ON BEHALF OF a subject
// customer, but APPROVAL is admin-only (RBAC enforced on the backend).

const subject = ref(localStorage.getItem('ops.subject') || '')
const network = ref('BSC')
const toAddress = ref('')
const amount = ref('')
const requesting = ref(false)
const intentTracker = createWithdrawalIntentTracker()

const queue = ref([])   // pending/approved items awaiting admin action (admin only)
const mine = ref([])    // all withdrawals (operator visibility)
const loadingQueue = ref(false)
const loadingMine = ref(false)

const networks = NETWORKS
const isAdmin = session.role === 'admin'

let timer = null

async function refreshQueue() {
  if (!isAdmin) return
  loadingQueue.value = true
  try {
    const { data } = await Withdrawals.adminList()
    // Show actionable items first (PENDING_APPROVAL), then others.
    queue.value = data.items.slice().sort((a, b) => (a.status === 'PENDING_APPROVAL' ? -1 : 1))
  } catch (e) {
    toasts.push({ id: Date.now(), message: e?.response?.data?.detail || 'Queue load failed', type: 'error' })
  } finally {
    loadingQueue.value = false
  }
}

async function refreshMine() {
  loadingMine.value = true
  try {
    const { data } = await Withdrawals.list(subject.value.trim() || null)
    mine.value = data.items
  } catch (e) {
    toasts.push({ id: Date.now(), message: e?.response?.data?.detail || 'List failed', type: 'error' })
  } finally {
    loadingMine.value = false
  }
}

async function submitRequest() {
  if (!subject.value.trim()) {
    toasts.push({ id: Date.now(), message: 'Enter a subject (customer) user id', type: 'error' })
    return
  }
  if (!toAddress.value.trim() || !amount.value) {
    toasts.push({ id: Date.now(), message: 'Fill destination + amount', type: 'error' })
    return
  }
  requesting.value = true
  try {
    const values = [subject.value.trim(), network.value, toAddress.value.trim(), amount.value, ''].join('|')
    const idempotencyKey = intentTracker.keyFor(values)
    const { data } = await Withdrawals.request(
      subject.value.trim(), network.value, toAddress.value.trim(), parseFloat(amount.value),
      null, idempotencyKey,
    )
    toasts.push({ id: Date.now(), message: `Withdrawal #${data.id} created (PENDING_APPROVAL)`, type: 'success' })
    intentTracker.reset()
    toAddress.value = ''; amount.value = ''
    refreshMine(); refreshQueue()
  } catch (e) {
    toasts.push({ id: Date.now(), message: e?.response?.data?.detail || 'Request failed', type: 'error' })
  } finally {
    requesting.value = false
  }
}

async function approve(id, notes = '') {
  try {
    await Withdrawals.approve(id, notes)
    toasts.push({ id: Date.now(), message: `Approved + broadcast #${id}`, type: 'success' })
    refreshQueue(); refreshMine()
  } catch (e) {
    toasts.push({ id: Date.now(), message: e?.response?.data?.detail || 'Approve failed', type: 'error' })
  }
}

async function deny(id, notes = '') {
  try {
    await Withdrawals.deny(id, notes)
    toasts.push({ id: Date.now(), message: `Denied #${id}`, type: 'info' })
    refreshQueue(); refreshMine()
  } catch (e) {
    toasts.push({ id: Date.now(), message: e?.response?.data?.detail || 'Deny failed', type: 'error' })
  }
}

const statusClass = (s) => ({
  'PENDING_APPROVAL': 'chip-brand',
  'APPROVED': 'chip-accent',
  'PROCESSING': 'chip-accent',
  'RECONCILIATION_REQUIRED': 'chip-danger',
  'BROADCASTED': 'chip-accent',
  'CONFIRMED': 'chip-accent',
  'DENIED': 'chip-danger',
  'FAILED': 'chip-danger',
}[s] || 'chip-brand')

onMounted(() => { refreshMine(); refreshQueue(); timer = setInterval(refreshMine, 10000) })
onUnmounted?.(() => timer && clearInterval(timer))
</script>

<template>
  <div class="space-y-5">
    <!-- Subject + new request -->
    <div class="bento bento-pad">
      <div class="label mb-1">Subject customer (withdrawal on behalf of)</div>
      <input v-model="subject" class="input w-full mb-3" placeholder="e.g. cust-1001" />
      <div class="grid sm:grid-cols-3 gap-3">
        <select v-model="network" class="input">
          <option v-for="n in networks" :key="n.value" :value="n.value">{{ n.label }}</option>
        </select>
        <input v-model="toAddress" class="input" placeholder="destination address" />
        <input v-model="amount" class="input" type="number" step="any" placeholder="amount" />
      </div>
      <button class="liquid w-full mt-3" :disabled="requesting" @click="submitRequest">
        {{ requesting ? 'Submitting...' : 'Create withdrawal request' }}
      </button>
      <p class="mt-2 text-[11px] text-slate-500">No on-chain action occurs until an <b>admin</b> approves.</p>
    </div>

    <!-- Admin approval queue -->
    <div v-if="isAdmin" class="bento bento-pad">
      <div class="flex items-center justify-between mb-3">
        <div class="font-display font-semibold text-white">Approval queue</div>
        <button class="liquid-ghost !px-3 !py-1.5 text-xs" @click="refreshQueue">Refresh</button>
      </div>
      <div v-if="!queue.length" class="text-slate-500 text-sm py-4">No withdrawals.</div>
      <div v-else class="space-y-2">
        <div v-for="w in queue" :key="w.id"
             class="rounded-2xl border border-white/5 bg-ink-950/40 p-3 flex items-center gap-3">
          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-2">
              <span class="chip" :class="statusClass(w.status)">{{ w.status }}</span>
              <span class="text-xs mono text-slate-400">#{{ w.id }}</span>
              <span class="text-xs text-slate-500">{{ w.user_id }}</span>
            </div>
            <div class="mt-1 text-xs mono text-slate-300 truncate">
              {{ w.network }} · {{ w.amount }} → {{ w.to_address }}
            </div>
            <div v-if="w.tx_hash" class="text-[10px] text-accent-400 mono truncate">tx: {{ w.tx_hash }}</div>
          </div>
          <div v-if="w.status === 'PENDING_APPROVAL'" class="flex gap-2 shrink-0">
            <button class="liquid !px-3 !py-1.5 text-xs" @click="approve(w.id)">Approve</button>
            <button class="liquid-ghost !px-3 !py-1.5 text-xs border-danger-500/40 text-danger-400" @click="deny(w.id)">Deny</button>
          </div>
        </div>
      </div>
    </div>

    <!-- All withdrawals (operator visibility) -->
    <div class="bento bento-pad">
      <div class="flex items-center justify-between mb-3">
        <div class="font-display font-semibold text-white">Withdrawals (live)</div>
        <button class="liquid-ghost !px-3 !py-1.5 text-xs" @click="refreshMine">Refresh</button>
      </div>
      <div v-if="!mine.length" class="text-slate-500 text-sm py-4">No withdrawals yet.</div>
      <div v-else class="space-y-2">
        <div v-for="w in mine" :key="w.id"
             class="rounded-2xl border border-white/5 bg-ink-950/40 p-3">
          <div class="flex items-center gap-2">
            <span class="chip" :class="statusClass(w.status)">{{ w.status }}</span>
            <span class="text-xs mono text-slate-400">#{{ w.id }}</span>
            <span class="text-xs text-slate-500">{{ w.network }} · {{ w.asset_key }}</span>
          </div>
          <div class="mt-1 text-xs mono text-slate-300 truncate">{{ w.amount }} → {{ w.to_address }}</div>
          <div v-if="w.tx_hash" class="text-[10px] text-accent-400 mono truncate">tx: {{ w.tx_hash }}</div>
        </div>
      </div>
    </div>
  </div>
</template>
