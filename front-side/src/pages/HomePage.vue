<script setup>
import { ref, reactive, onMounted, onUnmounted } from 'vue'
import { Stats } from '../api.js'
import { session } from '../store.js'
import { toast } from '../toast.js'

const loading = ref(true)
const error = ref('')
const generatedAt = ref('')
const stats = reactive({
  users_total: 0,
  wallets_total: 0,
  wallets_active: 0,
  wallets_retired: 0,
  deposits_total: 0,
  deposits_total_amount: 0,
  sweeps_total: 0,
  sweeps_by_status: {},
  withdrawals_total: 0,
  withdrawals_by_status: {},
  pending_withdrawals: 0,
})

const PINNED = ['users_total', 'wallets_total', 'deposits_total', 'pending_withdrawals']
const pinnedMeta = {
  users_total: { label: 'Customers', icon: '◍', hint: 'distinct users with wallets' },
  wallets_total: { label: 'Deposit Wallets', icon: '⛁', hint: 'active + retired EOAs' },
  deposits_total: { label: 'Deposits', icon: '↓', hint: 'parsed on-chain deposits' },
  pending_withdrawals: { label: 'Pending Withdrawals', icon: '⏳', hint: 'awaiting admin approval' },
}

const sweepColor = (s) =>
  ({ CONFIRMED: 'chip-accent', FAILED: 'chip-danger', BROADCASTED: 'chip-brand',
     GAS_TOPUP_REQUIRED: 'chip-brand' }[s] || 'chip')
const wdColor = (s) =>
  ({ PENDING_APPROVAL: 'chip-brand', APPROVED: 'chip-accent', BROADCASTED: 'chip-brand',
     CONFIRMED: 'chip-accent', DENIED: 'chip-danger', FAILED: 'chip-danger' }[s] || 'chip')

async function load() {
  loading.value = true
  error.value = ''
  try {
    const { data } = await Stats.overview()
    stats.users_total = data.users_total
    stats.wallets_total = data.wallets_total
    stats.wallets_active = data.wallets_active
    stats.wallets_retired = data.wallets_retired
    stats.deposits_total = data.deposits_total
    stats.deposits_total_amount = data.deposits_total_amount
    stats.sweeps_total = data.sweeps_total
    stats.sweeps_by_status = data.sweeps_by_status || {}
    stats.withdrawals_total = data.withdrawals_total
    stats.withdrawals_by_status = data.withdrawals_by_status || {}
    stats.pending_withdrawals = data.pending_withdrawals
    generatedAt.value = data.generated_at
  } catch (e) {
    error.value = e?.response?.data?.detail || 'failed to load custody stats'
    toast.error(error.value)
  } finally {
    loading.value = false
  }
}

// Auto-refresh the overview.
let timer = null
onMounted(() => { load(); timer = setInterval(load, 15000) })
onUnmounted(() => { if (timer) clearInterval(timer) })

const emit = defineEmits(['navigate'])
const navTo = (tab) => emit('navigate', tab)
</script>

<template>
  <div class="mx-auto max-w-7xl px-4 sm:px-6 py-6">
    <!-- Header -->
    <div class="flex flex-wrap items-end justify-between gap-4 mb-6">
      <div>
        <div class="flex items-center gap-2 mb-1">
          <span class="section-bar"></span>
          <span class="label">Operator Console</span>
        </div>
        <h1 class="font-display text-2xl sm:text-3xl text-slate-900 font-semibold">Custody Overview</h1>
        <p class="text-sm text-slate-500 mt-1">
          Aggregate view of the MPC custodial wallet service. Customer deposit addresses are never listed here.
        </p>
      </div>
      <div class="text-right">
        <button class="liquid-ghost" @click="load" :disabled="loading">↻ Refresh</button>
        <p v-if="generatedAt" class="text-[11px] text-slate-400 mt-2 mono">
          updated {{ generatedAt.slice(11, 19) }}
        </p>
      </div>
    </div>

    <div v-if="error" class="kpi border-danger-200 !text-danger-600 mb-4">
      {{ error }}
    </div>

    <!-- Pinned KPIs -->
    <div class="bento-grid mb-6">
      <div v-for="k in PINNED" :key="k" class="kpi">
        <div class="flex items-center gap-3">
          <div class="kpi-icon">{{ pinnedMeta[k].icon }}</div>
          <div>
            <div class="label">{{ pinnedMeta[k].label }}</div>
            <div class="stat-num">{{ loading ? '—' : stats[k].toLocaleString() }}</div>
            <div class="text-[11px] text-slate-400 mt-0.5">{{ pinnedMeta[k].hint }}</div>
          </div>
        </div>
      </div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
      <!-- Wallets -->
      <div class="bento bento-pad">
        <div class="flex items-center gap-2 mb-3">
          <span class="section-bar"></span>
          <span class="label">Deposit Wallets</span>
        </div>
        <div class="flex items-end gap-6">
          <div>
            <div class="text-[11px] text-slate-400">Active</div>
            <div class="stat-num">{{ loading ? '—' : stats.wallets_active.toLocaleString() }}</div>
          </div>
          <div>
            <div class="text-[11px] text-slate-400">Retired</div>
            <div class="stat-num text-slate-500">{{ loading ? '—' : stats.wallets_retired.toLocaleString() }}</div>
          </div>
          <div class="ml-auto">
            <div class="text-[11px] text-slate-400">Total</div>
            <div class="stat-num text-slate-900">{{ loading ? '—' : stats.wallets_total.toLocaleString() }}</div>
          </div>
        </div>
        <div class="text-[11px] text-slate-400 mt-3">
          All deposit addresses are EOA (externally-owned), derived via HD semantics per user.
        </div>
      </div>

      <!-- Deposits -->
      <div class="bento bento-pad">
        <div class="flex items-center gap-2 mb-3">
          <span class="section-bar"></span>
          <span class="label">Deposits</span>
        </div>
        <div class="stat-num">{{ loading ? '—' : stats.deposits_total.toLocaleString() }}</div>
        <div class="text-[11px] text-slate-400 mt-1">total parsed deposits</div>
        <div class="mt-3 flex items-baseline gap-2">
          <span class="text-slate-400 text-sm">∑</span>
          <span class="font-display text-lg text-slate-900 font-semibold tabular-nums">
            {{ loading ? '—' : stats.deposits_total_amount.toLocaleString(undefined, { maximumFractionDigits: 4 }) }}
          </span>
          <span class="text-[11px] text-slate-400">aggregate (native units)</span>
        </div>
      </div>

      <!-- Sweeps -->
      <div class="bento bento-pad">
        <div class="flex items-center gap-2 mb-3">
          <span class="section-bar"></span>
          <span class="label">Sweeps (EOA → Hot)</span>
        </div>
        <div class="stat-num">{{ loading ? '—' : stats.sweeps_total.toLocaleString() }}</div>
        <div class="text-[11px] text-slate-400 mt-1">custody-signed sweeps to hot wallet</div>
        <div class="flex flex-wrap gap-1.5 mt-3">
          <span v-for="(c, s) in stats.sweeps_by_status" :key="s" :class="['chip', sweepColor(s)]">
            {{ s }} · {{ c }}
          </span>
          <span v-if="!stats.sweeps_total" class="chip">no sweeps yet</span>
        </div>
      </div>
    </div>

    <!-- Withdrawals + quick actions -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
      <div class="bento bento-pad lg:col-span-2">
        <div class="flex items-center gap-2 mb-3">
          <span class="section-bar"></span>
          <span class="label">Withdrawals (admin-approved)</span>
        </div>
        <div class="flex items-end gap-6 mb-3">
          <div>
            <div class="text-[11px] text-slate-400">Total</div>
            <div class="stat-num">{{ loading ? '—' : stats.withdrawals_total.toLocaleString() }}</div>
          </div>
          <div>
            <div class="text-[11px] text-slate-400">Pending Approval</div>
            <div class="stat-num text-brand-700">{{ loading ? '—' : stats.pending_withdrawals.toLocaleString() }}</div>
          </div>
        </div>
        <div class="flex flex-wrap gap-1.5">
          <span v-for="(c, s) in stats.withdrawals_by_status" :key="s" :class="['chip', wdColor(s)]">
            {{ s }} · {{ c }}
          </span>
          <span v-if="!stats.withdrawals_total" class="chip">no withdrawals yet</span>
        </div>
        <div class="text-[11px] text-slate-400 mt-3">
          No on-chain transaction is broadcast before manual admin approval. Every action is audit-logged.
        </div>
      </div>

      <div class="bento bento-pad">
        <div class="flex items-center gap-2 mb-3">
          <span class="section-bar"></span>
          <span class="label">Quick Actions</span>
        </div>
        <div class="grid grid-cols-1 gap-2">
          <button class="liquid w-full" @click="navTo('deposit')">＋ Deposit / Sweep</button>
          <button class="liquid-accent w-full" @click="navTo('withdrawal')">↗ Withdrawal</button>
          <button v-if="['operator', 'admin'].includes(session.role)" class="liquid-ghost w-full"
                  @click="navTo('admin')">⚙ Admin Approvals</button>
          <button v-if="['operator', 'admin'].includes(session.role)" class="liquid-ghost w-full"
                  @click="navTo('gas')">⛽ Gas Station</button>
        </div>
      </div>
    </div>
  </div>
</template>