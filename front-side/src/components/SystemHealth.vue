<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import api from '../api.js'
import { toast } from '../toast.js'

// Live system-health rollup (operator/auditor view).
const data = ref(null)
const loading = ref(false)
const err = ref('')
let poll = null

async function load() {
  loading.value = true
  err.value = ''
  try {
    const { data: d } = await api.get('/ops/system/health', {
      headers: { 'x-user-id': 'ops', 'x-role': 'operator' },
    })
    data.value = d
  } catch (e) {
    err.value = e?.response?.data?.detail || 'Failed to load system health'
  } finally {
    loading.value = false
  }
}

const STATUS_RANK = { OK: 0, NA: 1, DEGRADED: 2, DOWN: 3 }
function chipClass(s) {
  return {
    OK: 'chip-accent',
    DEGRADED: 'chip-brand',
    DOWN: 'chip-danger',
    NA: 'chip',
  }[s] || 'chip'
}
function bannerClass(s) {
  return {
    OK: 'border-accent-400/40 bg-accent-400/5',
    DEGRADED: 'border-brand-400/40 bg-brand-400/5',
    DOWN: 'border-danger-400/50 bg-danger-400/10',
    NA: 'border-white/10 bg-white/5',
  }[s] || 'border-white/10 bg-white/5'
}

function startPolling() {
  clearInterval(poll)
  poll = setInterval(load, 15000)
}
onMounted(() => { load(); startPolling() })
onUnmounted(() => clearInterval(poll))
</script>

<template>
  <div class="bento bento-pad">
    <div class="flex items-center justify-between mb-4">
      <div class="flex items-center gap-2">
        <span class="section-bar"></span>
        <div>
          <div class="label">System health</div>
          <div class="font-display text-white text-lg">Live dependency probes</div>
        </div>
      </div>
      <div class="flex items-center gap-3">
        <span v-if="data" class="mono text-xs text-slate-500">
          uptime {{ Math.floor((data.uptime_seconds || 0) / 60) }}m
        </span>
        <button class="liquid-ghost !px-3 !py-1.5 text-xs" @click="load"
                :disabled="loading">Refresh</button>
      </div>
    </div>

    <p v-if="err" class="text-sm text-danger-400 mb-3">{{ err }}</p>

    <!-- Aggregate banner -->
    <div v-if="data" :class="['rounded-xl border px-4 py-3 mb-4 flex flex-wrap items-center justify-between gap-3', bannerClass(data.status)]">
      <div class="flex items-center gap-3">
        <span class="chip" :class="chipClass(data.status)">{{ data.status }}</span>
        <span class="text-sm text-slate-300">
          Aggregate status across {{ data.components.length }} probes
        </span>
      </div>
      <div class="flex items-center gap-4 text-xs text-slate-400">
        <span>stuck sweeps: <b class="text-slate-200">{{ data.pending_sweeps }}</b></span>
        <span>pending withdrawals: <b class="text-slate-200">{{ data.pending_withdrawals }}</b></span>
      </div>
    </div>

    <!-- Component bento grid -->
    <div v-if="data" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
      <div v-for="c in data.components" :key="c.component"
           class="rounded-2xl bg-white/5 border border-white/8 px-4 py-3 transition hover:border-brand-400/30">
        <div class="flex items-center justify-between mb-1">
          <span class="font-display text-slate-200 capitalize">{{ c.component.replace('_', ' ') }}</span>
          <span class="chip" :class="chipClass(c.status)">{{ c.status }}</span>
        </div>
        <p class="text-[11px] text-slate-400 leading-snug">{{ c.detail }}</p>
        <p v-if="c.metric && Object.keys(c.metric).length"
           class="mt-1 mono text-[10px] text-slate-500">{{ JSON.stringify(c.metric) }}</p>
        <p class="mt-1 mono text-[10px] text-slate-600">{{ c.checked_at }}</p>
      </div>
    </div>
    <div v-else-if="loading" class="text-slate-500 text-sm">Probing dependencies...</div>
  </div>
</template>