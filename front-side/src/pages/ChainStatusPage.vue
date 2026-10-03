<script setup>
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { Chains } from '../api.js'

const rows = ref([])
const status = ref('')
const onlineCount = ref(0)
const totalCount = ref(0)
const loading = ref(false)
const error = ref('')
let timer = null

async function refresh () {
  loading.value = true
  error.value = ''
  try {
    const { data } = await Chains.status()
    rows.value = data.chains
    status.value = data.status
    onlineCount.value = data.online_count
    totalCount.value = data.total_count
  } catch (e) {
    error.value = e?.response?.data?.detail || e.message || 'failed to load chain status'
  } finally {
    loading.value = false
  }
}

function badge (online) {
  return online ? 'bg-emerald-500/15 text-emerald-400 ring-1 ring-emerald-500/40'
                : 'bg-red-500/15 text-red-400 ring-1 ring-red-500/40'
}

onMounted(() => {
  refresh()
  timer = setInterval(refresh, 30000) // auto-refresh every 30s
})
onBeforeUnmount(() => clearInterval(timer))
</script>

<template>
  <div>
    <div class="flex items-center justify-between mb-4">
      <div>
        <h2 class="text-xl font-semibold text-slate-100">Chain / Node Status</h2>
        <p class="text-sm text-slate-400">
          Live RPC probe of every supported network (block height + latency).
        </p>
      </div>
      <button class="btn" :disabled="loading" @click="refresh">
        {{ loading ? 'Probing…' : 'Refresh now' }}
      </button>
    </div>

    <div v-if="error" class="mb-4 rounded-lg bg-red-500/10 text-red-300 px-4 py-3 text-sm">
      {{ error }}
    </div>

    <div class="card p-4 mb-4 flex items-center gap-4">
      <span class="text-sm text-slate-400">Overall:</span>
      <span :class="badge(status === 'ok')" class="px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase">
        {{ status }}
      </span>
      <span class="text-sm text-slate-400">
        {{ onlineCount }} / {{ totalCount }} nodes online
      </span>
      <span v-if="status === 'degraded'" class="text-xs text-amber-400">
        some RPCs unreachable — sweeps may be delayed until a fallback answers
      </span>
    </div>

    <div class="card overflow-x-auto">
      <table class="w-full text-sm">
        <thead class="text-left text-slate-400 border-b border-slate-700/60">
          <tr>
            <th class="py-2.5 px-4 font-medium">Chain</th>
            <th class="py-2.5 px-4 font-medium">Status</th>
            <th class="py-2.5 px-4 font-medium">Node host</th>
            <th class="py-2.5 px-4 font-medium">Block height</th>
            <th class="py-2.5 px-4 font-medium">Latency</th>
            <th class="py-2.5 px-4 font-medium">Sync</th>
            <th class="py-2.5 px-4 font-medium">Memo</th>
            <th class="py-2.5 px-4 font-medium">Last error</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="c in rows" :key="c.chain_id"
              class="border-b border-slate-800/60 hover:bg-slate-800/30 transition-colors">
            <td class="py-3 px-4">
              <div class="font-semibold text-slate-200">{{ c.display_name }}</div>
              <div class="text-xs text-slate-500">{{ c.chain_id }} · {{ c.kind }}</div>
            </td>
            <td class="py-3 px-4">
              <span :class="badge(c.online)"
                    class="px-2 py-0.5 rounded-full text-xs font-semibold">ONLINE</span>
              <span v-if="!c.online"
                    class="ml-2 px-2 py-0.5 rounded-full text-xs font-semibold bg-slate-600/30 text-slate-400">OFFLINE</span>
            </td>
            <td class="py-3 px-4 font-mono text-xs text-slate-300">{{ c.node_host || '—' }}</td>
            <td class="py-3 px-4 font-mono text-xs text-slate-300">{{ c.block_height ?? '—' }}</td>
            <td class="py-3 px-4 font-mono text-xs"
                :class="(c.latency_ms ?? 9999) > 1500 ? 'text-amber-400' : 'text-emerald-400'">
              {{ c.latency_ms != null ? c.latency_ms + ' ms' : '—' }}
            </td>
            <td class="py-3 px-4 text-xs text-slate-300">{{ c.sync_status }}</td>
            <td class="py-3 px-4 text-xs">
              <span v-if="c.memo_required"
                    class="px-2 py-0.5 rounded bg-violet-500/15 text-violet-300">required</span>
              <span v-else class="text-slate-500">—</span>
            </td>
            <td class="py-3 px-4 text-xs text-red-300 max-w-[220px] truncate" :title="c.last_error">
              {{ c.last_error || '—' }}
            </td>
          </tr>
          <tr v-if="!rows.length && !loading">
            <td colspan="8" class="py-6 text-center text-slate-500">no chains configured</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>