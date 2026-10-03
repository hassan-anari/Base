<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { Withdrawals } from '../api.js'
import { toast } from '../toast.js'

const items = ref([])
let poll = null

async function load() {
  try {
    const { data } = await Withdrawals.adminList()
    items.value = data.items
  } catch (e) {
    toast(e?.response?.data?.detail || 'Admin load failed', 'error')
  }
}

async function approve(id) {
  try {
    await Withdrawals.approve(id, 'approved via console')
    toast(`#${id} approved & broadcast by MPC signer`, 'success')
    await load()
  } catch (e) {
    toast(e?.response?.data?.detail || 'Approve failed', 'error')
  }
}

async function deny(id) {
  try {
    await Withdrawals.deny(id, 'denied via console')
    toast(`#${id} denied`, 'info')
    await load()
  } catch (e) {
    toast(e?.response?.data?.detail || 'Deny failed', 'error')
  }
}

function statusChip(s) {
  return {
    PENDING_APPROVAL: 'chip',
    APPROVED: 'chip-brand',
    BROADCASTED: 'chip-brand',
    CONFIRMED: 'chip-accent',
    DENIED: 'chip-danger',
    FAILED: 'chip-danger',
  }[s] || 'chip'
}

function startPolling() {
  clearInterval(poll)
  poll = setInterval(load, 4000)
}

onMounted(() => { load(); startPolling() })
onUnmounted(() => clearInterval(poll))
</script>

<template>
  <div class="space-y-5">
    <div class="bento">
      <div class="bento-pad flex items-center justify-between">
        <div>
          <div class="label">Withdrawal approval queue</div>
          <div class="font-display text-white text-lg">Manual admin control (RBAC)</div>
        </div>
        <span class="chip chip-danger">ADMIN</span>
      </div>
    </div>

    <div class="bento">
      <div class="bento-pad">
        <div v-if="!items.length" class="text-center text-slate-500 py-10">
          Queue is empty.
        </div>
        <div v-else class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="text-left text-slate-500 text-[11px] uppercase tracking-wider">
                <th class="pb-3 pr-4">ID</th>
                <th class="pb-3 pr-4">User</th>
                <th class="pb-3 pr-4">Network</th>
                <th class="pb-3 pr-4">To</th>
                <th class="pb-3 pr-4">Amount</th>
                <th class="pb-3 pr-4">Status</th>
                <th class="pb-3 pr-4">Tx</th>
                <th class="pb-3">Action</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-white/5">
              <tr v-for="w in items" :key="w.id" class="text-slate-300">
                <td class="py-3 pr-4 mono">#{{ w.id }}</td>
                <td class="py-3 pr-4 mono text-[12px]">{{ w.user_id }}</td>
                <td class="py-3 pr-4">{{ w.network }}</td>
                <td class="py-3 pr-4 mono text-[11px] max-w-[180px] truncate" :title="w.to_address">{{ w.to_address }}</td>
                <td class="py-3 pr-4 white-space-nowrap">{{ w.amount }}</td>
                <td class="py-3 pr-4"><span class="chip" :class="statusChip(w.status)">{{ w.status }}</span></td>
                <td class="py-3 pr-4 mono text-[11px] text-brand-300 max-w-[140px] truncate">{{ w.tx_hash || '—' }}</td>
                <td class="py-3 whitespace-nowrap space-x-2">
                  <button v-if="w.status === 'PENDING_APPROVAL'" class="liquid-accent !px-3 !py-1.5 text-xs" @click="approve(w.id)">Approve</button>
                  <button v-if="w.status === 'PENDING_APPROVAL'" class="liquid-danger !px-3 !py-1.5 text-xs" @click="deny(w.id)">Deny</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <p class="mt-4 text-[12px] text-slate-500">
          Approving triggers MPC signing + broadcast; status advances APPROVED → BROADCASTED → CONFIRMED.
          Every action is written to AdminActionLog.
        </p>
      </div>
    </div>
  </div>
</template>