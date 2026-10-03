<script setup>
import { ref, computed } from 'vue'
import HomePage from './pages/HomePage.vue'
import DepositPage from './pages/DepositPage.vue'
import WithdrawalPage from './pages/WithdrawalPage.vue'
import AdminPage from './pages/AdminPage.vue'
import OpsDashboard from './pages/OpsDashboard.vue'
import ChainTokenPage from './pages/ChainTokenPage.vue'
import BlocklistPage from './pages/BlocklistPage.vue'
import GasStationPage from './pages/GasStationPage.vue'
import AddressLookupPage from './pages/AddressLookupPage.vue'
import IndexerPage from './pages/IndexerPage.vue'
import ChainStatusPage from './pages/ChainStatusPage.vue'
import ApiPlaygroundPage from './pages/ApiPlaygroundPage.vue'
import { session, setSession, clearSession } from './store.js'
import { toasts } from './toast.js'
import { Auth } from './api.js'

const tab = ref('home')
const nav = [
  { id: 'home', label: 'Overview', icon: '◉' },
  { id: 'deposit', label: 'Deposit', icon: '⬇' },
  { id: 'withdraw', label: 'Withdraw', icon: '⬆' },
  { id: 'admin', label: 'Admin', icon: '🛡', adminOnly: true },
  { id: 'chains', label: 'Chains', icon: '🪙', adminOnly: true },
  { id: 'blocklist', label: 'Blocklist', icon: '🚫', adminOnly: true },
  { id: 'ops', label: 'Ops', icon: '📊', adminOnly: true },
  { id: 'gas', label: 'Gas Stations', icon: '⛽', adminOnly: true },
  { id: 'lookup', label: 'Address Lookup', icon: '🔎', adminOnly: true },
  { id: 'indexer', label: 'Indexer', icon: '🛰', adminOnly: true },
  { id: 'chainstatus', label: 'Node Status', icon: '🟢' },
  { id: 'playground', label: 'API Playground', icon: '🧪' },
]
const visibleNav = computed(() => nav.filter((n) => !n.adminOnly || session.role === 'admin'))

// ---------------- Login gate ----------------
const username = ref('')
const password = ref('')
const loggingIn = ref(false)
const loginErr = ref('')

async function login() {
  loginErr.value = ''
  loggingIn.value = true
  try {
    const { data } = await Auth.login(username.value.trim(), password.value)
    setSession(data.access_token, data.user_id, data.role)
    tab.value = data.role === 'admin' ? 'admin' : 'deposit'
    toasts.push({ id: Date.now(), message: `Signed in as ${data.user_id}`, type: 'success' })
  } catch (e) {
    loginErr.value = e?.response?.data?.detail || 'Login failed'
  } finally {
    loggingIn.value = false
  }
}

function logout() {
  clearSession()
  username.value = ''
  password.value = ''
  tab.value = 'deposit'
  toasts.push({ id: Date.now(), message: 'Signed out', type: 'info' })
}
</script>

<template>
  <div class="min-h-screen flex">
    <!-- Login gate -->
    <div v-if="!session.authed" class="flex-1 grid place-items-center p-6">
      <div class="bento w-full max-w-sm">
        <div class="bento-pad">
          <div class="flex items-center gap-3 mb-6">
            <div class="h-11 w-11 rounded-2xl bg-gradient-to-br from-brand-500 to-accent-500
                        grid place-items-center text-ink-950 font-display font-bold shadow-glow text-lg">M</div>
            <div>
              <div class="font-display font-semibold text-white leading-tight">MPC Custody</div>
              <div class="text-[11px] text-slate-500 tracking-wide">Exchange · Testnet</div>
            </div>
          </div>
          <div class="label mb-1">Username</div>
          <input v-model="username" type="text" autocomplete="username"
                 @keyup.enter="login"
                 class="input w-full mb-3" placeholder="ops / admin / audit / viewer" />
          <div class="label mb-1">Password</div>
          <input v-model="password" type="password" autocomplete="current-password"
                 @keyup.enter="login"
                 class="input w-full mb-4" placeholder="••••••••" />
          <button class="liquid w-full" :disabled="loggingIn" @click="login">
            {{ loggingIn ? 'Signing in...' : 'Sign in' }}
          </button>
          <p v-if="loginErr" class="mt-3 text-sm text-danger-400">{{ loginErr }}</p>
           <p class="mt-4 text-[11px] text-slate-500 leading-relaxed">
             Operator console. Demo logins (username / password):<br/>
             <span class="mono">ops / ops</span>
             (operator) · <span class="mono">admin / admin</span> (approver / admin)
             · <span class="mono">audit / audit</span> (auditor) · <span class="mono">viewer / viewer</span> (read-only).
           </p>
        </div>
      </div>
    </div>

    <!-- Dashboard (authed) -->
    <template v-else>
    <!-- Sidebar -->
    <aside class="hidden sm:flex w-64 shrink-0 flex-col gap-2 p-5 border-r border-white/5
                   bg-ink-900/60 backdrop-blur-xl">
      <div class="flex items-center gap-3 px-2 pb-6">
        <div class="h-10 w-10 rounded-2xl bg-gradient-to-br from-brand-500 to-accent-500
                    grid place-items-center text-ink-950 font-display font-bold shadow-glow">M</div>
        <div>
          <div class="font-display font-semibold text-white leading-tight">MPC Custody</div>
          <div class="text-[11px] text-slate-500 tracking-wide">Exchange · Testnet</div>
        </div>
      </div>

      <nav class="flex flex-col gap-1">
        <button v-for="n in visibleNav" :key="n.id" @click="tab = n.id"
          class="nav-pill flex items-center gap-3 justify-start"
          :class="{ active: tab === n.id }">
          <span class="text-base">{{ n.icon }}</span>{{ n.label }}
        </button>
      </nav>

      <div class="mt-auto space-y-3">
        <div class="bento bento-pad !p-4">
          <div class="label mb-1">Session</div>
          <div class="mono text-slate-300 truncate">{{ session.userId }}</div>
          <div class="mt-2">
            <span class="chip" :class="session.role === 'admin' ? 'chip-danger' : 'chip-brand'">
              {{ session.role }}
            </span>
          </div>
        </div>
        <button class="liquid-ghost w-full" @click="logout">Sign out</button>
      </div>
    </aside>

    <!-- Main -->
    <div class="flex-1 min-w-0 flex flex-col">
      <!-- Topbar -->
      <header class="sticky top-0 z-20 flex items-center justify-between gap-4 px-5 sm:px-8 py-4
                     border-b border-white/5 bg-ink-950/70 backdrop-blur-xl">
        <div class="flex items-center gap-3 sm:hidden">
          <div class="h-9 w-9 rounded-xl bg-gradient-to-br from-brand-500 to-accent-500
                      grid place-items-center text-ink-950 font-display font-bold">M</div>
          <span class="font-display font-semibold text-white">MPC Custody</span>
        </div>
         <h1 class="hidden sm:block font-display text-lg text-white tracking-tight">
           {{ tab === 'home' ? 'Custody Overview' : tab === 'deposit' ? 'Customer Wallets & Auto-Sweep' : tab === 'withdraw' ? 'Withdrawal Console' : tab === 'admin' ? 'Approval Console' : tab === 'chains' ? 'Chains & Tokens' : tab === 'blocklist' ? 'Compliance Blocklist' : tab === 'gas' ? 'Gas Stations' : tab === 'lookup' ? 'Address Lookup' : tab === 'indexer' ? 'Indexer Nodes' : tab === 'playground' ? 'API Playground (Test Tool)' : 'Ops Console' }}
         </h1>
        <div class="flex items-center gap-2">
          <span class="chip chip-brand animate-pulse-ring">● Live</span>
          <button class="liquid-ghost !px-3 !py-2 sm:hidden" @click="logout">Sign out</button>
        </div>
      </header>

      <!-- Mobile tab bar -->
      <nav class="sm:hidden flex gap-2 px-4 py-3 border-b border-white/5">
        <button v-for="n in visibleNav" :key="n.id" @click="tab = n.id"
          class="nav-pill flex-1" :class="{ active: tab === n.id }">{{ n.label }}</button>
      </nav>

      <main class="flex-1 p-5 sm:p-8">
        <HomePage v-if="tab === 'home'" @navigate="tab = $event" />
        <DepositPage v-else-if="tab === 'deposit'" @navigate="tab = $event" />
        <WithdrawalPage v-else-if="tab === 'withdraw'" />
        <AdminPage v-else-if="tab === 'admin'" />
        <ChainTokenPage v-else-if="tab === 'chains'" />
        <BlocklistPage v-else-if="tab === 'blocklist'" />
        <GasStationPage v-else-if="tab === 'gas'" />
        <AddressLookupPage v-else-if="tab === 'lookup'" />
        <IndexerPage v-else-if="tab === 'indexer'" />
        <ChainStatusPage v-else-if="tab === 'chainstatus'" />
        <ApiPlaygroundPage v-else-if="tab === 'playground'" />
        <OpsDashboard v-else />
      </main>
    </div>
    </template>

    <!-- Toasts -->
    <div class="fixed bottom-5 right-5 z-50 flex flex-col gap-2 w-80 max-w-[90vw]">
      <transition-group name="toast">
        <div v-for="t in toasts" :key="t.id"
          class="bento bento-pad !p-3.5 text-sm"
          :class="t.type === 'error' ? 'border-danger-500/40' : t.type === 'success' ? 'border-accent-500/40' : 'border-brand-500/30'">
          <span class="mr-2">{{ t.type === 'error' ? '⚠' : t.type === 'success' ? '✓' : 'i' }}</span>
          <span class="text-slate-200">{{ t.message }}</span>
        </div>
      </transition-group>
    </div>
  </div>
</template>

<style>
.toast-enter-active, .toast-leave-active { transition: all .35s ease; }
.toast-enter-from, .toast-leave-to { opacity: 0; transform: translateX(40px); }
</style>