<template>
  <div class="min-h-screen text-slate-800">
    <header class="bg-slate-900 text-white px-6 py-4 flex items-center justify-between">
      <div>
        <h1 class="text-lg font-semibold">MPC Custody · API Simulator</h1>
        <p class="text-xs text-slate-400">
          Standalone API testing console — exercises every backend endpoint. No real keys.
        </p>
      </div>
      <a href="/" class="text-xs bg-slate-700 hover:bg-slate-600 px-3 py-1.5 rounded"
        >← Back to Exchange Console</a
      >
    </header>

    <div class="grid grid-cols-12 gap-4 p-4">
      <section class="col-span-4 space-y-4">
        <div class="bg-white rounded-lg shadow p-4">
          <h2 class="font-semibold mb-2 text-sm uppercase tracking-wide text-slate-500">
            End-to-End Scenarios
          </h2>
          <select v-model="selectedScenario" class="w-full border rounded px-2 py-1.5 text-sm mb-2">
            <option v-for="s in SCENARIOS" :key="s.id" :value="s.id">{{ s.name }}</option>
          </select>
          <p class="text-xs text-slate-500 mb-3">{{ currentScenario.desc }}</p>
          <button
            @click="runScenario"
            :disabled="running"
            class="w-full bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white rounded px-3 py-2 text-sm font-medium"
          >
            {{ running ? 'Running...' : '▶ Run Scenario' }}
          </button>
          <button @click="resetState" class="w-full mt-2 text-xs text-slate-500 hover:text-slate-700">
            Reset scenario state
          </button>
        </div>

        <div v-if="running || scenarioLog.length" class="bg-white rounded-lg shadow p-4">
          <h2 class="font-semibold mb-2 text-sm uppercase tracking-wide text-slate-500">
            Scenario Steps
          </h2>
          <ol class="space-y-1 text-sm">
            <li v-for="(step, i) in scenarioLog" :key="i" class="flex items-start gap-2">
              <span
                class="mt-0.5 inline-block w-4 h-4 rounded-full text-[10px] text-center"
                :class="stepClass(step)"
                >{{ stepIcon(step) }}</span
              >
              <span>
                <span class="font-mono text-xs">{{ step.endpoint }}</span>
                <span class="text-slate-500 text-xs"> — {{ step.note }}</span>
              </span>
            </li>
          </ol>
        </div>

        <div class="bg-white rounded-lg shadow p-4">
          <h2 class="font-semibold mb-2 text-sm uppercase tracking-wide text-slate-500">
            Scenario State (vars)
          </h2>
          <div class="grid grid-cols-2 gap-2 text-xs">
            <div v-for="(v, k) in stateVars" :key="k">
              <label class="block text-slate-400">{{ k }}</label>
              <input v-model="stateVars[k]" class="w-full border rounded px-1.5 py-1 mono" />
            </div>
          </div>
        </div>
      </section>

      <section class="col-span-4 bg-white rounded-lg shadow p-4">
        <h2 class="font-semibold mb-2 text-sm uppercase tracking-wide text-slate-500">
          Endpoint Catalog
        </h2>
        <div v-for="g in GROUPS" :key="g" class="mb-3">
          <h3 class="text-xs font-bold text-slate-700 mb-1">{{ g }}</h3>
          <button
            v-for="ep in endpointsByGroup(g)"
            :key="ep.id"
            @click="runSingle(ep)"
            :disabled="running"
            class="w-full text-left flex items-center gap-2 border rounded px-2 py-1.5 mb-1 hover:bg-slate-50 disabled:opacity-50"
          >
            <span class="text-[10px] font-bold px-1.5 py-0.5 rounded" :class="methodClass(ep.method)">{{
              ep.method
            }}</span>
            <span class="mono text-xs truncate">{{ ep.path }}</span>
            <span class="ml-auto text-[10px] text-slate-400">{{ ep.role }}</span>
          </button>
        </div>
      </section>

      <section class="col-span-4 bg-white rounded-lg shadow p-4">
        <div class="flex items-center justify-between mb-2">
          <h2 class="font-semibold text-sm uppercase tracking-wide text-slate-500">Live Results</h2>
          <button @click="results = []" class="text-xs text-slate-400 hover:text-slate-600">clear</button>
        </div>
        <div v-if="!results.length" class="text-xs text-slate-400">
          Run a scenario or click an endpoint to see responses.
        </div>
        <div v-for="(r, i) in results" :key="i" class="border-b border-slate-100 py-2 text-xs">
          <div class="flex items-center gap-2 mb-1">
            <span
              class="font-bold px-1.5 py-0.5 rounded text-[10px]"
              :class="r.ok ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'"
              >{{ r.status }}</span
            >
            <span class="mono font-semibold">{{ r.method }} {{ r.url }}</span>
          </div>
          <pre
            v-if="r.requestBody"
            class="bg-slate-50 rounded p-1.5 overflow-x-auto text-[10px] text-slate-600 mb-1"
            >REQ {{ pretty(r.requestBody) }}</pre
          >
          <pre
            class="bg-slate-900 text-green-200 rounded p-1.5 overflow-x-auto text-[10px]"
            >{{ pretty(r.data) }}</pre
          >
        </div>
      </section>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { ENDPOINTS, GROUPS, ENDPOINT_MAP } from './endpoints.js'
import { SCENARIOS, scenarioById } from './scenarios.js'
import { callEndpoint, login } from './api.js'

const results = ref([])
const running = ref(false)
const selectedScenario = ref('deposit_sweep')
const scenarioLog = ref([])
const stateVars = reactive({
  subject_user_id: 'demo-user-001',
  network: 'ETH',
  asset_key: 'ETH',
  address: '',
  to_address: '0xRecipientExternalAddress',
  amount: '0.5',
  sweep_id: '',
  wd_id: '',
  idempotency_key: crypto.randomUUID(),
})

const currentScenario = computed(() => scenarioById(selectedScenario.value))
const endpointsByGroup = (g) => ENDPOINTS.filter((e) => e.group === g)

function pretty(v) {
  try {
    return JSON.stringify(v, null, 2)
  } catch {
    return String(v)
  }
}
function methodClass(m) {
  return (
    {
      GET: 'bg-blue-100 text-blue-700',
      POST: 'bg-emerald-100 text-emerald-700',
      PATCH: 'bg-amber-100 text-amber-700',
    }[m] || 'bg-slate-100 text-slate-700'
  )
}
function stepClass(step) {
  if (step.status === 'running') return 'bg-indigo-100 text-indigo-700 animate-pulse'
  if (step.ok) return 'bg-green-100 text-green-700'
  if (step.expectedFail && !step.ok) return 'bg-amber-100 text-amber-700'
  return 'bg-red-100 text-red-700'
}
function stepIcon(step) {
  if (step.status === 'running') return '...'
  if (step.ok || step.expectedFail) return '✓'
  return '✗'
}

function logResult(entry, ep) {
  results.value.unshift({
    method: ep.method,
    url: entry.url,
    status: entry.status,
    ok: entry.ok,
    data: entry.data,
    requestBody: entry.body,
  })
}

function flatten(obj, prefix = '', out = {}) {
  if (obj == null || typeof obj !== 'object') return out
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k
    if (v && typeof v === 'object' && !Array.isArray(v)) flatten(v, key, out)
    else out[key] = v
  }
  return out
}

function captureExtract(ep, res) {
  if (!ep.extract || !res.ok) return
  const flat = flatten(res.data)
  for (const [srcKey, dstVar] of Object.entries(ep.extract)) {
    if (flat[srcKey] != null) stateVars[dstVar] = String(flat[srcKey])
  }
}

async function runSingle(ep) {
  const res = await callEndpoint(ep, { ...stateVars })
  logResult(res, ep)
  captureExtract(ep, res)
}

async function runScenario() {
  running.value = true
  scenarioLog.value = []
  const scenario = currentScenario.value
  let currentRole = null

  for (const step of scenario.steps) {
    if (step.endpointId === 'login') currentRole = step.role
    const ep = ENDPOINT_MAP[step.endpointId]
    if (!ep) {
      scenarioLog.value.push({ endpoint: step.endpointId, note: step.note, ok: false, status: 'error' })
      continue
    }
    scenarioLog.value.push({ endpoint: ep.path, note: step.note, ok: null, status: 'running' })
    const idx = scenarioLog.value.length - 1

    if (currentRole && ep.role !== 'public') {
      await login(currentRole)
    }

    try {
      if (step.poll) {
        let done = false
        let pollRes = null
        for (let i = 0; i < 24 && !done; i++) {
          const vars = { ...stateVars }
          vars[step.poll.key] = stateVars[step.poll.key]
          pollRes = await callEndpoint(ep, vars)
          logResult(pollRes, ep)
          const val = pollRes.ok ? flatten(pollRes.data)[step.poll.field] : null
          captureExtract(ep, pollRes)
          if (val && step.poll.done.includes(val)) {
            done = true
            break
          }
          await new Promise((r) => setTimeout(r, 400))
        }
        const finalVal = pollRes && pollRes.ok ? flatten(pollRes.data)[step.poll.field] : null
        const ok = step.poll.done.includes(finalVal)
        scenarioLog.value[idx] = {
          ...scenarioLog.value[idx],
          ok,
          status: ok ? 'done' : 'error',
          note: step.note + (finalVal ? ` (status=${finalVal})` : ''),
        }
      } else {
        const res = await callEndpoint(ep, { ...stateVars })
        logResult(res, ep)
        captureExtract(ep, res)
        const ok = step.expectStatus ? res.status === step.expectStatus : res.ok
        scenarioLog.value[idx] = {
          ...scenarioLog.value[idx],
          ok,
          expectedFail: !!step.expectStatus && !res.ok,
          status: ok ? 'done' : 'error',
          note: step.note + (step.expectStatus ? ` (expected ${step.expectStatus}, got ${res.status})` : ''),
        }
      }
    } catch (e) {
      scenarioLog.value[idx] = {
        ...scenarioLog.value[idx],
        ok: false,
        status: 'error',
        note: step.note + ' (exception: ' + e.message + ')',
      }
    }
  }
  running.value = false
}

function resetState() {
  Object.assign(stateVars, {
    subject_user_id: 'demo-user-001',
    network: 'ETH',
    asset_key: 'ETH',
    address: '',
    to_address: '0xRecipientExternalAddress',
    amount: '0.5',
    sweep_id: '',
    wd_id: '',
    idempotency_key: crypto.randomUUID(),
  })
  scenarioLog.value = []
  results.value = []
}
</script>
