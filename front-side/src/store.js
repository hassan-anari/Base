import { reactive } from 'vue'
import { Config } from './api.js'

// Reactive session store holding the backend-issued JWT.
// The token is sent as `Authorization: Bearer <token>` on every request.
const TOKEN_KEY = 'mpc_jwt'

export const session = reactive({
  token: localStorage.getItem(TOKEN_KEY) || '',
  userId: '',
  role: '', // 'user' | 'admin' | 'operator' | 'auditor' | 'read_only'
  authed: !!localStorage.getItem(TOKEN_KEY),
})

// Chain + asset registry pulled from GET /api/config (config-driven backend).
// Lets the UI offer any asset the backend supports (native + tokens like USDT)
// without hardcoding them in the frontend.
export const registry = reactive({
  loaded: false,
  chains: [],          // [{ chain_id, kind, display_name, memo_required, ... }]
  assets: [],          // [{ asset_key, chain_id, symbol, decimals, ... }]
  assetsByChain: {},   // chain_id -> [AssetConfigDTO]
})

export async function loadRegistry() {
  if (registry.loaded) return
  try {
    const { data } = await Config.load()
    registry.chains = data.chains || []
    registry.assets = data.assets || []
    registry.assetsByChain = data.assets_by_chain || {}
    registry.loaded = true
  } catch (e) {
    // Non-fatal: UI falls back to NETWORKS constant.
    registry.loaded = true
  }
}

export function assetsForChain(chainId) {
  return registry.assetsByChain[chainId] || []
}

export function setSession(token, userId, role) {
  session.token = token
  session.userId = userId
  session.role = role
  session.authed = true
  localStorage.setItem(TOKEN_KEY, token)
}

export function clearSession() {
  session.token = ''
  session.userId = ''
  session.role = ''
  session.authed = false
  localStorage.removeItem(TOKEN_KEY)
}
