import axios from 'axios'
import { session } from './store.js'
import { buildWithdrawalRequestBody } from './withdrawalIntent.js'

// Real JWT auth: send the bearer token on every request.
const api = axios.create({ baseURL: '/api' })

api.interceptors.request.use((config) => {
  if (session.token) {
    config.headers['Authorization'] = `Bearer ${session.token}`
  }
  return config
})

export const Auth = {
  login: (username, password) => api.post('/auth/login', { username, password }),
}

export const NETWORKS = [
  { value: 'ETH', label: 'Ethereum', sub: 'Sepolia', color: 'brand', eoa: '0x…' },
  { value: 'BSC', label: 'BNB Chain', sub: 'Testnet', color: 'accent', eoa: '0x…' },
  { value: 'TRX', label: 'Tron', sub: 'Nile', color: 'brand', eoa: 'T…' },
  { value: 'SOL', label: 'Solana', sub: 'Devnet', color: 'accent', eoa: '…' },
  { value: 'TON', label: 'Ton', sub: 'Testnet', color: 'brand', eoa: 'EQ…', memo: true },
]

// The operator console acts ON BEHALF OF a subject (customer) user.
// Every custody call therefore carries subject_user_id (the customer id).
export const Wallet = {
  getAddress: (subjectUserId, network, addressIndex = 0, assetKey = null) =>
    api.post('/wallet/address',
      { subject_user_id: subjectUserId, network, address_index: addressIndex, asset_key: assetKey }),
  // Provision a subject customer's deposit wallet across networks/assets (idempotent).
  // payload: { subject_user_id, networks?: string[], asset_keys?: string[] }
  create: (subjectUserId, payload = {}) =>
    api.post('/wallet/create', { subject_user_id: subjectUserId, ...payload }),
  checkBalance: (subjectUserId, network, assetKey = null) =>
    api.post('/wallet/balance/check',
      { subject_user_id: subjectUserId, network, asset_key: assetKey }),
  sweepStatus: (id) => api.get(`/sweeps/${id}`),
}

// Global custody aggregates for the operator home/overview dashboard.
export const Chains = {
  status: (chain) => api.get('/chains/status', { params: chain ? { chain } : {} }),
}

export const Stats = {
  overview: () => api.get('/stats'),
}

export const Withdrawals = {
  // Operator creates a withdrawal ON BEHALF OF a subject customer.
  request: (subjectUserId, network, toAddress, amount, assetKey, idempotencyKey) =>
    api.post('/withdrawals/request',
      buildWithdrawalRequestBody(
        subjectUserId, network, toAddress, amount, assetKey, idempotencyKey,
      )),
  // List withdrawals (optionally scoped to a subject customer).
  list: (subject = null) =>
    api.get('/withdrawals', { params: subject ? { subject } : {} }),
  detail: (id) => api.get(`/withdrawals/${id}`),
  adminList: () => api.get('/admin/withdrawals'),
  approve: (id, notes) => api.post(`/withdrawals/${id}/approve`, { admin_notes: notes }),
  deny: (id, notes) => api.post(`/withdrawals/${id}/deny`, { admin_notes: notes }),
}

export const Ops = {
  summary: () => api.get('/ops/summary'),
  chains: () => api.get('/ops/chains'),
  assets: () => api.get('/ops/assets'),
  nodesHealth: () => api.get('/ops/nodes/health'),
  nodes: (params = {}) => api.get('/ops/nodes', { params }),
  probeNode: (nodeId) => api.post(`/ops/nodes/${nodeId}/probe`),
  balances: (params = {}) => api.get('/ops/balances', { params }),
  transactions: (params = {}) => api.get('/ops/transactions', { params }),
  alerts: (params = {}) => api.get('/ops/alerts', { params }),
  activity: () => api.get('/ops/activity'),
  ackAlert: (alertId, note) => api.post(`/ops/alerts/${alertId}/ack`, { note }),
  addAsset: (payload) => api.post('/ops/assets', payload),
  addNode: (payload) => api.post('/ops/nodes', payload),
  updateNode: (nodeId, payload) => api.patch(`/ops/nodes/${nodeId}`, payload),
}

// Chain + asset (token) administration + compliance blocklist.
export const ChainTokens = {
  // Create a new chain (admin). payload: { chain_id, kind, display_name, ... }
  create: (payload) => api.post('/ops/chains', payload),
  // Update an existing chain (enable/disable, thresholds, explorer urls...).
  update: (chainId, payload) => api.patch(`/ops/chains/${chainId}`, payload),
  // Add a token asset to a chain.
  addAsset: (payload) => api.post('/ops/assets', payload),
}

export const Blocklist = {
  // List current blocklist entries (admin).
  list: () => api.get('/ops/blocklist'),
  // Add an entry. payload: { scope, value?, chain_id?, asset_key?, reason, note? }
  add: (payload) => api.post('/ops/blocklist', payload),
  // Toggle enabled state. payload: { enabled }
  update: (id, payload) => api.patch(`/ops/blocklist/${id}`, payload),
}

// Public metadata registry; capability flags determine operational support.
export const Config = {
  load: () => api.get('/config'),
}

// Custody gas-station addresses + balances per chain (operator/admin view).
export const GasStation = {
  list: () => api.get('/gas-station'),
  // Operator/admin manual top-up of a gas-station address.
  // payload: { chain_id, to_address, amount, memo? }
  topup: (payload) => api.post('/gas-station/topup', payload),
}

// Address ownership lookup: does this address belong to our platform?
// Returns whether it's one of our user deposit EOAs or custody hot/gas EOAs.
export const AddressLookup = {
  resolve: (address, chainId = null) =>
    api.post('/admin/address/resolve', { address, chain_id: chainId }),
}

export default api
