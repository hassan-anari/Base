// Complete API catalog for the MPC Custodial Exchange backend.
// Every route is documented here and can be invoked individually by the
// simulator, or chained as a scenario. `role` indicates the minimum
// RBAC role the backend requires (admin > operator > auditor > read_only).
//
// body/params values support {{var}} interpolation from scenario state.
// Available scenario vars: subject_user_id, network, asset_key, address,
// memo, sweep_id, wd_id, alert_id, node_id, block_id,
// chain_id, to_address, amount, address_index, idempotency_key.

export const NETWORKS = ['ETH', 'BSC', 'TRX', 'SOL', 'TON']

export const ENDPOINTS = [
  // ---------------- Auth ----------------
  {
    id: 'login',
    group: 'Auth',
    method: 'POST',
    path: '/api/auth/login',
    role: 'public',
    desc: 'Exchange username/password for a signed JWT.',
    body: { username: 'ops', password: 'ops' },
  },
  {
    id: 'config',
    group: 'Auth',
    method: 'GET',
    path: '/api/config',
    role: 'public',
    desc: 'Public chain + asset registry (no secrets).',
  },

  // ---------------- Custody: Wallets ----------------
  {
    id: 'wallet_address',
    group: 'Custody',
    method: 'POST',
    path: '/api/wallet/address',
    role: 'operator',
    desc: 'Provision/return a user deposit EOA (idempotent) for (subject, network, asset).',
    body: { subject_user_id: '{{subject_user_id}}', network: 'ETH', address_index: 0 },
  },
  {
    id: 'wallet_create',
    group: 'Custody',
    method: 'POST',
    path: '/api/wallet/create',
    role: 'operator',
    desc: 'Provision deposit EOAs for a subject across networks/assets (idempotent).',
    body: { subject_user_id: '{{subject_user_id}}', networks: ['ETH', 'BSC', 'TRX', 'SOL', 'TON'] },
  },
  {
    id: 'balance_check',
    group: 'Custody',
    method: 'POST',
    path: '/api/wallet/balance/check',
    role: 'operator',
    desc: 'User-triggered balance check -> indexer -> gas topup + auto-sweep when above threshold.',
    body: { subject_user_id: '{{subject_user_id}}', network: '{{network}}', asset_key: '{{asset_key}}' },
  },
  {
    id: 'sweep_status',
    group: 'Custody',
    method: 'GET',
    path: '/api/sweeps/{sweep_id}',
    role: 'any',
    desc: 'Poll sweep status, including manual RECONCILIATION_REQUIRED outcomes.',
  },
  {
    id: 'address_resolve',
    group: 'Custody',
    method: 'POST',
    path: '/api/admin/address/resolve',
    role: 'operator',
    desc: 'Resolve whether an address belongs to OUR platform (user EOA / hot wallet).',
    body: { address: '{{address}}', chain_id: '{{network}}' },
  },
  {
    id: 'gas_station',
    group: 'Custody',
    method: 'GET',
    path: '/api/gas-station',
    role: 'operator',
    desc: 'Custody gas-station + hot-wallet addresses and balances per chain.',
  },
  {
    id: 'stats',
    group: 'Custody',
    method: 'GET',
    path: '/api/stats',
    role: 'any',
    desc: 'Global custody aggregates (counts only, no per-customer PII).',
  },

  // ---------------- Withdrawals ----------------
  {
    id: 'wd_request',
    group: 'Withdrawals',
    method: 'POST',
    path: '/api/withdrawals/request',
    role: 'operator',
    desc: 'Operator creates a withdrawal ON BEHALF OF a subject -> PENDING_APPROVAL. No broadcast yet.',
    body: {
      subject_user_id: '{{subject_user_id}}',
      network: '{{network}}',
      to_address: '{{to_address}}',
      amount: '{{amount}}',
      asset_key: '{{asset_key}}',
      idempotency_key: '{{idempotency_key}}',
    },
  },
  {
    id: 'wd_list',
    group: 'Withdrawals',
    method: 'GET',
    path: '/api/withdrawals',
    role: 'any',
    desc: 'List withdrawals (optionally scoped to subject).',
    params: { subject: '{{subject_user_id}}' },
  },
  {
    id: 'wd_detail',
    group: 'Withdrawals',
    method: 'GET',
    path: '/api/withdrawals/{wd_id}',
    role: 'any',
    desc: 'Withdrawal detail / status polling.',
  },
  {
    id: 'wd_approve',
    group: 'Withdrawals',
    method: 'POST',
    path: '/api/withdrawals/{wd_id}/approve',
    role: 'admin',
    desc: 'ADMIN approval -> signs via MPC + broadcasts. Enforced server-side.',
    body: { admin_notes: 'approved by simulator' },
  },
  {
    id: 'wd_deny',
    group: 'Withdrawals',
    method: 'POST',
    path: '/api/withdrawals/{wd_id}/deny',
    role: 'admin',
    desc: 'ADMIN denies a pending withdrawal.',
    body: { admin_notes: 'denied by simulator' },
  },
  {
    id: 'wd_admin_list',
    group: 'Withdrawals',
    method: 'GET',
    path: '/api/admin/withdrawals',
    role: 'admin',
    desc: 'Admin list of all withdrawal requests.',
  },

  // ---------------- Ops / Chain & Token admin ----------------
  { id: 'ops_summary', group: 'Ops', method: 'GET', path: '/api/ops/summary', role: 'operator', desc: 'Ops dashboard summary aggregates.' },
  { id: 'ops_chains', group: 'Ops', method: 'GET', path: '/api/ops/chains', role: 'operator', desc: 'List chains.' },
  { id: 'ops_assets', group: 'Ops', method: 'GET', path: '/api/ops/assets', role: 'operator', desc: 'List token assets.' },
  { id: 'ops_nodes_health', group: 'Ops', method: 'GET', path: '/api/ops/nodes/health', role: 'operator', desc: 'Node/ RPC health per chain.' },
  { id: 'ops_balances', group: 'Ops', method: 'GET', path: '/api/ops/balances', role: 'operator', desc: 'Custody address balances.', params: { chain_id: '{{network}}' } },
  { id: 'ops_transactions', group: 'Ops', method: 'GET', path: '/api/ops/transactions', role: 'operator', desc: 'Custody transactions.', params: { chain_id: '{{network}}' } },
  { id: 'ops_alerts', group: 'Ops', method: 'GET', path: '/api/ops/alerts', role: 'operator', desc: 'Compliance/ops alerts.', params: {} },
  { id: 'ops_activity', group: 'Ops', method: 'GET', path: '/api/ops/activity', role: 'operator', desc: 'Recent operator activity.' },
  { id: 'ops_blocklist', group: 'Ops', method: 'GET', path: '/api/ops/blocklist', role: 'operator', desc: 'Compliance blocklist entries.' },

  // ---------------- Health ----------------
  { id: 'health_live', group: 'Health', method: 'GET', path: '/api/health/live', role: 'public', desc: 'Liveness probe.' },
  { id: 'health_ready', group: 'Health', method: 'GET', path: '/api/health/ready', role: 'public', desc: 'Readiness probe.' },
  { id: 'health_system', group: 'Health', method: 'GET', path: '/api/ops/system/health', role: 'operator', desc: 'System health overview.' },
  { id: 'health_history', group: 'Health', method: 'GET', path: '/api/ops/system/health/history', role: 'operator', desc: 'Component health history.' },
]

export const ENDPOINT_MAP = Object.fromEntries(ENDPOINTS.map((e) => [e.id, e]))
export const GROUPS = ['Auth', 'Custody', 'Withdrawals', 'Ops', 'Health']
