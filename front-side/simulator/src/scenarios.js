// Predefined end-to-end scenarios that chain API calls and capture state
// (e.g. deposit_address, sweep_id, withdrawal wd_id) for subsequent steps.
//
// Each step references an endpoint by `endpointId` (from endpoints.js), the
// `role` the simulator must authenticate as before calling, an optional
// `vars` override, an optional `extract` map (response field -> state var),
// and an optional `poll` descriptor (poll until status in `done`).

export const SCENARIOS = [
  {
    id: 'deposit_sweep',
    name: 'Deposit → Balance Check → Auto-Sweep',
    desc: 'Provision a user deposit EOA, then simulate the user "clicking Check Balance". The backend calls the indexer (stub returns funded balance), triggers gas top-up + automatic sweeper (EOA → hot wallet). We then poll the sweep job to completion.',
    steps: [
      { endpointId: 'login', role: 'ops', note: 'Operator authenticates (acts on behalf of the customer).', vars: {} },
      {
        endpointId: 'wallet_address',
        role: 'ops',
        note: 'Provision the user deposit EOA (always an EOA, never a contract).',
        vars: { network: 'ETH' },
        extract: { deposit_address: 'address', memo: 'memo' },
      },
      { endpointId: 'config', role: 'public', note: 'Load chain/asset registry (verifies TON memo requirement etc.).', vars: {} },
      { endpointId: 'address_resolve', role: 'ops', note: 'Operator verifies the deposit address belongs to OUR platform.', vars: {} },
      {
        endpointId: 'balance_check',
        role: 'ops',
        note: 'User clicks "Check Balance": backend indexes, funds > threshold → gas top-up + auto-sweep triggered.',
        vars: {},
        extract: { sweep_job_id: 'sweep_id' },
      },
      {
        endpointId: 'sweep_status',
        role: 'ops',
        note: 'Poll the SweepJob until CONFIRMED (idempotent; repeated balance checks must not double-sweep).',
        vars: {},
        poll: { field: 'status', done: ['CONFIRMED', 'FAILED', 'RECONCILIATION_REQUIRED'], key: 'sweep_id' },
      },
      { endpointId: 'stats', role: 'ops', note: 'Confirm custody aggregates reflect the new deposit + sweep.', vars: {} },
    ],
  },
  {
    id: 'withdrawal_approval',
    name: 'Withdrawal Request → Admin Approve → Broadcast',
    desc: 'Operator creates a withdrawal on behalf of the customer (PENDING_APPROVAL, no broadcast). Admin lists, approves, and the MPC signer broadcasts. We poll the withdrawal status.',
    steps: [
      { endpointId: 'login', role: 'ops', note: 'Operator authenticates.', vars: {} },
      {
        endpointId: 'wd_request',
        role: 'ops',
        note: 'Create withdrawal (PENDING_APPROVAL). NO on-chain tx yet.',
        vars: { network: 'ETH', to_address: '0xRECIPIENT_PLACEHOLDER', amount: '0.5' },
        extract: { id: 'wd_id' },
      },
      { endpointId: 'wd_list', role: 'ops', note: 'Operator lists (verifies PENDING_APPROVAL).', vars: {} },
      { endpointId: 'login', role: 'admin', note: 'Switch to ADMIN context (RBAC enforced server-side).', vars: {} },
      { endpointId: 'wd_admin_list', role: 'admin', note: 'Admin views pending withdrawals.', vars: {} },
      {
        endpointId: 'wd_approve',
        role: 'admin',
        note: 'Admin approves → MPC signs + broadcasts. Status APPROVED→BROADCASTED→CONFIRMED.',
        vars: {},
        poll: { field: 'status', done: ['CONFIRMED', 'FAILED', 'BROADCASTED', 'RECONCILIATION_REQUIRED'], key: 'wd_id' },
      },
      { endpointId: 'wd_detail', role: 'admin', note: 'Final withdrawal detail with tx_hash + status.', vars: {} },
    ],
  },
  {
    id: 'ton_memo',
    name: 'TON Deposit with Memo Attribution',
    desc: 'TON deposit addresses require a memo for user attribution. Verify the generated address carries a memo and the indexer path honors it.',
    steps: [
      { endpointId: 'login', role: 'ops', vars: {} },
      {
        endpointId: 'wallet_address',
        role: 'ops',
        note: 'TON deposit EOA + memo (u<subject>.<idx>).',
        vars: { network: 'TON' },
        extract: { deposit_address: 'address', memo: 'memo' },
      },
      {
        endpointId: 'balance_check',
        role: 'ops',
        note: 'Balance check INCLUDING memo mapping (TON attribution).',
        vars: {},
        extract: { sweep_job_id: 'sweep_id' },
      },
      {
        endpointId: 'sweep_status',
        role: 'ops',
        note: 'Poll sweep to completion.',
        vars: {},
        poll: { field: 'status', done: ['CONFIRMED', 'FAILED', 'RECONCILIATION_REQUIRED'], key: 'sweep_id' },
      },
    ],
  },
  {
    id: 'negative_rbac',
    name: 'Negative Test: RBAC Enforcement',
    desc: 'Verify that a non-admin role CANNOT approve withdrawals (server-side enforcement). Operator creates a withdrawal, then attempts to approve it and must receive 403.',
    steps: [
      { endpointId: 'login', role: 'ops', note: 'Operator authenticates.', vars: {} },
      {
        endpointId: 'wd_request',
        role: 'ops',
        note: 'Create a withdrawal as operator (PENDING_APPROVAL).',
        vars: { network: 'ETH', to_address: '0xRECIPIENT_PLACEHOLDER', amount: '0.1' },
        extract: { id: 'wd_id' },
      },
      {
        endpointId: 'wd_approve',
        role: 'ops',
        note: 'EXPECT 403: operator must NOT be able to approve (admin only).',
        expectStatus: 403,
        vars: {},
      },
    ],
  },
]

export function scenarioById(id) {
  return SCENARIOS.find((s) => s.id === id)
}
