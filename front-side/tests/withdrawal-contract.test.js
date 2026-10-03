import test from 'node:test'
import assert from 'node:assert/strict'
import { buildWithdrawalRequestBody, createWithdrawalIntentTracker } from '../src/withdrawalIntent.js'

test('withdrawal retries retain one key until the logical payload changes', () => {
  const tracker = createWithdrawalIntentTracker()
  const first = tracker.keyFor('customer|ETH|0x1|1|ETH')
  assert.equal(tracker.keyFor('customer|ETH|0x1|1|ETH'), first)
  assert.notEqual(tracker.keyFor('customer|ETH|0x2|1|ETH'), first)
  assert.match(first, /^[0-9a-f-]{36}$/)
})

test('frontend body includes the backend idempotency contract', () => {
  const body = buildWithdrawalRequestBody('customer', 'ETH', '0x1', 1, 'ETH', 'key-12345')
  assert.equal(body.idempotency_key, 'key-12345')
  assert.equal(body.subject_user_id, 'customer')
})
