export function newIdempotencyKey() {
  return crypto.randomUUID()
}

export function buildWithdrawalRequestBody(
  subjectUserId, network, toAddress, amount, assetKey, idempotencyKey,
) {
  return {
    subject_user_id: subjectUserId,
    network,
    to_address: toAddress,
    amount,
    asset_key: assetKey,
    idempotency_key: idempotencyKey,
  }
}

export function createWithdrawalIntentTracker() {
  let fingerprint = null
  let key = null
  return {
    keyFor(payloadFingerprint) {
      if (!key || fingerprint !== payloadFingerprint) {
        fingerprint = payloadFingerprint
        key = newIdempotencyKey()
      }
      return key
    },
    reset() {
      fingerprint = null
      key = null
    },
  }
}
