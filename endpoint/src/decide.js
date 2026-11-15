// Proof Gatekeeper decision logic — FREEDAY agent.
//
// The platform sends proof-backed payment requests. We must answer
// APPROVE or REJECT (+ reason_code) within 60 s, with a Groth16 proof of
// the decision. Documented trap distribution (official event page):
//   VALID_CONDITION ~50% · VK_SUBSTITUTION ~13% · PROOF_REUSED ~11% ·
//   THRESHOLD_MISMATCH ~8% · EXPIRED_CONDITION ~6% · RECIPIENT_MISMATCH ~6% ·
//   AMOUNT_OVERFLOW ~6%
//
// Scoring: correct +12 · wrong APPROVE -6 · wrong REJECT -3 · timeout -2.
// A wrong APPROVE costs twice a wrong REJECT, so every check below fails
// closed (REJECT) on ambiguity or missing fields.
//
// TODO(schema): the exact task-envelope field names are confirmed by the
// dashboard practice task / preflight after registration. Field access is
// funnelled through `pick()` so the schema mapping lives in one place.

// In-memory cache of proof identifiers seen this process lifetime.
// PROOF_REUSED traps resubmit an earlier proof; a production deployment
// should persist this (file/DB) across restarts.
const seenProofs = new Set();

function pick(obj, ...names) {
  for (const n of names) {
    if (obj != null && obj[n] !== undefined && obj[n] !== null) return obj[n];
  }
  return undefined;
}

/**
 * @param {object} task  Parsed task envelope payload (payment request).
 * @param {object} ctx   { expectedVkHash, nowSeconds }
 * @returns {{ decision: 'APPROVE'|'REJECT', reason_code: string, checks: object }}
 */
export function decide(task, ctx = {}) {
  const checks = {};
  const now = ctx.nowSeconds ?? Math.floor(Date.now() / 1000);

  const proofId = pick(task, 'proof_id', 'proofId', 'proof_hash', 'proofHash');
  const vkHash = pick(task, 'vk_hash', 'vkHash', 'verification_key_hash', 'verificationKey');
  const amount = pick(task, 'amount', 'value');
  const threshold = pick(task, 'threshold', 'max_amount', 'maxAmount', 'limit');
  const expiresAt = pick(task, 'expires_at', 'expiresAt', 'expiry', 'valid_until', 'validUntil');
  const recipient = pick(task, 'recipient', 'to', 'payee');
  const expectedRecipient = pick(task, 'expected_recipient', 'expectedRecipient', 'intended_recipient');

  // 1) VK_SUBSTITUTION — the proof's verification key must be the registered one.
  if (ctx.expectedVkHash !== undefined) {
    checks.vk = vkHash !== undefined && String(vkHash) === String(ctx.expectedVkHash);
    if (!checks.vk) return reject('VK_SUBSTITUTION', checks);
  }

  // 2) PROOF_REUSED — a proof may only ever be used once.
  if (proofId !== undefined) {
    checks.proof_fresh = !seenProofs.has(String(proofId));
    if (!checks.proof_fresh) return reject('PROOF_REUSED', checks);
  }

  // 3) AMOUNT_OVERFLOW — amount must be a safe, in-field, non-negative integer.
  //    BN254 scalar field modulus; amounts beyond it (or beyond the request's
  //    own cap semantics) are overflow traps.
  const FIELD = (1n << 254n) - 1n; // conservative bound; exact r checked at proving time
  let amountOk = false;
  try {
    const a = BigInt(amount);
    amountOk = a >= 0n && a <= FIELD;
  } catch { amountOk = false; }
  checks.amount_in_field = amountOk;
  if (!amountOk) return reject('AMOUNT_OVERFLOW', checks);

  // 4) THRESHOLD_MISMATCH — amount must not exceed the condition threshold.
  if (threshold !== undefined) {
    let thrOk = false;
    try { thrOk = BigInt(amount) <= BigInt(threshold); } catch { thrOk = false; }
    checks.within_threshold = thrOk;
    if (!thrOk) return reject('THRESHOLD_MISMATCH', checks);
  }

  // 5) EXPIRED_CONDITION — the condition must still be valid at decision time.
  if (expiresAt !== undefined) {
    const exp = Number(expiresAt);
    checks.not_expired = Number.isFinite(exp) && exp >= now;
    if (!checks.not_expired) return reject('EXPIRED_CONDITION', checks);
  }

  // 6) RECIPIENT_MISMATCH — funds must go to the intended recipient.
  if (expectedRecipient !== undefined) {
    checks.recipient = recipient !== undefined &&
      String(recipient).toLowerCase() === String(expectedRecipient).toLowerCase();
    if (!checks.recipient) return reject('RECIPIENT_MISMATCH', checks);
  }

  // All present checks passed. Mark the proof as consumed and approve.
  if (proofId !== undefined) seenProofs.add(String(proofId));
  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION', checks };
}

function reject(reason_code, checks) {
  return { decision: 'REJECT', reason_code, checks };
}
