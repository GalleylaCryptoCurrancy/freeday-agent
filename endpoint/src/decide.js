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
// A wrong APPROVE costs twice a wrong REJECT, so every check fails closed.
//
// CIRCUIT TRUTH (verified 2026-11-15 by probing the official
// gatekeeper.wasm + exporting the VK from gatekeeper_final.zkey):
// the circuit has exactly 13 scalar inputs — registeredVkHash, proofVkHash,
// minimum, publicBalance, expiryBlock, currentBlock, recipient,
// conditionRecipient, amount, maxTransfer, decision, taskId, salt — and it
// ENFORCES decision == 1 iff all of these hold:
//   proofVkHash == registeredVkHash · publicBalance >= minimum ·
//   amount <= maxTransfer · currentBlock <= expiryBlock ·
//   recipient == conditionRecipient
// A wrong decision cannot even produce a witness (assert fails in
// GatekeeperEvaluation), so mirroring these checks exactly is what makes
// every response provable.
//
// Reason-code mapping — ASSUMPTION A, VALIDATED LIVE 2026-11-15 in
// dashboard practice (10/10 correct, proofs verified): VK_SUBSTITUTION,
// AMOUNT_OVERFLOW (amount > maxTransfer), EXPIRED_CONDITION,
// RECIPIENT_MISMATCH, PROOF_REUSED and VALID_CONDITION all confirmed
// against the platform's expected decisions. THRESHOLD_MISMATCH follows
// the same circuit check (publicBalance < minimum) and is locally proven.
//   proofVkHash mismatch            -> VK_SUBSTITUTION
//   request proof seen before       -> PROOF_REUSED      (platform-side too)
//   amount not a valid field int    -> AMOUNT_OVERFLOW   (representation)
//   amount > maxTransfer            -> AMOUNT_OVERFLOW   (over the cap)
//   publicBalance < minimum         -> THRESHOLD_MISMATCH (below threshold)
//   currentBlock > expiryBlock      -> EXPIRED_CONDITION
//   recipient != conditionRecipient -> RECIPIENT_MISMATCH
//   all pass                        -> VALID_CONDITION / APPROVE
//
// SCHEMA (confirmed live 2026-11-15): the task condition nests under
// envelope.input with snake_case names (registered_vk, proof_vk,
// public_balance, expiry_block, current_block, condition_recipient,
// max_transfer, proof_tx, ...); index.js merges envelope-level task_id
// into the task view. Extraction goes through pick() with aliases so the
// mapping lives in one place.

// BN254 (bn128) scalar field prime.
export const FIELD_R =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// The platform's registered Gatekeeper VK hash (GET /api/circuit-info).
export const PLATFORM_VK_HASH =
  '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';

// In-memory cache of request-proof identifiers seen this process lifetime.
// PROOF_REUSED traps resubmit an earlier request proof; a production
// deployment should persist this (file/DB) across restarts.
const seenProofs = new Set();

function pick(obj, ...names) {
  for (const n of names) {
    if (obj != null && obj[n] !== undefined && obj[n] !== null) return obj[n];
  }
  return undefined;
}

// Parse a value as BigInt (decimal or 0x-hex string, number, bigint).
// Returns null when unparseable.
function toBig(v) {
  if (v === undefined || v === null) return null;
  try {
    if (typeof v === 'bigint') return v;
    if (typeof v === 'number') return Number.isInteger(v) ? BigInt(v) : null;
    const s = String(v).trim();
    if (s === '') return null;
    return BigInt(s);
  } catch {
    return null;
  }
}

const mod = (a) => ((a % FIELD_R) + FIELD_R) % FIELD_R;

// Field-element equality (values may arrive as full 256-bit hashes, hex or
// decimal strings, or already reduced mod r).
function fieldEq(a, b) {
  const x = toBig(a);
  const y = toBig(b);
  if (x === null || y === null) {
    return a !== undefined && b !== undefined &&
      String(a).toLowerCase() === String(b).toLowerCase();
  }
  return mod(x) === mod(y);
}

/**
 * Extract the circuit condition from a task envelope.
 * registeredVkHash falls back to the platform constant (public info).
 */
export function extractCondition(task, ctx = {}) {
  return {
    registeredVkHash: pick(task, 'registeredVkHash', 'registered_vk_hash', 'registered_vk', 'expectedVkHash')
      ?? ctx.expectedVkHash ?? PLATFORM_VK_HASH,
    proofVkHash: pick(task, 'proofVkHash', 'proof_vk_hash', 'proof_vk', 'vkHash', 'vk_hash', 'verification_key_hash'),
    minimum: pick(task, 'minimum', 'minBalance', 'min_balance', 'min_balance_required'),
    publicBalance: pick(task, 'publicBalance', 'public_balance', 'balance'),
    expiryBlock: pick(task, 'expiryBlock', 'expiry_block', 'expiresAtBlock', 'valid_until_block'),
    currentBlock: pick(task, 'currentBlock', 'current_block', 'blockNumber', 'block_number'),
    recipient: pick(task, 'recipient', 'to', 'payee'),
    conditionRecipient: pick(task, 'conditionRecipient', 'condition_recipient', 'expectedRecipient', 'expected_recipient', 'intended_recipient'),
    amount: pick(task, 'amount', 'value'),
    maxTransfer: pick(task, 'maxTransfer', 'max_transfer', 'maxAmount', 'max_amount', 'cap'),
    taskId: pick(task, 'taskId', 'task_id', 'id'),
  };
}

// True when every circuit input is present and usable. taskId may arrive
// as a string id ("gk_...") — prover.js derives a field element for those,
// so a non-empty string counts as complete.
export function conditionComplete(c) {
  const fieldsOk = ['proofVkHash', 'minimum', 'publicBalance', 'expiryBlock', 'currentBlock',
    'recipient', 'conditionRecipient', 'amount', 'maxTransfer']
    .every((k) => toBig(c[k]) !== null);
  const taskOk = toBig(c.taskId) !== null
    || (typeof c.taskId === 'string' && c.taskId.length > 0)
    || typeof c.taskId === 'number';
  return fieldsOk && taskOk;
}

/**
 * Mirror of the circuit's own checks. Returns the first failing reason
 * (Assumption A precedence) or null when the condition is valid.
 */
export function firstFailure(c) {
  if (!fieldEq(c.proofVkHash, c.registeredVkHash)) return 'VK_SUBSTITUTION';
  const amount = toBig(c.amount);
  if (amount === null || amount < 0n || amount >= FIELD_R) return 'AMOUNT_OVERFLOW';
  const maxTransfer = toBig(c.maxTransfer);
  if (maxTransfer !== null && amount > maxTransfer) return 'AMOUNT_OVERFLOW';
  const balance = toBig(c.publicBalance);
  const minimum = toBig(c.minimum);
  if (balance === null || minimum === null || balance < minimum) return 'THRESHOLD_MISMATCH';
  const current = toBig(c.currentBlock);
  const expiry = toBig(c.expiryBlock);
  if (current === null || expiry === null || current > expiry) return 'EXPIRED_CONDITION';
  if (!fieldEq(c.recipient, c.conditionRecipient)) return 'RECIPIENT_MISMATCH';
  return null;
}

/**
 * @param {object} task  Parsed task envelope payload (payment request).
 * @param {object} ctx   { expectedVkHash }
 * @returns {{ decision: 'APPROVE'|'REJECT', reason_code: string,
 *             condition: object, checks: object }}
 */
export function decide(task, ctx = {}) {
  const condition = extractCondition(task, ctx);
  const checks = { complete: conditionComplete(condition) };

  // PROOF_REUSED — the requester's proof may only ever be used once.
  // Record every first sight (whatever the decision): a proof_tx that
  // backed any earlier task — approved or not — is spent.
  const proofId = pick(task, 'proof_tx', 'proof_id', 'proofId', 'proof_hash', 'proofHash', 'request_proof_hash');
  checks.proof_fresh = proofId === undefined ? null : !seenProofs.has(String(proofId));
  if (checks.proof_fresh === false) {
    return { decision: 'REJECT', reason_code: 'PROOF_REUSED', condition, checks };
  }
  if (proofId !== undefined) seenProofs.add(String(proofId));

  const failure = firstFailure(condition);
  checks.first_failure = failure;
  if (failure !== null) {
    return { decision: 'REJECT', reason_code: failure, condition, checks };
  }

  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION', condition, checks };
}
