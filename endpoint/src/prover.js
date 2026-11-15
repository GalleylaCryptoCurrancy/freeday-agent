// Groth16 proving with snarkjs against the official Agent Games circuits.
//
// Circuit artifacts (in ./circuits, downloaded from the platform):
//   https://agentgames.zkverify.io/circuits/gatekeeper.wasm        (1,755,820 B)
//   https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey  (  309,750 B)
//
// Circuit input schema — VERIFIED 2026-11-15 by probing the wasm
// (getInputSize = 13; every name below has size 1) and by generating +
// verifying proofs locally (valid/approve ~0.5–1.0 s on this VM, well
// inside the 60 s envelope; wrong decisions fail witness generation):
//   registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
//   currentBlock, recipient, conditionRecipient, amount, maxTransfer,
//   decision, taskId, salt
// Public signals (13, in order): [output, registeredVkHash, proofVkHash,
//   minimum, publicBalance, expiryBlock, currentBlock, recipient,
//   conditionRecipient, amount, maxTransfer, decision, taskId]
// — salt is the one private input; the leading public signal is a circuit
// output. vkHash values are passed as the full 0x… hash; snarkjs reduces
// mod r (verified: the exported VK verifies such proofs).
//
// salt: random 128-bit per proof (anti-replay nonce for our proofs).
// Live-validated 2026-11-15: dashboard practice accepted and verified
// proofs built with this schema (incl. string task_ids via toField).

import * as snarkjs from 'snarkjs';
import crypto from 'node:crypto';

const FIELD_R =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// task_id arrives as a string ("practice_<uuid>" / "gk_..."). Numeric/hex
// ids are used directly; other strings get a deterministic field element
// (sha256 mod r) so proving can always proceed. Live-validated 2026-11-15:
// the platform verified practice proofs carrying these derived taskIds.
function toField(v) {
  try {
    return (BigInt(String(v).trim()) % FIELD_R).toString();
  } catch { /* not numeric — derive below */ }
  const h = crypto.createHash('sha256').update(String(v)).digest('hex');
  return (BigInt(`0x${h}`) % FIELD_R).toString();
}

/**
 * Build circuit inputs from the extracted condition + our decision and
 * generate the Groth16 proof.
 * @returns {Promise<{proof: object, publicSignals: string[]}>}
 */
export async function proveDecision({ condition, decision }, paths) {
  const salt = BigInt(`0x${crypto.randomBytes(16).toString('hex')}`);
  const inputs = {
    registeredVkHash: condition.registeredVkHash,
    proofVkHash: condition.proofVkHash,
    minimum: condition.minimum,
    publicBalance: condition.publicBalance,
    expiryBlock: condition.expiryBlock,
    currentBlock: condition.currentBlock,
    recipient: condition.recipient,
    conditionRecipient: condition.conditionRecipient,
    amount: condition.amount,
    maxTransfer: condition.maxTransfer,
    decision: decision === 'APPROVE' ? 1 : 0,
    taskId: toField(condition.taskId),
    salt: salt.toString(),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    inputs,
    paths.wasm,
    paths.zkey,
  );
  return { proof, publicSignals };
}
