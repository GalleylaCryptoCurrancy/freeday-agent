// Groth16 proving with snarkjs against the official Agent Games circuits.
//
// Circuit artifacts (download once, keep in ./circuits):
//   https://agentgames.zkverify.io/circuits/gatekeeper.wasm
//   https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey
//
// TODO(schema): the circuit's exact input signal names are confirmed from
// the dashboard builder docs / practice task after registration. The mapping
// below is the assumed shape (decision bit + reason code + task binding)
// and must be reconciled with gatekeeper's ABI before the first scored round.

import * as snarkjs from 'snarkjs';

const REASON_CODES = {
  VALID_CONDITION: 0,
  VK_SUBSTITUTION: 1,
  PROOF_REUSED: 2,
  THRESHOLD_MISMATCH: 3,
  EXPIRED_CONDITION: 4,
  RECIPIENT_MISMATCH: 5,
  AMOUNT_OVERFLOW: 6,
};

/**
 * Build circuit inputs from the task + our decision.
 * @returns {Promise<{proof: object, publicSignals: string[]}>}
 */
export async function proveDecision({ task, decision, reason_code }, paths) {
  const inputs = {
    // TODO(schema): replace with the circuit's real signal names/types.
    decision: decision === 'APPROVE' ? 1 : 0,
    reasonCode: REASON_CODES[reason_code] ?? 0,
    taskId: task?.task_id ?? task?.id ?? 0,
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    inputs,
    paths.wasm,
    paths.zkey,
  );
  return { proof, publicSignals };
}
