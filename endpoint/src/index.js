// FREEDAY — Proof Gatekeeper agent endpoint (zkVerify Agent Games Season 01).
//
// Protocol (from the official event pages / builder docs):
//   - Platform POSTs task envelopes signed with HMAC-SHA256 over the RAW body,
//     header: x-agent-games-signature.
//   - Agent must verify the signature, decide, and respond within 60 s with
//     the decision + a Groth16 proof (see prover.js). Responses are signed
//     the same way (HMAC-SHA256 over the raw response body).
//   - GET /health is the dashboard health-check target.
//
// The HMAC secret is issued by the dashboard after agent registration and is
// provided via AGENT_GAMES_HMAC_SECRET. It is never logged.

import express from 'express';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { decide, conditionComplete, firstFailure } from './decide.js';
import { proveDecision } from './prover.js';

const PORT = process.env.PORT ?? 8080;

// Secret resolution: AGENT_GAMES_HMAC_SECRET env wins; otherwise read the
// `hmac_secret` field from the credentials file (path via
// AGENT_GAMES_CREDENTIALS_FILE, default the Agent Games credentials.json).
// The value is never logged.
function loadSecret() {
  if (process.env.AGENT_GAMES_HMAC_SECRET) return process.env.AGENT_GAMES_HMAC_SECRET;
  const file = process.env.AGENT_GAMES_CREDENTIALS_FILE
    ?? '/home/hatch/workspace/agentgames/credentials.json';
  try {
    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
    return typeof data.hmac_secret === 'string' ? data.hmac_secret : '';
  } catch {
    return '';
  }
}
const SECRET = loadSecret();
// Idempotent replay cache: a retried task_id gets the byte-identical
// signed response (task ids are unique per task; rounds are small).
const responseCache = new Map();
const ENDPOINT_ROOT = new URL('..', import.meta.url).pathname;
const CIRCUITS = {
  wasm: process.env.CIRCUIT_WASM ?? `${ENDPOINT_ROOT}circuits/gatekeeper.wasm`,
  zkey: process.env.CIRCUIT_ZKEY ?? `${ENDPOINT_ROOT}circuits/gatekeeper_final.zkey`,
};
const EXPECTED_VK_HASH = process.env.EXPECTED_VK_HASH; // unset -> decide.js uses the platform constant from /api/circuit-info

if (!SECRET) {
  console.warn('[freeday] AGENT_GAMES_HMAC_SECRET is empty — signature checks will fail closed.');
}

function hmacHex(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}

function signatureValid(secret, rawBody, headerValue) {
  if (!secret || !headerValue) return false;
  const expected = Buffer.from(hmacHex(secret, rawBody), 'utf8');
  const given = Buffer.from(String(headerValue).trim(), 'utf8');
  return expected.length === given.length && crypto.timingSafeEqual(expected, given);
}

const app = express();

// Raw body is required for HMAC verification — do not use express.json() here.
// The platform's signed preflight POSTs to the registered URL itself
// (bare origin returned 404 in the first dashboard save attempt), so the
// task handler is mounted at BOTH /task and / — the registered URL is the
// bare origin, and /task keeps working if the platform appends it.
const taskHandler = async (req, res) => {
  const raw = req.body;
  const sig = req.header('x-agent-games-signature');
  if (!signatureValid(SECRET, raw, sig)) {
    return res.status(401).json({ error: 'bad_signature' });
  }

  let envelope;
  try {
    envelope = JSON.parse(raw.toString('utf8'));
  } catch {
    return res.status(400).json({ error: 'bad_json' });
  }

  // Schema confirmed live 2026-11-15 (preflight + practice, see below).
  // { type: "agent-games.preflight.v1", agent_id, issued_at, nonce } and
  // the agent must return { ok: true, protocolVersion: "v1" }, signed.
  if (envelope.type === 'agent-games.preflight.v1') {
    const body = JSON.stringify({ ok: true, protocolVersion: 'v1' });
    res.setHeader('x-agent-games-signature', hmacHex(SECRET, body));
    return res.type('application/json').send(body);
  }

  // Real task schema (per /build): the condition fields nest under
  // envelope.input; task_id / mode / type live at envelope level. Merge
  // them into one task view for decide.js.
  const input = envelope.input ?? envelope.task ?? envelope.payload ?? envelope;
  const task = {
    ...input,
    task_id: envelope.task_id ?? input.task_id,
    mode: envelope.mode,
    type: envelope.type,
  };
  const taskKey = task.task_id != null ? String(task.task_id) : null;

  // Idempotent replay: a retried task_id gets the byte-identical response.
  if (taskKey && responseCache.has(taskKey)) {
    const cached = responseCache.get(taskKey);
    res.setHeader('x-agent-games-signature', hmacHex(SECRET, cached));
    return res.type('application/json').send(cached);
  }

  try {
    let { decision, reason_code, condition } = decide(task, { expectedVkHash: EXPECTED_VK_HASH });
    let proof = null;
    let publicSignals = null;
    // PROOF_REUSED is a platform-level trap the circuit cannot see: the
    // condition itself may be fully valid, so the circuit would enforce
    // APPROVE — the rejection is unprovable by design. Documented agent
    // behaviour is to return the decision without a proof; never flip it.
    const circuitInvisible = reason_code === 'PROOF_REUSED';
    if (!circuitInvisible && conditionComplete(condition)) {
      try {
        ({ proof, publicSignals } = await proveDecision({ condition, decision }, CIRCUITS));
      } catch (proveErr) {
        // The circuit enforces decision == (all checks pass). If our
        // decision cannot be proven (logic/encoding drift), flip once: the
        // opposite decision is the only other provable answer.
        const flipped = decision === 'APPROVE' ? 'REJECT' : 'APPROVE';
        console.warn(`[freeday] prove failed for ${decision} (${proveErr?.message ?? proveErr}); flipping to ${flipped}`);
        ({ proof, publicSignals } = await proveDecision({ condition, decision: flipped }, CIRCUITS));
        decision = flipped;
        reason_code = flipped === 'APPROVE'
          ? 'VALID_CONDITION'
          : (firstFailure(condition) ?? 'VK_SUBSTITUTION');
      }
    }
    // Fail closed: an APPROVE we could not prove becomes a decision-only
    // REJECT rather than an unproven approval or a bare 500.
    if (!proof && !circuitInvisible && decision === 'APPROVE') {
      decision = 'REJECT';
      reason_code = firstFailure(condition) ?? reason_code;
    }

    const responseBody = JSON.stringify({
      task_id: task.task_id ?? condition.taskId ?? null,
      decision,
      reason_code,
      ...(task.proof_tx ? { proof_tx: task.proof_tx } : {}),
      ...(proof ? { proof, public_signals: publicSignals } : {}),
    });
    if (taskKey) responseCache.set(taskKey, responseBody);
    res.setHeader('x-agent-games-signature', hmacHex(SECRET, responseBody));
    return res.type('application/json').send(responseBody);
  } catch (err) {
    console.error('[freeday] task handling failed:', err?.message ?? err);
    return res.status(500).json({ error: 'internal' });
  }
};

const rawBody = express.raw({ type: '*/*', limit: '1mb' });
app.post('/task', rawBody, taskHandler);
app.post('/', rawBody, taskHandler);

const healthHandler = (_req, res) => res.json({ ok: true, agent: 'FREEDAY', track: 'proof-gatekeeper' });
app.get('/health', healthHandler);
app.get('/', healthHandler);

app.listen(PORT, () => console.log(`[freeday] gatekeeper endpoint listening on :${PORT}`));
