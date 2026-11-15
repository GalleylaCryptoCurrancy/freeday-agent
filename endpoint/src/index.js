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
import { decide } from './decide.js';
import { proveDecision } from './prover.js';

const PORT = process.env.PORT ?? 8080;
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET ?? '';
const CIRCUITS = {
  wasm: process.env.CIRCUIT_WASM ?? './circuits/gatekeeper.wasm',
  zkey: process.env.CIRCUIT_ZKEY ?? './circuits/gatekeeper_final.zkey',
};
const EXPECTED_VK_HASH = process.env.EXPECTED_VK_HASH; // TODO: set from platform VK after preflight

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
app.post('/task', express.raw({ type: '*/*', limit: '1mb' }), async (req, res) => {
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

  // TODO(schema): confirm envelope shape (task nested under .task / .payload?)
  // from the signed preflight + practice task after registration.
  const task = envelope.task ?? envelope.payload ?? envelope;

  try {
    const { decision, reason_code } = decide(task, { expectedVkHash: EXPECTED_VK_HASH });
    const { proof, publicSignals } = await proveDecision(
      { task, decision, reason_code },
      CIRCUITS,
    );

    const responseBody = JSON.stringify({
      task_id: task.task_id ?? task.id ?? null,
      decision,
      reason_code,
      proof,
      public_signals: publicSignals,
    });
    res.setHeader('x-agent-games-signature', hmacHex(SECRET, responseBody));
    return res.type('application/json').send(responseBody);
  } catch (err) {
    console.error('[freeday] task handling failed:', err?.message ?? err);
    return res.status(500).json({ error: 'internal' });
  }
});

app.get('/health', (_req, res) => res.json({ ok: true, agent: 'FREEDAY', track: 'proof-gatekeeper' }));

app.listen(PORT, () => console.log(`[freeday] gatekeeper endpoint listening on :${PORT}`));
