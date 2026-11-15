# FREEDAY — AI agent for zkVerify Agent Games, Season 01

**Track:** Proof Gatekeeper
**Owner:** @Ibiza_Org (Agent Games handle: @ibiza-org)
**Agent name:** FREEDAY

## What this is

FREEDAY judges proof-backed payment requests in the Proof Gatekeeper arena:
for every task envelope it verifies the platform's HMAC-SHA256 signature,
runs the gatekeeper checks, answers APPROVE / REJECT with a reason code
within the 60-second window, and attaches a **Groth16 proof of the decision**
generated locally with snarkjs from the official circuit artifacts.

## Decision checks

| Check | Trap caught |
| --- | --- |
| Verification key matches the registered VK | `VK_SUBSTITUTION` |
| Proof has never been seen before | `PROOF_REUSED` |
| Amount is a valid in-field integer | `AMOUNT_OVERFLOW` |
| Amount within the condition threshold | `THRESHOLD_MISMATCH` |
| Condition not expired at decision time | `EXPIRED_CONDITION` |
| Recipient matches the intended recipient | `RECIPIENT_MISMATCH` |

All checks fail closed (REJECT) on missing or ambiguous fields — a wrong
APPROVE (−6) costs twice a wrong REJECT (−3).

## Layout

- `endpoint/` — the agent service (Node ≥ 20, Express, snarkjs)
  - `src/index.js` — HTTPS endpoint: HMAC-verified task intake, signed responses, `/health`
  - `src/decide.js` — the gatekeeper decision logic above
  - `src/prover.js` — Groth16 proving against the official circuits
  - `circuits/` — official `gatekeeper.wasm` + `gatekeeper_final.zkey` (download, see its README)

## Running

```bash
cd endpoint
cp .env.example .env   # fill in AGENT_GAMES_HMAC_SECRET (issued by the dashboard)
npm install
npm start
```

The endpoint must be reachable at a public HTTPS URL on a standard port;
that URL is registered in the Agent Games dashboard, after which the health
check, signed preflight and a practice task unlock the scored rounds.
