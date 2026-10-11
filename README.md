# 🛡️ Bankism: Blue-Team AI Firewall & Guardrail Defense Kernel

> **Hackathon prototype of a defense-in-depth input firewall and a synthetic two-phase transaction demo. It is not a production banking control.** Intercepts, sanitizes, and evaluates untrusted natural language user inputs before any privileged banking action can execute.

[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen)]()

---

## 🏛️ Architecture: Single Unified Next.js Serverless Stack

Bankism is deployed as a single, cohesive full-stack TypeScript application on Next.js 14 (App Router) containing:
1. **Interactive Security Dashboard:** High-contrast pink/purple cyberpunk FinTech UI with scenario selector, live 4-layer inspection trace, simulated bank account status, and raw JSON auditor drawer.
2. **Phase 1 Inspection Endpoint (`POST /api/firewall/inspect`):** Bounded normalizer, deterministic heuristics, fail-closed semantic guardrail, and financial policy boundary engine. Returns structured verdicts and cryptographic confirmation tokens.
3. **Phase 2 Confirmation Endpoint (`POST /api/ledger/confirm`):** Signed, expiring confirmation token and server-side pending-transfer checks for a process-local synthetic demo ledger.

---

## 🔒 The 4-Layer Defense-in-Depth Pipeline

```
                       [ Untrusted Customer Input ]
                                    │
  ┌─────────────────────────────────▼─────────────────────────────────┐
  │  LAYER 0: Bounded De-cloaking Normalizer (< 2ms)                  │
  │  • Preserves raw original input for immutable audit logs.         │
  │  • Strips zero-width and invisible control characters.            │
  │  • Bounded Base64 detection: decodes only printable ASCII chunks  │
  │    containing command keywords (prevents data corruption).        │
  │  • Normalizes mixed-script Cyrillic/Greek homoglyphs.             │
  └─────────────────────────────────┬─────────────────────────────────┘
                                    │
  ┌─────────────────────────────────▼─────────────────────────────────┐
  │  LAYER 1: Deterministic Heuristics & Signatures (< 1ms)           │
  │  • Delimiter breakout detection (###, <|im_start|>, [INST]).      │
  │  • Jailbreak signatures (DAN, developer mode, oppo mode).         │
  │  • Policy overrides ("ignore previous instructions", fake CFO).  │
  │  • System prompt exfiltration probes & SQL/shell injections.      │
  └─────────────────────────────────┬─────────────────────────────────┘
                                    │ (Early-exit if attack detected)
  ┌─────────────────────────────────▼─────────────────────────────────┐
  │  LAYER 2: Dual-Chamber Semantic & Rules-Based Guardrail (~10ms)            │
  │  • Isolates input in untrusted sandbox (<untrusted>).             │
  │  • Extracts structured intent (Transfer, Inquiry, Bill Pay).      │
  │  • Flags conversational jailbreaks & semantic evasions.           │
  │  • Fail-closed timeout wrapper: defaults to BLOCKED on fault.    │
  └─────────────────────────────────┬─────────────────────────────────┘
                                    │
  ┌─────────────────────────────────▼─────────────────────────────────┐
  │  LAYER 3: Deterministic Financial Boundary Engine (< 2ms)         │
  │  • Disassociates AI approval from execution (Requires Phase 2).   │
  │  • Memo Sanitizer: Quarantines/blocks indirect prompt injections  │
  │    (never silently rewrites and approves).                        │
  │  • Ambiguity Guard: Blocks indeterminate recipients/amounts.      │
  │  • Safety Ceiling: Enforces >$5,000 Step-up 2FA (REVIEW_REQUIRED).│
  │  • Balance Guard: Prevents over-drafting simulated funds.         │
  └─────────────────────────────────┬─────────────────────────────────┘
                                    │
              [ Standardized Machine-Readable JSON Verdict ]
              Status: APPROVED / BLOCKED / REVIEW_REQUIRED
```

---

## 📋 Standardized JSON Verdict Specification

Every request returns an auditable, machine-readable JSON verdict:

```json
{
  "request_id": "bnk_sec_109a",
  "timestamp": "2026-10-11T05:32:14.281Z",
  "verdict": "APPROVED",
  "risk_score": 0.08,
  "risk_level": "LOW",
  "threat_category": [],
  "trigger_layer": "NONE",
  "rationale": "Deterministic boundaries satisfied. Transaction authorized for confirmation.",
  "original_input": "Transfer $24.50 to @alice for lunch memo: burger split",
  "normalized_input": "Transfer $24.50 to @alice for lunch memo: burger split",
  "extracted_banking_action": {
    "intent": "TRANSFER",
    "amount": 24.50,
    "currency": "USD",
    "recipient": "@alice",
    "memo": "burger split"
  },
  "transaction_authorized": true,
  "execution_status": "AWAITING_CONFIRMATION",
  "confirmation_token": "cft_89a0b12cf90172e04",
  "idempotency_key": "idemp_44b029aa18df",
  "pipeline_trace": [
    { "layer": "LAYER_0_NORMALIZER", "status": "PASSED", "latency_ms": 0.22 },
    { "layer": "LAYER_1_HEURISTICS", "status": "PASSED", "latency_ms": 0.14 },
    { "layer": "LAYER_2_AI_GUARDRAIL", "status": "PASSED", "latency_ms": 0.35 },
    { "layer": "LAYER_3_FINANCIAL_BOUNDARY", "status": "PASSED", "latency_ms": 0.18 }
  ],
  "total_latency_ms": 0.89,
  "shield_signature": "hmac-sha256:7f01a8b29c01720b..."
}
```

---

## 🧪 Reproducible Security Benchmark Suite

Run the automated evaluation suite locally:

```bash
npm run test:firewall
```

### Benchmark reporting

The repository includes a curated 30-case evaluation script. **The historical figures below have not been independently reproduced in this environment and should not be presented as verified results.** Run `npm ci` on your target OS (do not copy `node_modules` from Windows to Linux), then run `npm run test:firewall`. Record the exact commit, runtime, environment, case-level outputs, and latency measurement scope before publishing any recall, false-positive, or p50/p95 numbers. The security tests separately exercise confirmation-token and idempotency behavior.

---

## 🚀 Two-Phase Demo Confirmation Flow

1. **Phase 1: Inspection & Authorization Check**
   ```bash
   curl -X POST https://<your-domain>/api/firewall/inspect \
     -H "Content-Type: application/json" \
     -d '{
       "prompt": "Transfer $24.50 to @alice for lunch memo: burger split"
     }'
   ```
   *For a valid simulated transfer, the response includes `verdict: "APPROVED"`, `execution_status: "AWAITING_CONFIRMATION"`, and a signed, expiring `confirmation_token`. The server stores the pending transfer parameters; the browser does not define the committed amount or recipient.*

2. **Phase 2: Demo Confirmation**
   ```bash
   curl -X POST https://<your-domain>/api/ledger/confirm \
     -H "Content-Type: application/json" \
     -d '{
       "request_id": "bnk_sec_...",
       "confirmation_token": "cft_...",
       "idempotency_key": "idemp_...",
       "confirmed_amount": 24.50,
       "confirmed_recipient": "@alice"
     }'
   ```
   *Debits the process-local synthetic ledger and deduplicates exact replays in this demo. This is not durable or multi-instance atomic storage; use a database transaction and unique idempotency constraint before production use.*

---

## 💻 Local Quickstart

```powershell
# 1. Navigate to project
cd "C:\Users\navya shree\.gemini\antigravity\scratch\bankism-firewall"

# 2. Run automated test suite
npm run test:firewall

# 3. Start development server
npm run dev
```

Visit **`http://localhost:3000`** in your browser.

---

## 🌐 Deploy to Vercel in 60 Seconds

1. Push to GitHub:
   ```powershell
   git add .
   git commit -m "feat: complete Bankism 2-phase AI firewall"
   git remote add origin https://github.com/<your-username>/bankism-firewall.git
   git branch -M main
   git push -u origin main
   ```
2. Import repository at [vercel.com/new](https://vercel.com/new) and click **Deploy**.


## Security scope and deployment notes

- **Layer 2 is a local regex/rule-based parser, not a connected LLM.** It recognizes selected intent and attack patterns; it can miss novel phrasing and can misclassify legitimate requests. Do not describe it as model-based semantic understanding.
- **The ledger is synthetic. No real bank API or real funds are connected.** In local development, the in-process store supports demonstration and security tests only. State does not survive process restarts and is not shared across serverless instances.
- **Before production use:** replace `confirmation_store.ts` with a durable database-backed implementation using a single database transaction, row locking or equivalent concurrency control, and a unique idempotency constraint. Add real authentication/authorization and derive user/account identity server-side. Do not enable real-money execution with this demo adapter.
- Set `BANKISM_AUDIT_SECRET` and `BANKISM_CONFIRMATION_SECRET` to independently generated random secrets of at least 32 characters in the deployment environment. The code uses development-only fallback values only outside production.
- `POST /api/ledger/confirm` is disabled in production unless `BANKISM_DEMO_MODE=true` is explicitly set. This flag only enables the **synthetic demo**, not real banking. Do not set it as a substitute for real authentication or durable storage.
- The benchmark output is a local test result, not a universal guarantee. Report attack recall, false-positive rate, and latency only after running the suite in the target environment and recording the sample set and measurement conditions.
- Confirmation tests cover changed amount, recipient substitution, token tampering, wrong idempotency key, and duplicate replay. Expiry and cross-instance persistence still require integration tests when a durable adapter is added.
