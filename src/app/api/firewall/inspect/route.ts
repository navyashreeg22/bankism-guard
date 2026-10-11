import { NextRequest, NextResponse } from 'next/server';
import { inspectPrompt } from '@/lib/firewall/engine';
import { FirewallRequestInput } from '@/lib/firewall/types';

// CORS Headers for cross-origin access during hackathon judge evaluations
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
};

export async function OPTIONS() {
  return NextResponse.json({}, { headers: corsHeaders });
}

export async function GET() {
  return NextResponse.json(
    {
      service: 'Bankism: Blue-Team AI Firewall & Guardrail Defense Kernel',
      version: '2.6.0-hackathon-demo',
      architecture: 'Next.js App Router Serverless Route Handlers',
      status: 'ARMED_AND_OPERATIONAL',
      active_layers: [
        'Layer 0: Bounded De-cloaking Normalizer (Zero-width, Homoglyphs, Encoded variants)',
        'Layer 1: Deterministic Heuristics & Signatures (Delimiters, Roleplay, Policy Overrides)',
        'Layer 2: Local rules-based intent guardrail (not an external LLM; fail-closed on exceptions)',
        'Layer 3: Deterministic Financial Boundary Engine (Ceiling Limits, Memo Quarantine, Ambiguity Guard)',
      ],
      two_phase_execution: {
        phase_1_inspection: 'POST /api/firewall/inspect (Emits verdict + confirmation_token)',
        phase_2_confirmation: 'POST /api/ledger/confirm (Synthetic demo commit; in-process state only)',
      },
      verdict_schema: {
        request_id: 'string (e.g. bnk_sec_...)',
        timestamp: 'ISO8601 string',
        verdict: 'APPROVED | BLOCKED | REVIEW_REQUIRED',
        risk_score: 'float 0.00 to 1.00 (Calibrated risk metric)',
        risk_level: 'LOW | MEDIUM | HIGH | CRITICAL',
        threat_category: 'Array of strings (Empty array [] for benign)',
        trigger_layer: 'string (LAYER_0_NORMALIZER | LAYER_1_HEURISTICS | ...)',
        rationale: 'string (Human-readable decision explanation)',
        original_input: 'string (Preserved raw input for audit)',
        normalized_input: 'string',
        extracted_banking_action: 'object or null',
        transaction_authorized: 'boolean (Deterministic code authorization, NEVER from LLM)',
        execution_status: 'NOT_EXECUTED | AWAITING_CONFIRMATION | EXECUTED | REJECTED',
        confirmation_token: 'string or undefined (Required for Phase 2 commit)',
        idempotency_key: 'string or undefined',
        pipeline_trace: 'Array of layer traces with measured latency',
        total_latency_ms: 'float (Measured end-to-end execution time)',
        shield_signature: 'string (HMAC-SHA256 signature over selected verdict fields; not a full immutable audit log)',
      },
    },
    { headers: corsHeaders }
  );
}

export async function POST(req: NextRequest) {
  try {
    const body = (await req.json()) as FirewallRequestInput;

    if (!body || typeof body.prompt !== 'string') {
      return NextResponse.json(
        {
          error: 'BAD_REQUEST',
          message: 'Missing required string field "prompt" in JSON body.',
        },
        { status: 400, headers: corsHeaders }
      );
    }

    const verdict = await inspectPrompt(body);

    return NextResponse.json(verdict, {
      status: 200,
      headers: {
        ...corsHeaders,
        'X-Bankism-Verdict': verdict.verdict,
        'X-Bankism-Threats': verdict.threat_category.join(',') || 'NONE',
        'X-Bankism-Latency-Ms': verdict.total_latency_ms.toString(),
        'X-Bankism-Signature': verdict.shield_signature,
      },
    });
  } catch (error) {
    console.error('Firewall inspection error:', error);
    // Strict fail-closed response on unhandled exception
    return NextResponse.json(
      {
        request_id: `bnk_fault_${Date.now()}`,
        timestamp: new Date().toISOString(),
        verdict: 'BLOCKED',
        risk_score: 1.0,
        risk_level: 'CRITICAL',
        threat_category: ['SYSTEM_FAULT'],
        trigger_layer: 'LAYER_2_AI_GUARDRAIL',
        rationale: 'Security inspection kernel encountered an unhandled exception. Failed-closed to prevent bypass.',
        original_input: '',
        normalized_input: '',
        extracted_banking_action: null,
        transaction_authorized: false,
        execution_status: 'NOT_EXECUTED',
        pipeline_trace: [],
        total_latency_ms: 0,
        shield_signature: 'fault_fail_closed',
      },
      { status: 500, headers: corsHeaders }
    );
  }
}
