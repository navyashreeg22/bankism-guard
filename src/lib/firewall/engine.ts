// Bankism AI Firewall - Main Pipeline Orchestrator
// Coordinates Defense-in-Depth layers and emits standardized machine-readable JSON verdicts.

import crypto from 'crypto';
import {
  FirewallVerdict,
  FirewallRequestInput,
  PipelineStepTrace,
  ThreatCategory,
  RiskLevel,
  VerdictStatus,
} from './types';
import { normalizeInput } from './layer0_normalizer';
import { scanHeuristics } from './layer1_heuristics';
import { inspectAIGuardrail } from './layer2_ai_guardrail';
import { validateFinancialBoundary } from './layer3_financial_boundary';
import { createPendingTransfer, getConfirmationSecret, getDemoBalance } from './confirmation_store';

function auditSecret(): string {
  const secret = process.env.BANKISM_AUDIT_SECRET || process.env.BANKISM_CONFIRMATION_SECRET;
  if (secret && secret.length >= 32) return secret;
  if (process.env.NODE_ENV !== 'production') return 'local-development-only-secret-change-before-deploy-2026';
  throw new Error('BANKISM_AUDIT_SECRET must be configured (minimum 32 characters).');
}

function generateRequestId(): string {
  const rand = crypto.randomBytes(4).toString('hex');
  return `bnk_sec_${Date.now().toString(36)}_${rand}`;
}

function generateHmacAuditSignature(
  requestId: string,
  timestamp: string,
  verdict: string,
  riskScore: number,
  threatCategories: string[]
): string {
  const payload = `${requestId}|${timestamp}|${verdict}|${riskScore.toFixed(2)}|${threatCategories.sort().join(',')}`;
  const hmac = crypto.createHmac('sha256', auditSecret());
  hmac.update(payload);
  return `hmac-sha256:${hmac.digest('hex').substring(0, 32)}`;
}


export async function inspectPrompt(input: FirewallRequestInput): Promise<FirewallVerdict> {
  const globalStart = performance.now();
  const requestId = generateRequestId();
  const timestamp = new Date().toISOString();
  const traces: PipelineStepTrace[] = [];

  const rawPrompt = input.prompt || '';
  // Never trust balance/user/account identity supplied by the browser. This repo uses a server-side synthetic demo ledger.
  const currentBalance = getDemoBalance();

  // -------------------------------------------------------------
  // LAYER 0: Bounded De-cloaking Normalizer
  // -------------------------------------------------------------
  const normResult = normalizeInput(rawPrompt);
  const normalizedText = normResult.normalized_variant;

  let layer0Status: 'PASSED' | 'FLAGGED' = 'PASSED';
  let layer0Details = 'Clean input. No token obfuscation or hidden evasion detected.';

  if (normResult.obfuscation_detected) {
    layer0Status = 'FLAGGED';
    layer0Details = `De-cloaked mutations: [${normResult.evidence.map(e => e.type).join(', ')}]. ${normResult.evidence.map(e => e.rationale).join(' ')}`;
  }

  traces.push({
    layer: 'LAYER_0_NORMALIZER',
    name: 'Bounded De-cloaking & Normalizer',
    status: layer0Status,
    latency_ms: normResult.latency_ms,
    details: layer0Details,
  });

  // -------------------------------------------------------------
  // LAYER 1: Deterministic Heuristic & Signature Engine
  // -------------------------------------------------------------
  const heuristicResult = scanHeuristics(normalizedText);

  // If layer 0 found explicit Base64/leetspeak command attacks or Layer 1 matched signatures
  if (!heuristicResult.passed || normResult.obfuscation_detected) {
    const threats: ThreatCategory[] = [...heuristicResult.threatCategories];
    if (normResult.obfuscation_detected && !threats.includes('TOKEN_OBFUSCATION')) {
      threats.unshift('TOKEN_OBFUSCATION');
    }

    const riskScore = Math.max(heuristicResult.maxRiskScore, normResult.obfuscation_detected ? 0.95 : 0.90);
    const riskLevel: RiskLevel = heuristicResult.recommendedRiskLevel || 'CRITICAL';
    const topThreat = threats[0] || 'DIRECT_PROMPT_INJECTION';

    traces.push({
      layer: 'LAYER_1_HEURISTICS',
      name: 'Deterministic Signature Engine',
      status: 'BLOCKED',
      latency_ms: heuristicResult.latency_ms,
      details: heuristicResult.passed
        ? `Blocked on Layer 0 token obfuscation evasion: ${normResult.evidence.map(e => e.rationale).join('; ')}`
        : heuristicResult.rationale,
    });

    const totalLatency = Math.round((performance.now() - globalStart) * 100) / 100;
    const signature = generateHmacAuditSignature(requestId, timestamp, 'BLOCKED', riskScore, threats);

    return {
      request_id: requestId,
      timestamp,
      verdict: 'BLOCKED',
      risk_score: riskScore,
      risk_level: riskLevel,
      threat_category: threats,
      trigger_layer: topThreat === 'TOKEN_OBFUSCATION' ? 'LAYER_0_NORMALIZER' : 'LAYER_1_HEURISTICS',
      rationale: topThreat === 'TOKEN_OBFUSCATION'
        ? `Adversarial Token Obfuscation Block: Hidden encoded instructions de-cloaked: ${normResult.evidence.map(e => e.rationale).join('; ')}`
        : heuristicResult.rationale,
      original_input: rawPrompt,
      normalized_input: normalizedText,
      extracted_banking_action: null,
      transaction_authorized: false,
      execution_status: 'NOT_EXECUTED',
      pipeline_trace: traces,
      total_latency_ms: totalLatency,
      shield_signature: signature,
    };
  }

  traces.push({
    layer: 'LAYER_1_HEURISTICS',
    name: 'Deterministic Signature Engine',
    status: 'PASSED',
    latency_ms: heuristicResult.latency_ms,
    details: 'Zero known jailbreak, delimiter breakout, or policy override signatures matched.',
  });

  // -------------------------------------------------------------
  // LAYER 2: Dual-Chamber Semantic & AI Guardrail Inspector
  // -------------------------------------------------------------
  const aiResult = await inspectAIGuardrail(normalizedText);

  if (!aiResult.passed && !aiResult.threat_category.includes('AMBIGUOUS_FINANCIAL_INTENT')) {
    traces.push({
      layer: 'LAYER_2_AI_GUARDRAIL',
      name: 'Local Rules-Based Intent Guardrail',
      status: 'BLOCKED',
      latency_ms: aiResult.latency_ms,
      details: aiResult.rationale,
    });

    const totalLatency = Math.round((performance.now() - globalStart) * 100) / 100;
    const signature = generateHmacAuditSignature(requestId, timestamp, 'BLOCKED', aiResult.risk_score, aiResult.threat_category);

    return {
      request_id: requestId,
      timestamp,
      verdict: 'BLOCKED',
      risk_score: aiResult.risk_score,
      risk_level: aiResult.risk_level,
      threat_category: aiResult.threat_category,
      trigger_layer: 'LAYER_2_AI_GUARDRAIL',
      rationale: aiResult.rationale,
      original_input: rawPrompt,
      normalized_input: normalizedText,
      extracted_banking_action: aiResult.extracted_action,
      transaction_authorized: false,
      execution_status: 'NOT_EXECUTED',
      pipeline_trace: traces,
      total_latency_ms: totalLatency,
      shield_signature: signature,
    };
  }

  traces.push({
    layer: 'LAYER_2_AI_GUARDRAIL',
    name: 'Local Rules-Based Intent Guardrail',
    status: 'PASSED',
    latency_ms: aiResult.latency_ms,
    details: `Local rules-based parser classified intent as [${aiResult.extracted_action.intent}]. This is heuristic classification, not an external LLM.`,
  });

  // -------------------------------------------------------------
  // LAYER 3: Deterministic Financial Boundary Engine
  // -------------------------------------------------------------
  const finResult = validateFinancialBoundary(
    aiResult.extracted_action,
    currentBalance
  );

  let layer3Status: 'PASSED' | 'BLOCKED' | 'FLAGGED' = 'PASSED';
  if (finResult.verdict === 'BLOCKED') layer3Status = 'BLOCKED';
  else if (finResult.verdict === 'REVIEW_REQUIRED') layer3Status = 'FLAGGED';

  traces.push({
    layer: 'LAYER_3_FINANCIAL_BOUNDARY',
    name: 'Deterministic Financial Policy Boundary',
    status: layer3Status,
    latency_ms: finResult.latency_ms,
    details: finResult.rationale,
  });

  const finalVerdict: VerdictStatus = finResult.verdict;
  const finalThreats: ThreatCategory[] = finResult.threat_categories;
  const triggerLayer = finalVerdict === 'APPROVED' ? 'NONE' : 'LAYER_3_FINANCIAL_BOUNDARY';

  let confirmationToken: string | undefined;
  let idempotencyKey: string | undefined;

  // If approved and awaiting user confirmation, generate the atomic confirmation token
  if (finResult.execution_status === 'AWAITING_CONFIRMATION') {
    // Require a configured server-side secret in production; never mint weak fallback tokens there.
    getConfirmationSecret();
    const pending = createPendingTransfer({
      requestId,
      amount: aiResult.extracted_action.amount!,
      recipient: aiResult.extracted_action.recipient!,
      currency: aiResult.extracted_action.currency || 'USD',
    });
    confirmationToken = pending.confirmationToken;
    idempotencyKey = pending.idempotencyKey;
  }

  const totalLatency = Math.round((performance.now() - globalStart) * 100) / 100;
  const signature = generateHmacAuditSignature(requestId, timestamp, finalVerdict, finResult.risk_score, finalThreats);

  return {
    request_id: requestId,
    timestamp,
    verdict: finalVerdict,
    risk_score: finResult.risk_score,
    risk_level: finResult.risk_level,
    threat_category: finalThreats,
    trigger_layer: triggerLayer,
    rationale: finResult.rationale,
    original_input: rawPrompt,
    normalized_input: normalizedText,
    extracted_banking_action: aiResult.extracted_action,
    transaction_authorized: finResult.transaction_authorized,
    execution_status: finResult.execution_status,
    confirmation_token: confirmationToken,
    idempotency_key: idempotencyKey,
    pipeline_trace: traces,
    total_latency_ms: totalLatency,
    shield_signature: signature,
  };
}
