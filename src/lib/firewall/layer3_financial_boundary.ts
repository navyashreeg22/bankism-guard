// Layer 3: Deterministic Financial Boundary Engine (< 2ms)
// Enforces zero-trust boundaries on all extracted banking transactions:
// 1. Blocks any adversarial imperative instructions inside memos (NEVER silently alters memo to approve)
// 2. Disassociates AI approval from execution (Requires 2-Phase Confirmation)
// 3. Rejects ambiguous transfer parameters
// 4. Enforces $5,000 threshold for Step-up Review

import { ExtractedBankingAction, ThreatCategory, RiskLevel, VerdictStatus, ExecutionStatus } from './types';

export interface FinancialBoundaryResult {
  passed: boolean;
  verdict: VerdictStatus;
  threat_categories: ThreatCategory[];
  risk_score: number;
  risk_level: RiskLevel;
  rationale: string;
  transaction_authorized: boolean; // Deterministic authorization flag
  execution_status: ExecutionStatus; // Always NOT_EXECUTED or AWAITING_CONFIRMATION at firewall stage
  latency_ms: number;
}

const MAX_UNAUTHENTICATED_TRANSFER = 5000.00; // $5,000 USD limit before human review/2FA

// Patterns indicating indirect prompt injection or imperative commands hidden in payment memo
const ADVERSARIAL_MEMO_PATTERNS = [
  /(?:system\s*(?:override|update|message|directive|alert))/i,
  /(?:ignore|disregard|override|bypass)\s+(?:all\s+)?(?:rules|instructions|prior|limits)/i,
  /(?:transfer|wire|send|forward|pay)\s+(?:all|remaining|additional|\$?\d+)/i,
  /(?:admin|cfo|sudo|root|superuser)/i,
  /(?:to\s+(?:0x[a-fA-F0-9]+|wallet|hacker|external))/i,
  /<script[\s>]|javascript:|curl\s+|eval\s*\(/i,
];

export function validateFinancialBoundary(
  action: ExtractedBankingAction | null,
  currentBalance = 12450.00
): FinancialBoundaryResult {
  const startTime = performance.now();

  // If non-transactional or informational
  if (!action || action.intent === 'UNKNOWN') {
    const endTime = performance.now();
    return {
      passed: true,
      verdict: 'APPROVED',
      threat_categories: [],
      risk_score: 0.05,
      risk_level: 'LOW',
      rationale: 'Informational conversation allowed. Zero financial capability requested.',
      transaction_authorized: false,
      execution_status: 'NOT_EXECUTED',
      latency_ms: Math.round((endTime - startTime) * 100) / 100,
    };
  }

  // 1. Read-only Telemetry Actions (Balance Inquiry / Transaction History)
  if (action.intent === 'BALANCE_INQUIRY' || action.intent === 'TRANSACTION_HISTORY') {
    const endTime = performance.now();
    return {
      passed: true,
      verdict: 'APPROVED',
      threat_categories: [],
      risk_score: 0.02,
      risk_level: 'LOW',
      rationale: 'Read-only financial telemetry inquiry approved. Zero fund movement capability granted.',
      transaction_authorized: false,
      execution_status: 'NOT_EXECUTED',
      latency_ms: Math.round((endTime - startTime) * 100) / 100,
    };
  }

  // 2. Reject Ambiguity Before Authorization
  if (action.is_ambiguous || !action.amount || !action.recipient) {
    const reasons = action.ambiguity_reasons.length > 0
      ? action.ambiguity_reasons.join('; ')
      : 'Ambiguous parameters: Transaction amount and recipient must be explicitly defined.';

    const endTime = performance.now();
    return {
      passed: false,
      verdict: 'BLOCKED',
      threat_categories: ['AMBIGUOUS_FINANCIAL_INTENT'],
      risk_score: 0.55,
      risk_level: 'MEDIUM',
      rationale: `Deterministic Boundary Block: ${reasons}. Privileged banking tool execution denied.`,
      transaction_authorized: false,
      execution_status: 'NOT_EXECUTED',
      latency_ms: Math.round((endTime - startTime) * 100) / 100,
    };
  }

  // 3. Inspect Payment Memo for Indirect Injection
  // CRITICAL SECURITY RULE: If an adversarial instruction is detected in a memo,
  // we do NOT silently rewrite the memo and approve! We strictly BLOCK the request.
  if (action.memo) {
    for (const pattern of ADVERSARIAL_MEMO_PATTERNS) {
      if (pattern.test(action.memo)) {
        const endTime = performance.now();
        return {
          passed: false,
          verdict: 'BLOCKED',
          threat_categories: ['MEMO_INDIRECT_INJECTION'],
          risk_score: 0.96,
          risk_level: 'CRITICAL',
          rationale: `Adversarial Injection in Memo detected: The transaction memo contained forbidden imperative instructions or system override tokens: "${action.memo}". Request quarantined.`,
          transaction_authorized: false,
          execution_status: 'NOT_EXECUTED',
          latency_ms: Math.round((endTime - startTime) * 100) / 100,
        };
      }
    }
  }

  // 4. Validate Amount Numbers
  if (action.amount <= 0 || isNaN(action.amount)) {
    const endTime = performance.now();
    return {
      passed: false,
      verdict: 'BLOCKED',
      threat_categories: ['AMBIGUOUS_FINANCIAL_INTENT'],
      risk_score: 0.60,
      risk_level: 'MEDIUM',
      rationale: `Invalid transaction amount: $${action.amount}. Must be a positive numeric value.`,
      transaction_authorized: false,
      execution_status: 'NOT_EXECUTED',
      latency_ms: Math.round((endTime - startTime) * 100) / 100,
    };
  }

  // Check stepped-up 2FA limit first (Single transaction ceiling $5,000)
  if (action.amount > MAX_UNAUTHENTICATED_TRANSFER) {
    const endTime = performance.now();
    return {
      passed: false,
      verdict: 'REVIEW_REQUIRED',
      threat_categories: ['UNAUTHORIZED_TRANSACTION_LIMIT'],
      risk_score: 0.70,
      risk_level: 'HIGH',
      rationale: `High-value transfer limit exceeded: Single transfer of $${action.amount.toFixed(2)} exceeds unauthenticated threshold of $${MAX_UNAUTHENTICATED_TRANSFER.toFixed(2)}. Flagged for Step-up 2FA / Dual-Officer Authorization.`,
      transaction_authorized: false,
      execution_status: 'NOT_EXECUTED',
      latency_ms: Math.round((endTime - startTime) * 100) / 100,
    };
  }

  // Check against available mock balance
  if (action.amount > currentBalance) {
    const endTime = performance.now();
    return {
      passed: false,
      verdict: 'BLOCKED',
      threat_categories: ['INSUFFICIENT_FUNDS'],
      risk_score: 0.50,
      risk_level: 'MEDIUM',
      rationale: `Insufficient funds: Requested amount ($${action.amount.toFixed(2)}) exceeds current ledger balance ($${currentBalance.toFixed(2)}).`,
      transaction_authorized: false,
      execution_status: 'NOT_EXECUTED',
      latency_ms: Math.round((endTime - startTime) * 100) / 100,
    };
  }

  // 5. Valid Approved Transaction (Ready for Phase 2 User Confirmation)
  // CRITICAL: Notice execution_status is AWAITING_CONFIRMATION, NOT EXECUTED!
  const endTime = performance.now();
  return {
    passed: true,
    verdict: 'APPROVED',
    threat_categories: [],
    risk_score: 0.08,
    risk_level: 'LOW',
    rationale: `Deterministic boundaries satisfied. Transaction authorized for confirmation: $${action.amount.toFixed(2)} to ${action.recipient}. Awaiting 2-phase user confirmation token.`,
    transaction_authorized: true,
    execution_status: 'AWAITING_CONFIRMATION',
    latency_ms: Math.round((endTime - startTime) * 100) / 100,
  };
}
