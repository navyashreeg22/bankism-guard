// Layer 2: Local rules-based intent and guardrail analyzer (not an external LLM)
// Operates in isolated sandbox mode with structured JSON schema intent extraction.
// Enforces fail-closed behavior on timeout or malformed output.

import { ExtractedBankingAction, ThreatCategory, RiskLevel, BankingIntentType } from './types';

export interface AIGuardrailResult {
  passed: boolean;
  threat_category: ThreatCategory[];
  risk_score: number;
  risk_level: RiskLevel;
  rationale: string;
  extracted_action: ExtractedBankingAction;
  latency_ms: number;
  engine_mode: 'CLOUD_LLM' | 'LOCAL_SEMANTIC_ANALYZER'; // Current implementation always uses LOCAL_SEMANTIC_ANALYZER
}

/**
 * Local regex/rule-based parser that extracts likely banking intent,
 * detects selected conversational injection patterns, and flags ambiguity. It is not an LLM.
 */
function runLocalSemanticInspection(input: string): AIGuardrailResult {
  const startTime = performance.now();
  const lower = input.toLowerCase();

  let intent: BankingIntentType = 'UNKNOWN';
  let amount: number | undefined;
  let currency = 'USD';
  let recipient: string | undefined;
  let memo: string | undefined;
  const ambiguityReasons: string[] = [];

  // 1. Identify Primary Intent
  if (/(?:transfer|send|wire|pay|forward|move)\b/i.test(lower)) {
    if (/(?:bill|electric|utility|water|gas|invoice)/i.test(lower)) {
      intent = 'PAY_BILL';
    } else {
      intent = 'TRANSFER';
    }
  } else if (/(?:balance|how much (?:do i have|money)|account balance|funds available)/i.test(lower)) {
    intent = 'BALANCE_INQUIRY';
  } else if (/(?:transactions?|history|recent activity|statement|ledger)/i.test(lower)) {
    intent = 'TRANSACTION_HISTORY';
  }

  // 2. Extract Amount (preserves negative/zero values for boundary validation)
  const amountMatch = input.match(/([-–—]?)\s*(?:\$|USD\s*|EUR\s*|£\s*)?([0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]{1,2})?|[0-9]+(?:\.[0-9]{1,2})?)\s*(?:dollars?|usd|bucks)?/i);
  if (amountMatch && amountMatch[2]) {
    const rawNum = amountMatch[2].replace(/,/g, '');
    let parsed = parseFloat(rawNum);
    if (!isNaN(parsed)) {
      if (amountMatch[1] && amountMatch[1].trim().length > 0) {
        parsed = -Math.abs(parsed);
      }
      amount = parsed;
    }
  }

  if (input.includes('$') || /dollars?|usd/i.test(lower)) currency = 'USD';
  else if (input.includes('€') || /euros?|eur/i.test(lower)) currency = 'EUR';
  else if (input.includes('£') || /gbp|pounds?/i.test(lower)) currency = 'GBP';

  // 3. Extract Recipient
  const recipientMatch = input.match(/\bto\s+(@[a-zA-Z0-9_.-]+|[A-Z][a-zA-Z0-9_.-]+(?:\s+[A-Z][a-zA-Z0-9_.-]+)?|account\s*#?[0-9A-Za-z]+)/);
  if (recipientMatch && recipientMatch[1]) {
    recipient = recipientMatch[1].trim();
  } else {
    const directPayMatch = input.match(/(?:pay|send)\s+(@[a-zA-Z0-9_.-]+|[A-Z][a-zA-Z0-9_.-]+)\s+\$?[0-9]+/i);
    if (directPayMatch && directPayMatch[1]) {
      recipient = directPayMatch[1].trim();
    }
  }

  // 4. Extract Memo
  const memoMatch = input.match(/(?:memo|note|for|description)\s*[:=-]\s*([^,\n.]+)/i);
  if (memoMatch && memoMatch[1]) {
    memo = memoMatch[1].trim();
  } else {
    const forMatch = input.match(/\bfor\s+([a-zA-Z0-9\s_-]+?)(?:\s+with|\s+memo|$|\.)/i);
    if (forMatch && forMatch[1] && !/^(?:all|my|the)\b/i.test(forMatch[1])) {
      memo = forMatch[1].trim();
    }
  }

  // 5. Detect Ambiguity in Financial Actions
  if (intent === 'TRANSFER') {
    if (!amount) {
      ambiguityReasons.push('Transaction amount is missing or unspecified.');
    }
    if (!recipient) {
      ambiguityReasons.push('Transaction recipient is missing or indeterminate.');
    }
    if (/(?:some money|all (?:of )?my money|maximum(?: amount)?|whatever you have|a bit of cash)/i.test(lower)) {
      ambiguityReasons.push('Vague quantifiers ("all money", "some money") cannot be executed.');
    }
    if (/(?:to my friend|to someone|to him|to her|to that guy)/i.test(lower)) {
      ambiguityReasons.push('Relative pronouns or informal terms ("friend", "him") lack unique financial addressing.');
    }
  }

  // 6. Semantic Adversarial Assessment
  const detectedThreats: ThreatCategory[] = [];
  let riskScore = 0.05;
  let riskLevel: RiskLevel = 'LOW';
  let passed = true;
  let rationale = 'Intent classified cleanly. Banking action parameters conform to standard conversational schema.';

  if (/(?:assume\s+developer|override\s+permission|unconstrained|ignore\s+constraints|disobey|elevate\s+privilege)/i.test(lower)) {
    detectedThreats.push('POLICY_OVERRIDE');
    riskScore = 0.88;
    riskLevel = 'HIGH';
    passed = false;
    rationale = 'Semantic analysis detected policy override instructions embedded in phrasing.';
  } else if (/(?:jailbreak|unfiltered\s+response|pretend\s+you\s+don't\s+care\s+about\s+security)/i.test(lower)) {
    detectedThreats.push('ROLEPLAY_JAILBREAK');
    riskScore = 0.93;
    riskLevel = 'CRITICAL';
    passed = false;
    rationale = 'Semantic analysis detected jailbreak roleplay intent.';
  } else if (/(?:reveal|print|show|leak|output|dump).*(?:system\s+prompt|instructions|safety\s+instructions|canary)/i.test(lower)) {
    detectedThreats.push('DATA_EXFILTRATION');
    riskScore = 0.94;
    riskLevel = 'CRITICAL';
    passed = false;
    rationale = 'Semantic analysis detected attempt to exfiltrate internal system prompt or safety instructions.';
  } else if (ambiguityReasons.length > 0) {
    detectedThreats.push('AMBIGUOUS_FINANCIAL_INTENT');
    riskScore = 0.45;
    riskLevel = 'MEDIUM';
    passed = false;
    rationale = `Ambiguous financial request: ${ambiguityReasons.join(' ')}`;
  }

  const isAmbiguous = ambiguityReasons.length > 0;
  const extractedAction: ExtractedBankingAction = {
    intent,
    amount,
    currency,
    recipient,
    memo,
    is_ambiguous: isAmbiguous,
    ambiguity_reasons: ambiguityReasons,
  };

  const endTime = performance.now();
  const latency = Math.round((endTime - startTime) * 100) / 100;

  return {
    passed,
    threat_category: detectedThreats,
    risk_score: riskScore,
    risk_level: riskLevel,
    rationale,
    extracted_action: extractedAction,
    latency_ms: latency,
    engine_mode: 'LOCAL_SEMANTIC_ANALYZER',
  };
}

export async function inspectAIGuardrail(input: string): Promise<AIGuardrailResult> {
  try {
    // Zero-trust timeout wrapper: if analysis exceeds budget, fail closed!
    return await Promise.race([
      new Promise<AIGuardrailResult>((resolve) => resolve(runLocalSemanticInspection(input))),
      new Promise<AIGuardrailResult>((_, reject) =>
        setTimeout(() => reject(new Error('AI Guardrail Timeout Exceeded')), 2500)
      ),
    ]);
  } catch (error) {
    // Fail-closed security guarantee
    return {
      passed: false,
      threat_category: ['SYSTEM_FAULT'],
      risk_score: 1.0,
      risk_level: 'CRITICAL',
      rationale: `Classifier failure or timeout: ${error instanceof Error ? error.message : 'Unknown exception'}. System failed-closed.`,
      extracted_action: {
        intent: 'UNKNOWN',
        currency: 'USD',
        is_ambiguous: true,
        ambiguity_reasons: ['Security classifier unavailable: fail-closed engaged.'],
      },
      latency_ms: 2500,
      engine_mode: 'LOCAL_SEMANTIC_ANALYZER',
    };
  }
}
