// Bankism AI Firewall - Strict Machine-Readable Types

export type VerdictStatus = 'APPROVED' | 'BLOCKED' | 'REVIEW_REQUIRED';

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type ThreatCategory =
  | 'DIRECT_PROMPT_INJECTION'
  | 'ROLEPLAY_JAILBREAK'
  | 'POLICY_OVERRIDE'
  | 'MEMO_INDIRECT_INJECTION'
  | 'TOKEN_OBFUSCATION'
  | 'DATA_EXFILTRATION'
  | 'AMBIGUOUS_FINANCIAL_INTENT'
  | 'UNAUTHORIZED_TRANSACTION_LIMIT'
  | 'INSUFFICIENT_FUNDS'
  | 'SYSTEM_FAULT';

export type TriggerLayer =
  | 'NONE'
  | 'LAYER_0_NORMALIZER'
  | 'LAYER_1_HEURISTICS'
  | 'LAYER_2_AI_GUARDRAIL'
  | 'LAYER_3_FINANCIAL_BOUNDARY';

export type ExecutionStatus =
  | 'NOT_EXECUTED'
  | 'AWAITING_CONFIRMATION'
  | 'EXECUTED'
  | 'REJECTED';

export type BankingIntentType =
  | 'TRANSFER'
  | 'BALANCE_INQUIRY'
  | 'TRANSACTION_HISTORY'
  | 'PAY_BILL'
  | 'UNKNOWN';

export interface ExtractedBankingAction {
  intent: BankingIntentType;
  amount?: number;
  currency: string;
  recipient?: string;
  memo?: string;
  is_ambiguous: boolean;
  ambiguity_reasons: string[];
}

export interface PipelineStepTrace {
  layer: TriggerLayer;
  name: string;
  status: 'PASSED' | 'FLAGGED' | 'BLOCKED';
  latency_ms: number;
  details: string;
}

export interface FirewallVerdict {
  request_id: string;
  timestamp: string;
  verdict: VerdictStatus;
  risk_score: number; // Calibrated 0.00 (Benign) to 1.00 (Critical Threat)
  risk_level: RiskLevel;
  threat_category: ThreatCategory[]; // ALWAYS an array
  trigger_layer: TriggerLayer;
  rationale: string;
  original_input: string; // Preserved for immutable audit
  normalized_input: string;
  extracted_banking_action: ExtractedBankingAction | null;
  transaction_authorized: boolean; // Deterministic authorization only, NEVER from LLM
  execution_status: ExecutionStatus;
  confirmation_token?: string; // Token required for 2-phase atomic commit
  idempotency_key?: string;
  pipeline_trace: PipelineStepTrace[];
  total_latency_ms: number;
  shield_signature: string; // Real HMAC-SHA256 signature
}

export interface FirewallRequestInput {
  prompt: string;
  account_context?: {
    account_id?: string;
    balance?: number;
    currency?: string;
    authenticated_user_id?: string;
  };
}

export interface TransactionConfirmationRequest {
  request_id: string;
  confirmation_token: string;
  idempotency_key: string;
  confirmed_amount: number;
  confirmed_recipient: string;
}

export interface TransactionConfirmationResponse {
  success: boolean;
  transaction_id?: string;
  execution_status: ExecutionStatus;
  delta_amount: number;
  previous_balance: number;
  new_balance: number;
  message: string;
  executed_at: string;
}
