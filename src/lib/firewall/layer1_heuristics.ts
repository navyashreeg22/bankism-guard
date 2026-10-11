// Layer 1: Deterministic Heuristic & Signature Engine (< 5ms)
// Matches known prompt injection, jailbreak, delimiter breakout, and policy override signatures.

import { ThreatCategory, RiskLevel } from './types';

export interface HeuristicMatch {
  ruleId: string;
  category: ThreatCategory;
  riskLevel: RiskLevel;
  riskScore: number;
  description: string;
  matchedPattern: string;
}

export interface HeuristicScanResult {
  passed: boolean;
  matches: HeuristicMatch[];
  threatCategories: ThreatCategory[];
  primaryThreat: ThreatCategory | null;
  maxRiskScore: number;
  recommendedRiskLevel: RiskLevel;
  rationale: string;
  latency_ms: number;
}

interface HeuristicRule {
  id: string;
  category: ThreatCategory;
  riskLevel: RiskLevel;
  riskScore: number;
  description: string;
  regex: RegExp;
}

const HEURISTIC_RULES: HeuristicRule[] = [
  // 1. Delimiter Breakouts & Format Tampering
  {
    id: 'DELIM_01',
    category: 'DIRECT_PROMPT_INJECTION',
    riskLevel: 'CRITICAL',
    riskScore: 0.95,
    description: 'LLM control token or delimiter injection attempt',
    regex: /(?:<\|im_start\|>|<\|im_end\|>|<\|system\|>|\[INST\]|\[\/INST\]|```(?:system|admin|override)|###\s*(?:System|Instruction|Assistant|Human)|<\/(?:system|instruction|prompt)>)/i,
  },
  {
    id: 'DELIM_02',
    category: 'DIRECT_PROMPT_INJECTION',
    riskLevel: 'HIGH',
    riskScore: 0.88,
    description: 'Fake administrative divider or section breakout',
    regex: /(?:---|===)\s*(?:BEGIN|START)\s*(?:ADMIN|SYSTEM|OVERRIDE|ROOT|INTERNAL)\s*(?:POLICY|MODE|INSTRUCTION|CONFIG)/i,
  },

  // 2. Policy Overrides & Rule Disregard
  {
    id: 'OVERRIDE_01',
    category: 'POLICY_OVERRIDE',
    riskLevel: 'CRITICAL',
    riskScore: 0.98,
    description: 'Direct command to disregard/ignore prior system instructions',
    regex: /(?:ignore|disregard|forget|bypass|override)\s+(?:all\s+)?(?:previous|prior|above|existing|system|security)\s+(?:security\s+)?(?:instructions|rules|prompts|guidelines|policies|constraints|safeguards)/i,
  },
  {
    id: 'OVERRIDE_02',
    category: 'POLICY_OVERRIDE',
    riskLevel: 'HIGH',
    riskScore: 0.92,
    description: 'Privilege escalation or fake authorization assertion',
    regex: /(?:system\s+administrator\s+override|cfo\s+override|emergency\s+(?:banking\s+)?protocol\s+#?\d+|bypass\s+(?:kyc|aml|compliance|2fa|security\s+checks?)|auth(?:orized)?\s+by\s+(?:cfo|ceo|admin|compliance))/i,
  },
  {
    id: 'OVERRIDE_03',
    category: 'POLICY_OVERRIDE',
    riskLevel: 'HIGH',
    riskScore: 0.85,
    description: 'New policy injection declaration',
    regex: /(?:new\s+rule\s*:|from\s+now\s+on\s*,\s*(?:you\s+must|you\s+will|disregard)|you\s+are\s+no\s+longer\s+bound\s+by)/i,
  },

  {
    id: 'OVERRIDE_04',
    category: 'POLICY_OVERRIDE',
    riskLevel: 'CRITICAL',
    riskScore: 0.99,
    description: 'Request to disable firewall/security controls or bypass explicit transaction confirmation',
    // Block direct attempts to disable controls and requests to skip confirmation in a financial action.
    regex: /(?:\bdisable\s+(?:the\s+)?(?:firewall|security(?:\s+controls?)?|safeguards?)\b|\b(?:do\s+not|don't|without)\s+(?:ask\s+for\s+)?confirmation\b|\bskip\s+(?:the\s+)?confirmation\b)/i,
  },

  // 3. Roleplay & Jailbreaks
  {
    id: 'JAILBREAK_01',
    category: 'ROLEPLAY_JAILBREAK',
    riskLevel: 'CRITICAL',
    riskScore: 0.99,
    description: 'Known jailbreak persona persona (DAN / Developer Mode / Evil Twin)',
    regex: /(?:\bDAN\b\s*\((?:Do\s+Anything\s+Now)\)|developer\s+mode\s+(?:v\d+|enabled|active)|evil\s+(?:banker|twin|ai)|unfiltered\s+mode|unrestricted\s+ai|oppo\s+mode)/i,
  },
  {
    id: 'JAILBREAK_02',
    category: 'ROLEPLAY_JAILBREAK',
    riskLevel: 'HIGH',
    riskScore: 0.89,
    description: 'Hypothetical or fiction framing to circumvent ethical guardrails',
    regex: /(?:let(?:'s|\s+us)\s+play\s+a\s+game|in\s+a\s+fictional\s+world|pretend\s+(?:you\s+are|there\s+are\s+no\s+(?:rules|laws|limits))|hypothetically(?:,\s+if\s+you\s+had\s+to\s+steal|\s+speaking,\s+bypass))/i,
  },
  {
    id: 'JAILBREAK_03',
    category: 'ROLEPLAY_JAILBREAK',
    riskLevel: 'HIGH',
    riskScore: 0.82,
    description: 'Social engineering Grandma / emotional coercion jailbreak',
    regex: /(?:my\s+(?:late\s+)?grandmother\s+used\s+to\s+(?:read\s+me|tell\s+me)\s+(?:the\s+system\s+prompt|how\s+to\s+bypass)|act\s+as\s+my\s+dying\s+relative)/i,
  },

  // 4. Data Exfiltration & System Leakage Probes
  {
    id: 'EXFIL_01',
    category: 'DATA_EXFILTRATION',
    riskLevel: 'CRITICAL',
    riskScore: 0.95,
    description: 'Attempt to exfiltrate system prompt or hidden instructions',
    regex: /(?:reveal|print|output|display|show|leak|echo|dump|give\s+me)\s+(?:all\s+)?(?:the\s+)?(?:initial|system|hidden|internal|developer|secret|confidential)*\s*(?:system\s+)?(?:prompts?|instructions?|messages?|directives?|rules?|guidelines?)/i,
  },
  {
    id: 'EXFIL_02',
    category: 'DATA_EXFILTRATION',
    riskLevel: 'HIGH',
    riskScore: 0.90,
    description: 'Database dumping or credential exfiltration probe',
    regex: /(?:select\s+\*\s+from\s+(?:users|accounts|wallets|credentials|api_keys)|cat\s+\/etc\/passwd|env\s*\|\s*grep|dump\s+(?:database|credentials|keys))/i,
  },

  // 5. Code Injection / Shell Exec Probes
  {
    id: 'EXEC_01',
    category: 'DIRECT_PROMPT_INJECTION',
    riskLevel: 'CRITICAL',
    riskScore: 0.94,
    description: 'Direct code execution or shell evaluation payload injection',
    regex: /(?:;\s*rm\s+-rf|eval\s*\(|exec\s*\(|subprocess\.Popen|<script[\s>]|javascript:|curl\s+https?:\/\/.*\|\s*(?:sh|bash))/i,
  },
];

export function scanHeuristics(input: string): HeuristicScanResult {
  const startTime = performance.now();
  const matches: HeuristicMatch[] = [];

  for (const rule of HEURISTIC_RULES) {
    const match = input.match(rule.regex);
    if (match) {
      matches.push({
        ruleId: rule.id,
        category: rule.category,
        riskLevel: rule.riskLevel,
        riskScore: rule.riskScore,
        description: rule.description,
        matchedPattern: match[0],
      });
    }
  }

  const passed = matches.length === 0;
  let maxRiskScore = 0;
  let primaryThreat: ThreatCategory | null = null;
  let recommendedRiskLevel: RiskLevel = 'LOW';
  let rationale = 'Deterministic heuristic inspection passed: No known adversarial signatures or injection vectors detected.';

  if (!passed) {
    // Sort matches by risk score descending
    matches.sort((a, b) => b.riskScore - a.riskScore);
    const topMatch = matches[0];
    maxRiskScore = topMatch.riskScore;
    primaryThreat = topMatch.category;
    recommendedRiskLevel = topMatch.riskLevel;
    rationale = `Detected signature [${topMatch.ruleId}]: ${topMatch.description}. Matched pattern: "${topMatch.matchedPattern}".`;
  }

  const threatCategories = Array.from(new Set(matches.map((m) => m.category)));

  const endTime = performance.now();
  const latency = Math.round((endTime - startTime) * 100) / 100;

  return {
    passed,
    matches,
    threatCategories,
    primaryThreat,
    maxRiskScore,
    recommendedRiskLevel,
    rationale,
    latency_ms: latency,
  };
}
