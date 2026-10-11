// Layer 0: Bounded De-cloaking Normalizer (< 2ms)
// Preserves original input for audit while inspecting a bounded set of normalization variants.
// Defends against zero-width characters, mixed-script homoglyphs, and encoded command payloads.

export interface NormalizerEvidence {
  type: string;
  original_segment: string;
  normalized_segment: string;
  rationale: string;
}

export interface NormalizerResult {
  original_input: string;
  normalized_variant: string;
  has_suspicious_mutation: boolean;
  obfuscation_detected: boolean;
  evidence: NormalizerEvidence[];
  latency_ms: number;
}

// Adversarial intent markers to verify decoded payloads against
const ADVERSARIAL_PAYLOAD_SIGNATURES = /(?:ignore|disregard|override|bypass|system\s+prompt|admin|root|transfer|wire|send|eval|cat\s+\/|exec)/i;

export function normalizeInput(rawInput: string): NormalizerResult {
  const startTime = performance.now();
  const original = rawInput || '';
  let variant = original;
  const evidence: NormalizerEvidence[] = [];
  let obfuscationDetected = false;

  // 1. Bounded Zero-Width & Control Characters Check
  // Flags invisible characters used to break keyword tokenizers
  const zeroWidthRegex = /[\u200B-\u200D\uFEFF\u00A0\u00AD\u2060\u202A-\u202E]/g;
  if (zeroWidthRegex.test(original)) {
    const stripped = original.replace(zeroWidthRegex, '');
    evidence.push({
      type: 'ZERO_WIDTH_STRIPPED',
      original_segment: '[INVISIBLE_UNICODE_DETECTED]',
      normalized_segment: stripped,
      rationale: 'Removed invisible zero-width unicode control characters that could break token boundaries.',
    });
    variant = stripped;
    obfuscationDetected = true;
  }

  // 2. Canonical NFKD Normalization
  const preNfkd = variant;
  const nfkd = variant.normalize('NFKD');
  if (preNfkd !== nfkd) {
    variant = nfkd;
  }

  // 3. Bounded Base64 Detection & Conditional De-cloaking
  // Only flags if decoded string is printable ASCII AND contains actionable instruction verbs
  const base64CandidateRegex = /\b[A-Za-z0-9+/]{20,}={0,2}\b/g;
  variant = variant.replace(base64CandidateRegex, (match) => {
    try {
      const decoded = Buffer.from(match, 'base64').toString('utf-8');
      // Must be readable printable ASCII text
      if (/^[\x20-\x7E\n\r\t]{10,}$/.test(decoded)) {
        if (ADVERSARIAL_PAYLOAD_SIGNATURES.test(decoded)) {
          obfuscationDetected = true;
          evidence.push({
            type: 'BASE64_ADVERSARIAL_PAYLOAD',
            original_segment: match,
            normalized_segment: decoded,
            rationale: `Decoded Base64 segment containing command keywords: "${decoded}"`,
          });
          return ` [DECODED_PAYLOAD: ${decoded}] `;
        }
      }
    } catch {
      // Non-destructive: preserve un-decodable tokens
    }
    return match;
  });

  // 4. Mixed-Script Homoglyph Detection
  // Common visual lookalikes (Cyrillic to Latin)
  const homoglyphMap: Record<string, string> = {
    '\u0430': 'a', '\u0410': 'A',
    '\u0435': 'e', '\u0415': 'E',
    '\u043E': 'o', '\u041E': 'O',
    '\u0440': 'p', '\u0420': 'P',
    '\u0441': 'c', '\u0421': 'C',
    '\u0443': 'y', '\u0423': 'Y',
    '\u0445': 'x', '\u0425': 'X',
    '\u0456': 'i', '\u0406': 'I',
  };

  const hasMixedCyrillic = /[\u0430\u0410\u0435\u0415\u043E\u041E\u0440\u0420\u0441\u0421\u0443\u0423\u0445\u0425\u0456\u0406]/.test(variant);
  if (hasMixedCyrillic) {
    const canonicalized = variant.replace(/[\u0430\u0410\u0435\u0415\u043E\u041E\u0440\u0420\u0441\u0421\u0443\u0423\u0445\u0425\u0456\u0406]/g, c => homoglyphMap[c] || c);
    if (ADVERSARIAL_PAYLOAD_SIGNATURES.test(canonicalized)) {
      obfuscationDetected = true;
      evidence.push({
        type: 'HOMOGLYPH_EVASION_ATTEMPT',
        original_segment: variant,
        normalized_segment: canonicalized,
        rationale: 'Detected mixed-script Cyrillic homoglyphs disguising command keywords.',
      });
      variant = canonicalized;
    }
  }

  // 5. Bounded Leetspeak Canonicalization
  const leetSubstitutions: Array<[RegExp, string]> = [
    [/\b1gn[0o]r[3e]\b/gi, 'ignore'],
    [/\bbyp[@a]ss\b/gi, 'bypass'],
    [/\b[o0]v[3e]rr[1i]d[3e]\b/gi, 'override'],
    [/\b[a@]dm[1i]n\b/gi, 'admin'],
  ];

  for (const [regex, replacement] of leetSubstitutions) {
    if (regex.test(variant)) {
      obfuscationDetected = true;
      evidence.push({
        type: 'LEETSPEAK_OBFUSCATION',
        original_segment: variant,
        normalized_segment: variant.replace(regex, replacement),
        rationale: `Substituted leetspeak variation targeting "${replacement}".`,
      });
      variant = variant.replace(regex, replacement);
    }
  }

  const endTime = performance.now();
  const latency = Math.round((endTime - startTime) * 100) / 100;

  return {
    original_input: original,
    normalized_variant: variant.trim(),
    has_suspicious_mutation: evidence.length > 0,
    obfuscation_detected: obfuscationDetected,
    evidence,
    latency_ms: latency,
  };
}
