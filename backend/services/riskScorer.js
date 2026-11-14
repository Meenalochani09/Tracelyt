'use strict';
// Explainable Risk Scoring Module (0-100)
// ------------------------------------------------------------------------------------------
// Turns the findings produced by the rule engine (riskAnalyzer.js) into ONE numeric score.
//
// How the score is calculated (every step is returned in `breakdown` so it can be shown in the UI):
//   1. Each rule has a fixed indicator WEIGHT (see RULE_WEIGHTS below).
//   2. Findings count: the first finding of a rule earns its full weight. Each extra, distinct
//      finding of the same rule adds REPEAT_BONUS (25%) of the weight, up to MAX_REPEATS extras.
//   3. Diversity bonus: +DIVERSITY_BONUS for every indicator category beyond the second
//      (scam messages usually combine several tactics), up to MAX_DIVERSITY_BONUS.
//   4. The total is capped at 100.
//   5. Consistency with the rule-based rating (so the number never contradicts the label):
//        - high_concern rating  -> score is at least HIGH_FLOOR
//        - any other rating     -> score is at most HIGH_FLOOR - 1
//      When this adjustment changes the number, it is reported as an adjustment line.
//
// The score measures how many weighted scam indicators were observed. It is NOT a probability
// of fraud and NOT proof that anyone committed fraud.
// ------------------------------------------------------------------------------------------

// Indicator weights. Edit this table to tune the scoring - nothing else needs to change.
// `group` is the label shown in the UI (matches the five indicator groups in the architecture).
const RULE_WEIGHTS = {
  otp_request:      { weight: 25, group: 'OTP / credential request' },
  remote_access:    { weight: 25, group: 'Remote access' },
  suspicious_url:   { weight: 20, group: 'Suspicious links' },
  urgency:          { weight: 15, group: 'Urgency' },
  account_block:    { weight: 15, group: 'Urgency' },
  verification_fee: { weight: 15, group: 'Payment demands' },
  payment_request:  { weight: 10, group: 'Payment demands' },
  upi_request:      { weight: 10, group: 'Payment demands' },
  impersonation:    { weight: 10, group: 'Impersonation' },
  kyc_claim:        { weight: 8,  group: 'Impersonation' },
  verify_request:   { weight: 8,  group: 'OTP / credential request' },
  click_link:       { weight: 5,  group: 'Suspicious links' },
};
const DEFAULT_WEIGHT = 5; // any future rule without an explicit weight

const REPEAT_BONUS = 0.25;
const MAX_REPEATS = 2;
const DIVERSITY_BONUS = 5;
const MAX_DIVERSITY_BONUS = 15;
const HIGH_FLOOR = 60;

// Score bands. `max` is inclusive.
const BANDS = [
  { max: 0,   id: 'none',     label: 'No indicators',  colour: '#53e5b3' },
  { max: 29,  id: 'low',      label: 'Low risk',       colour: '#53e5b3' },
  { max: 59,  id: 'moderate', label: 'Moderate risk',  colour: '#eabf79' },
  { max: 79,  id: 'high',     label: 'High risk',      colour: '#ff9a6b' },
  { max: 100, id: 'critical', label: 'Critical risk',  colour: '#ff8e91' },
];

const bandFor = (score) => BANDS.find((b) => score <= b.max) || BANDS[BANDS.length - 1];

// findings: array from riskAnalyzer. riskLevel: 'high_concern' | 'needs_verification' | 'insufficient_evidence'
function scoreFindings(findings, riskLevel) {
  const list = Array.isArray(findings) ? findings : [];

  // Group findings by rule.
  const byRule = new Map();
  for (const f of list) {
    if (!byRule.has(f.rule_id)) byRule.set(f.rule_id, []);
    byRule.get(f.rule_id).push(f);
  }

  const breakdown = [];
  let subtotal = 0;
  for (const [ruleId, fs] of byRule) {
    const cfg = RULE_WEIGHTS[ruleId] || { weight: DEFAULT_WEIGHT, group: 'Other' };
    const extras = Math.min(Math.max(fs.length - 1, 0), MAX_REPEATS);
    const points = Math.round(cfg.weight * (1 + REPEAT_BONUS * extras) * 10) / 10;
    subtotal += points;
    breakdown.push({
      rule_id: ruleId,
      indicator: fs[0].indicator,
      group: cfg.group,
      category: fs[0].category,
      weight: cfg.weight,
      findings_count: fs.length,
      repeat_multiplier: 1 + REPEAT_BONUS * extras,
      points,
      evidence_ids: [...new Set(fs.map((f) => f.evidence_id))],
    });
  }
  breakdown.sort((a, b) => b.points - a.points);

  const categories = new Set(list.map((f) => f.category));
  const diversity = Math.min(Math.max(categories.size - 2, 0) * DIVERSITY_BONUS, MAX_DIVERSITY_BONUS);

  const adjustments = [];
  if (diversity > 0) {
    adjustments.push({ id: 'diversity', label: `Multiple tactic types combined (${categories.size} categories)`, points: diversity });
  }

  let raw = Math.round(subtotal + diversity);
  let score = Math.min(raw, 100);
  if (raw > 100) adjustments.push({ id: 'cap', label: 'Capped at 100', points: 100 - raw });

  // Keep the number consistent with the rule-based rating.
  if (list.length && riskLevel === 'high_concern' && score < HIGH_FLOOR) {
    adjustments.push({ id: 'high_floor', label: `Raised to the minimum for a High-concern rating (credential/OTP or remote-access request, or 3+ indicator types)`, points: HIGH_FLOOR - score });
    score = HIGH_FLOOR;
  } else if (list.length && riskLevel !== 'high_concern' && score > HIGH_FLOOR - 1) {
    adjustments.push({ id: 'below_high', label: `Held below ${HIGH_FLOOR}: no credential/OTP or remote-access request and fewer than 3 indicator types`, points: (HIGH_FLOOR - 1) - score });
    score = HIGH_FLOOR - 1;
  }
  if (!list.length) score = 0;

  const band = bandFor(score);

  // Group totals for the "indicator groups" view (OTP requests, Urgency, Suspicious links, ...).
  const groupMap = new Map();
  for (const b of breakdown) groupMap.set(b.group, (groupMap.get(b.group) || 0) + b.points);
  const groups = [...groupMap.entries()].map(([group, points]) => ({ group, points: Math.round(points * 10) / 10 })).sort((a, b) => b.points - a.points);

  const explanation = !list.length
    ? 'Score 0: no rule matched the submitted evidence. This does not mean the content is safe.'
    : `Score ${score}/100 (${band.label}): ${breakdown.length} indicator rule(s) fired across ${categories.size} categor${categories.size === 1 ? 'y' : 'ies'}. ` +
      `Top contributors: ${breakdown.slice(0, 3).map((b) => `${b.indicator} (+${b.points})`).join(', ')}.` +
      (adjustments.length ? ` Adjustments: ${adjustments.map((a) => a.label).join('; ')}.` : '');

  return {
    risk_score: score,
    score_band: band.id,
    score_label: band.label,
    score_colour: band.colour,
    score_max: 100,
    score_breakdown: {
      formula: 'score = Σ(rule weight × repeat multiplier) + diversity bonus, capped at 100, then aligned with the rule-based rating',
      subtotal: Math.round(subtotal * 10) / 10,
      indicators: breakdown,
      groups,
      adjustments,
      explanation,
      bands: BANDS.map((b) => ({ id: b.id, label: b.label, upto: b.max })),
      disclaimer: 'Indicator-weight score, not a probability of fraud and not proof of wrongdoing.',
    },
  };
}

module.exports = { scoreFindings, bandFor, RULE_WEIGHTS, BANDS, HIGH_FLOOR };
