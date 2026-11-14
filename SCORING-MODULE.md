# Explainable Risk Scoring Module (0-100)

Added to the Rule-Driven Analysis & Relationship Engine. Everything else in the project is unchanged.

## Files
| File | Change |
|---|---|
| `backend/services/riskScorer.js` | **NEW** - the scoring module (pure function, no DB, no network) |
| `backend/services/riskAnalyzer.js` | calls `scoreFindings()` and returns `risk_score`, `score_band`, `score_label`, `score_breakdown` |
| `backend/controllers/investigationController.js` | new `getScore` handler |
| `backend/routes/analysisRoutes.js` | new route `GET /api/investigations/:id/score` |
| `backend/services/reportGenerator.js` | score + breakdown added to the JSON/PDF report |
| `backend/tests/engine.test.js` | 4 new tests (run: `node backend/tests/engine.test.js`) |
| `frontend/insight.js`, `app.js`, `style.css` | gauge, breakdown table, score chips |

No database migration is needed: the score is computed live from the stored entities, exactly like the existing risk rating.

## How the score is calculated
1. Each rule has a fixed **weight** (`RULE_WEIGHTS` at the top of `riskScorer.js`).
2. **Findings count**: first finding of a rule = full weight; each extra finding of the same rule adds 25% (max 2 extras).
3. **Diversity bonus**: +5 per indicator category beyond the second (max +15).
4. Total is **capped at 100**.
5. **Consistency**: a *High concern* rating is never scored below 60, any other rating is never scored above 59.

Bands: 0 none · 1-29 Low · 30-59 Moderate · 60-79 High · 80-100 Critical.

Default weights: OTP/credential request 25, remote access 25, suspicious URL 20, urgency 15, account-block claim 15,
verification fee 15, payment wording 10, UPI payment request 10, impersonation 10, KYC claim 8, verify request 8, click-link 5.
To tune the scoring, edit only the `RULE_WEIGHTS` table.

## API
`GET /api/investigations/:id/risk`  -> existing payload + `risk_score`, `score_band`, `score_label`, `score_breakdown`
`GET /api/investigations/:id/score` -> score and breakdown only

The score is an indicator-weight score. It is **not** a probability of fraud and not proof of wrongdoing.

## Single-evidence behaviour
The score depends only on the findings, never on having several evidence items, so one item gets a full score.
- Saving (or editing) evidence now runs the analysis automatically, so the score is ready without pressing Run Analysis.
- A fully analysed item with no indicators shows **"No indicators found" / score 0** (not "Insufficient evidence"). This is not proof the content is safe.
- Added rules: prize/lottery, easy-loan, work-from-home, service-disconnection threat and app-install instructions; OTP requests are
  also recognised as "asked for / need your OTP". Genuine warnings such as "Never share your OTP" are not flagged.
