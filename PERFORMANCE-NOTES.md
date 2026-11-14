# Performance changes

| Change | File | Effect |
|---|---|---|
| Combined endpoint `GET /api/investigations/:id/bundle` | `backend/controllers/investigationController.js`, `routes/analysisRoutes.js` | Opening a case: 6 requests / 15 queries -> 1 request / 5 parallel queries |
| Batched inserts in Run Analysis | `investigationController.js` (`batchInsert`) | 33 queries -> 12 (22 single-row INSERTs -> 3 multi-row INSERTs) |
| Health check + case list load in parallel; case data via `/bundle` | `frontend/app.js` | First page load: 9 requests -> 3 |
| Loading feedback (progress bar, buttons disabled while busy, "Running analysis…") | `frontend/app.js`, `style.css`, `index.html` | Clicks no longer feel frozen; prevents double-clicks |

The frontend falls back to the old separate requests automatically if an older backend without `/bundle` is deployed.
The old endpoints (`/evidence`, `/entities`, `/risk`, `/relationships`, `/timeline`) are unchanged.

## Not code - do this on Vercel
Set the function region to the one closest to your Aiven database (Vercel project -> Settings -> Functions -> Function Region).
A database in another continent adds 150-300 ms to EVERY query, which is usually the largest remaining delay.
