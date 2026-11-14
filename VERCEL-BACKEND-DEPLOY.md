# TRACELYT AI — Vercel deployment

## Recommended: deploy the complete app as one Vercel project

This archive keeps the complete frontend and backend together. The root `vercel.json` and `api/index.js` serve the frontend and route API requests to the Express backend.

1. Extract the ZIP.
2. If you upload the extracted `tracelyt` folder contents to GitHub repository root, set Vercel **Root Directory** to `./`.
   If you upload the outer folder unchanged, set Vercel **Root Directory** to `tracelyt`.
3. Framework Preset: **Other**.
4. Use Node.js 20 or newer.
5. Add the environment variable `DATABASE_URL` with your PostgreSQL connection string.
6. Optionally add `DATABASE_CA` if your database provider requires a CA certificate.
7. Deploy. The frontend and API use the same domain; no separate `FRONTEND_ORIGIN` is needed for same-origin browser requests.

Check `https://YOUR-DOMAIN.vercel.app/api/health`. A successful response includes `ok: true` and `database: connected`.

## Separate backend deployment option

The `backend/package.json` and `backend/vercel.json` are copied from the supplied backend-configuration ZIP, as requested. To deploy only the backend as a separate Vercel project, import the same repository and set **Root Directory** to `backend`. Set `DATABASE_URL`, `FRONTEND_ORIGIN` (the exact frontend deployment origin), and optionally `DATABASE_CA`. Deploy the frontend separately from `frontend/`, then set its API URL in Settings to the backend deployment origin.

## Important

- Never commit `.env`, real database passwords or API secrets.
- Vercel serverless storage is ephemeral. Uploaded screenshot files in this prototype are not durable; use object storage for persistent evidence files.
- The app's risk engine is rule-based and explainable, not a machine-learning fraud probability.
- Screenshot OCR is not installed. Type visible screenshot text into the evidence record before analysis.
- The PDF report is an investigative summary, not a statutory certificate or proof of chain of custody.
