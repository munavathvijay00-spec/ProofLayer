# Deployment — Render backend + Vercel frontend

## Render

1. Push this directory to your repository and create a Python Web Service using `backend` as the root directory.
2. Build command: `pip install -r requirements.txt`.
3. Start command: `python -m uvicorn app.main:app --host 0.0.0.0 --port $PORT`.
4. Set `ENVIRONMENT=production`, a strong random `CONSOLE_API_KEY`, and `CORS_ORIGINS` to the exact deployed frontend origin. For multiple explicit origins, separate with commas.
5. Optional live mode: set `OPENAI_API_KEY` and `OPENAI_MODEL` on Render only.
6. Set `DB_PATH=/var/data/prooflayer.db` and attach a persistent disk mounted at `/var/data`. Without a persistent disk, audit history disappears on redeployment/restart. Run one service instance with one Uvicorn worker: this SQLite prototype is not designed for multiple replicas.
7. Set health check path to `/health`. Verify that anonymous `/events` returns 401 and requests with your console key succeed.

`render.yaml` provides an optional Blueprint configuration with a persistent disk. A disk may require a paid service plan; inspect pricing and host choices before provisioning. This build did not create a billed resource.

## Vercel

1. Import the same repository, set root directory to `frontend`, and select the Next.js framework.
2. Set `BACKEND_URL` to your backend's HTTPS origin **before building** to use the default same-origin proxy. Alternatively, set `NEXT_PUBLIC_API_URL` for direct browser-to-backend requests. These URLs are not credentials.
3. Deploy and add that exact frontend origin to backend `CORS_ORIGINS`. Redeploy the backend if the variable changed.
4. In the console's **Connection settings**, enter the backend `CONSOLE_API_KEY`. It stays in browser memory and is lost on refresh; never place it in a `NEXT_PUBLIC_*` variable.
5. Run the email scenario protected and baseline, run evaluation, and download the evidence JSON.

## Go-live checks

- Browser indicates API connected with no CORS or mixed-content errors.
- Live mode is enabled only when a backend model key is configured; run at least one successful model call.
- A denied event has `executed=false`, `result=null`, and no matching local outbox/export/restricted-read effect.
- Protected workflow persists a verified summary with agent-submitted facts matching the source.
- Baseline can only produce synthetic local effects.
- Download and retain live traces, replay results, and regression-test output separately.

## Demo sequence — 90 seconds

1. Show the user's narrow invoice task and injected instruction in the source document.
2. Run a live protected trial. If the model proposes an attack, open that call and show denial, no executor invocation, and the summary outcome.
3. If the model refuses the injection, say so and switch to explicitly labeled vulnerable replay to show the independent boundary.
4. Run baseline to reveal the persisted synthetic unauthorized effect.
5. Run the suite and show observed blocking, trials without attacks, unauthorized effects, and verified summary counts.
6. Explain the boundary: independent authorization of tool calls, not a claim to detect every injection or sandbox arbitrary code.

Live evaluation jobs run in the backend process and are polled through the API. Restarts mark unfinished jobs interrupted; jobs are not retried automatically. Model and Vercel/Render credentials were not configured, so no live-provider result or hosted deployment is claimed.

## Local model demo without API charges

Use the Ollama setup in README.md on your Mac and run both services there. Do not set `MODEL_PROVIDER=ollama` on Render unless an Ollama server is actually reachable from that backend. A remote backend cannot use your Mac's localhost. The Cloud Browser replay remains available without model credentials.
