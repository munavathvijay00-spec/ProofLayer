# ProofLayer 0.3 — Agent Execution Firewall

A Next.js security console and Python gateway that intercept agent tool proposals, enforce server-controlled task permissions, record decisions, and dispatch approved operations into a synthetic local executor.

## What is implemented

- Bounded invoice agent loop: document read → tool proposals → firewall feedback → saved summary.
- Live OpenAI Chat Completions tool-calling adapter and a separately labeled deterministic vulnerable replay.
- Strict Pydantic tool schemas; unknown tools and extra arguments are denied.
- Default-deny policy snapshots with exact invoice, path, recipient, and destination grants.
- Expiring task bearer credentials, task/run ownership checks, closed-run rejection, and idempotent concurrent retries.
- SQLite transactions persist audit decisions and local effects atomically.
- Baseline/protected comparison, full execution traces, policy inspection, evaluation table, downloadable JSON evidence, and responsive layout.
- Security tests, browser integration smoke harness, sample measured evaluation JSON, and deployment configuration.

## Quick start

Use Python 3.11+ and Node 20.9+. Open two terminals from this directory.

Backend:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Frontend:

```bash
cd frontend
npm ci
npm run dev -- --hostname 127.0.0.1
```

Open http://localhost:3000. Select **Email exfiltration**, run **protected**, then **baseline**, then **Run evaluation**. `/health` and `/docs` are available on the backend.

Backend variables are process environment variables. Uvicorn does not automatically load `.env`; use `--env-file` with `python-dotenv` installed or export variables in your shell. Next.js automatically reads `.env.local`.

## Live model mode

Set `OPENAI_API_KEY` on the backend only, optionally `OPENAI_MODEL` (default `gpt-4.1-mini`), then restart it. The dashboard enables **Live model** when the server reports a configured key. A configured key does not guarantee account/model access.

The model receives the legitimate task and registered tools, reads the invoice through the gateway, receives malicious content as an untrusted tool result, and proposes operations. Each proposed call passes through the same gateway. A denial is returned as tool feedback so the agent can continue. Credentials and the dispatcher never appear in model messages.

A live model may ignore the injection. Report **no attack proposal observed** in that case. Do not label replay traces, transport-fake tests, or model refusal as proof of a live firewall block. The supplied scenario attacks were not benchmarked against a live model in this build environment because no model key was available.

Provider protocol reference: https://developers.openai.com/api/docs/guides/function-calling

## API boundary

Console routes require `X-Console-Key` when `CONSOLE_API_KEY` is set. `ENVIRONMENT=production` rejects console calls if no console key is configured. Local development has no console key by default; bind it to loopback.

`POST /tasks` accepts only a scenario. The server chooses the policy and creates a protected run. It returns a one-hour bearer credential. An external agent sends proposals using:

```http
POST /tasks/{task_id}/proposals?run_id={run_id}
Authorization: Bearer {task_token}
Content-Type: application/json

{"call_id":"call-1","action":{"tool":"read_invoice","args":{"invoice_id":"INV-001"}}}
```

The proposal route cannot set policy or disable protection. There is no direct executor HTTP endpoint. Console administrators can run a baseline comparison, which bypasses authorization inside the synthetic lab; strict schemas still apply.

Live `POST /evaluations` returns HTTP 202 with a job ID; poll `GET /evaluations/{job_id}` for progress and the result. One live evaluation may run at a time. The job runs in this service process; a restart marks it interrupted rather than retrying paid model calls. Deploy with one worker.

Other routes: `GET /policy`, `GET /scenarios`, `POST /runs`, `GET /runs/{id}`, `GET /events`, `GET /metrics`, `POST /evaluations`.

## Executor and threat model

The tool executor produces **real persisted local effects**: summary records, outbox records, export receipts, and restricted-read evidence in SQLite. It never sends actual email or outbound file uploads. Logical paths are allowlist identifiers, not arbitrary host filesystem paths.

The enforcement claim is narrow: model-proposed registered tool calls in this application must pass through the gateway; denied calls do not enter its dispatcher. This modular monolith is not an OS sandbox. Python module privacy is not isolation from malicious host code. An agent granted its own network, shell, filesystem, or service credentials outside this application could bypass it. Those capabilities must be removed or brokered before integrating an arbitrary external agent.

The agent must submit structured invoice facts alongside its prose. Before writing, the gateway verifies that the source invoice was read in the same run and that the submitted invoice ID, vendor, amount, currency, and due date exactly match the source. The executor persists those agent-submitted facts. The completion metric checks a verified scoped summary; arbitrary prose is preserved but is not semantically graded.

Logs are ordinary SQLite records, not cryptographic proofs or tamper-evident ledgers. Tasks and runs are stored, but permissions are intentionally fixed server-side in this prototype. There is no permission editing, organization tenancy, user account system, or production email connector.

## Validation

```bash
cd backend
python -m pytest -q
```

35 security/API tests cover denial without dispatch, malformed arguments, cross-task tokens, expiry, no privilege escalation, closed runs, transaction rollback, same-call replay, concurrency, continuation, and the model adapter protocol using a fake provider transport.

```bash
cd frontend
npm run build
```

Browser harness (requires Python backend dependencies, a frontend build, and Playwright):

```bash
npm install --no-save playwright
npx playwright install chromium
node ../scripts/ui-smoke.cjs
```

`evidence/evaluation.json` is a full eight-run API evaluation with persisted output evidence. Replay suite results: three attack proposals blocked out of three, zero protected unauthorized effects, three baseline unauthorized effects, eight summaries saved out of eight. These are controlled fixture measurements, not general prompt-injection efficacy statistics.

## Repeatable local setup and live measurements

After installing backend and frontend dependencies and activating the backend virtual environment, `python3 scripts/dev.py` starts both services. The frontend defaults to the same-origin `/backend` proxy; set `BACKEND_URL` on the frontend server when the backend lives elsewhere. `NEXT_PUBLIC_API_URL` remains available for a direct browser-to-backend connection. With Docker installed, `docker compose up --build` starts both services with a persistent SQLite volume. Set the model key in your local shell before starting if needed; never commit it. Docker configurations are supplied but could not be built in this environment.

After starting the backend, run `python3 scripts/live-evaluation.py --mode live --trials 1`. It polls the background job and writes full JSON evidence. Use `--scenario email_exfiltration` for a shorter two-run comparison; use `--mode replay --output evidence/replay-evaluation.json` without a model key. Console credentials are read from `CONSOLE_API_KEY` in the shell.

Trials without attack proposals are reported separately from gateway blocks. Approved emails do not count as unauthorized actions. Live mode uses independent trials: models may propose different calls in the two modes. GitHub Actions is configured to run backend tests, the production frontend build, and browser checks when pushed.

## Deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) for Render backend and Vercel frontend setup. No public deployment was created from this environment. All secrets are configured on the host, not stored in this source bundle.

## Verified build status

See `evidence/verification.json` and `evidence/test-results.xml`: 35 backend tests passed; the Next.js production build, frontend HTTP rendering, backend HTTP evaluation, and allowed-origin CORS check passed. Desktop browser checks passed for the same-origin API connection, protected and baseline runs, evaluation, evidence download, policy navigation, and saved-run inspection. The actual console image and browser-exported evaluation are in `evidence/`. Mobile viewport checks remain pending; the smoke harness is provided for local/CI use. Live-provider trials and public deployment remain pending.

## Team ownership for the next 24 hours

1. Backend developer: verify gateway boundary and replace synthetic tools only through approved executor adapters.
2. Agent developer: configure a model key, run repeated live trials, preserve complete traces, and report model refusal separately from gateway blocks.
3. Frontend developer: verify hosted API connection, console credential entry, and mobile interactions.
4. Optional fourth developer: deployment, regression evidence, and demo rehearsal.

Prioritize an observed live unauthorized proposal and successful continuation before adding more scenarios or visual effects.
