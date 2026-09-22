# SENTINEL Security Dashboard — integrated MVP

This folder contains the previously approved Cloudflare-inspired React interface **plus a new read-only FastAPI adapter** that reads saved artifacts from the official SENTINEL simulator. It does not alter `my-defense/` or the official simulator.

## Architecture

```text
indabax/
  my-defense/                     existing decision service :8080
  src/sentinel/                   official simulator; do not modify
  policies/                        official YAML policy definitions
  scenarios/                       scenario titles + allowed tool lists
  artifacts/                       created by `sentinel run/eval`
  dashboard/
    backend/                       read-only FastAPI adapter :8090
    frontend/                      React + Vite :5173
    design-reference.png           approved visual reference
```

Data flow: simulator saves **JSONL events**, `*.summary.json` outcomes and `scorecards/*.json` evaluations → dashboard backend normalizes and redacts → frontend `/api/dashboard` via Vite's proxy. The defense service on `:8080` remains entirely independent.

## 1. Add it to your branch

Extract the integrated ZIP **at the root of your existing `indabax/` checkout**. It contains only `dashboard/`. If you already extracted the earlier frontend ZIP, the new ZIP replaces those frontend files with the API-compatible version and adds `dashboard/backend/`.

```bash
cd ~/path/to/indabax
git switch defense-v2
git switch -c dashboard-mvp
unzip -o ~/Downloads/sentinel-dashboard-integrated.zip -d .
```

If you already created `dashboard-mvp`, just `git switch dashboard-mvp`; don't create it twice. Review `git diff` before committing.

## 2. Run the defense (terminal A)

```bash
cd ~/path/to/indabax/my-defense
uvicorn app.main:app --host 127.0.0.1 --port 8080
```

Use the virtual environment/dependencies you already installed for the defense. The dashboard does not require this service simply to display previously recorded runs.

## 3. Generate a real trace (terminal B)

From the **repository root**:

```bash
cd ~/path/to/indabax
uv sync
uv run sentinel run \
  --scenario scenarios/public/enterprise/enterprise_poisoned_invoice.yaml \
  --defense-url http://127.0.0.1:8080 \
  --model mock \
  --artifacts artifacts
```

The official simulator writes `artifacts/<unique-group>/<run-id>.jsonl` and a matching `artifacts/<unique-group>/<run-id>.summary.json`. The dashboard reads those files; it doesn't need Qwen3-8B or Hugging Face.

## 4. Run the dashboard backend (terminal C)

From the **repository root** (its `pyproject.toml` already has FastAPI, Uvicorn and PyYAML):

```bash
uv run uvicorn dashboard.backend.app:app --host 127.0.0.1 --port 8090
```

Check `http://127.0.0.1:8090/api/healthz` and `http://127.0.0.1:8090/api/dashboard`. If you saved artifacts elsewhere, set `SENTINEL_ARTIFACTS_DIR` before starting Uvicorn, e.g. `SENTINEL_ARTIFACTS_DIR=/absolute/path/to/artifacts uv run uvicorn dashboard.backend.app:app --host 127.0.0.1 --port 8090`.

The read-only endpoints are:

- `GET /api/dashboard` — all runs, domain policies and scorecard experiments
- `GET /api/runs` and `GET /api/runs/{run_id}` — normalized runs
- `GET /api/evaluations` — actual saved scorecards only
- `GET /api/policies` — the repository's actual YAML policies
- `GET /api/healthz` and `GET /api/docs` — health and API docs

There is intentionally no endpoint for modifying policies, sending emails, executing tools or altering defense decisions. `Playground` remains a future feature; its POST endpoint is not included in this read-only MVP.

## 5. Run the React frontend (terminal D)

```bash
cd ~/path/to/indabax/dashboard/frontend
npm install
cp .env.api.example .env
npm run dev
```

Open **http://127.0.0.1:5173**. The frontend proxies `/api/` to port 8090. In API mode it defaults to **All time**, so deterministic simulator timestamps do not hide newly saved runs. To use illustrative data instead, change `.env` to `VITE_DASHBOARD_MODE=demo` and restart Vite.

Once the UI is working, the `Runs` page should show your actual scenario, defense decisions, measured risk scores, reason codes and **defense latencies** (when a matching `.summary.json` exists). Select a row to open the decision inspector. `Evaluations` displays only saved `scorecards/*.json`; run `uv run sentinel eval public --defense-url http://127.0.0.1:8080 --artifacts artifacts` to populate it.

## 6. Tests

From the repository root:

```bash
uv run pytest -q dashboard/backend/tests
cd dashboard/frontend
npm run typecheck
npm run build
```

The Python tests exercise the same JSONL event and `.summary.json` shapes emitted by the official simulator, with synthetic fixtures. For full end-to-end verification, record a real scenario, then inspect the dashboard's trace and compare it with the simulator's replay.

## Data limitations and security

- **Server-side redaction by default.** Arbitrary free text such as `body`, `content`, `query`, `subject`, tool results and defense explanations is not returned to the browser. Recipient local parts are masked; known synthetic record IDs and structured statuses may be displayed. Never publish `artifacts/` or expose the dashboard API publicly without authentication.
- Real simulator `DEFENSE_DECISION` events record decision, risk, confidence, reason codes, original action and any rewrite. They **do not record** the defense's `metadata` containing per-module scores. The Risk Analysis bars correctly show “—” until you add an *explicit opt-in, redacted* metadata journal; this adapter does not invent signals.
- The simulator logs a **logical clock**. Its event timestamps show ordering, not wall-clock step duration. The UI's trace “Defense latency” is evaluator-measured when a summary exists. Run duration, model identity and other unrecorded fields are shown as unavailable rather than guessed.
- A failed attack is **not necessarily an attack blocked by the defense**. Actual evaluator summary outcomes populate `taskSuccess`, `attackSuccess`, `criticalViolation` and `dataFlowViolation` independently. A missing summary yields `not_evaluated` and `null` outcome flags.
- Policy YAML contains **domain-wide rules**, not a blanket list of permitted tools. Permissions vary by scenario. The Run Summary tab also reads scenario-specific `allowed_tools`, `policy_profile` and `forbidden_effects` when its scenario YAML is available.
- Official decision events do not include complete source-provenance records. The UI does **not** infer or fabricate source trust from action arguments.
- Only HTTP `127.0.0.1` is recommended. The backend is local/read-only with no authentication in this hackathon MVP.

## Commit

```bash
git add dashboard/
git diff --staged
git commit -m "Connect SENTINEL dashboard to real run artifacts"
git push -u origin dashboard-mvp
```

Open a pull request **from `dashboard-mvp` into `defense-v2`** after checking your actual run in the dashboard.
