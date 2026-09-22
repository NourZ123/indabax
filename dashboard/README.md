# SENTINEL dashboard — frontend MVP

A React + Vite + TypeScript frontend designed to live alongside the existing SENTINEL simulator and `my-defense` folder. The approved design is a restrained, Cloudflare-inspired light security console with **dot-and-text decisions (no pills)**. See `design-reference.png` for the original approved visual reference.

**Current scope:** frontend only. The application launches with **clearly marked synthetic demonstration data**. The charts, example evaluation percentages and demonstration scenario outcomes are **not benchmark measurements**. No simulator, LLM or live defense is connected until the dashboard backend is implemented.

## Integrate into your existing repo

Extract the ZIP **at the root of** `NourZ123/indabax` so that you have:

```text
indabax/
├── my-defense/
├── src/sentinel/
├── scenarios/
├── policies/
└── dashboard/
    ├── design-reference.png
    ├── README.md
    └── frontend/
        ├── src/
        ├── package.json
        └── vite.config.ts
```

**Do not replace or merge any files under `my-defense/`.** This is a self-contained frontend addition.

## Run locally on Pop!_OS

Requires Node.js 20+ and an internet connection for the initial npm dependency installation.

```bash
cd indabax/dashboard/frontend
npm install
npm run dev
```

Open **http://127.0.0.1:5173**. Initially, the app redirects to the illustrative `RUN-042` trace, matching your approved screenshot.

```bash
npm run build       # strict TypeScript check and production Vite build
npm run preview     # preview the compiled production app
npm run typecheck   # TypeScript only
```

The frontend dev server uses **5173**, while your defense service can continue using **8080**. They do not interfere. No backend is required to see and interact with demo pages.

## Implemented pages

- **Overview:** time-filtered metrics, daily decision activity, domain coverage, recent runs and recent interventions.
- **Runs:** filter/search run list, clickable trace rows, action inspector with Details / Defense analysis / Provenance / Raw data, step navigation, decision filters, risk bars, decision distribution, Summary / Artifacts / Evaluator tabs and JSON/CSV exports.
- **Evaluations:** experiment comparison table, baseline/ablation filters, task-utility vs. attack-success bars, downloadable CSV.
- **Policies:** Enterprise / Finance / SOC selection, permission table, confirmation requirements, rule inspector, related decision signals. **Read-only.**
- **Incidents:** a filterable queue of blocked, escalated and rewritten actions.
- **Data & Artifacts:** downloadable normalized demonstration run records.
- **Playground:** editable JSON request and parser; does not fabricate defense decisions in demo mode. A future backend may implement POST `/api/playground`.
- **Settings:** local table-density preference and connection guidance.

Global search matches run IDs, scenario names and tool names. The global time-range selector filters run-based pages. All action statuses use a small colored dot plus plain text, as requested.

## Future backend connection

The frontend is deliberately decoupled from the existing defense API. **Do not send run-history or evaluation UI traffic through `POST /v1/decision`.** Keep decision enforcement and dashboard observability separate.

When a dashboard FastAPI adapter exists, expose:

```text
GET /api/dashboard
```

It should return the `DashboardData` structure from `frontend/src/types/sentinel.ts`:

```json
{
  "runs": [],
  "policies": [],
  "experiments": []
}
```

Use `frontend/src/data/demo.ts` only as an example of the expected field shapes. The real backend should parse saved SENTINEL traces/evaluation artifacts, record explicit outcome values and report missing fields as `null` rather than guessing. Scenario-effective permissions can differ from general policy files.

To switch to API mode:

```bash
cd dashboard/frontend
cp .env.example .env
# Edit .env:
# VITE_DASHBOARD_MODE=api
npm run dev
```

Vite proxies `/api` to `http://127.0.0.1:8090` in development. The backend on that port **does not exist in this frontend-only delivery**.

Optional future endpoint for the Playground:

```text
POST /api/playground
```

## Security and correctness requirements for integration

- **Redact credentials and restricted values on the backend**, before placing traces into browser-visible API responses. The frontend's demo redactions are not a substitute for backend sanitization.
- Never infer `attack_success` or `task_success` from a single block or allow decision. Ingest authoritative simulator/evaluator outcomes.
- Keep action risk scores distinct from measured evaluation outcomes; missing signals must be represented as missing.
- The frontend JSON and CSV exports operate on the records loaded into the browser. CSV export escapes cells beginning with common spreadsheet formula characters.
- The selected Policies environment shows illustrative, general policy data. Do not present it as the exact `policy_context` of every scenario.

## Suggested Git workflow

From the repository root, after extraction:

```bash
git switch defense-v2
git switch -c dashboard-mvp
git add dashboard/
git commit -m "Add SENTINEL frontend dashboard"
git push -u origin dashboard-mvp
```

Create a PR from `dashboard-mvp` into `defense-v2` after local testing and team review.
