# SENTINEL React dashboard

React + Vite + TypeScript frontend, preserving the approved light interface and dot-and-text decisions. The integrated package also contains the read-only API at `../backend`.

From `dashboard/frontend/`: `npm install`, `cp .env.api.example .env`, `npm run dev`. For illustrative standalone data use `VITE_DASHBOARD_MODE=demo` instead. Open http://127.0.0.1:5173. Vite proxies `/api` to the dashboard backend on localhost:8090.

See **`../README.md`** for the full four-terminal setup, artifact contract, data limitations, backend tests and Git instructions. No code in `my-defense/` is changed.
