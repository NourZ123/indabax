"""Local, read-only FastAPI API for SENTINEL's React investigation dashboard.

Start at repository root:
    uv run uvicorn dashboard.backend.app:app --host 127.0.0.1 --port 8090

The dashboard does not call /v1/decision and cannot execute tools or edit policies.
"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException

from .policies import read_policies
from .reader import read_experiments, read_runs


def create_app(repo_root: Path | None = None, artifacts_root: Path | None = None) -> FastAPI:
    root = (repo_root or Path(os.environ.get('SENTINEL_REPO_ROOT', Path(__file__).resolve().parents[2]))).expanduser().resolve()
    artifacts = (artifacts_root or Path(os.environ.get('SENTINEL_ARTIFACTS_DIR', root / 'artifacts'))).expanduser().resolve()
    service = FastAPI(title='SENTINEL Dashboard API', version='0.2.0', docs_url='/api/docs', redoc_url=None)

    @service.get('/api/healthz')
    def health() -> dict[str, object]:
        return {'status': 'ok', 'artifactDirectoryFound': artifacts.is_dir(), 'policyDirectoryFound': (root / 'policies').is_dir()}

    @service.get('/api/dashboard')
    def dashboard() -> dict[str, object]:
        return {'runs': read_runs(root, artifacts), 'policies': read_policies(root), 'experiments': read_experiments(artifacts)}

    @service.get('/api/runs')
    def runs() -> list[dict]:
        return read_runs(root, artifacts)

    @service.get('/api/runs/{run_id}')
    def run_by_id(run_id: str) -> dict:
        # Lookup by normalized IDs, not path construction: no arbitrary file reads.
        for run in read_runs(root, artifacts):
            if run['id'] == run_id:
                return run
        raise HTTPException(status_code=404, detail='Run not found')

    @service.get('/api/evaluations')
    def evaluations() -> list[dict]:
        return read_experiments(artifacts)

    @service.get('/api/policies')
    def policies() -> list[dict]:
        return read_policies(root)

    return service


app = create_app()
