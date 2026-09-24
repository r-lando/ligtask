# LIGTASK — CLAUDE CONTEXT

Compact, current-state map. Root: `C:\Users\a0995\ligtask` (Windows / PowerShell).

## Stack
- **Backend**: Python 3 + FastAPI + SQLite. Entry `backend/app/main.py`. Tests: pytest, run from `backend/`.
- **Frontend**: React 18 + TypeScript + Vite 8. Entry `frontend/src/main.tsx` → `frontend/src/App.tsx`. Inline styles + `var(--…)` tokens; single app shell with an if/else screen switch (not a router).

## Layout (authoritative paths)
```
backend/
  app/main.py                     # FastAPI app; CORS; mounts /api routes
  app/api/assessments.py          # HTTP endpoints (POST /assessments, GET …/findings …)
  app/services/
    database_service.py           # SQLite schema, migrations, INSERT, row->finding mapping
    semgrep_service.py            # semgrep scan execution + JSON parsing
    finding_normalizer.py         # severity + recommended_action normalization logic
    dependency_service.py, secret_service.py, github_service.py, enrichment_service.py,
    correlation_service.py, repository_service.py, config_service.py,
    report_service.py, pdf_report_service.py, profiler.py, database_service.py
  app/models/assessment_models.py # Pydantic types (RecommendedAction lives here)
  app/models/__init__.py
  tests/                          # pytest suite (81 passing)
frontend/src/
  App.tsx                         # shell: screen state + if-chain; theme non-present
  main.tsx, index.css             # tokens: --bg-*, --text-*, --border, --sev-*; :root dark default
  components/Sidebar.tsx          # props: { current, navigate } only (no theme props in base)
  components/Logo.tsx
  pages/
    HomeScreen.tsx                # entry / landing
    RepoConfigScreen.tsx          # repo input + config
    ScanningScreen.tsx            # in-progress assessment
    HistoryScreen.tsx             # past assessments
    AssessmentResultsScreen.tsx   # results + severity filter chips
    FindingDetailScreen.tsx       # single finding; renders recommended_action banner
    AboutScreen.tsx, PrivacyScreen.tsx
  services/api.ts                 # fetch wrapper, AssessmentResult types
  types/assessment.ts
```

## Key flow — recommended_action (THE feature)
Backend computes it in `finding_normalizer.py`; must be **persisted** by `database_service.py`:
- schema column `recommended_action` (created in CREATE TABLE + guarded migration)
- INSERT binds it (after `guidance_source`)
- `row_to_finding` (~L757-758) reads it back so `GET /findings` returns it
- `FindingDetailScreen.tsx` renders the green "Recommended Action / mitigation" banner when the field is truthy.

If the green banner stops appearing on fresh scans, the backend likely regressed (it must not resurrect to speculation). Frontend build: `frontend/` → `vite build`.

## Scripts / checks
- Backend tests: from `backend/`: `.venv\Scripts\python.exe -m pytest -q tests` → expect **81 passed**
- Frontend build: from `frontend/`: `.\node_modules\.bin\vite build` → must end `✓ built`
- Branch: `ui/design-tokens` — see git: backend commit carries the fix; frontend reverted to the working recommended_action base. **Do not push to main.**

## Forbidden / revert-prone work (reverted 3×)
Stay conservative on the frontend: inline styles use many hex literals that ARE the designed look. No theme/day-night toggle, no speculative sweeps.
