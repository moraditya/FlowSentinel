.PHONY: setup test lint dev dev-stop demo clean

VENV       := venv
PYTHON     := $(VENV)/bin/python
PIP        := $(VENV)/bin/pip
PYTEST     := $(VENV)/bin/pytest
RUFF       := $(VENV)/bin/ruff
UVICORN    := $(VENV)/bin/uvicorn
PID_FILE   := /tmp/nids-dev-uvicorn.pid
API_KEY    ?= dev-key-change-me
FRONTEND_PORT ?= 3001

# ── Setup ────────────────────────────────────────────────────────────

setup:
	@echo "=== Backend setup ==="
	cd backend && python3 -m venv $(VENV)
	cd backend && $(PIP) install -q -r requirements-dev.txt
	@echo "=== Frontend setup ==="
	cd frontend && npm ci --prefer-offline
	@echo "=== Done ==="

# ── Test ─────────────────────────────────────────────────────────────

test:
	@echo "=== Backend tests ==="
	cd backend && $(PYTEST) -q
	@echo "=== Frontend tests ==="
	cd frontend && npx jest --runInBand --watch=false

# ── Lint ─────────────────────────────────────────────────────────────

lint:
	@echo "=== Backend lint (ruff) ==="
	cd backend && $(RUFF) check app/ tests/ evaluation/ datasets/
	@echo "=== Frontend lint (next lint) ==="
	cd frontend && npx next lint

# ── Dev ──────────────────────────────────────────────────────────────

dev:
	@echo "Starting backend + frontend..."
	cd backend && $(UVICORN) app.main:app --reload --host 0.0.0.0 --port 8000 & echo $$! > $(PID_FILE)
	@echo "Backend PID saved to $(PID_FILE)"
	@echo "Backend: http://localhost:8000"
	@echo "Frontend: http://localhost:$(FRONTEND_PORT)"
	@echo "Run 'make dev-stop' to stop the backend."
	cd frontend && npm run dev -- --port $(FRONTEND_PORT)

dev-stop:
	@if [ -f $(PID_FILE) ]; then \
		kill $$(cat $(PID_FILE)) 2>/dev/null && echo "Backend stopped." || echo "Backend already stopped."; \
		rm -f $(PID_FILE); \
	else \
		echo "No PID file found."; \
	fi

# ── Demo ─────────────────────────────────────────────────────────────

demo:
	@echo "Starting backend for demo replay..."
	@cd backend && $(UVICORN) app.main:app --host 0.0.0.0 --port 8000 & echo $$! > $(PID_FILE)
	@sleep 3
	cd backend && $(PYTHON) replay.py --scenario mixed --speed 2 --api-key $(API_KEY); \
		EXIT_CODE=$$?; \
		kill $$(cat $(PID_FILE)) 2>/dev/null; \
		rm -f $(PID_FILE); \
		exit $$EXIT_CODE

# ── Clean ────────────────────────────────────────────────────────────

clean:
	find backend -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf frontend/.next
	rm -f backend/models/evaluation.lock
	rm -f backend/models/*.joblib
	rm -f backend/models/evaluation.json
