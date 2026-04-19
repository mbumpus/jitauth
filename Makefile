# JITAuth development targets
#
# Usage:
#   make test              — run SQLite-backed tests (fast, no dependencies)
#   make test-postgres     — start Postgres, run Postgres tests, stop Postgres
#   make test-all          — run both SQLite and Postgres suites
#   make test-postgres-up  — start Postgres (leave running for iteration)
#   make test-postgres-run — run Postgres tests (assumes DB already running)
#   make test-postgres-down — stop Postgres and clean up volumes

.PHONY: test test-postgres test-all test-postgres-up test-postgres-run test-postgres-down lint

PG_URL := postgresql://jitauth_test:testpass@localhost:5433/jitauth_test
COMPOSE_FILE := docker-compose.test.yaml

# ---------- SQLite tests (default) ----------

test:
	python -m pytest tests/ -q --tb=short -m "not postgres"

# ---------- Postgres tests ----------

test-postgres-up:
	docker compose -f $(COMPOSE_FILE) up -d --wait
	@echo "Postgres ready at $(PG_URL)"

test-postgres-run:
	JITAUTH_TEST_DATABASE_URL="$(PG_URL)" \
		python -m pytest tests/test_postgres.py -v --tb=short

test-postgres-down:
	docker compose -f $(COMPOSE_FILE) down -v

test-postgres: test-postgres-up
	@$(MAKE) test-postgres-run; rc=$$?; $(MAKE) test-postgres-down; exit $$rc

# ---------- Full matrix ----------

test-all: test test-postgres

# ---------- Lint ----------

lint:
	ruff check src/ tests/
	ruff format --check src/ tests/
