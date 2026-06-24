# Convenience targets for Cybersecurity 101.
# Requires Python 3.10+. `make help` lists available targets.

PYTHON := python3
PIP    := $(PYTHON) -m pip

.PHONY: help install lint typecheck check test all clean

help:            ## Show this help.
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install:         ## Install all optional runtime deps into the current env.
	$(PIP) install -r requirements.txt

dev:             ## Install lint/type tooling (ruff, mypy).
	$(PIP) install ruff mypy

lint:            ## Run ruff (lint only; no auto-fix).
	$(PYTHON) -m ruff check .

format:          ## Apply ruff's safe auto-fixes + format the code.
	$(PYTHON) -m ruff check --fix .
	$(PYTHON) -m ruff format .

typecheck:       ## Run mypy across every script.
	$(PYTHON) -m mypy *.py

check: lint typecheck  ## Lint + type-check.

test:            ## Run every module's built-in test suite.
	@status=0; \
	for f in *.py; do \
	  printf "  %-30s " "$$f"; \
	  if $(PYTHON) "$$f" >/dev/null 2>&1; then echo "OK"; else echo "FAIL"; status=1; fi; \
	done; \
	test $$status -eq 0 && echo "All module suites passed."

all: check test  ## Lint + type-check + tests.

clean:           ## Remove caches and generated artifacts.
	rm -rf __pycache__ .mypy_cache .ruff_cache .pytest_cache ecb_pattern.png
