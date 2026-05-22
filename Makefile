# ASRH: Agent Safety Regression Harness
# Verification-style regression testing for tool-using LLM agents.
#
# This Makefile is intentionally mock-first and safety-first:
# - build and test the harness before calling external providers;
# - validate YAML cases before running regressions;
# - keep traces and generated reports local by default;
# - keep all MVP tools simulated unless the implementation explicitly documents otherwise.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help
.DELETE_ON_ERROR:

PROJECT_NAME := agent-safety-regression-harness
PACKAGE := asrh

PYTHON ?= python3
VENV ?= .venv
VENV_PY := $(VENV)/bin/python
PY := $(if $(wildcard $(VENV_PY)),$(VENV_PY),$(PYTHON))
PIP := $(PY) -m pip

SUITE_DIR ?= suites
RUN_DIR ?= runs
REPORT_DIR ?= reports
LOG_DIR ?= .logs
DIST_DIR ?= dist

MODEL ?= mock/safe
UNSAFE_MODEL ?= mock/unsafe_leaker
REAL_MODEL ?= openai/gpt-4o-mini
MITIGATION ?= none
GUARD ?= tool_policy_guard

CASE ?= $(SUITE_DIR)/secret_exfiltration/case_001.yaml
SUITE ?= $(SUITE_DIR)
OUT ?= $(RUN_DIR)/run.jsonl
BASELINE_RUN ?= $(RUN_DIR)/baseline.jsonl
GUARDED_RUN ?= $(RUN_DIR)/tool_policy_guard.jsonl
REPORT_OUT ?= $(REPORT_DIR)/report.md
COMPARISON_OUT ?= $(REPORT_DIR)/comparison.md

export PYTHONPATH := $(CURDIR):$(PYTHONPATH)

.PHONY: help
help: ## Show available Make targets.
	@awk 'BEGIN {FS = ":.*##"; printf "\n%s\n\n", "ASRH development targets"} /^[a-zA-Z0-9_.-]+:.*##/ {printf "  \033[36m%-28s\033[0m %s\n", $$1, $$2} END {printf "\n"}' $(MAKEFILE_LIST)
	@printf "Common overrides:\n"
	@printf "  PYTHON=%s VENV=%s\n" "$(PYTHON)" "$(VENV)"
	@printf "  SUITE=%s CASE=%s\n" "$(SUITE)" "$(CASE)"
	@printf "  MODEL=%s REAL_MODEL=%s MITIGATION=%s GUARD=%s\n\n" "$(MODEL)" "$(REAL_MODEL)" "$(MITIGATION)" "$(GUARD)"

.PHONY: print-config
print-config: ## Print active Makefile configuration.
	@printf "PROJECT_NAME=%s\n" "$(PROJECT_NAME)"
	@printf "PACKAGE=%s\n" "$(PACKAGE)"
	@printf "PYTHON=%s\n" "$(PYTHON)"
	@printf "PY=%s\n" "$(PY)"
	@printf "VENV=%s\n" "$(VENV)"
	@printf "SUITE_DIR=%s\n" "$(SUITE_DIR)"
	@printf "RUN_DIR=%s\n" "$(RUN_DIR)"
	@printf "REPORT_DIR=%s\n" "$(REPORT_DIR)"
	@printf "MODEL=%s\n" "$(MODEL)"
	@printf "UNSAFE_MODEL=%s\n" "$(UNSAFE_MODEL)"
	@printf "REAL_MODEL=%s\n" "$(REAL_MODEL)"
	@printf "MITIGATION=%s\n" "$(MITIGATION)"
	@printf "GUARD=%s\n" "$(GUARD)"

.PHONY: preflight
preflight: ## Check required top-level files, Python version, and pyproject.toml syntax.
	@test -f README.md
	@test -f pyproject.toml
	@test -f Makefile
	@test -f .gitignore
	@test -f .env.example
	@$(PYTHON) -c 'import pathlib, sys, tomllib; assert sys.version_info >= (3, 11), "Python 3.11+ required"; cfg = tomllib.loads(pathlib.Path("pyproject.toml").read_text(encoding="utf-8")); project = cfg.get("project", {}); required = ["name", "version", "description", "dependencies"]; missing = [key for key in required if key not in project]; assert not missing, f"pyproject.toml missing required fields: {missing}"; assert project["name"] == "agent-safety-regression-harness"; print("pyproject.toml OK: {} {}".format(project["name"], project["version"]))'
	@grep -q '^OPENAI_API_KEY=$$' .env.example
	@grep -q '^ANTHROPIC_API_KEY=$$' .env.example
	@grep -q '^ASRH_ALLOW_REAL_SHELL=false$$' .env.example
	@grep -q '^ASRH_ALLOW_REAL_EMAIL=false$$' .env.example
	@grep -q '^ASRH_ALLOW_REAL_NETWORK=false$$' .env.example
	@printf "Top-level project files OK.\n"

.PHONY: mkdirs
mkdirs: ## Create runtime directories used by runs, reports, and logs.
	@mkdir -p "$(RUN_DIR)" "$(REPORT_DIR)" "$(LOG_DIR)"
	@touch "$(RUN_DIR)/.gitkeep" "$(REPORT_DIR)/.gitkeep"

.PHONY: init-dirs
init-dirs: mkdirs ## Create the repository directory skeleton from the technical spec.
	@mkdir -p \
		$(PACKAGE)/cli \
		$(PACKAGE)/cases \
		$(PACKAGE)/envs \
		$(PACKAGE)/tools \
		$(PACKAGE)/models \
		$(PACKAGE)/agents \
		$(PACKAGE)/mitigations \
		$(PACKAGE)/checkers \
		$(PACKAGE)/runner \
		$(PACKAGE)/report \
		$(PACKAGE)/utils \
		$(SUITE_DIR)/prompt_injection \
		$(SUITE_DIR)/secret_exfiltration \
		$(SUITE_DIR)/tool_misuse \
		$(SUITE_DIR)/instruction_conflict \
		$(SUITE_DIR)/reward_hacking \
		docs paper tests
	@touch "$(PACKAGE)/py.typed"
	@printf "Initialized ASRH directory skeleton.\n"

.PHONY: env
env: ## Create .env from .env.example if .env does not already exist.
	@if [ -f .env ]; then \
		echo ".env already exists; not overwriting."; \
	else \
		cp .env.example .env; \
		echo "Created .env from .env.example"; \
	fi

.PHONY: venv
venv: ## Create a local Python virtual environment and upgrade packaging tools.
	@test -d "$(VENV)" || $(PYTHON) -m venv "$(VENV)"
	@$(VENV_PY) -m pip install --upgrade pip setuptools wheel

.PHONY: install
install: venv ## Install package in editable mode with core dependencies.
	@$(VENV_PY) -m pip install -e .

.PHONY: install-dev
install-dev: venv ## Install package in editable mode with development tooling.
	@$(VENV_PY) -m pip install -e ".[dev]"

.PHONY: install-providers
install-providers: venv ## Install development tooling plus OpenAI/Anthropic provider clients.
	@$(VENV_PY) -m pip install -e ".[dev,providers]"

.PHONY: install-analysis
install-analysis: venv ## Install analysis/reporting extras.
	@$(VENV_PY) -m pip install -e ".[analysis]"

.PHONY: install-docs
install-docs: venv ## Install documentation extras.
	@$(VENV_PY) -m pip install -e ".[docs]"

.PHONY: install-local
install-local: venv ## Install local-model extras. This is intentionally separate because it is heavyweight.
	@$(VENV_PY) -m pip install -e ".[local]"

.PHONY: install-all
install-all: venv ## Install all declared extras plus development tooling.
	@$(VENV_PY) -m pip install -e ".[dev,providers,analysis,docs,local]"

.PHONY: init
init: init-dirs env install-dev ## Initialize directories, .env, and development installation.

.PHONY: format
format: ## Format Python code with Ruff.
	@$(PY) -m ruff format $(PACKAGE) tests

.PHONY: format-check
format-check: ## Check formatting without modifying files.
	@$(PY) -m ruff format --check $(PACKAGE) tests

.PHONY: lint
lint: ## Run Ruff lint checks.
	@$(PY) -m ruff check $(PACKAGE) tests

.PHONY: lint-fix
lint-fix: ## Run Ruff lint checks and apply safe fixes.
	@$(PY) -m ruff check --fix $(PACKAGE) tests

.PHONY: typecheck
typecheck: ## Run mypy strict type checks.
	@$(PY) -m mypy $(PACKAGE)

.PHONY: test
test: ## Run the full pytest suite.
	@$(PY) -m pytest

.PHONY: test-unit
test-unit: ## Run fast deterministic unit tests only.
	@$(PY) -m pytest -m "not integration and not provider and not slow"

.PHONY: test-integration
test-integration: ## Run integration tests, excluding external provider tests.
	@$(PY) -m pytest -m "integration and not provider"

.PHONY: test-provider
test-provider: ## Run provider tests that require external API credentials.
	@$(PY) -m pytest -m provider

.PHONY: coverage
coverage: ## Run tests and generate coverage reports.
	@$(PY) -m pytest --cov=$(PACKAGE) --cov-report=term-missing --cov-report=xml --cov-report=html

.PHONY: security
security: ## Run Bandit security checks against the package.
	@$(PY) -m bandit -r $(PACKAGE)

.PHONY: quality
quality: preflight format-check lint typecheck test-unit security ## Run the standard local quality gate.

.PHONY: check
check: quality ## Alias for quality.

.PHONY: pre-commit-install
pre-commit-install: ## Install pre-commit hooks.
	@$(PY) -m pre_commit install

.PHONY: pre-commit
pre-commit: ## Run pre-commit hooks across all files.
	@$(PY) -m pre_commit run --all-files

.PHONY: validate-cases
validate-cases: mkdirs ## Validate YAML cases against the ASRH schema.
	@$(PY) -m asrh.cli.validate_cases --suite "$(SUITE_DIR)"

.PHONY: list-cases
list-cases: ## List discovered YAML cases.
	@$(PY) -m asrh.cli.list_cases --suite "$(SUITE_DIR)"

.PHONY: case-count
case-count: ## Count YAML cases currently present under SUITE_DIR.
	@find "$(SUITE_DIR)" -type f \( -name '*.yaml' -o -name '*.yml' \) | sort | wc -l | awk '{print $$1 " YAML cases"}'

.PHONY: run-one
run-one: mkdirs ## Run one case. Override CASE, MODEL, MITIGATION, and OUT as needed.
	@$(PY) -m asrh.cli.run \
		--case "$(CASE)" \
		--model "$(MODEL)" \
		--mitigation "$(MITIGATION)" \
		--out "$(OUT)"

.PHONY: run-suite
run-suite: mkdirs ## Run a suite or the full suites directory. Override SUITE, MODEL, MITIGATION, and OUT.
	@$(PY) -m asrh.cli.run \
		--suite "$(SUITE)" \
		--model "$(MODEL)" \
		--mitigation "$(MITIGATION)" \
		--out "$(OUT)"

.PHONY: run-all-mock
run-all-mock: mkdirs ## Run all suites with the safe deterministic mock model.
	@$(MAKE) run-suite SUITE="$(SUITE_DIR)" MODEL="mock/safe" MITIGATION="none" OUT="$(RUN_DIR)/all_mock_safe.jsonl"

.PHONY: run-baseline
run-baseline: mkdirs ## Run all suites with MODEL and no mitigation into BASELINE_RUN.
	@$(MAKE) run-suite SUITE="$(SUITE_DIR)" MODEL="$(MODEL)" MITIGATION="none" OUT="$(BASELINE_RUN)"

.PHONY: run-guarded
run-guarded: mkdirs ## Run all suites with MODEL and GUARD into GUARDED_RUN.
	@$(MAKE) run-suite SUITE="$(SUITE_DIR)" MODEL="$(MODEL)" MITIGATION="$(GUARD)" OUT="$(GUARDED_RUN)"

.PHONY: run-mock-baseline
run-mock-baseline: mkdirs ## Run all suites with the unsafe mock model and no mitigation.
	@$(MAKE) run-suite SUITE="$(SUITE_DIR)" MODEL="$(UNSAFE_MODEL)" MITIGATION="none" OUT="$(BASELINE_RUN)"

.PHONY: run-mock-guarded
run-mock-guarded: mkdirs ## Run all suites with the unsafe mock model and the configured guard.
	@$(MAKE) run-suite SUITE="$(SUITE_DIR)" MODEL="$(UNSAFE_MODEL)" MITIGATION="$(GUARD)" OUT="$(GUARDED_RUN)"

.PHONY: run-real-baseline
run-real-baseline: mkdirs ## Run all suites against REAL_MODEL with no mitigation into BASELINE_RUN.
	@$(MAKE) run-suite SUITE="$(SUITE_DIR)" MODEL="$(REAL_MODEL)" MITIGATION="none" OUT="$(BASELINE_RUN)"

.PHONY: run-real-guarded
run-real-guarded: mkdirs ## Run all suites against REAL_MODEL with GUARD into GUARDED_RUN.
	@$(MAKE) run-suite SUITE="$(SUITE_DIR)" MODEL="$(REAL_MODEL)" MITIGATION="$(GUARD)" OUT="$(GUARDED_RUN)"

.PHONY: report
report: mkdirs ## Generate a Markdown report from OUT into REPORT_OUT.
	@$(PY) -m asrh.cli.report \
		--run "$(OUT)" \
		--out "$(REPORT_OUT)"

.PHONY: report-baseline
report-baseline: mkdirs ## Generate a Markdown report from BASELINE_RUN.
	@$(PY) -m asrh.cli.report \
		--run "$(BASELINE_RUN)" \
		--out "$(REPORT_DIR)/baseline.md"

.PHONY: compare
compare: mkdirs ## Compare BASELINE_RUN and GUARDED_RUN into COMPARISON_OUT.
	@$(PY) -m asrh.cli.report \
		--compare "$(BASELINE_RUN)" "$(GUARDED_RUN)" \
		--out "$(COMPARISON_OUT)"

.PHONY: mvp-smoke
mvp-smoke: validate-cases run-one report ## Validate cases, run one case, and generate one report.

.PHONY: smoke
smoke: mvp-smoke ## Alias for mvp-smoke.

.PHONY: mock-regression
mock-regression: run-mock-baseline run-mock-guarded compare ## Run the mock baseline-vs-guard regression flow.

.PHONY: demo-mock
demo-mock: mock-regression ## Alias for the mock baseline-vs-guard demo.

.PHONY: real-regression
real-regression: run-real-baseline run-real-guarded compare ## Run the real-model baseline-vs-guard regression flow.

.PHONY: mvp-real
mvp-real: real-regression ## Alias for the MVP real-model baseline and guarded comparison.

.PHONY: docs-build
docs-build: ## Build MkDocs documentation if docs dependencies are installed.
	@$(PY) -m mkdocs build --strict

.PHONY: docs-serve
docs-serve: ## Serve MkDocs documentation locally if docs dependencies are installed.
	@$(PY) -m mkdocs serve

.PHONY: build
build: clean-build ## Build source and wheel distributions.
	@$(PY) -m build

.PHONY: twine-check
twine-check: build ## Validate built distributions with Twine.
	@$(PY) -m twine check $(DIST_DIR)/*

.PHONY: clean-cache
clean-cache: ## Remove Python, Ruff, mypy, pytest, and coverage caches.
	@find . -type d \( -name "__pycache__" -o -name ".pytest_cache" -o -name ".mypy_cache" -o -name ".ruff_cache" -o -name ".hypothesis" \) -prune -exec rm -rf {} +
	@find . -type f -name "*.py[co]" -delete
	@rm -f .coverage coverage.xml
	@rm -rf htmlcov

.PHONY: clean-build
clean-build: ## Remove Python packaging outputs.
	@rm -rf build $(DIST_DIR) *.egg-info .eggs

.PHONY: clean-runs
clean-runs: ## Remove generated JSONL traces while preserving runs/.gitkeep.
	@mkdir -p "$(RUN_DIR)"
	@find "$(RUN_DIR)" -type f ! -name ".gitkeep" -delete

.PHONY: clean-reports
clean-reports: ## Remove generated reports while preserving sample reports and .gitkeep.
	@mkdir -p "$(REPORT_DIR)"
	@find "$(REPORT_DIR)" -type f ! -name ".gitkeep" ! -name "sample_*.md" -delete

.PHONY: clean
clean: clean-cache clean-build ## Remove local caches and build artifacts.

.PHONY: clean-all
clean-all: clean clean-runs clean-reports ## Remove caches, builds, generated runs, and generated reports.

.PHONY: distclean
distclean: clean-all ## Remove local virtualenv and generated local state.
	@rm -rf "$(VENV)" "$(LOG_DIR)"
