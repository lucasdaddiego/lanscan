# lanscan — common tasks. Run `make` (or `make help`) for the list.

VENV           := .venv
PY             := $(VENV)/bin/python
UV             := uv
PYTHON_VERSION := 3.14

RUFF_VERSION   := 0.16.10

.DEFAULT_GOAL := help
.PHONY: help install run vendors dev lock test lint clean distclean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

# Bootstrap: create the venv and install lanscan (editable) plus exactly the
# runtime deps pinned in uv.lock. --locked refuses a stale lock instead of
# silently re-resolving, so a fresh install gets the set CI tested.
$(PY):
	$(UV) sync --locked --no-dev --python $(PYTHON_VERSION)

install: $(PY) vendors ## Full setup: venv, locked deps, vendor DB, PATH symlink (~/.bin)
	@mkdir -p "$(HOME)/.bin"
	@ln -sf "$(CURDIR)/$(VENV)/bin/lanscan" "$(HOME)/.bin/lanscan"
	@echo "done — linked $(HOME)/.bin/lanscan; run 'make run' or 'lanscan'"

run: $(PY) ## Launch the live TUI
	@$(PY) -m lanscan

vendors: $(PY) ## Download the IEEE/Wireshark MAC vendor database
	@$(PY) -m lanscan --update-vendors

dev: ## Install the locked test/dev dependencies into the venv
	$(UV) sync --locked --group dev --python $(PYTHON_VERSION)

lock: ## Re-resolve uv.lock after changing dependencies in pyproject.toml
	$(UV) lock

test: dev ## Run the test suite (enforces 100% coverage)
	@$(PY) -m pytest --cov=lanscan --cov-report=term-missing

lint: dev ## ruff (same version CI pins) + mypy
	@uvx ruff@$(RUFF_VERSION) check .
	@$(PY) -m mypy

clean: ## Remove caches and build artifacts
	@rm -rf *.egg-info build dist .pytest_cache .ruff_cache .coverage coverage.xml htmlcov
	@find . -name '__pycache__' -type d -prune -exec rm -rf {} +
	@echo "cleaned"

distclean: clean ## Also remove the virtualenv
	@rm -rf $(VENV) && echo "removed $(VENV)"
