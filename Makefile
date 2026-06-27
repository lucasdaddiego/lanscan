# lanscan — common tasks. Run `make` (or `make help`) for the list.

VENV           := .venv
PY             := $(VENV)/bin/python
UV             := uv
PYTHON_VERSION := 3.14

RUFF_VERSION   := 0.15.20

.DEFAULT_GOAL := help
.PHONY: help install run vendors dev test lint clean distclean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

# Bootstrap: create the venv and editable-install lanscan (+ deps).
$(PY):
	$(UV) venv --python $(PYTHON_VERSION) $(VENV)
	$(UV) pip install --python $(PY) -e .

install: $(PY) vendors ## Full setup: venv, deps, vendor DB, PATH symlink (~/.bin)
	@mkdir -p "$(HOME)/.bin"
	@ln -sf "$(CURDIR)/$(VENV)/bin/lanscan" "$(HOME)/.bin/lanscan"
	@echo "done — linked $(HOME)/.bin/lanscan; run 'make run' or 'lanscan'"

run: $(PY) ## Launch the live TUI
	@$(PY) -m lanscan

vendors: $(PY) ## Download the IEEE/Wireshark MAC vendor database
	@$(PY) -m lanscan --update-vendors

dev: $(PY) ## Install test/dev dependencies into the venv
	$(UV) pip install --python $(PY) -e ".[dev]"

test: dev ## Run the test suite (enforces 100% coverage)
	@$(PY) -m pytest --cov=lanscan --cov-report=term-missing

lint: ## Lint with ruff (same version CI pins)
	@uvx ruff@$(RUFF_VERSION) check .

clean: ## Remove caches and build artifacts
	@rm -rf lanscan/__pycache__ __pycache__ *.egg-info build dist
	@find . -name '*.pyc' -delete
	@echo "cleaned"

distclean: clean ## Also remove the virtualenv
	@rm -rf $(VENV) && echo "removed $(VENV)"
