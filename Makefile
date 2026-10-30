.DEFAULT_GOAL := help
PYTHON ?= python3

.PHONY: help install-dev test cov lint fmt typecheck go-test go-build build check clean

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'

install-dev:  ## Editable install with all dev tools
	$(PYTHON) -m pip install -e ".[dev]"

test:  ## Run the Python test suite
	$(PYTHON) -m pytest

cov:  ## Tests with coverage report
	$(PYTHON) -m pytest --cov --cov-report=term-missing

lint:  ## Static checks (ruff)
	$(PYTHON) -m ruff check src tests

fmt:  ## Auto-format Python and Go
	$(PYTHON) -m ruff format src tests
	$(PYTHON) -m ruff check --fix src tests
	cd engine && gofmt -w .

typecheck:  ## Strict type checking (mypy)
	$(PYTHON) -m mypy

go-test:  ## Vet and test the optional Go engine (race detector on)
	cd engine && go vet ./... && go test -race -count=1 ./...

go-build:  ## Build the static Go engine into ./dist/dnstune-probe
	mkdir -p dist
	cd engine && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o ../dist/dnstune-probe .

build:  ## Build sdist and wheel
	$(PYTHON) -m build

check: lint typecheck test go-test  ## Everything CI runs

clean:  ## Remove build artefacts
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
