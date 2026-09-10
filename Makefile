.PHONY: install test run lint typecheck clean frontend wizard backend app app-smoke release

# Default target
all: install test

# Install package in development mode
install:
	pip install -e .[dev]

# Run tests
test:
	pytest

# Run the CLI scan command
run:
	python -m cbomscan scan $(PATH) -o cbom.json -f json

# Run with custom args: make run PATH=../some-repo ARGS="-o out.json -f md"
run-args:
	python -m cbomscan scan $(PATH) $(ARGS)

# Lint with ruff
lint:
	ruff check cbomscan tests

# Format with black
format:
	black cbomscan tests

# Type check with mypy
typecheck:
	mypy cbomscan

# Clean build artifacts
clean:
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .coverage htmlcov
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

# Build the React dashboard
frontend:
	cd frontend && npm install && npm run build

# Build both Python executables: the setup wizard and the engine the app spawns
wizard backend: frontend
	pyinstaller CBOMScan.spec --noconfirm --clean

# Build the Electron desktop app (installer + portable). Needs the backend exe.
app: backend
	cd desktop && npm install && npx electron-builder --win --publish never

# Assemble the distribution ZIP (setup wizard + payload). Copies only.
release: app
	python tools/make_release.py

# Drive the real desktop app headlessly and assert on the rendered UI
app-smoke:
	cd desktop && npx electron smoke-test.js && type smoke-report.txt

# Full check pipeline
check: lint typecheck test

# Schema spike - test cyclonedx-python-lib
schema-spike:
	python -c "
import json
from cyclonedx.model import CryptoProperties, AlgorithmProperties, CryptoFunctions
from cyclonedx.model.component import Component, ComponentType

# Try to create a cryptographic-asset component with cryptoProperties
try:
    alg_props = AlgorithmProperties(
        primitive='pke',
        parameter_set_identifier='2048',
        execution_environment='software-plain-ram',
        crypto_functions=[CryptoFunctions.ENCRYPT, CryptoFunctions.DECRYPT],
        classical_security_level=112,
        nist_quantum_security_level=0,
    )
    crypto_props = CryptoProperties(
        asset_type='algorithm',
        algorithm_properties=alg_props,
        oid='1.2.840.113549.1.1.1'
    )
    comp = Component(
        type=ComponentType.CRYPTOGRAPHIC_ASSET,
        name='RSA-2048',
        crypto_properties=crypto_props
    )
    print('SUCCESS: cyclonedx-python-lib supports cryptoProperties')
    print(json.dumps(comp.to_json(), indent=2))
except Exception as e:
    print(f'FAILED: {e}')
    print('Will need manual dict construction + jsonschema validation')
"