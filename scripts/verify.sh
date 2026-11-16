#!/usr/bin/env bash
set -euo pipefail
mkdir -p reports
python -m pytest tests -v --junitxml=reports/tests.xml
bandit -r app -f json -o reports/bandit.json
pip-audit -r requirements.txt --strict -f json -o reports/pip-audit.json
