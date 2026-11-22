# SPDX-License-Identifier: GPL-3.0-only
VENV := device/.venv
PY := $(VENV)/bin/python

.PHONY: dev test lint schemas serve doctor
dev:
	python3 -m venv $(VENV) && $(VENV)/bin/pip install -q -e 'device[dev]'
test:
	cd device && .venv/bin/pytest -q
lint:
	cd device && .venv/bin/ruff check . && .venv/bin/ruff format --check . && .venv/bin/mypy
schemas:
	$(VENV)/bin/netcaliper schemas
serve:
	NETCALIPER_HW=$${NETCALIPER_HW:-mock:uconsole-cm4-full} $(VENV)/bin/netcaliper serve --data-dir device/var
doctor:
	$(VENV)/bin/netcaliper doctor
