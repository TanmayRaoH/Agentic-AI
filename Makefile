.PHONY: setup demo-servers gateway admin eval eval-quick bench eval-unprotected test report clean

setup:
	uv sync

demo-servers:
	@echo "The demo servers are started on demand by the gateway (upstreams.yaml, stdio); nothing to run."

gateway:
	uv run python -m firewall.server

admin:
	uv run python -m firewall.admin_api

eval:
	uv run python -m eval.run_all

eval-quick:
	uv run python -m eval.run_all --quick

bench:
	uv run python -m eval.bench

eval-unprotected:
	uv run python -m eval.runner --modes unprotected

test:
	uv run pytest

report:
	uv run python -m eval.report

clean:
	rm -rf .pytest_cache fw.db fw.db-wal fw.db-shm eval/results/2*.json
