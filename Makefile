.PHONY: setup demo-servers gateway admin eval eval-unprotected test report clean

setup:
	uv sync

demo-servers:
	@echo "TODO Phase 1: demo servers are launched by upstreams.yaml (stdio)"

gateway:
	uv run python -m firewall.server

admin:
	uv run python -m firewall.admin_api

eval:
	uv run python -m eval.runner --modes unprotected monitor enforce

eval-unprotected:
	uv run python -m eval.runner --modes unprotected

test:
	uv run pytest

report:
	uv run python -m eval.report

clean:
	rm -rf .pytest_cache fw.db fw.db-wal fw.db-shm eval/results/*.json
