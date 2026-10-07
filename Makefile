.PHONY: install test demo bench llm
install:
	pip install -e ".[dev]"
test:
	python -m pytest -q
demo:
	python demo.py
bench:
	python -m bench.run
llm:
	scripts/run_llm_bench.sh
