#!/usr/bin/env bash
# Runs the decider evaluation and the end-to-end real-model benchmark against a local Ollama server.
# Usage: scripts/run_llm_bench.sh [investigator models, comma-separated] [decider model]
set -euo pipefail
MODELS="${1:-qwen2.5:7b,llama3.1:8b}"
DECIDER="${2:-qwen2.5:3b}"
BASE="${LLM_BASE_URL:-http://localhost:11434/v1}"
if command -v ollama >/dev/null; then
  for m in ${MODELS//,/ } "$DECIDER"; do ollama pull "$m"; done
fi
python -m bench.decider_eval --base-url "$BASE" --model "$DECIDER"
python -m bench.llm_run --base-url "$BASE" --models "$MODELS" --decider-model "$DECIDER" --trials "${TRIALS:-3}"
echo "Results: results/decider_eval.md  results/llm_benchmark.md"
