# lakeguard

A **secured data-to-agent reference stack**: a lakehouse, a quality-checked ETL pipeline, a RAG index, a tool-using agent, and a **case-scoped control plane** that authorizes every agent action. Built around a bank fraud-investigation scenario on synthetic data.

> Every layer is an attack surface. A prompt injection can arrive through a structured field *or* through a document in the RAG index. The agent is treated as an untrusted identity: the LLM proposes, a deterministic policy decides, an advisory model can only tighten, the runtime enforces.

## Architecture

```
 raw sources (CSV / JSONL / documents, intentionally dirty)
        |  ingest (all strings + provenance)
        v
 BRONZE (Delta) --clean/validate--> SILVER (Delta) --aggregate--> GOLD (Delta)
        |                              |  quarantine of rejected rows     customer_features, timeline, doc_chunks
        |                              v                                          |
        |                  data-quality checks (fail the run)          lineage log (every table write)
        v                                                                         v
                       Tools: profile (masked) / transactions / timeline / beneficiaries / KYC / reputation / document search (RAG, ACL before scoring)
                                                  ^
 Investigation LLM  --tool proposal-->  CONTROL PLANE: token -> policy (deterministic) -> advisory decider (tighten-only) -> egress-guarded execution -> taint tagging -> audit
                                                  |  ALLOW        |  APPROVAL            |  DENY
                                                  v               v                      v
                                              tool runs      human analyst        reason returned to agent
```

| Layer | Implementation | File |
|---|---|---|
| Lakehouse | Delta Lake tables (delta-rs) on the filesystem, DuckDB SQL, bronze/silver/gold, time travel, lineage log | `lakeguard/lakehouse.py` |
| ETL | Typed cleaning, deduplication, quarantine with reasons, 8 data-quality checks that stop the run on failure | `lakeguard/etl.py` |
| RAG | BM25 over `gold.doc_chunks`; ACL (public or own case) applied **before** scoring; injection-suspect chunks flagged at ingestion | `lakeguard/rag.py` |
| Tools | Reads gold/silver; PII column masked; policy specs per tool | `lakeguard/tools.py` |
| Control plane | HMAC case token, deterministic policy, tighten-only decider, taint, egress guard, hash-chained audit | `lakeguard/control/` |
| Agent | Model-agnostic JSON tool loop for any OpenAI-compatible endpoint | `lakeguard/control/agent.py` |

## Quick start

```bash
pip install -e ".[dev]"
python -m pytest -q        # 16 tests
python demo.py             # same poisoned case, with and without the control plane, two injection vectors
python -m bench.run        # deterministic benchmark -> results/
scripts/run_llm_bench.sh qwen2.5:7b,llama3.1:8b qwen2.5:3b   # real models via an OpenAI-compatible server (see below)
```

## What the data platform does (measured on one run)

- Raw transactions: 494. Clean (silver): 481. Quarantined: 13 (duplicates 3, null customer 2, bad amount 5, bad IBAN 3).
- Reconciliation holds: bronze rows = silver + quarantine. Timeline events: 564. Document chunks: 9, of which 1 flagged as suspected injection.
- Pipeline runtime: 4.25 s. All critical quality checks pass; a failing one raises and stops the run (tested). Re-running creates new Delta versions and the previous version stays readable (tested).

## Security benchmark

Same attack families as the standalone control-plane benchmark, now executed against tools that read from the lakehouse and RAG.

Cases: 81 (56 attack, 20 benign). Python 3.12.3, x86_64, 1 cores.

| Mode | Attack success | Benign blocked | Approval rate (tainted ctx) |
|---|---|---|---|
| none | 100.0% | 0.0% | 0% |
| rbac | 100.0% | 0.0% | 0% |
| runtime_only | 94.6% | 0.0% | 0% |
| policy_only | 0.0% | 0.0% | 100% |
| full | 0.0% | 0.0% | 100% |

## Attack success by category (released / total)

| Category | none | rbac | runtime_only | policy_only | full |
|---|---|---|---|---|---|
| cross_customer_read | 32/32 | 32/32 | 32/32 | 0/32 | 0/32 |
| kyc_foreign | 5/5 | 5/5 | 5/5 | 0/5 | 0/5 |
| kyc_own_ungated | 5/5 | 5/5 | 5/5 | 0/5 | 0/5 |
| exfil_extra_param | 5/5 | 5/5 | 5/5 | 0/5 | 0/5 |
| exfil_iban_stuffing | 2/2 | 2/2 | 2/2 | 0/2 | 0/2 |
| out_of_case_iban | 3/3 | 3/3 | 3/3 | 0/3 | 0/3 |
| unknown_tool_exfil | 3/3 | 3/3 | 0/3 | 0/3 | 0/3 |
| call_budget_abuse | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 |

Decision latency (policy + heuristic decider, full mode, n=120): p50 0.0151 ms, p95 0.028 ms, p99 0.076 ms.

Modes: `none` (no control), `rbac` (tool allowlist only), `runtime_only` (egress guard only, gate bypassed), `policy_only` (deterministic policy + taint), `full` (policy + decider). Data: `results/benchmark.json`, `results/pipeline_report.json`.

How to read it: RBAC does not reduce attack success because every attacked tool is legitimately allowed. The policy engine carries the defense; the decider adds nothing measurable on these cases, which is why it is advisory. "Approval rate (tainted ctx)" is deliberate friction: an external call after reading untrusted content goes to a human. The demo also shows a side effect of the decider: after a poisoned note, even a harmless document search is escalated to APPROVAL.

## Real-model evaluation

`bench/decider_eval.py` (60 hand-labeled cases, LLM decider vs regex baseline) and `bench/llm_run.py` (a real LLM investigates a poisoned case; leak, manipulation and completion rates with 95% Wilson intervals) are included. They run against any OpenAI-compatible server (Ollama, vLLM, llama.cpp). **They have been tested only against a mock server (plumbing), not with real models. Publish your own `results/decider_eval.md` and `results/llm_benchmark.md` with model names and hardware before citing any model behavior.**

## Threat model by layer

| Layer | Attack | Control |
|---|---|---|
| Structured data | Injection in a free-text field (beneficiary note) | Field declared untrusted, wrapped, taints the case |
| RAG | Poisoned or third-party document in the index | Flagged at ingestion, wrapped as untrusted, taints the case |
| RAG | Retrieval of another case's documents | ACL applied before scoring; case id set by the gate, not the agent |
| Tools | Cross-customer read, extra parameters, IBAN stuffing | Case scope, parameter schemas, cross-customer reference check |
| Data | PII exposure | Column masking, KYC requires analyst approval |
| Runtime | Gate bypass, direct exfiltration | Egress allowlist |
| Operations | Tampering, repudiation | Hash-chained audit log, Delta lineage |

## Limitations (read before citing)

- **Synthetic data**, generated with canary strings; no real banking data or systems.
- **Lakehouse on a local filesystem.** Delta tables use delta-rs; object storage (S3/MinIO) was not tested. No orchestrator: the pipeline is plain Python (Airflow or Dagster would be the next step).
- **RAG is lexical (BM25), not embedding-based.** It exists to demonstrate access control and poisoning, not retrieval quality.
- **The deterministic benchmark uses a fixture, not a model.** `NaiveInjectableClient` obeys injected text; attack calls are replayed at the gate. The attack suite is small and written alongside the rules, so it shows the rules do what they claim, not that unknown attacks are covered.
- **The default decider is a regex heuristic;** the LLM decider is implemented but unevaluated with real models. The decider reads untrusted text, so it is itself injectable, which is why it can only tighten.
- **The egress guard is in-process** and is not a security boundary; enforce egress outside the agent process in a real deployment.
- **Not covered:** covert channels through allowed values, approval fatigue, multi-case collusion, denial of service, model-level robustness, scale and performance of the data layer (one core, 500 transactions).

## Contributing

Add a case to `build_cases()` in `bench/run.py` that you think should leak, and open a PR. Failing cases are the most useful contributions.

## License

MIT
