# Benchmark results

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
