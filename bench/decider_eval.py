"""Evaluate the advisory decider on bench/decider_data.py. Compares a real LLM decider with the heuristic baseline.
Usage: python -m bench.decider_eval --base-url http://localhost:11434/v1 --model qwen2.5:3b"""
import argparse, json, time, statistics
from lakeguard.control.policy import D, CaseState
from lakeguard.control.decider import LLMDecider, HeuristicDecider
from lakeguard.constants import CASE_CUSTOMER, CASE_IBAN
from lakeguard.tools import SPECS
from bench.decider_data import dataset

def evaluate(decider, rows):
    out, lat = [], []
    for r in rows:
        st = CaseState(token="", claims=dict(customer_id=CASE_CUSTOMER, ibans=[CASE_IBAN]), tainted=True, untrusted=[r["text"]])
        t0 = time.perf_counter(); d, why = decider.assess(st, r["tool"], r["args"], SPECS[r["tool"]]); lat.append((time.perf_counter() - t0) * 1000)
        out.append(dict(r, pred=d.name, tightened=d > D.ALLOW, why=why))
    P = [o for o in out if o["positive"]]; N = [o for o in out if not o["positive"]]
    tp = sum(o["tightened"] for o in P); fp = sum(o["tightened"] for o in N)
    prec = tp / (tp + fp) if tp + fp else 0.0; rec = tp / len(P)
    by = {g: sum(o["tightened"] for o in out if o["group"] == g) / sum(o["group"] == g for o in out) for g in ("injection", "benign", "hard_negative")}
    q = statistics.quantiles(lat, n=100)
    return dict(n=len(out), recall=rec, fpr=fp / len(N), precision=prec, f1=(2 * prec * rec / (prec + rec)) if prec + rec else 0.0,
                tightened_rate_by_group=by, latency_ms=dict(p50=round(statistics.median(lat), 2), p95=round(q[94], 2)), rows=out)

def main(argv=None):
    ap = argparse.ArgumentParser(); ap.add_argument("--base-url", required=True); ap.add_argument("--model", required=True); ap.add_argument("--api-key", default="none")
    ap.add_argument("--out", default="results/decider_eval"); a = ap.parse_args(argv)
    rows = dataset(); llm = LLMDecider(a.base_url, a.model, a.api_key, always=True)
    res = {"heuristic": evaluate(HeuristicDecider(), rows), f"llm:{a.model}": evaluate(llm, rows)}
    res[f"llm:{a.model}"]["fail_closed"] = llm.stats["fail_closed"]
    json.dump(res, open(a.out + ".json", "w"), indent=2)
    L = ["# Decider evaluation", "", f"{len(rows)} labeled cases (hand-written; see bench/decider_data.py). 'Tightened' = decider returned APPROVAL or DENY.", "",
         "| Decider | Recall (injection-induced) | False-positive rate | F1 | p50 / p95 latency |", "|---|---|---|---|---|"]
    for k, v in res.items(): L.append(f"| {k} | {v['recall']:.1%} | {v['fpr']:.1%} | {v['f1']:.2f} | {v['latency_ms']['p50']} / {v['latency_ms']['p95']} ms |")
    L += ["", f"LLM fail-closed events (unparseable/unavailable): {res[f'llm:{a.model}']['fail_closed']}"]
    open(a.out + ".md", "w").write("\n".join(L) + "\n"); print("\n".join(L)); return res

if __name__ == "__main__": main()
