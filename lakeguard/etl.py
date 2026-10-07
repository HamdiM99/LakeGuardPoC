"""Bronze (raw, all strings + provenance) -> Silver (typed, validated, deduplicated; rejects quarantined) -> Gold (features, timeline, doc index).
Includes data-quality checks that fail the run when a critical check fails."""
import csv, json, os, re, time, datetime as dt
import pyarrow as pa
from .lakehouse import Lake
from .control.decider import PATTERNS

SOURCES = {"customers": "customers.csv", "kyc": "kyc.csv", "transactions": "transactions.jsonl",
           "auth_events": "auth_events.csv", "devices": "devices.csv", "beneficiaries": "beneficiaries.csv"}

def _rows(path):
    if path.endswith(".csv"):
        with open(path) as f: return list(csv.DictReader(f))
    with open(path) as f: return [json.loads(l) for l in f if l.strip()]

def ingest_bronze(raw, lake):
    now = dt.datetime.now(dt.timezone.utc).isoformat(); counts = {}
    for name, file in SOURCES.items():
        rows = _rows(os.path.join(raw, file)); cols = list(rows[0])
        data = {c: [None if r.get(c) is None else str(r[c]) for r in rows] for c in cols}
        data["_source"], data["_ingested_at"] = [file] * len(rows), [now] * len(rows)
        lake.write("bronze", name, pa.table(data), "ingest", [file]); counts[name] = len(rows)
    return counts

def _chunks(docdir):
    out = []
    for fn in sorted(os.listdir(docdir)):
        head, _, body = open(os.path.join(docdir, fn)).read().partition("\n\n")
        meta = dict(l.split(": ", 1) for l in head.splitlines() if ": " in l)
        for i, para in enumerate(p.strip() for p in body.split("\n\n") if p.strip()):
            hits = sum(bool(re.search(p, para, re.I)) for p in PATTERNS)
            out.append(dict(chunk_id=f"{fn}#{i}", doc=fn, title=meta.get("title", fn), acl=meta.get("acl", "public"),
                            source=meta.get("source", "unknown"), flagged=hits >= 2, text=para))
    return out

def build_silver_gold(raw, lake):
    S, B = lake.sql, lambda n: lake.read("bronze", n)
    tx = S("""with t as (select tx_id, nullif(customer_id,'') customer_id, try_cast(ts as timestamp) ts, try_cast(amount as double) amount, iban, memo,
              row_number() over (partition by tx_id) rn from b)
              select *, case when rn>1 then 'duplicate' when customer_id is null then 'null_customer' when amount is null or amount<=0 then 'bad_amount'
              when ts is null then 'bad_ts' when not regexp_full_match(coalesce(iban,''),'[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}') then 'bad_iban' end reason from t""", b=B("transactions"))
    silver_tx = S("select tx_id, customer_id, ts, amount, iban, memo from q where reason is null", q=tx)
    quarantine = S("select tx_id, customer_id, cast(ts as varchar) ts, cast(amount as varchar) amount, iban, reason from q where reason is not null", q=tx)
    lake.write("silver", "transactions", silver_tx, "clean", ["bronze.transactions"]); lake.write("silver", "transactions_quarantine", quarantine, "clean", ["bronze.transactions"])
    cust = S("select id, name, kind, risk, cr from b", b=B("customers")); lake.write("silver", "customers", cust, "clean", ["bronze.customers"])
    lake.write("silver", "kyc", S("select customer_id, secret from b", b=B("kyc")), "clean", ["bronze.kyc"])
    auth = S("select customer_id, try_cast(ts as timestamp) ts, type from b", b=B("auth_events")); lake.write("silver", "auth_events", auth, "clean", ["bronze.auth_events"])
    dev = S("select customer_id, try_cast(ts as timestamp) ts, device_id, cast(is_new as integer) is_new from b", b=B("devices")); lake.write("silver", "devices", dev, "clean", ["bronze.devices"])
    ben = S("select customer_id, iban, try_cast(created_ts as timestamp) created_ts, note from b", b=B("beneficiaries")); lake.write("silver", "beneficiaries", ben, "clean", ["bronze.beneficiaries"])
    feat = S("""select customer_id, count(*) tx_count, round(avg(amount),2) avg_amount, round(coalesce(stddev_samp(amount),0),2) std_amount,
                max(amount) max_amount, max(ts) last_tx_ts from tx group by 1""", tx=silver_tx)
    lake.write("gold", "customer_features", feat, "aggregate", ["silver.transactions"])
    tl = S("""select customer_id, ts, 'transaction' event_type, 'amount='||cast(amount as varchar)||' iban='||iban||' memo='||memo detail from tx
              union all select customer_id, ts, 'auth', type from au
              union all select customer_id, ts, 'device', 'device_id='||device_id||' new='||cast(is_new as varchar) from dv
              union all select customer_id, created_ts, 'beneficiary_created', 'iban='||iban from bn order by customer_id, ts""", tx=silver_tx, au=auth, dv=dev, bn=ben)
    lake.write("gold", "timeline", tl, "union", ["silver.transactions", "silver.auth_events", "silver.devices", "silver.beneficiaries"])
    ch = _chunks(os.path.join(raw, "docs"))
    lake.write("gold", "doc_chunks", pa.Table.from_pylist(ch), "index", ["raw/docs"])
    return dict(silver_tx=silver_tx.num_rows, quarantined=quarantine.num_rows, timeline=tl.num_rows, chunks=len(ch), flagged_chunks=sum(c["flagged"] for c in ch),
                reasons={r: sum(1 for x in quarantine.column("reason").to_pylist() if x == r) for r in set(quarantine.column("reason").to_pylist())})

def quality(lake, bronze_counts, stats):
    S, R = lake.sql, lake.read; checks = []
    def chk(name, ok, detail, critical=True): checks.append(dict(check=name, passed=bool(ok), critical=critical, detail=detail))
    tx, cu = R("silver", "transactions"), R("silver", "customers")
    chk("silver.transactions: tx_id unique", len(set(tx.column("tx_id").to_pylist())) == tx.num_rows, f"{tx.num_rows} rows")
    chk("silver.transactions: no nulls in key columns", all(tx.column(c).null_count == 0 for c in ("tx_id", "customer_id", "amount", "ts")), "tx_id, customer_id, amount, ts")
    chk("silver.transactions: amount > 0", S("select min(amount) m from t", t=tx).column("m")[0].as_py() > 0, "min(amount) > 0")
    chk("silver.customers: id unique", len(set(cu.column("id").to_pylist())) == cu.num_rows, f"{cu.num_rows} rows")
    orphans = S("select count(*) n from t where customer_id not in (select id from c)", t=tx, c=cu).column("n")[0].as_py()
    chk("referential integrity: transactions -> customers", orphans == 0, f"{orphans} orphans")
    chk("reconciliation: bronze = silver + quarantine", bronze_counts["transactions"] == stats["silver_tx"] + stats["quarantined"], f"{bronze_counts['transactions']} = {stats['silver_tx']} + {stats['quarantined']}")
    rate = stats["quarantined"] / bronze_counts["transactions"]
    chk("quarantine rate under 25%", rate < 0.25, f"{rate:.1%}")
    chk("gold.timeline not empty", R("gold", "timeline").num_rows > 0, f"{R('gold', 'timeline').num_rows} events")
    chk("documents: suspected injection chunks (informational)", True, f"{stats['flagged_chunks']} flagged of {stats['chunks']}", critical=False)
    return checks

def run_pipeline(raw, lake):
    t0 = time.time(); bronze = ingest_bronze(raw, lake); stats = build_silver_gold(raw, lake); checks = quality(lake, bronze, stats)
    failed = [c for c in checks if c["critical"] and not c["passed"]]
    report = dict(bronze_rows=bronze, **stats, checks=checks, seconds=round(time.time() - t0, 2), ok=not failed)
    json.dump(report, open(os.path.join(lake.root, "quality_report.json"), "w"), indent=2)
    if failed: raise RuntimeError("critical data-quality checks failed: " + "; ".join(c["check"] for c in failed))
    return report
