"""Agent tools reading from the lakehouse (gold/silver) and the RAG index, plus the policy specs the control plane enforces."""
import json, urllib.request
import pyarrow.compute as pc

CID, IBAN = r"C-\d{4,6}", r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}"
SPECS = {
    "get_customer_profile":         dict(sens="medium", external=False, params={"customer_id": CID}, untrusted=()),
    "get_customer_transactions":    dict(sens="medium", external=False, params={"customer_id": CID}, untrusted=()),
    "get_timeline":                 dict(sens="medium", external=False, params={"customer_id": CID}, untrusted=()),
    "get_beneficiaries":            dict(sens="medium", external=False, params={"customer_id": CID}, untrusted=("note",)),
    "get_full_KYC":                 dict(sens="high",   external=False, params={"customer_id": CID}, untrusted=()),
    "check_beneficiary_reputation": dict(sens="medium", external=True,  params={"iban": IBAN},      untrusted=("comment",)),
    "search_case_documents":        dict(sens="medium", external=False, params={"query": r"[^\n]{3,200}"}, untrusted=("text",), needs_case=True),
}
ROLE_TOOLS = {"investigator": set(SPECS)}

def make_tools(lake, rag, reputation_url):
    T = {n: lake.read(l, n) for l, n in [("silver", "customers"), ("silver", "transactions"), ("silver", "beneficiaries"), ("silver", "kyc"), ("gold", "timeline"), ("gold", "customer_features")]}
    def rows(name, cid, col="customer_id"): return T[name].filter(pc.equal(T[name][col], cid)).to_pylist()
    def profile(customer_id):
        c = rows("customers", customer_id, "id"); f = rows("customer_features", customer_id)
        for r in c: r["cr"] = "CR-****" + r["cr"][-3:]                                  # column-level masking
        return [dict(r, **({k: str(v) for k, v in f[0].items()} if f else {})) for r in c]
    def reputation(iban, **extra):                                                     # deliberately naive wrapper: forwards whatever it is given
        req = urllib.request.Request(reputation_url, json.dumps({"iban": iban, **extra}).encode(), {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=3) as r: return json.load(r)
    return {
        "get_customer_profile": profile,
        "get_customer_transactions": lambda customer_id: [{k: str(v) if k == "ts" else v for k, v in r.items() if k != "tx_id"} for r in rows("transactions", customer_id)],
        "get_timeline": lambda customer_id: [dict(r, ts=str(r["ts"])) for r in rows("timeline", customer_id)],
        "get_beneficiaries": lambda customer_id: [dict(r, created_ts=str(r["created_ts"])) for r in rows("beneficiaries", customer_id)],
        "get_full_KYC": lambda customer_id: rows("kyc", customer_id),
        "check_beneficiary_reputation": reputation,
        "search_case_documents": lambda query, _case: rag.search(query, _case),
    }
