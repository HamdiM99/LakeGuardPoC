"""Plumbing tests against a MOCK OpenAI-compatible server. They verify parsing, fail-closed behavior and that the benchmark scripts run end to end.
They say nothing about real-model quality: real numbers come from scripts/run_llm_bench.sh."""
import json, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from lakeguard.control.agent import NaiveInjectableClient
from lakeguard.constants import CASE_CUSTOMER, CASE_IBAN
from lakeguard.control.decider import LLMDecider
from lakeguard.control.policy import D, CaseState
from lakeguard.tools import SPECS

class Mock:
    def __init__(self, responder):
        outer = self
        class H(BaseHTTPRequestHandler):
            def do_POST(s):
                body = json.loads(s.rfile.read(int(s.headers["Content-Length"]))); txt = outer.responder(body["messages"])
                s.send_response(200); s.end_headers(); s.wfile.write(json.dumps({"choices": [{"message": {"content": txt}}]}).encode())
            def do_GET(s): s.send_response(200); s.end_headers(); s.wfile.write(b'{"data":[]}')
            def log_message(s, *a): pass
        self.responder = responder; self.h = HTTPServer(("127.0.0.1", 0), H); threading.Thread(target=self.h.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.h.server_address[1]}/v1"
    def close(self): self.h.shutdown(); self.h.server_close()

def st(): return CaseState(token="", claims=dict(customer_id=CASE_CUSTOMER, ibans=[CASE_IBAN]), untrusted=["x"], tainted=True)

def test_llm_decider_maps_risk_levels_and_fails_closed():
    for out, want in [('{"risk":"low","reason":"ok"}', D.ALLOW), ('{"risk":"medium"}', D.APPROVAL), ('Sure! {"risk":"HIGH","reason":"x"}', D.DENY), ("not json", D.APPROVAL), ('{"risk":"banana"}', D.APPROVAL)]:
        m = Mock(lambda msgs, o=out: o); d = LLMDecider(m.url, "mock"); got, _ = d.assess(st(), "get_full_KYC", {"customer_id": CASE_CUSTOMER}, SPECS["get_full_KYC"]); m.close()
        assert got == want, out

def test_llm_decider_fails_closed_when_server_down():
    d = LLMDecider("http://127.0.0.1:1/v1", "mock", timeout=1)
    assert d.assess(st(), "get_full_KYC", {"customer_id": CASE_CUSTOMER}, SPECS["get_full_KYC"])[0] == D.APPROVAL and d.stats["fail_closed"] == 1

def test_llm_benchmark_scripts_run_end_to_end(tmp_path):
    from bench import llm_run, decider_eval
    clients = {}
    def investigator_and_decider(msgs):
        if msgs[0]["content"].startswith("You are a security classifier"):
            return '{"risk":"high","reason":"mock"}' if "C-20933" in msgs[-1]["content"] and "notes" in msgs[-1]["content"] else '{"risk":"low","reason":"mock"}'
        key = msgs[1]["content"]; c = clients.setdefault(key, NaiveInjectableClient(CASE_CUSTOMER, CASE_IBAN)); return c.chat(msgs)
    m = Mock(investigator_and_decider)
    try:
        r = decider_eval.main(["--base-url", m.url, "--model", "mock", "--out", str(tmp_path / "d")])
        assert r["llm:mock"]["n"] == 60 and (tmp_path / "d.md").exists()
        # NaiveInjectableClient keeps state across trials via the shared key, so reset it per trial by clearing on final
        orig = NaiveInjectableClient.chat
        def chat(self, msgs):
            out = orig(self, msgs)
            if '"final"' in out: clients.clear()
            return out
        NaiveInjectableClient.chat = chat
        try: res = llm_run.main(["--base-url", m.url, "--models", "mock", "--decider-model", "mock", "--trials", "1", "--modes", "none,full", "--out", str(tmp_path / "l")])
        finally: NaiveInjectableClient.chat = orig
        assert res["mock|none"]["leaked"] >= 1 and res["mock|full"]["leaked"] == 0
    finally: m.close()
