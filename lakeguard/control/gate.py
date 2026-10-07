"""The gate: verify -> policy -> advisory decider (tighten-only) -> egress-guarded execution -> taint tagging -> audit."""
import time, contextlib
from .policy import D, CaseState, issue_token, verify_token
from .runtime import egress_guard

def tag(obj, fields):
    hit = []
    def mark(v): hit.append(v); return f"<untrusted>{v}</untrusted>"
    def w(o):
        if isinstance(o, dict): return {k: (mark(v) if k in fields and isinstance(v, str) else w(v)) for k, v in o.items()}
        if isinstance(o, list): return [w(x) for x in o]
        return o
    return w(obj), hit

class ControlPlane:
    """mode: none | rbac | runtime_only | policy_only | full  (the first four are benchmark baselines/ablations)."""
    def __init__(self, tools, specs, policy, decider=None, audit=None, secret=b"dev-secret", egress=(), approver=None, mode="full"):
        self.tools, self.specs, self.policy, self.decider, self.audit = tools, specs, policy, decider, audit
        self.secret, self.egress, self.approver, self.mode = secret, set(egress), approver, mode

    def open_case(self, case_id, customer_id, ibans, role="investigator"):
        return CaseState(issue_token(self.secret, dict(case_id=case_id, customer_id=customer_id, ibans=list(ibans), role=role)))

    def submit(self, st: CaseState, tool: str, args: dict):
        t0 = time.perf_counter(); claims = verify_token(self.secret, st.token)
        if claims is None: dec, why = D.DENY, ["invalid or expired case token"]
        else:
            st.claims = claims
            if self.mode in ("none", "runtime_only"): dec, why = D.ALLOW, []
            elif self.mode == "rbac": dec, why = (D.ALLOW, []) if tool in self.tools else (D.DENY, ["unknown tool"])
            else:
                dec, why = self.policy.evaluate(st, tool, args)
                if self.mode == "full" and self.decider and (st.untrusted or getattr(self.decider, "always", False)):
                    s, r = self.decider.assess(st, tool, args, self.specs.get(tool, {}))
                    if s > dec: dec = s; why.append("decider: " + r)   # tighten-only: a lower signal is ignored
        ms = (time.perf_counter() - t0) * 1000; st.calls += 1
        out = {"decision": dec.name, "reasons": why, "decision_ms": ms}
        approved = dec == D.APPROVAL and self.approver is not None and bool(self.approver(tool, args, why))
        if dec == D.ALLOW or approved: out["result"] = self._exec(st, tool, args)
        out["approved"] = approved
        if self.audit: self.audit.log(case=(claims or {}).get("case_id"), tool=tool, args=args, decision=dec.name, reasons=why, tainted=st.tainted, approved=approved)
        return out

    def _exec(self, st, tool, args):
        guard = egress_guard(self.egress) if self.mode in ("runtime_only", "policy_only", "full") else contextlib.nullcontext()
        try:
            if self.specs.get(tool, {}).get("needs_case"): args = {**args, "_case": st.claims["case_id"]}   # set by the gate, never by the agent
            with guard: res = self.tools[tool](**args)
        except Exception as e:
            return {"error": f"{type(e).__name__}: {e}"}
        if self.mode in ("policy_only", "full"):
            res, hit = tag(res, self.specs.get(tool, {}).get("untrusted", ()))
            if hit: st.tainted = True; st.sources.append(tool); st.untrusted += hit
        return res
