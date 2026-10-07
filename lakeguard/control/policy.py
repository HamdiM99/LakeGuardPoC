"""Deterministic policy engine + HMAC case tokens. This module is the authority: nothing else can relax its decision."""
import hmac, hashlib, json, time, base64, re
from dataclasses import dataclass, field
from enum import IntEnum

class D(IntEnum):
    ALLOW = 0; APPROVAL = 1; DENY = 2

def issue_token(secret: bytes, claims: dict, ttl: int = 900) -> str:
    body = json.dumps({**claims, "exp": time.time() + ttl}, sort_keys=True).encode()
    return base64.urlsafe_b64encode(body).decode() + "." + hmac.new(secret, body, hashlib.sha256).hexdigest()

def verify_token(secret: bytes, token: str):
    try:
        b, sig = token.split("."); body = base64.urlsafe_b64decode(b)
        if not hmac.compare_digest(sig, hmac.new(secret, body, hashlib.sha256).hexdigest()): return None
        c = json.loads(body); return c if c["exp"] > time.time() else None
    except Exception:
        return None

@dataclass
class CaseState:
    token: str
    claims: dict = field(default_factory=dict)
    tainted: bool = False
    sources: list = field(default_factory=list)
    untrusted: list = field(default_factory=list)
    calls: int = 0

class Policy:
    def __init__(self, specs, role_tools, max_calls=25):
        self.specs, self.role_tools, self.max_calls = specs, role_tools, max_calls

    def evaluate(self, st: CaseState, tool: str, args: dict):
        c, d, why = st.claims, D.ALLOW, []
        def up(x, r):
            nonlocal d; d = max(d, x); why.append(r)
        if tool not in self.specs or tool not in self.role_tools.get(c.get("role"), ()):
            return D.DENY, ["tool not permitted for role"]
        spec = self.specs[tool]
        if set(args) - set(spec["params"]): up(D.DENY, "unexpected parameters: " + ",".join(sorted(set(args) - set(spec["params"]))))
        for k, pat in spec["params"].items():
            v = args.get(k)
            if not isinstance(v, str) or not re.fullmatch(pat, v): up(D.DENY, f"parameter '{k}' missing or fails schema")
        if args.get("customer_id") not in (None, c.get("customer_id")): up(D.DENY, "customer outside case scope")
        for v in args.values():
            if isinstance(v, str) and any(m != c.get("customer_id") for m in re.findall(r"C-\d{4,6}", v)): up(D.DENY, "argument references another customer")
        if "iban" in args and args["iban"] not in c.get("ibans", []): up(D.DENY, "iban outside case scope")
        if st.calls >= self.max_calls: up(D.DENY, "call budget exhausted")
        if spec["sens"] == "high": up(D.APPROVAL, "sensitive data requires analyst approval")
        if spec["external"] and st.tainted: up(D.APPROVAL, "external call with untrusted content in context")
        return d, why
