"""Append-only, hash-chained audit log (tamper-evident)."""
import json, hashlib, time

class Audit:
    def __init__(self, path=None): self.path, self.prev, self.events = path, "0" * 64, []
    def log(self, **ev):
        ev = {"t": time.time(), **ev, "prev": self.prev}
        self.prev = hashlib.sha256(json.dumps(ev, sort_keys=True, default=str).encode()).hexdigest()
        ev["hash"] = self.prev; self.events.append(ev)
        if self.path:
            with open(self.path, "a") as f: f.write(json.dumps(ev, default=str) + "\n")
    def verify(self):
        prev = "0" * 64
        for e in self.events:
            body = {k: v for k, v in e.items() if k != "hash"}
            if body["prev"] != prev or hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest() != e["hash"]: return False
            prev = e["hash"]
        return True
