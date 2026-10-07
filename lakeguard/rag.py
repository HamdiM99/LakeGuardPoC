"""Lexical RAG (BM25) over the gold.doc_chunks table. Access control is applied BEFORE scoring: a case can only see public documents and its own."""
import re, math
from collections import Counter

TOK = re.compile(r"[a-z0-9\-]+")
class Retriever:
    def __init__(self, chunks, k1=1.5, b=0.75):
        self.rows, self.k1, self.b = chunks.to_pylist(), k1, b
        self.toks = [TOK.findall((r["title"] + " " + r["text"]).lower()) for r in self.rows]
        self.df = Counter(t for ts in self.toks for t in set(ts)); self.avg = sum(map(len, self.toks)) / max(len(self.toks), 1)
    def search(self, query, case_id, k=3):
        q, n, scored = TOK.findall(query.lower()), len(self.rows), []
        for r, ts in zip(self.rows, self.toks):
            if r["acl"] not in ("public", case_id): continue                      # row-level security on documents
            tf, s = Counter(ts), 0.0
            for t in q:
                if t in tf: s += math.log(1 + (n - self.df[t] + .5) / (self.df[t] + .5)) * tf[t] * (self.k1 + 1) / (tf[t] + self.k1 * (1 - self.b + self.b * len(ts) / self.avg))
            if s > 0: scored.append((s, r))
        return [dict(doc=r["doc"], title=r["title"], source=r["source"], flagged=r["flagged"], text=r["text"]) for s, r in sorted(scored, key=lambda x: -x[0])[:k]]
