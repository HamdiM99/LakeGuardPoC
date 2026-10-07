"""Delta Lake tables (delta-rs) on the filesystem + DuckDB SQL + a lineage log. Layers: bronze / silver / gold."""
import os, json, time, duckdb
from deltalake import write_deltalake, DeltaTable

class Lake:
    def __init__(self, root):
        self.root = root; os.makedirs(root, exist_ok=True); self.lineage = os.path.join(root, "lineage.jsonl")
    def path(self, layer, name): return os.path.join(self.root, layer, name)
    def write(self, layer, name, table, step, inputs=()):
        write_deltalake(self.path(layer, name), table, mode="overwrite")
        rec = dict(ts=time.time(), step=step, output=f"{layer}.{name}", inputs=list(inputs), rows=table.num_rows, version=DeltaTable(self.path(layer, name)).version())
        with open(self.lineage, "a") as f: f.write(json.dumps(rec) + "\n")
    def read(self, layer, name, version=None):
        return DeltaTable(self.path(layer, name), version=version).to_pyarrow_table()
    def version(self, layer, name): return DeltaTable(self.path(layer, name)).version()
    @staticmethod
    def sql(query, **tables):
        con = duckdb.connect()
        for k, v in tables.items(): con.register(k, v)
        return con.execute(query).to_arrow_table()
