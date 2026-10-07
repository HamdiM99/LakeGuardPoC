"""One call builds the whole stack: synthetic sources -> lakehouse -> quality-checked pipeline -> RAG index -> tools."""
from .constants import INJECTION
from .synth import generate
from .lakehouse import Lake
from .etl import run_pipeline
from .rag import Retriever
from .tools import make_tools

class Stack:
    def __init__(self, workdir, injection=INJECTION, n=40, poison_note=True, poison_doc=True):
        raw = f"{workdir}/raw"; generate(raw, injection, n, poison_note=poison_note, poison_doc=poison_doc)
        self.lake = Lake(f"{workdir}/lake"); self.report = run_pipeline(raw, self.lake)
        self.rag = Retriever(self.lake.read("gold", "doc_chunks")); self.ids = self.lake.read("silver", "customers").column("id").to_pylist()
    def tools(self, reputation_url): return make_tools(self.lake, self.rag, reputation_url)
