"""A real local HTTP service that records every request body (used as 'external reputation API' and as attacker sink)."""
import json, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

class RecordingServer:
    def __init__(self, comment="Beneficiary account opened recently."):
        self.bodies, outer = [], self
        class H(BaseHTTPRequestHandler):
            def do_POST(s):
                outer.bodies.append(json.loads(s.rfile.read(int(s.headers["Content-Length"]))))
                s.send_response(200); s.end_headers()
                s.wfile.write(json.dumps({"score": 0.8, "comment": comment}).encode())
            def log_message(s, *a): pass
        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
    @property
    def url(self): return f"http://127.0.0.1:{self.port}/"
    @property
    def addr(self): return f"127.0.0.1:{self.port}"
    def clear(self): self.bodies.clear()
    def close(self): self.httpd.shutdown(); self.httpd.server_close()
