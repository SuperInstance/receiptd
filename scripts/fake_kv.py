#!/usr/bin/env python3
"""fake_kv.py -- a LOCAL Cloudflare KV double that ENFORCES TOKEN PERMISSIONS.

The point of this file is not to be a mock. It is to be an ORACLE.

`tipnotary` closes the third leg of the witness model: a chain that
re-derives proves only self-consistency, so a full rewrite with recomputed
hashes also verifies. An external anchor catches that -- but only if the
person rewriting the chain CANNOT rewrite the anchor.

**That is a permission question, and a mock that ignores permissions
cannot answer it.** A double that accepted every token for every verb
would let the anchor "pass" a test that proves nothing.

So this double implements the two namespaces and the two token roles the
real thing has:

  namespace  notary-ns   the anchor's namespace. The NOTARY writes it.
  namespace  writer-ns   a second namespace the chain-writer may write.

  token      write-token        GET + PUT on notary-ns. The NOTARY holds it.
  token      read-token         GET only, on any namespace. A VERIFIER holds it.
  token      chain-writer-token GET only on notary-ns. It may write writer-ns.
  (no token)                   GET only. A public-read namespace.

**The split, enforced:** a token with GET only CANNOT PUT. If the code
under test does not honour the split, this double says so -- and the test
that proves the split FAILS.

Run:  python3 scripts/fake_kv.py --port 8781
"""
import argparse
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# token -> (may_write_notary_ns, label)
TOKENS = {
    "write-token": (True, "the NOTARY: GET + PUT on the anchor namespace"),
    "read-token": (False, "a VERIFIER: GET only"),
}
CHAIN_WRITER_TOKEN = "chain-writer-token"
NAMESPACES = {"notary-ns", "writer-ns"}
NOTARY_ONLY = {"notary-ns"}

STORE = {}
LOCK = threading.Lock()
KV_PATH = re.compile(r"^/client/v4/accounts/[^/]+/storage/kv/namespaces/([^/]+)/values/(.+)$")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _auth(self):
        h = self.headers.get("Authorization", "")
        tok = h[7:].strip() if h.startswith("Bearer ") else None
        if tok is None:
            return None, (False, "anonymous (public read)")
        if tok == CHAIN_WRITER_TOKEN:
            return tok, (False, "the CHAIN WRITER: read only on the anchor namespace")
        return tok, TOKENS.get(tok, (False, "unknown token: no write"))

    def _send(self, code, body=b""):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _err(self, code, msg):
        self._send(code, json.dumps({"success": False, "errors": [{"message": msg}]}).encode())

    def do_GET(self):
        m = KV_PATH.match(self.path)
        if not m:
            return self._err(404, "no such route")
        ns, key = m.group(1), m.group(2)
        if ns not in NAMESPACES:
            return self._err(404, "namespace not found")
        with LOCK:
            val = STORE.get((ns, key))
        if val is None:
            return self._err(404, "key not found")
        self._send(200, val.encode())

    def do_PUT(self):
        m = KV_PATH.match(self.path)
        if not m:
            return self._err(404, "no such route")
        ns, key = m.group(1), m.group(2)
        if ns not in NAMESPACES:
            return self._err(404, "namespace not found")
        tok, (can_write, who) = self._auth()
        if tok is None:
            return self._err(401, "PUT requires a token")
        if not can_write:
            return self._err(403, f"PUT refused: this token has read only ({who})")
        if ns in NOTARY_ONLY and tok == CHAIN_WRITER_TOKEN:
            return self._err(403, "PUT refused: the chain writer may not write the anchor namespace")
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode()
        with LOCK:
            STORE[(ns, key)] = body
        self._send(200, json.dumps({"success": True, "result": {"key": key}}).encode())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8781)
    a = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    print(f"fake_kv on http://127.0.0.1:{a.port}  namespaces={sorted(NAMESPACES)}  "
          f"tokens={sorted(TOKENS)} + {CHAIN_WRITER_TOKEN}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
