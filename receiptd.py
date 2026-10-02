#!/usr/bin/env python3
"""receiptd — the fleet's trust layer, slice 1 (headless).

One append-only JSONL hash chain. Daemon + CLI twin (same file).
Trust = re-execution (slice 2 wires champion_audit); slice 1 proves the
chain: tamper a byte and verify names the line.

Record:
  {seq, ts, lane, corr, room?, verb, kind?, claim, v (-1|0|+1),
   usage? {tok,wh,usd}, evidence?, note?, h_prev, h}
  h = sha256(h_prev + "\\n" + canonical(rec minus h)); canonical = sorted
  keys, compact separators. Genesis h_prev = 64 zeros. Appended line is
  canonical(full rec incl. h) — the file is self-verifying.

Protocol (unix socket, NDJSON): one request per line, one reply per line.
  {"op":"append","rec":{...}}      -> {"ok":true,"seq":N,"h":...}
  {"op":"get","seq":N}             -> {"ok":true,"rec":{...}}
  {"op":"by-corr","corr":C}        -> {"ok":true,"recs":[...]}
  {"op":"tail","n":20}             -> {"ok":true,"recs":[...]}
  {"op":"verify"}                  -> {"ok":true,"verified":true,"checked":N}
  {"op":"stats"}                   -> {"ok":true,"count":N,"h_head":...}
Failure: {"ok":false,"error":"..."} — connection survives errors.

Laws: append-only (verify catches deletions via seq gaps), O(chunk) reads,
flock-serialized appends (multi-process safe), stdlib only, fail-loud rc=2.
"""
import argparse, fcntl, hashlib, json, os, socket, subprocess, sys, threading, time
from pathlib import Path

STATE_DIR = Path(os.environ.get("SI_STATE_DIR", str(Path.home() / ".local/state/si")))
STORE = STATE_DIR / "receipts.jsonl"
SOCK = STATE_DIR / "receiptd.sock"
GENESIS = "0" * 64
VALID_VERBS = {"ask", "answer", "gist", "interrupt", "handoff", "receipt",
               "pin", "audit", "demote", "note",
               "notarize", "built", "planned", "d12-forced"}


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def rec_hash(h_prev, rec):
    body = {k: v for k, v in rec.items() if k != "h"}
    return hashlib.sha256((h_prev + "\n" + canonical(body)).encode()).hexdigest()


def validate(rec):
    for k in ("lane", "corr", "verb", "claim"):
        if not str(rec.get(k) or "").strip():
            raise ValueError(f"missing required field: {k}")
    if rec.get("v") not in (-1, 0, 1):
        raise ValueError("v must be -1, 0, or +1 (three-valued or not at all)")
    if rec["verb"] not in VALID_VERBS:
        raise ValueError(f"unknown verb: {rec['verb']} (valid: {sorted(VALID_VERBS)})")
    if not isinstance(rec.get("usage", {}), dict):
        raise ValueError("usage must be an object")


def _last_line(f):
    """Read the final non-empty line without loading the file. O(block)."""
    f.seek(0, 2)
    end = f.tell()
    if end == 0:
        return None
    block = 65536
    while True:
        size = min(end, block)
        f.seek(end - size)
        data = f.read(size)
        lines = [l for l in data.split(b"\n") if l.strip()]
        if lines:
            return lines[-1].decode()
        if size >= end:
            return None
        block *= 4
        if block > 64 * 1024 * 1024:
            raise IOError("last-line scan exceeded 64MB tail")


def append_rec(rec):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    rec = dict(rec)
    rec.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    validate(rec)
    with open(STORE, "ab+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        last = _last_line(f)   # binary handle: bytes in, bytes out; writes O_APPEND to EOF
        if last:
            prev = json.loads(last)
            h_prev, seq = prev["h"], prev["seq"] + 1
        else:
            h_prev, seq = GENESIS, 1
        rec["seq"] = seq
        rec["h_prev"] = h_prev
        rec["h"] = rec_hash(h_prev, rec)
        f.write(canonical(rec).encode() + b"\n")
        f.flush()
        os.fsync(f.fileno())
        fcntl.flock(f, fcntl.LOCK_UN)
    return rec


def stream_recs():
    """Yield (offset, rec) O(chunk) at a time."""
    if not STORE.exists():
        return
    with open(STORE) as f:
        for line in f:
            line = line.strip()
            if line:
                yield line


def verify_chain():
    """Re-derive the whole chain. Returns (True, count) or (False, dict)."""
    prev_h, expect_seq, checked = GENESIS, 1, 0
    for i, line in enumerate(stream_recs(), start=1):
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as e:
            return False, {"line": i, "why": f"unparseable JSON: {e}"}
        if rec.get("seq") != expect_seq:
            return False, {"line": i, "why": f"seq gap/repeat: got {rec.get('seq')}, expected {expect_seq} (deletion or rewrite)"}
        if rec.get("h_prev") != prev_h:
            return False, {"line": i, "seq": rec["seq"], "why": f"broken link: h_prev != previous h"}
        if rec.get("h") != rec_hash(prev_h, rec):
            return False, {"line": i, "seq": rec["seq"], "why": "hash mismatch: record content or order was altered"}
        prev_h, expect_seq, checked = rec["h"], rec["seq"] + 1, checked + 1
    return True, checked


# ---------------- daemon ----------------

class Index:
    """In-memory index; disk is the source of truth (verify re-derives)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.by_seq = {}    # seq -> rec
        self.by_corr = {}   # corr -> [rec]
        self.count = 0
        self.head = GENESIS
        self.rebuild()

    def rebuild(self):
        for line in stream_recs():
            rec = json.loads(line)
            self._add(rec)

    def _add(self, rec):
        with self.lock:
            self.by_seq[rec["seq"]] = rec
            self.by_corr.setdefault(rec["corr"], []).append(rec)
            self.count += 1
            self.head = rec["h"]

    def add(self, rec):
        self._add(rec)

    def get(self, seq):
        with self.lock:
            r = self.by_seq.get(seq)
            return dict(r) if r else None

    def corr(self, c):
        with self.lock:
            return [dict(r) for r in self.by_corr.get(c, [])]

    def tail(self, n):
        with self.lock:
            seqs = sorted(self.by_seq)[-n:]
            return [dict(self.by_seq[s]) for s in seqs]


def handle(req, idx):
    op = req.get("op")
    if op == "append":
        rec = append_rec(req.get("rec") or {})
        idx.add(rec)
        return {"ok": True, "seq": rec["seq"], "h": rec["h"]}
    if op == "get":
        r = idx.get(int(req.get("seq", -1)))
        return {"ok": True, "rec": r} if r else {"ok": False, "error": f"no receipt seq={req.get('seq')}"}
    if op == "by-corr":
        return {"ok": True, "recs": idx.corr(str(req.get("corr", "")))}
    if op == "tail":
        return {"ok": True, "recs": idx.tail(max(1, min(int(req.get("n", 20)), 1000)))}
    if op == "verify":
        ok, info = verify_chain()
        return {"ok": True, "verified": ok, "checked": info} if ok else {"ok": True, "verified": False, "bad": info}
    if op == "stats":
        return {"ok": True, "count": idx.count, "h_head": idx.head}
    return {"ok": False, "error": f"unknown op: {op}"}


def serve(sock_path=None):
    sock_path = Path(sock_path or SOCK)
    sock_path.parent.mkdir(parents=True, exist_ok=True)
    if sock_path.exists():
        sock_path.unlink()
    idx = Index()
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(sock_path))
    os.chmod(str(sock_path), 0o600)
    srv.listen(16)
    print(f"receiptd: {len(idx.by_seq)} receipts indexed, head {idx.head[:12]}…, listening on {sock_path}", flush=True)

    def client(conn):
        try:
            buf = b""
            while True:
                while b"\n" not in buf:
                    chunk = conn.recv(65536)
                    if not chunk:
                        return
                    buf += chunk
                line, buf = buf.split(b"\n", 1)
                if not line.strip():
                    continue
                try:
                    resp = handle(json.loads(line), idx)
                except (ValueError, KeyError, json.JSONDecodeError) as e:
                    resp = {"ok": False, "error": str(e)}
                conn.sendall((canonical(resp) + "\n").encode())
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            conn.close()

    try:
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=client, args=(conn,), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()
        sock_path.unlink(missing_ok=True)


# ---------------- CLI ----------------

def connect_or_spawn(timeout=8.0):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(str(SOCK))
        return s
    except (FileNotFoundError, ConnectionRefusedError, socket.timeout):
        pass
    subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "serve"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=True)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect(str(SOCK))
            return s
        except (FileNotFoundError, ConnectionRefusedError, socket.timeout):
            time.sleep(0.15)
    print(f"receipt: could not reach or spawn daemon at {SOCK}", file=sys.stderr)
    sys.exit(2)


def rpc(req):
    s = connect_or_spawn()
    try:
        s.sendall((canonical(req) + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        return json.loads(buf.split(b"\n", 1)[0])
    finally:
        s.close()


def main():
    global SOCK
    ap = argparse.ArgumentParser(prog="receipt", description="receiptd CLI twin — the fleet's trust layer")
    ap.add_argument("--socket", help="override socket path")
    sub = ap.add_subparsers(dest="cmd", required=True)
    pa = sub.add_parser("append")
    pa.add_argument("--lane", required=True)
    pa.add_argument("--corr", required=True)
    pa.add_argument("--verb", required=True, choices=sorted(VALID_VERBS))
    pa.add_argument("--claim", required=True)
    pa.add_argument("--v", type=int, default=0, choices=(-1, 0, 1))
    pa.add_argument("--room")
    pa.add_argument("--kind")
    pa.add_argument("--usage", help='JSON, e.g. {"tok":1200}')
    pa.add_argument("--evidence", help="JSON")
    pa.add_argument("--note")
    pg = sub.add_parser("get"); pg.add_argument("seq", type=int)
    pc = sub.add_parser("by-corr"); pc.add_argument("corr")
    pt = sub.add_parser("tail"); pt.add_argument("n", type=int, nargs="?", default=20)
    sub.add_parser("verify")
    sub.add_parser("stats")
    ps = sub.add_parser("serve"); ps.add_argument("--socket")

    a = ap.parse_args()
    if a.socket:
        SOCK = Path(a.socket)

    if a.cmd == "serve":
        serve(a.socket)
        return
    if a.cmd == "append":
        rec = {"lane": a.lane, "corr": a.corr, "verb": a.verb, "claim": a.claim, "v": a.v}
        if a.room: rec["room"] = a.room
        if a.kind: rec["kind"] = a.kind
        if a.usage: rec["usage"] = json.loads(a.usage)
        if a.evidence: rec["evidence"] = json.loads(a.evidence)
        if a.note: rec["note"] = a.note
        r = rpc({"op": "append", "rec": rec})
    else:
        r = rpc({"op": a.cmd, **({"seq": a.seq} if a.cmd == "get" else {}),
                 **({"corr": a.corr} if a.cmd == "by-corr" else {}),
                 **({"n": a.n} if a.cmd == "tail" else {})})
    print(json.dumps(r, indent=2, sort_keys=True))
    if a.cmd == "verify" and not r.get("verified"):
        sys.exit(2)
    if not r.get("ok"):
        sys.exit(2)


if __name__ == "__main__":
    main()
