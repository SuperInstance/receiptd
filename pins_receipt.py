#!/usr/bin/env python3
"""FAIL-first pins for receiptd slice 1. SI_STATE_DIR must point at a TEST dir.
The runner pre-warms the daemon (RED if it won't come up — that's pin zero's honesty).
rc=0 all green; rc=2 any failure."""
import json, os, socket, subprocess, sys, threading, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
RD = HERE / "receiptd.py"
STATE = Path(os.environ.get("SI_STATE_DIR", ""))


def sh(*args, env=None):
    e = dict(os.environ)
    if env:
        e.update(env)
    return subprocess.run([sys.executable, str(RD), *args], capture_output=True, text=True, env=e)


def rpc(req, state_dir=None):
    sp = (state_dir or STATE) / "receiptd.sock"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(str(sp))
    s.sendall((json.dumps(req, sort_keys=True) + "\n").encode())
    buf = b""
    while b"\n" not in buf:
        c = s.recv(65536)
        if not c:
            break
        buf += c
    s.close()
    return json.loads(buf.split(b"\n", 1)[0])


def rec(corr, verb="note", claim="pin claim", v=0, lane="pin-lane"):
    return {"lane": lane, "corr": corr, "verb": verb, "claim": claim, "v": v}


results = []
def pin(name, fn):
    try:
        detail = fn()
        results.append((name, True, detail))
        print(f"PASS {name} - {detail}")
    except Exception as e:
        results.append((name, False, f"{type(e).__name__}: {e}"))
        print(f"FAIL {name} - {type(e).__name__}: {e}")


def spawn_daemon(state_dir):
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "receipts.jsonl").unlink(missing_ok=True)
    (state_dir / "receiptd.sock").unlink(missing_ok=True)
    subprocess.Popen([sys.executable, str(RD), "serve"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     env=dict(os.environ, SI_STATE_DIR=str(state_dir)),
                     start_new_session=True)


def wait_sock(state_dir, timeout=8):
    end = time.time() + timeout
    while time.time() < end:
        if (state_dir / "receiptd.sock").exists():
            try:
                r = rpc({"op": "stats"}, state_dir)
                if r.get("ok"):
                    return r
            except Exception:
                pass
        time.sleep(0.15)
    return None


def p0_daemon_comes_up():
    global daemon_ok
    spawn_daemon(STATE)
    r = wait_sock(STATE)
    assert r, "daemon did not come up / stats unreachable"
    daemon_ok = True
    return f"stats ok, count={r.get('count')}"


def p1_roundtrip():
    r = rpc({"op": "append", "rec": rec("c-rt-1", claim="roundtrip", v=1)})
    assert r.get("ok") and r.get("seq") == 1, f"append: {r}"
    g = rpc({"op": "get", "seq": 1})
    assert g.get("ok") and g["rec"]["claim"] == "roundtrip" and g["rec"]["v"] == 1, f"get: {g}"
    return f"seq=1 h={r['h'][:12]}…"


def p2_verify_clean():
    v = rpc({"op": "verify"})
    assert v.get("ok") and v.get("verified") and v.get("checked", 0) >= 1, f"verify: {v}"
    return f"checked={v['checked']}"


def p3_tamper_named():
    store = STATE / "receipts.jsonl"
    orig = store.read_text()
    lines = orig.split("\n")
    tampered = orig.replace("roundtrip", "TAMPERED", 1)
    assert tampered != orig, "tamper no-op"
    store.write_text(tampered)
    v = rpc({"op": "verify"})
    assert v.get("ok") and v.get("verified") is False, f"tamper not caught: {v}"
    assert v["bad"].get("line") == 1, f"wrong line named: {v}"
    store.write_text(orig)  # restore byte-exact
    v2 = rpc({"op": "verify"})
    assert v2.get("verified") is True, f"restore failed: {v2}"
    return f"caught at line {v['bad']['line']}, restore -> PASS"


def p4_by_corr():
    replies = []
    for i in range(3):
        r = rpc({"op": "append", "rec": rec("c-thread-7", verb="ask" if i == 0 else "answer", claim=f"t{i}")})
        replies.append(r)
        assert r.get("ok"), f"append {i} refused: {r}"
    b = rpc({"op": "by-corr", "corr": "c-thread-7"})
    assert b.get("ok") and len(b["recs"]) == 3, f"by-corr: {b}"
    assert all(r["corr"] == "c-thread-7" for r in b["recs"]), "wrong corr in thread"
    return "3 receipts in thread"


def p5_malformed_survives():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(str(STATE / "receiptd.sock"))
    s.sendall(b"{this is not json\n")
    buf = b""
    while b"\n" not in buf:
        buf += s.recv(65536)
    r1 = json.loads(buf.split(b"\n", 1)[0])
    assert r1.get("ok") is False, f"malformed accepted: {r1}"
    s.sendall((json.dumps({"op": "stats"}) + "\n").encode())
    buf = b""
    while b"\n" not in buf:
        buf += s.recv(65536)
    r2 = json.loads(buf.split(b"\n", 1)[0])
    s.close()
    assert r2.get("ok") and r2.get("count", 0) >= 4, f"connection dead after error: {r2}"
    return f"error={str(r1.get('error'))[:40]}… then stats ok on same conn"


def p6_bad_verb():
    r = sh("append", "--lane", "x", "--corr", "y", "--verb", "smite", "--claim", "z")
    assert r.returncode == 2, f"rc={r.returncode} (want 2): {r.stdout}{r.stderr}"
    return "rc=2 refused"


def p7_bad_verdict():
    r = rpc({"op": "append", "rec": rec("c-v2", v=2)})
    assert r.get("ok") is False and "v must be" in r.get("error", ""), f"v=2 accepted: {r}"
    return "refused: v must be -1, 0, or +1"


def p8_deletion_gap():
    store = STATE / "receipts.jsonl"
    lines = store.read_text().rstrip("\n").split("\n")
    assert len(lines) >= 4, f"need >=4 lines, have {len(lines)}"
    victim = lines[2]
    del lines[2]
    store.write_text("\n".join(lines) + "\n")
    v = rpc({"op": "verify"})
    caught = v.get("verified") is False and "gap" in v.get("bad", {}).get("why", "")
    # restore byte-exact before asserting, so the store survives this pin
    store.write_text("\n".join(lines[:2] + [victim] + lines[2:]) + "\n")
    v2 = rpc({"op": "verify"})
    assert v2.get("verified") is True, f"restore failed: {v2}"
    assert caught, f"deletion not caught as gap: {v}"
    return f"gap named: {v['bad']['why'][:60]}…; restored -> PASS"


def p9_concurrent_clients():
    state2 = STATE.parent / "receiptd-pinrun2"
    spawn_daemon(state2)
    r = wait_sock(state2)
    assert r, "state2 daemon did not come up"
    warm = sh("append", "--lane", "L", "--corr", "warm", "--verb", "note", "--claim", "warm",
              env={"SI_STATE_DIR": str(state2)})
    assert warm.returncode == 0, f"warm-up append failed: {warm.returncode} {warm.stderr[:200]}"
    out = {}
    def worker(i):
        rr = sh("append", "--lane", "L", "--corr", f"c{i}", "--verb", "note", "--claim", f"w{i}",
                env={"SI_STATE_DIR": str(state2)})
        out[i] = (rr.returncode, rr.stderr[:200], rr.stdout[:200])
    ts = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    bad = {i: v for i, v in out.items() if v[0] != 0}
    assert not bad, f"concurrent failures: {bad}"
    v = rpc({"op": "verify"}, state2)
    assert v.get("verified") is True, f"chain broken after concurrency: {v}"
    seqs = sorted(json.loads(l)["seq"] for l in (state2 / "receipts.jsonl").read_text().splitlines())
    assert seqs == list(range(1, 10)), f"seqs wrong: {seqs}"  # warm-up + 8 workers
    return "8/8 concurrent clients + warm-up, seqs 1..9 unique contiguous, chain verifies"


def p10_canonical_stable():
    sys.path.insert(0, str(HERE))
    import receiptd as R
    a = {"claim": "same", "corr": "c", "lane": "l", "verb": "note", "v": 0, "usage": {"tok": 10}}
    b = {"usage": {"tok": 10}, "v": 0, "verb": "note", "lane": "l", "corr": "c", "claim": "same"}
    assert R.canonical(a) == R.canonical(b), "canonical differs on key order"
    assert R.rec_hash(R.GENESIS, a) == R.rec_hash(R.GENESIS, b), "hash differs on key order"
    return f"stable h={R.rec_hash(R.GENESIS, a)[:12]}…"


def p11_append_only_witness():
    store = STATE / "receipts.jsonl"
    ino_before = store.stat().st_ino
    n_before = len(store.read_text().splitlines())
    rpc({"op": "append", "rec": rec("c-witness", claim="witness")})
    assert store.stat().st_ino == ino_before, "store inode changed (rewrite!)"
    assert len(store.read_text().splitlines()) == n_before + 1, "not exactly +1 line"
    return "append-only witnessed (inode stable, +1 line)"


def main():
    if not STATE:
        print("set SI_STATE_DIR to a test dir", file=sys.stderr)
        sys.exit(2)
    subprocess.run(["pkill", "-f", "receiptd[.]py serve"], capture_output=True)
    time.sleep(0.3)
    pin("P0 daemon comes up and answers stats", p0_daemon_comes_up)
    pin("P1 append->get round-trip", p1_roundtrip)
    pin("P2 verify PASS on clean store", p2_verify_clean)
    pin("P3 tampered byte -> verify FAIL names line, restore -> PASS", p3_tamper_named)
    pin("P4 by-corr threads 3 receipts", p4_by_corr)
    pin("P5 malformed JSON refused, connection survives", p5_malformed_survives)
    pin("P6 unknown verb refused rc=2", p6_bad_verb)
    pin("P7 v=2 refused (three-valued or nothing)", p7_bad_verdict)
    pin("P8 deleted line -> verify FAIL (seq gap), restore -> PASS", p8_deletion_gap)
    pin("P9 8 concurrent clients -> unique seqs, chain verifies", p9_concurrent_clients)
    pin("P10 canonical hash stable across key order", p10_canonical_stable)
    pin("P11 append-only witnessed (inode + line count)", p11_append_only_witness)
    fails = [r for r in results if not r[1]]
    print(f"\n{'GREEN' if not fails else 'RED'}: {len(results) - len(fails)}/{len(results)} pins hold")
    sys.exit(0 if not fails else 2)


if __name__ == "__main__":
    main()
