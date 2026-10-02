#!/usr/bin/env python3
"""FAIL-first pins for tipnotary. LIVE KV but ISOLATED: key TIPNOTARY_KEY, chain in
./test-tipnotary — the production si/tip anchor is never touched. rc=0 all green,
rc=2 any failure. The pins restate the wardroom kill criteria:
  T5 is the load-bearing pin: self-consistent forgery must pass receiptd verify
  AND fail tipnotary check. If T5 ever goes red, the notary is decoration."""
import json, os, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
STATE = HERE / "test-tipnotary"
KEY = "test/tip"
ENV = dict(os.environ, SI_STATE_DIR=str(STATE), TIPNOTARY_KEY=KEY)

results = []
def pin(name, fn):
    try:
        detail = fn()
        results.append((name, True, detail))
        print(f"PASS {name} - {detail}")
    except Exception as e:
        results.append((name, False, f"{type(e).__name__}: {e}"))
        print(f"FAIL {name} - {type(e).__name__}: {e}")

def run(*args, extra_env=None):
    e = dict(ENV)
    if extra_env:
        e.update(extra_env)
    return subprocess.run([sys.executable, str(HERE / "tipnotary.py"), *args],
                          capture_output=True, text=True, env=e)

def rd(*args):
    return subprocess.run([sys.executable, str(HERE / "receiptd.py"), *args],
                          capture_output=True, text=True, env=ENV)

def chain_lines():
    return (STATE / "receipts.jsonl").read_text().splitlines()

def tip():
    return json.loads(chain_lines()[-1])

def ensure_chain():
    STATE.mkdir(parents=True, exist_ok=True)
    if not (STATE / "receipts.jsonl").exists() or len(chain_lines()) < 2:
        assert rd("append", "--lane", "pin", "--corr", "seed1", "--verb", "built",
                  "--claim", "seed receipt 1", "--v", "1").returncode == 0
        assert rd("append", "--lane", "pin", "--corr", "seed1", "--verb", "audit",
                  "--claim", "seed receipt 2", "--v", "1").returncode == 0

def p0_kv_reachable():
    r = run("check")
    # fresh dir may be 404 (no anchor) or match; only infrastructure errors are red
    assert "KV PUT failed" not in r.stderr and "KV GET failed" not in r.stderr, r.stderr[:200]
    return f"KV reachable, check rc={r.returncode} (0|2|3 all fine here)"

def p1_notarize_ok():
    ensure_chain()
    r = run("notarize")
    assert r.returncode == 0, f"rc={r.returncode}: {r.stderr[:200]}"
    t = tip()
    # the receipt (last line) documents the anchor one seq behind itself:
    # anchored tip = pre-receipt tip; stdout seq == evidence.anchored_seq == receipt seq - 1
    import re
    assert t["verb"] == "notarize" and t["evidence"]["anchored_seq"] == t["seq"] - 1, json.dumps(t)[:200]
    m = re.search(r"seq=(\d+) kv=match receipt=seq(\d+)", r.stdout)
    assert m and int(m.group(1)) == t["seq"] - 1 and int(m.group(2)) == t["seq"], r.stdout
    return f"anchored seq={m.group(1)} h={t['evidence']['anchored_h'][:12]}…, receipt seq={m.group(2)} documents it"

def p2_check_match():
    r = run("check")
    assert r.returncode == 0, f"rc={r.returncode}: {r.stdout}{r.stderr}"
    return r.stdout.strip()

def p3_notarize_twice_self_explains():
    n1 = run("notarize"); assert n1.returncode == 0, n1.stderr[:200]
    n2 = run("notarize"); assert n2.returncode == 0, n2.stderr[:200]
    c = run("check"); assert c.returncode == 0, f"trailing notarize receipts did not self-explain: {c.stderr[:200]}"
    assert len(chain_lines()) >= 4
    return f"two anchors + trailing receipts, check still rc=0"

def p4_growth_is_stale_then_refresh():
    n_before = len(chain_lines())
    assert rd("append", "--lane", "pin", "--corr", "grow", "--verb", "note",
              "--claim", "legit unanchored growth").returncode == 0
    c = run("check")
    assert c.returncode == 3, f"rc={c.returncode} (want 3 STALE): {c.stdout}{c.stderr}"
    assert "stale" in c.stdout, c.stdout
    r = run("notarize"); assert r.returncode == 0, r.stderr[:200]
    c2 = run("check"); assert c2.returncode == 0, c2.stderr[:200]
    return f"STALE named (+1 legit append), refresh -> rc=0 (chain {n_before}->{len(chain_lines())})"

def p5_self_consistent_forgery_named():
    store = STATE / "receipts.jsonl"
    orig = store.read_bytes()  # byte-exact restore
    f = run("forge-test", "--i-know-this-rewrites-the-chain")
    assert f.returncode == 0, f"forge harness failed: {f.stderr[:200]}"
    v = rd("verify")
    assert v.returncode == 0 and json.loads(v.stdout)["verified"] is True, \
        f"forgery did not pass verify — limit not demonstrated: {v.stdout}"
    c = run("check")
    assert c.returncode == 2, f"rc={c.returncode} (want 2 FORGED): {c.stdout}{c.stderr}"
    assert "FORGED" in c.stderr, c.stderr[:200]
    store.write_bytes(orig)  # restore byte-exact
    v2 = rd("verify"); assert json.loads(v2.stdout)["verified"] is True, "restore failed"
    r = run("notarize"); assert r.returncode == 0, r.stderr[:200]
    c2 = run("check"); assert c2.returncode == 0, c2.stderr[:200]
    return "verify blind (PASS on forgery), notary sighted (FORGED rc=2), restore+refresh -> rc=0"

def p6_kill_trial_alive():
    r = run("kill-trial", "--rounds", "5")
    assert r.returncode == 0 and "0 kills" in r.stdout, f"{r.returncode}: {r.stdout[-200:]}{r.stderr[:200]}"
    return "5/5 rounds, 0 kills"

def p7_empty_chain_genesis_anchor():
    d = HERE / "test-tipnotary-empty"
    import shutil; shutil.rmtree(d, ignore_errors=True)
    d.mkdir(parents=True)
    env = dict(ENV, SI_STATE_DIR=str(d))
    r = subprocess.run([sys.executable, str(HERE / "tipnotary.py"), "notarize"],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0 and "seq=0" in r.stdout, f"{r.stdout}{r.stderr[:200]}"
    c = subprocess.run([sys.executable, str(HERE / "tipnotary.py"), "check"],
                       capture_output=True, text=True, env=env)
    assert c.returncode == 0, f"{c.stdout}{c.stderr[:200]}"
    shutil.rmtree(d, ignore_errors=True)
    return "empty chain anchored at genesis seq=0, check rc=0"

def p8_bad_namespace_fails_loud():
    r = run("notarize", extra_env={"TIPNOTARY_KV_NS": "deadbeef0000000000000000000000000000000000000000000000000000000000"})
    assert r.returncode == 2 and ("KV PUT failed" in r.stderr or "KV GET failed" in r.stderr or "no namespace" in r.stderr), \
        f"rc={r.returncode}: {r.stdout[:100]}{r.stderr[:200]}"
    return f"dead namespace refused rc=2 named"

def main():
    pin("T0 KV reachable via new token", p0_kv_reachable)
    pin("T1 notarize anchors tip, receipt lands, kv=match", p1_notarize_ok)
    pin("T2 check rc=0 match", p2_check_match)
    pin("T3 trailing notarize receipts self-explain (no false stale)", p3_notarize_twice_self_explains)
    pin("T4 legit growth -> STALE rc=3 named -> refresh -> match", p4_growth_is_stale_then_refresh)
    pin("T5 THE PIN: self-consistent forgery passes verify, FORGED rc=2 named, restore ok", p5_self_consistent_forgery_named)
    pin("T6 kill-trial 5 alive", p6_kill_trial_alive)
    pin("T7 empty chain anchors at genesis", p7_empty_chain_genesis_anchor)
    pin("T8 dead namespace fails loud rc=2", p8_bad_namespace_fails_loud)
    fails = [r for r in results if not r[1]]
    print(f"\n{'GREEN' if not fails else 'RED'}: {len(results) - len(fails)}/{len(results)} tipnotary pins hold")
    sys.exit(0 if not fails else 2)

if __name__ == "__main__":
    main()
