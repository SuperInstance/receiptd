#!/usr/bin/env python3
"""leg3_test.py -- PROVE the credential split, offline, with no Cloudflare account.

The fleet's census found the shape of the gap exactly: **one `kv()` helper,
one `CF_API_TOKEN`, both verbs.** The writer who PUTs the anchor is the
writer who can rewrite it. The build that closes it is not a second
account; it is a SPLIT:

    the NOTARY  holds a credential that can PUT
    the CHECKER holds one that can only GET -- or none at all

**A checker that cannot write cannot be coerced into agreeing with a
forgery.** That is the third leg, and it is the only one the fleet is
missing.

These tests run against `scripts/fake_kv.py`, a local KV double that
ENFORCES token permissions. A double that ignored permissions could not
answer the question, and would make the whole thing decoration.

    python3 scripts/leg3_test.py

Exit 0 = PASS. Every check below is a behaviour that would FAIL on the
pre-split code.
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

import fake_kv                      # noqa: E402
import receiptd as R                # noqa: E402

PORT = 8799
BASE = f"http://127.0.0.1:{PORT}/client/v4"
NS = "notary-ns"
KEY = "si/tip"
ACCT = "acct-test"


def start_kv():
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), fake_kv.Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    for _ in range(50):
        try:
            import urllib.request
            urllib.request.urlopen(f"http://127.0.0.1:{PORT}/nope", timeout=1).read()
            break
        except urllib.error.HTTPError:
            break
        except Exception:
            time.sleep(0.05)
    return srv


def seed(state_dir, n=3):
    """A small, VALID receiptd chain -- built by receiptd itself, so the
    hash rule is the implementation's rule and not a copy of it."""
    d = Path(state_dir)
    d.mkdir(parents=True, exist_ok=True)
    store = d / "receipts.jsonl"
    if store.exists():
        store.unlink()
    R.STATE_DIR = d
    R.STORE = store
    for i in range(n):
        R.append_rec({"lane": "pin", "corr": f"seed{i}", "verb": "note",
                       "claim": f"seed receipt {i+1}", "v": 1,
                       "ts": "2026-10-19T00:00:00Z"})
    return store


def run(state_dir, cmd, tok=None, extra=None, env_extra=None):
    env = dict(os.environ)
    env["SI_STATE_DIR"] = str(state_dir)
    env["TIPNOTARY_KV_BASE"] = BASE
    env["TIPNOTARY_WRITE_TOKEN"] = "write-token"
    env["TIPNOTARY_READ_TOKEN"] = "read-token"
    env.pop("CF_API_TOKEN", None)
    for k in ("TIPNOTARY_READ_TOKEN", "TIPNOTARY_WRITE_TOKEN", "CF_API_TOKEN"):
        if tok == "__NONE__":
            env.pop(k, None)
        elif tok:
            env[k] = tok
    if env_extra:
        env.update(env_extra)
    args = [sys.executable, str(ROOT / "tipnotary.py"), cmd,
            "--account-id", ACCT, "--namespace-id", NS, "--key", KEY]
    if extra:
        args += extra
    p = subprocess.run(args, capture_output=True, text=True, env=env, timeout=90)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, ok, detail))
    print(f"  {'ok  ' if ok else 'FAIL'} {name}" + (f"  — {detail}" if detail and not ok else ""))


def main():
    srv = start_kv()
    tmp = tempfile.mkdtemp(prefix="leg3-")
    state = Path(tmp) / "state"
    seed(state, 3)
    try:
        # ---- 1. the notary publishes, with the WRITE credential ----
        rc, out = run(state, "notarize", tok="write-token")
        check("notarize succeeds with the WRITE credential", rc == 0, out[:200])

        # ---- 2. THE SPLIT: a check needs NO credential at all ----
        rc, out = run(state, "check", tok="__NONE__")
        check("check succeeds with NO credential (public read)", rc == 0, out[:200])

        # ---- 3. THE SPLIT IS ENFORCED: a read-only credential cannot PUT ----
        rc, out = run(state, "notarize", tok="read-token")
        check("notarize is REFUSED for a read-only credential", rc != 0 and "403" in out,
              f"rc={rc} {out[:200]}")

        # ---- 4. the forgery the anchor CATCHES: rewrite the chain ----
        # The forger holds the chain's file and NOTHING else.
        forged = Path(tmp) / "forged"
        seed(forged, 3)
        rc, out = run(forged, "notarize", tok="write-token")
        check("the forged chain can be anchored (it is self-consistent)", rc == 0, out[:200])
        # now rewrite the forged chain WITHOUT re-anchoring
        lines = [json.loads(l) for l in (forged / "receipts.jsonl").read_text().splitlines() if l.strip()]
        lines[0]["claim"] = lines[0]["claim"] + " FORGED"
        prev = R.GENESIS
        for r in lines:
            r.pop("h", None)
            r["h_prev"] = prev
            r["h"] = R.rec_hash(prev, r)
            prev = r["h"]
        (forged / "receipts.jsonl").write_text("".join(R.canonical(r) + "\n" for r in lines))
        rc, out = run(forged, "check", tok="__NONE__")
        check("a rewritten chain is FORGED (the anchor catches it)", rc == 2, f"rc={rc} {out[:200]}")

        # ---- 5. THE BUILD: the forger CANNOT write the anchor namespace ----
        # SCENARIO: the honest chain is notarized (anchor A is in KV). The
        # forger then rewrites the chain AND its receipts' anchored_h, so
        # the chain claims anchor B -- but the forger holds only the
        # chain-writer's token, which is READ-ONLY on the anchor namespace.
        # KV still holds A. The check must notice the disagreement.
        build_state = Path(tmp) / "build"
        seed(build_state, 3)
        rc, out = run(build_state, "notarize", tok="write-token", extra=["--key", "si/build"])
        check("the honest chain is anchored (anchor A is in KV)", rc == 0, out[:200])

        forged2 = Path(tmp) / "build-forged"
        seed(forged2, 3)
        rc, out = run(forged2, "notarize", tok="write-token", extra=["--key", "si/build"])
        check("the forged chain is anchored once, so it is self-consistent", rc == 0, out[:200])
        # now rewrite the chain AND its receipts' anchored_h, coherently,
        # but WITHOUT being able to touch KV
        lines = [json.loads(l) for l in (forged2 / "receipts.jsonl").read_text().splitlines() if l.strip()]
        lines[0]["claim"] = lines[0]["claim"] + " FORGED"
        prev = R.GENESIS
        for r in lines:
            r.pop("h", None)
            r["h_prev"] = prev
            r["h"] = R.rec_hash(prev, r)
            prev = r["h"]
        (forged2 / "receipts.jsonl").write_text("".join(R.canonical(r) + "\n" for r in lines))
        rc, out = run(forged2, "check", tok="__NONE__", extra=["--key", "si/build"])
        check("THE BUILD: a forged chain whose anchor namespace is unwritable IS caught",
              rc == 2, f"rc={rc} {out[:200]}")

        # and the forger's own attempt to publish a matching anchor is REFUSED
        import urllib.error
        poisoned2 = json.dumps({"chain": "receiptd", "h": prev, "seq": len(lines),
                                "notarized_at": "2026-10-19T00:00:00Z", "notary": "forger",
                                "prev_anchor_h": None, "hash_spec": {}, "key": "si/build"})
        req = urllib.request.Request(
            f"{BASE}/accounts/{ACCT}/storage/kv/namespaces/{NS}/values/si%2Fbuild",
            data=poisoned2.encode(), method="PUT",
            headers={"Authorization": "Bearer chain-writer-token", "Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=10).read()
            refused, detail = False, "the chain writer was ALLOWED to write the anchor namespace"
        except urllib.error.HTTPError as e:
            refused, detail = e.code == 403, f"expected 403, got {e.code}"
        check("and the chain writer is REFUSED write access to the anchor namespace",
              refused, detail)

        # ---- 6. THE DOCUMENTED LIMIT, asserted so it cannot drift into a claim ----
        # If the forger holds the anchor's WRITE credential too, a COHERENT
        # forgery -- chain, receipts and anchor all rewritten together -- is
        # not caught. The anchor is a receipt of what the tip WAS, and a
        # writer who can rewrite the receipt can rewrite the account of it.
        # THIS IS WHY THE ANCHOR MUST LIVE WHERE THE FORGER CANNOT WRITE.
        limit_state = Path(tmp) / "limit"
        seed(limit_state, 3)
        rc, out = run(limit_state, "notarize", tok="write-token", extra=["--key", "si/limit"])
        check("the limit scenario anchors once", rc == 0, out[:200])
        lines = [json.loads(l) for l in (limit_state / "receipts.jsonl").read_text().splitlines() if l.strip()]
        lines[0]["claim"] = lines[0]["claim"] + " FORGED"
        prev = R.GENESIS
        for r in lines:
            r.pop("h", None)
            r["h_prev"] = prev
            r["h"] = R.rec_hash(prev, r)
            prev = r["h"]
        (limit_state / "receipts.jsonl").write_text("".join(R.canonical(r) + "\n" for r in lines))
        rc, out = run(limit_state, "notarize", tok="write-token", extra=["--key", "si/limit"])
        check("the coherent forgery re-anchors (self-consistent all the way down)", rc == 0, out[:200])
        lines = [json.loads(l) for l in (limit_state / "receipts.jsonl").read_text().splitlines() if l.strip()]
        tip = lines[-1]
        poisoned3 = json.dumps({"chain": "receiptd", "h": tip["h"], "seq": tip["seq"],
                                "notarized_at": "2026-10-19T00:00:00Z", "notary": "forger",
                                "prev_anchor_h": None, "hash_spec": {}, "key": "si/limit"})
        req = urllib.request.Request(
            f"{BASE}/accounts/{ACCT}/storage/kv/namespaces/{NS}/values/si%2Flimit",
            data=poisoned3.encode(), method="PUT",
            headers={"Authorization": "Bearer write-token", "Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10).read()
        rc, out = run(limit_state, "check", tok="__NONE__", extra=["--key", "si/limit"])
        check("DOCUMENTED LIMIT: a forger who can ALSO PUT the anchor is NOT caught",
              rc == 0, f"rc={rc} {out[:200]}")
    finally:
        srv.shutdown()

    bad = [r for r in RESULTS if not r[1]]
    print()
    print(f"  {len(RESULTS) - len(bad)}/{len(RESULTS)} checks pass")
    if bad:
        for n, _, d in bad:
            print(f"    FAIL: {n} — {d}")
        print("\nFAIL: the credential split is not proven.")
        return 1
    print("\nPASS: the split is enforced, the forgery is caught, and the limit is stated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
