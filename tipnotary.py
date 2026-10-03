#!/usr/bin/env python3
"""tipnotary — anchor receiptd's chain tip in Cloudflare KV (external memory).

The limit it closes: `verify` proves a chain is SELF-consistent. A full-file
rewrite with recomputed hashes is self-consistent too — verify passes, the
forgery walks. An external anchor that holds the pre-rewrite tip makes the
rewrite detectable. Trust = re-execution; the anchor = someone else's receipt
of what the tip WAS.

Worked example:
  python3 tipnotary.py notarize
    -> TIPNOTARY OK seq=4 kv=match        (rc=0; receipt appended, KV anchored)
  python3 tipnotary.py check
    -> TIPNOTARY CHECK match tip=seq4     (rc=0)
  # ...forge: rewrite chain, recompute every hash, keep it self-consistent...
  python3 receiptd.py verify               # still passes! (the limit, demonstrated)
  python3 tipnotary.py check
    -> FORGED: anchor hash not present in local chain (rc=2)

Check is three-valued:
  rc=0 MATCH    anchor explains the tip (trailing receipts may only be
                `notarize` receipts that claim exactly this anchor)
  rc=3 STALE    chain advanced past the anchor by non-notarize receipts
                (healthy growth; re-run notarize to refresh)
  rc=2 FORGED   anchor hash absent/mismatched/behind: rewrite, KV poisoning,
                or rollback — fail loud, do not proceed

Anchor value (canonical JSON, byte-exact PUT/GET):
  {chain, h, seq, notarized_at, notary, prev_anchor_h,
   hash_spec:{fn:sha256, encoding:utf-8, unit:bytes, rule:...}}

Kill criteria (pre-registered, from the wardroom cross-hearing):
  kill-trial N over an IDLE chain: any readback!=write, any check!=MATCH,
  any receipt that fails to land -> KILL rc=2. 20 clean rounds = alive.

Config order: --flag > env > ~/.config/tipnotary/config.json
  {account_id, namespace_id};  token: env CF_API_TOKEN else key.txt at use-time.
Key: si/tip (URL-encoded si%2Ftip on the wire).
"""
import argparse, json, os, subprocess, sys, time, urllib.error, urllib.parse, urllib.request
from pathlib import Path

import receiptd as R

DEFAULT_KEY = "si/tip"  # override: --key / env TIPNOTARY_KEY / config.json "key"
HASH_SPEC = {
    "fn": "sha256", "encoding": "utf-8", "unit": "bytes",
    "rule": "h = sha256(h_prev + '\\n' + canonical(rec minus h))",
    "canonical": "json sort_keys compact separators",
}


def die(msg, rc=2):
    print(f"tipnotary: {msg}", file=sys.stderr)
    sys.exit(rc)


def load_config(args):
    cfg = {}
    p = Path.home() / ".config/tipnotary/config.json"
    if p.exists():
        cfg = json.loads(p.read_text())
    acct = args.account_id or os.environ.get("CF_ACCOUNT_ID") or cfg.get("account_id")
    ns = args.namespace_id or os.environ.get("TIPNOTARY_KV_NS") or cfg.get("namespace_id")
    key = args.key or os.environ.get("TIPNOTARY_KEY") or cfg.get("key") or DEFAULT_KEY
    if not acct:
        die("no account_id (flag --account-id / env CF_ACCOUNT_ID / config.json)")
    if not ns:
        die("no namespace_id (flag --namespace-id / env TIPNOTARY_KV_NS / config.json)")
    return acct, ns, key


def load_token():
    tok = os.environ.get("CF_API_TOKEN", "").strip()
    if tok:
        return tok
    for line in Path("/mnt/c/Users/casey/key.txt").read_text().splitlines():
        if line.startswith("CF_API_TOKEN"):
            tok = line.split("=", 1)[1].strip().strip('"').strip("'")
            break
    if not tok:
        die("no CF_API_TOKEN (env empty, key.txt line missing/empty)")
    return tok


def kv(acct, ns, tok, method, key, value=None):
    url = f"https://api.cloudflare.com/client/v4/accounts/{acct}/storage/kv/namespaces/{ns}/values/{urllib.parse.quote(key, safe='')}"
    req = urllib.request.Request(url, method=method,
                                 data=value.encode() if value is not None else None,
                                 headers={"Authorization": f"Bearer {tok}",
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:500]


def read_tip():
    """(h, seq) of last chain line, or (GENESIS, 0) on empty. O(block) tail."""
    store = R.STORE
    if not store.exists() or store.stat().st_size == 0:
        return R.GENESIS, 0
    with open(store, "rb") as f:
        f.seek(0, 2)
        end = f.tell()
        block = 65536
        while True:
            size = min(end, block)
            f.seek(end - size)
            lines = [l for l in f.read(size).split(b"\n") if l.strip()]
            if lines:
                rec = json.loads(lines[-1])
                return rec["h"], rec["seq"]
            if size >= end:
                return R.GENESIS, 0
            block *= 4


def chain_view():
    """One O(chunk) pass: recs at/below any seq by need -> dict seq->rec (small chains) + tip."""
    tip_h, tip_seq = read_tip()
    return tip_h, tip_seq


def rec_at_seq(seq):
    if seq <= 0:
        return None
    with open(R.STORE) as f:
        for line in f:
            line = line.strip()
            if line:
                r = json.loads(line)
                if r["seq"] == seq:
                    return r
    return None


def i2i_token():
    p = Path.home() / ".config/i2i/i2i-token"
    t = p.read_text().strip() if p.exists() else ""
    if not t:
        die("no i2i token at ~/.config/i2i/i2i-token (twin mode)")
    return t


def i2i_curl(method, path, body=None):
    """i2i MUST go through curl — Cloudflare 403s urllib (error 1010, lesson in memory)."""
    tok = i2i_token()
    cmd = ["curl", "-s", "-m", "30",
           "https://i2i-ledger.casey-digennaro.workers.dev" + path,
           "-H", f"Authorization: Bearer {tok}"]
    if body is not None:
        cmd += ["-X", method, "-H", "Content-Type: application/json", "-d", json.dumps(body)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        die(f"i2i curl failed rc={r.returncode}: {r.stderr[:150]}")
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        die(f"i2i curl returned non-JSON: {r.stdout[:150]}")


def i2i_book(gist, receipt_url, books_to):
    out = i2i_curl("POST", "/book", {"agent": "lucineer", "gist": gist,
                                      "receipt_url": receipt_url, "books_to": books_to})
    if not out.get("ok") or not out.get("id"):
        die(f"i2i book refused: {json.dumps(out)[:200]}")
    return out["id"]


def i2i_near(q):
    try:
        return i2i_curl("GET", "/near?q=" + urllib.parse.quote(q, safe=""))
    except SystemExit:
        return {"error": "near failed"}


def do_check(acct, ns, tok, key, quiet=False):
    ok, info = R.verify_chain()
    if not ok:
        die(f"chain verify FAILED before check: {info}")
    tip_h, tip_seq = read_tip()
    st, body = kv(acct, ns, tok, "GET", key)
    if st == 404:
        die(f"no anchor in KV (key {key} missing) — run notarize first")
    if st != 200:
        die(f"KV GET failed: HTTP {st} {body[:200]}")
    try:
        a = json.loads(body)
    except json.JSONDecodeError:
        die("KV anchor not JSON — poisoned or foreign writer")
    for k in ("h", "seq"):
        if k not in a:
            die(f"anchor missing field {k} — poisoned or foreign writer")
    if a["seq"] > tip_seq:
        die(f"FORGED: anchor ahead of chain (anchor seq={a['seq']} > tip seq={tip_seq}) — fork or rollback")
    if a["seq"] == 0:
        if a["h"] != R.GENESIS:
            die("FORGED: anchor claims empty chain but hash is not genesis")
    else:
        r = rec_at_seq(a["seq"])
        if r is None or r["h"] != a["h"]:
            die(f"FORGED: anchor hash not present in local chain at seq={a['seq']} "
                f"— file rewritten + re-derived (self-consistent forgery) or KV poisoned")
    unanchored = 0
    for j in range(a["seq"] + 1, tip_seq + 1):
        r = rec_at_seq(j)
        if r["verb"] != "notarize":
            unanchored += 1
            continue
        ev = r.get("evidence") or {}
        if ev.get("anchored_h") != a["h"]:
            die(f"FORGED: KV edited after the fact — receipt seq={j} claims anchor "
                f"{str(ev.get('anchored_h'))[:12]}…, KV holds {a['h'][:12]}…")
    if unanchored:
        print(f"TIPNOTARY CHECK stale tip=seq{tip_seq} anchor=seq{a['seq']} "
              f"unanchored={unanchored} — re-run notarize")
        sys.exit(3)
    twin_state = ""
    w = a.get("i2i_witness")
    if w:
        hits = i2i_near(tip_h[:24])
        rows = hits.get("results") or hits.get("hits") or hits.get("rows") or []
        found = any(json.dumps(r).find(tip_h[:24]) >= 0 or r.get("id") == w.get("id") for r in rows)
        if found:
            twin_state = " twin=confirmed"
        else:
            twin_state = " twin=unverified(search)"  # informational; ledger row remains the witness
        if not w.get("id"):
            die("FORGED: anchor claims i2i witness but carries no witness id")
    if not quiet:
        print(f"TIPNOTARY CHECK match tip=seq{tip_seq} anchor=seq{a['seq']}{twin_state}")
    return a


def do_notarize(acct, ns, tok, key, twin=False):
    ok, info = R.verify_chain()
    if not ok:
        die(f"chain verify FAILED, refusing to anchor a broken chain: {info}")
    tip_h, tip_seq = read_tip()
    st, prev_body = kv(acct, ns, tok, "GET", key)
    prev_h = None
    if st == 200:
        try:
            prev_h = json.loads(prev_body).get("h")
        except json.JSONDecodeError:
            prev_h = "UNPARSEABLE"
    witness = None
    if twin:
        wid = i2i_book(
            f"receiptd tip anchor seq={tip_seq} h={tip_h[:24]} (sha256-utf8; twin witness of KV {key})",
            "https://github.com/SuperInstance/receiptd", "tipnotary")
        witness = {"id": wid, "booked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    anchor = {"chain": "receiptd", "h": tip_h, "seq": tip_seq,
              "notarized_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "notary": "tipnotary-1", "prev_anchor_h": prev_h, "hash_spec": HASH_SPEC,
              "key": key}
    if witness:
        anchor["i2i_witness"] = witness
    val = R.canonical(anchor)
    st, body = kv(acct, ns, tok, "PUT", key, value=val)
    if st not in (200, 201):
        die(f"KV PUT failed: HTTP {st} {body[:200]}")
    st2, back = kv(acct, ns, tok, "GET", key)
    if st2 != 200:
        die(f"KV readback GET failed: HTTP {st2} {back[:200]}")
    if back != val:
        die(f"KV readback != write (PUT {len(val)}B, GET {len(back)}B) — KV not telling the truth")
    rec = R.append_rec({"lane": "tipnotary", "corr": f"anchor-{tip_seq}", "verb": "notarize",
                        "claim": f"anchored tip {tip_h[:12]}… seq={tip_seq} in KV ns={ns} key={key} kv=match"
                                 + (f" twin=i2i:{witness['id'][:8]}…" if witness else ""),
                        "v": 1,
                        "evidence": {"anchored_h": tip_h, "anchored_seq": tip_seq,
                                     "prev_anchor_h": prev_h, "kv_readback": "exact-match",
                                     **({"i2i_witness": witness} if witness else {})}})
    print(f"TIPNOTARY OK seq={tip_seq} kv=match receipt=seq{rec['seq']}"
          + (f" twin={witness['id'][:8]}…" if witness else ""))
    return anchor


def do_kill_trial(acct, ns, tok, key, n):
    for i in range(1, n + 1):
        h_before, s_before = read_tip()
        do_notarize(acct, ns, tok, key)
        a = do_check(acct, ns, tok, key, quiet=True)
        h_after, s_after = read_tip()   # tip advanced by the receipt itself
        if a["h"] != h_before or a["seq"] != s_before:
            die(f"KILL round {i}: anchor {a['h'][:12]}… != pre-round tip {h_before[:12]}…")
        if s_after != s_before + 1:
            die(f"KILL round {i}: tip seq moved {s_before}->{s_after} — unexpected append count during trial")
        print(f"  round {i}/{n}: anchored seq={s_before} check=match receipt=+1")
    print(f"TIPNOTARY KILL-TRIAL alive: {n}/{n} rounds, 0 kills, chain +{n}")
    return 0


def do_forge(acct, ns, tok, key):
    """THE LIMIT FINDER: self-consistent forgery passes verify, fails check.
    Guarded: only explicit test dirs, only with the flag."""
    sp = str(R.STORE.resolve())
    if not any(w in sp.lower() for w in ("test", "forgery")):
        die("forge-test refuses: state dir must contain 'test'/'forgery'")
    if not args.i_know_this_rewrites_the_chain:
        die("forge-test requires --i-know-this-rewrites-the-chain")
    lines = [json.loads(l) for l in R.STORE.read_text().splitlines() if l.strip()]
    if len(lines) < 2:
        die("need >=2 receipts to forge")
    lines[0]["claim"] = lines[0]["claim"] + " FORGED-CLAIM"
    prev = R.GENESIS
    for r in lines:
        r.pop("h", None)
        r["h_prev"] = prev
        r["h"] = R.rec_hash(prev, r)
        prev = r["h"]
    R.STORE.write_text("".join(R.canonical(r) + "\n" for r in lines))
    ok, info = R.verify_chain()
    print(f"forge: rewrote {len(lines)} receipts, recomputed every hash")
    print(f"forge: local verify on forged chain -> {'PASS (the limit: self-consistency is not truth)' if ok else f'FAIL {info}'}")
    if not ok:
        die("forgery did not pass verify — nothing demonstrated")
    st_body = kv(acct, ns, tok, "GET", key)
    print(f"forge: tipnotary check ->", end=" ")
    rc = do_check_or_capture(acct, ns, tok, key)
    if rc == 2:
        print(f"forge: LIMIT DEMONSTRATED — verify blind, notary sighted (rc=2)")
        return 0
    die(f"forge-test expected rc=2, got {rc} — check is not doing its job")


def do_check_or_capture(acct, ns, tok, key):
    try:
        do_check(acct, ns, tok, key)
        return 0
    except SystemExit as e:
        return e.code


def main():
    global args
    ap = argparse.ArgumentParser(prog="tipnotary", description="anchor receiptd's tip in CF KV")
    ap.add_argument("cmd", choices=["notarize", "check", "kill-trial", "forge-test"])
    ap.add_argument("--state-dir", help="override SI_STATE_DIR (receiptd state)")
    ap.add_argument("--account-id")
    ap.add_argument("--namespace-id")
    ap.add_argument("--key", help=f"KV key (default {DEFAULT_KEY})")
    ap.add_argument("--twin", action="store_true", help="also book the anchor into the i2i ledger (second witness, second domain)")
    ap.add_argument("--rounds", type=int, default=20, help="kill-trial rounds")
    ap.add_argument("--i-know-this-rewrites-the-chain", action="store_true")
    args = ap.parse_args()
    if args.state_dir:
        os.environ["SI_STATE_DIR"] = args.state_dir
        R.STATE_DIR = Path(args.state_dir)
        R.STORE = R.STATE_DIR / "receipts.jsonl"
        R.SOCK = R.STATE_DIR / "receiptd.sock"
    acct, ns, key = load_config(args)
    tok = load_token()
    if args.cmd == "notarize":
        sys.exit(do_notarize(acct, ns, tok, key, twin=args.twin) and 0)
    if args.cmd == "check":
        do_check(acct, ns, tok, key)
    if args.cmd == "kill-trial":
        sys.exit(do_kill_trial(acct, ns, tok, key, max(1, args.rounds)))
    if args.cmd == "forge-test":
        sys.exit(do_forge(acct, ns, tok, key))


if __name__ == "__main__":
    main()
