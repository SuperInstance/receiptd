---
name: receiptd
description: The fleet's trust layer — one append-only JSONL hash chain, daemon + CLI twin over a unix socket. Trust = re-execution; tamper a byte and verify names the line. Use when agent claims need receipts, threads need corr links, or audits need teeth.
---

# receiptd — the fleet's trust layer

Slice 1 (headless), born 2026-10-02 from the open-terminal ideation convergence:
all four models independently landed here. **The terminal is a view; the chain
is the product.**

- **One append-only JSONL file** (`~/.local/state/si/receipts.jsonl`), SHA-256
  hash chain: `h = sha256(h_prev + "\n" + canonical(rec))`, canonical = sorted
  keys, compact. Genesis `h_prev` = 64 zeros. The file is self-verifying.
- **Three-valued or nothing**: `v ∈ {-1, 0, +1}` — refused otherwise. (The
  ternary ensign's one survivor.)
- **corr threads**: every receipt carries a correlation id; `by-corr` returns
  the whole dialog — replay/repair is a chain lookup, not a scrollback parse.
- **Verify re-derives from disk** (O(chunk)): catches tampered content (hash
  mismatch, names the line), deletions (seq gap, names it), and rewrites
  (broken prev-links). Disk is the source of truth; the daemon's index is a view.

## Run it

```sh
python3 receiptd.py serve                     # the daemon (or let the CLI auto-spawn it)
python3 receiptd.py append --lane lane-a --corr t1 --verb ask --claim "run the gate" --v 0
python3 receiptd.py by-corr t1                # the thread
python3 receiptd.py verify                    # re-derive the whole chain (rc=2 on tamper)
python3 receiptd.py tail 5 ; python3 receiptd.py stats
SI_STATE_DIR=./test-dir python3 pins_receipt.py   # 12/12 pins, fail-first
```

Any agent that can `write()` to a unix socket can use it — NDJSON, one request
per line, one reply per line: `{"op":"append","rec":{...}}` →
`{"ok":true,"seq":N,"h":…}`. Errors reply `{"ok":false,"error":…}` and the
connection survives.

## Gotchas (each cost a pin run)

- **Store handle must be `"ab+"`** — `"a"` is write-only (`not readable` on the
  second append), text-mode breaks the bytes-based tail scan (`str.split(b"\n")`
  → TypeError). Binary in, binary out; writes are O_APPEND-atomic.
- **`global SOCK` before any use in main()** — the CLI died at parse time once
  already; fail-first pins caught it in under a second.
- Socket is `0600`; the daemon is per-user. `SI_STATE_DIR` relocates everything
  (pins use it for isolated dirs).
- The daemon's index is a VIEW — if someone appends to the file directly,
  `stats`/`by-corr` may lag until restart; `verify` never lies (re-derives).

## Slice 1.5 LIVE — tipnotary (external memory, 2026-10-02)

`verify` proves a chain is SELF-consistent. A full-file rewrite with every hash
recomputed is self-consistent too — verify passes and the forgery walks.
Demonstrated live: 23 receipts rewritten+re-derived → `verify` = `verified:true`.
That is verify's limit; tipnotary is the closure.

```sh
python3 tipnotary.py notarize        # verify → tip → KV PUT anchor → GET byte-readback → receipt
python3 tipnotary.py check           # rc=0 MATCH | rc=3 STALE (legit growth; re-notarize) | rc=2 FORGED (named)
SI_STATE_DIR=./test-tipnotary python3 tipnotary.py kill-trial --rounds 20
SI_STATE_DIR=./test-tipnotary python3 tipnotary.py forge-test --i-know-this-rewrites-the-chain
TIPNOTARY_KEY=test/tip python3 pins_tipnotary.py   # 9/9 pins, LIVE KV, isolated key/dir
```

- **Anchor** = canonical JSON `{chain, h, seq, notarized_at, notary, prev_anchor_h,
  hash_spec:{fn,encoding,unit,rule}, key}` at KV key `si/tip` (config: flag > env >
  `~/.config/tipnotary/config.json`; token read at use-time, never stored).
- **hash_spec anchors the SPELLING** — ours is `sha256/utf-8/bytes`; a distant cousin
  chain (quilt-dba's fnv1a64) hashes UTF-16 charCodeAt. Same names, different bytes.
  The spec field makes the difference machine-checkable, per the wardroom byte-mandate.
- **Verb taxonomy (slice 1.5)**: `built` / `planned` / `d12-forced` split — a plan and a
  build never share a verb; `notarize` receipts carry `evidence.anchored_h` so the
  writer's claim is re-derivable from KV (the self-check rider, embodied).
- **Check is three-valued like v**: MATCH / STALE / FORGED — a gate that can't say
  STALE will lie to you.
- **T5 is the load-bearing pin**: forgery must pass `verify` AND fail `check`. If T5
  goes red the notary is decoration.
- Gotchas: the receipt changes the tip it anchored (assert seq advance, not hash
  equality — third bite of convention-by-construction); pins must use an isolated
  TIPNOTARY_KEY or they clobber the production anchor; CF KV keys need `%2F` encoding
  on the wire (`si/tip`); the new CF token's account differs from old wrangler.toml
  `account_id` — resolve the account from `/accounts`, not from stale tomls.

## Slice 2 (the road)

- `receipt verify-exec <hash>` — spawn champion_audit in a sandbox lane, write
  a DERIVATIVE receipt with `re: <parent>` (never mutate the parent). Audit
  the audits.
- OSC 1338 envelope tap (tmux pipe-pane) → agents join with zero SDK.
- fleetd lanes: this daemon behind a stateless broker; terminal as read-only
  subscriber.

## Neighbors

jeviter (the ledger doctrine that found receiptd's missing prev-link pin) ·
champion-audit (the re-execution ritual slice 2 wires) · superinstance-api
(`witness_get` — the fleet-scale honesty surface) · quilt-gpu-lab (the
experiment law these pins follow) · git-agent (quilt_emit, the WAL ancestry).
