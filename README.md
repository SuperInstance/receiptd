# receiptd

> **The fleet's trust layer. One append-only hash chain. Trust = re-execution.**

Slice 1 is headless and pinned: a daemon + CLI twin over one JSONL file.
Tamper a byte → `verify` names the line. Delete a line → `verify` names the
gap. That is the whole contract, and 12/12 pins hold it.

Born 2026-10-02 from a four-model ideation convergence on what
SuperInstance/open-terminal should become — every model independently arrived
at `receiptd` first. Full trail:
`quilt-gpu-lab/scratch/open_terminal/ideation/SYNTHESIS.md`.

## Quickstart

```sh
python3 receiptd.py serve &          # or skip: the CLI auto-spawns it
python3 receiptd.py append --lane lane-a --corr t1 --verb ask --claim "deploy the gate" --v 0
python3 receiptd.py verify           # rc=2 if the chain was touched
```

## The pins are the README

```sh
SI_STATE_DIR=./test python3 pins_receipt.py   # FAIL-first, 12/12 GREEN
```

Read `SKILL.md` for the interface, the gotchas, and slice 2.
Verdicts are three-valued or nothing: `-1, 0, +1`. INCONCLUSIVE is a
first-class state — a gate that can't say UNKNOWN will lie to you.

## The credential split — and the limit that makes it mean something

`tipnotary` closes the third leg. A chain that re-derives proves only
**self-consistency**, so a full rewrite with recomputed hashes also
verifies — `verify` passes and the forgery walks. An external anchor
catches that, **but only if the person rewriting the chain cannot rewrite
the anchor.** The account is the unit of control.

So the two verbs are two credentials:

| | credential | may |
|---|---|---|
| `notarize` | `TIPNOTARY_WRITE_TOKEN` (or `CF_API_TOKEN`) | GET + PUT |
| `check` | `TIPNOTARY_READ_TOKEN` — **or none at all** | GET only |

A verifier that can only GET cannot be coerced into agreeing with a
forgery. A verifier that holds **both** can, and then the anchor proves
nothing. That is not a bug in the file; it is the shape of the property.

**AND IT IS TESTED, OFFLINE, AGAINST A DOUBLE THAT ENFORCES PERMISSIONS:**

```bash
python3 scripts/fake_kv.py --port 8799     # a local KV with per-token rules
python3 scripts/leg3_test.py                # 12 checks, no account needed
```

`scripts/fake_kv.py` is an oracle, not a mock: a double that ignored
permissions could not answer the question, and would make the whole thing
decoration. The test asserts all four of these, and each of them **fails
on the pre-split code**:

- a `check` needs **no credential** (public read);
- a read-only credential is **refused** a PUT — the split is enforced by
  the credential's permissions, not by which variable a token came from;
- a forged chain **is caught** when the anchor namespace is unwritable by
  the forger — **this is the build**;
- and a **coherent** forgery by a holder of both credentials is **not**
  caught — **this is the documented limit, asserted so it cannot drift
  into a claim.**

The limit is why the anchor has to live in a namespace the chain-writer
cannot write. That is the whole of the third leg, and it needs no second
account — only a second credential.
