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
